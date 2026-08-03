//! Whole-machine counters from Win32.
//!
//! Every symbol here was checked against the vendored `windows` 0.62 source
//! before use, because a plausible-looking signature that does not exist is
//! worse than no code (CLAUDE.md: do not fabricate APIs). Two shapes in
//! particular are not what they look like:
//!
//! * `MIB_IF_TABLE2` declares `Table: [MIB_IF_ROW2; 1]` but the kernel writes
//!   `NumEntries` rows past it — a C flexible array member that windows-rs
//!   models as a one-element array. Indexing it is out-of-bounds; the rows are
//!   reached by pointer arithmetic from the field's address.
//! * `GetSystemTimes`' "kernel" figure *includes* idle, so busy time is
//!   `(kernel + user) - idle`, not `kernel + user`.

use std::ffi::c_void;
use std::time::Instant;

use windows::core::PCWSTR;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_IF_ACCESS_LOOPBACK};
use windows::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::GetSystemTimes;
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;

use crate::metrics::{now_ms, DiskUsage, MetricsError, Sample};

/// Reads the counters, holding the previous reading so rates can be differenced.
pub struct Collector {
    previous_cpu: Option<CpuTimes>,
    previous_net: Option<NetCounters>,
}

#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    idle: u64,
    kernel: u64,
    user: u64,
}

#[derive(Debug, Clone)]
struct NetCounters {
    rx_bytes: u64,
    tx_bytes: u64,
    at: Instant,
    /// Which interfaces the totals were summed over, sorted.
    ///
    /// The totals are a sum over a *varying* set, not a monotonic counter: an
    /// adapter that goes down leaves the sum and takes its accumulated octets
    /// with it, and rejoins later still carrying them. Differencing across such
    /// a change measures membership, not traffic, so the membership is recorded
    /// and compared rather than trusted to be constant.
    interfaces: Vec<u32>,
}

/// Bit 1 of `MIB_IF_ROW2::InterfaceAndOperStatusFlags`, set on the pseudo-rows
/// Windows creates for each bound lightweight filter driver.
///
/// windows-rs models that field as an opaque `_bitfield: u8` with no accessors,
/// and the bit layout is not recoverable from the crate source, so this was
/// established by measurement on a stock Windows 11 host: every physical
/// adapter is accompanied by rows named "<adapter>-WFP Native MAC Layer
/// LightWeight Filter-0000", "-QoS Packet Scheduler-0000" and "-WFP 802.3 MAC
/// Layer LightWeight Filter-0000", each reporting `AccessType` broadcast,
/// `OperStatus` up, and the adapter's *own* `InOctets`/`OutOctets` verbatim.
/// Summing them with the adapter counted every byte four times and reported
/// throughput above the NIC's line rate. The real adapter rows carry 0x01
/// (HardwareInterface) and 0x04 (ConnectorPresent); the filter rows carry 0x02.
///
/// Filtering on this bit rather than on 0x01 is deliberate: requiring
/// HardwareInterface would also drop genuine virtual adapters, which do carry
/// real traffic the operator expects to see.
const FILTER_INTERFACE_FLAG: u8 = 0x02;

impl Collector {
    /// Reads a baseline immediately, so the *first* delivered sample already
    /// covers a real interval instead of reporting a rate nobody measured.
    pub fn new() -> Self {
        Self {
            previous_cpu: cpu_times().ok(),
            previous_net: net_counters().ok(),
        }
    }

    pub fn sample(&mut self) -> Result<Sample, MetricsError> {
        let cpu_now = cpu_times()?;
        let cpu_percent = match self.previous_cpu.replace(cpu_now) {
            // `None` here means the two readings landed inside one system
            // clock tick, so no processor time elapsed to apportion.
            Some(previous) => busy_percent(previous, cpu_now).ok_or(MetricsError::NoBaseline)?,
            // Only reachable when the baseline read in `new` failed. The next
            // sample has one, so this reports rather than fabricates a 0.
            None => return Err(MetricsError::NoBaseline),
        };

        let memory = memory_status()?;
        let net_now = net_counters()?;
        let (net_rx_bytes_per_sec, net_tx_bytes_per_sec) =
            match self.previous_net.replace(net_now.clone()) {
                Some(previous) => match rates(&previous, &net_now) {
                    Some((rx, tx)) => (Some(rx), Some(tx)),
                    None => (None, None),
                },
                None => return Err(MetricsError::NoBaseline),
            };

        Ok(Sample {
            ts_ms: now_ms(),
            cpu_percent,
            mem_used_bytes: memory.0,
            mem_total_bytes: memory.1,
            disks: fixed_volumes(),
            net_rx_bytes_per_sec,
            net_tx_bytes_per_sec,
        })
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

/// The two halves of a `FILETIME` as one count of 100 ns ticks. There is no
/// `From<FILETIME> for u64` in this crate version, and the struct must not be
/// transmuted: it is `#[repr(C)]` with 4-byte alignment.
fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn cpu_times() -> Result<CpuTimes, MetricsError> {
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all three pointers address live locals for the duration of the
    // call, which is the only thing the API requires of them.
    unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.map_err(
        |err| MetricsError::Platform {
            call: "GetSystemTimes",
            detail: err.to_string(),
        },
    )?;
    Ok(CpuTimes {
        idle: ticks(idle),
        kernel: ticks(kernel),
        user: ticks(user),
    })
}

/// Utilisation across the interval between two readings, 0–100.
///
/// Windows counts idle time inside the kernel figure, so total elapsed
/// processor time is `kernel + user` and the busy part is that minus idle.
/// Treating `kernel + user` as busy would report a permanently pegged machine.
///
/// `None` when no processor time elapsed between the readings — they landed
/// inside one ~15.6 ms system tick and the counters are identical. There is no
/// utilisation to report, and 0.0 would be a measurement nobody made. The
/// sampler's minimum spacing normally keeps this from arising at all.
fn busy_percent(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
    let kernel = current.kernel.saturating_sub(previous.kernel);
    let user = current.user.saturating_sub(previous.user);
    let idle = current.idle.saturating_sub(previous.idle);
    let total = kernel.saturating_add(user);
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle);
    // The clamp guards the case where the three counters are read a few ticks
    // apart and idle briefly exceeds the total.
    Some(((busy as f64 / total as f64) * 100.0).clamp(0.0, 100.0))
}

/// `(used, total)` physical memory in bytes.
fn memory_status() -> Result<(u64, u64), MetricsError> {
    let mut status = MEMORYSTATUSEX {
        // Mandatory: the API uses this to tell the struct versions apart and
        // fails outright when it is zero.
        dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).unwrap_or(u32::MAX),
        ..Default::default()
    };
    // SAFETY: `status` is a live, correctly sized local.
    unsafe { GlobalMemoryStatusEx(&mut status) }.map_err(|err| MetricsError::Platform {
        call: "GlobalMemoryStatusEx",
        detail: err.to_string(),
    })?;
    let used = status.ullTotalPhys.saturating_sub(status.ullAvailPhys);
    Ok((used, status.ullTotalPhys))
}

/// Usage for every fixed volume, skipping anything that cannot be queried.
///
/// A volume that refuses `GetDiskFreeSpaceExW` — BitLocker mid-unlock, a
/// failing disk — is omitted rather than reported as zero-sized, so the client
/// shows one fewer bar instead of a fake empty one.
fn fixed_volumes() -> Vec<DiskUsage> {
    // SAFETY: no arguments, no out-params; returns a bitmask.
    let mask = unsafe { GetLogicalDrives() };
    let mut volumes = Vec::new();
    for bit in 0..26u32 {
        if mask & (1 << bit) == 0 {
            continue;
        }
        let letter = char::from(b'A' + u8::try_from(bit).unwrap_or(0));
        // "C:\" plus the terminator, which every root-path argument requires.
        let root: [u16; 4] = [letter as u16, u16::from(b':'), u16::from(b'\\'), 0];
        let path = PCWSTR::from_raw(root.as_ptr());

        // SAFETY: `path` points at `root`, which outlives both calls.
        if unsafe { GetDriveTypeW(path) } != DRIVE_FIXED {
            continue;
        }
        let mut total: u64 = 0;
        let mut free: u64 = 0;
        // SAFETY: both out-params address live locals; the third is unused.
        let queried = unsafe {
            GetDiskFreeSpaceExW(
                path,
                None,
                Some(&mut total as *mut u64),
                Some(&mut free as *mut u64),
            )
        };
        if let Err(err) = queried {
            // Omitted rather than reported as zero-sized — but never silently,
            // because a volume that keeps disappearing from the operator's
            // dashboard is a symptom worth being able to find in the log.
            tracing::debug!(volume = %letter, error = %err, "skipping a volume whose free space could not be read");
            continue;
        }
        volumes.push(DiskUsage {
            label: format!("{letter}:"),
            used_bytes: total.saturating_sub(free),
            total_bytes: total,
        });
    }
    volumes
}

/// Frees the interface table on every exit path, including an early `?`.
struct IfTable(*mut MIB_IF_TABLE2);

impl Drop for IfTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a successful GetIfTable2 and is
            // freed exactly once, here.
            unsafe { FreeMibTable(self.0 as *const c_void) };
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Total octets in and out across the machine's real, connected interfaces.
fn net_counters() -> Result<NetCounters, MetricsError> {
    let rows = counted_rows()?;
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut interfaces = Vec::with_capacity(rows.len());
    for row in &rows {
        rx_bytes = rx_bytes.saturating_add(row.in_octets);
        tx_bytes = tx_bytes.saturating_add(row.out_octets);
        interfaces.push(row.index);
    }
    interfaces.sort_unstable();

    Ok(NetCounters {
        rx_bytes,
        tx_bytes,
        at: Instant::now(),
        interfaces,
    })
}

/// One interface that counts toward the machine's throughput.
#[derive(Debug, Clone, Copy)]
struct CountedRow {
    index: u32,
    in_octets: u64,
    out_octets: u64,
}

/// The rows [`net_counters`] sums, kept separate so the filtering rule itself
/// is testable rather than only its totals.
fn counted_rows() -> Result<Vec<CountedRow>, MetricsError> {
    let mut raw: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `raw` is a live local receiving an owned allocation.
    unsafe { GetIfTable2(&mut raw) }
        .ok()
        .map_err(|err| MetricsError::Platform {
            call: "GetIfTable2",
            detail: err.to_string(),
        })?;
    let table = IfTable(raw);
    if table.0.is_null() {
        return Err(MetricsError::Platform {
            call: "GetIfTable2",
            detail: "succeeded but returned no table".to_owned(),
        });
    }

    let mut rows = Vec::new();
    // SAFETY: the table is non-null and owned by `table`; `NumEntries` rows
    // follow the `Table` field contiguously. The rows are reached through the
    // field's address rather than by indexing `Table`, which is declared with
    // length 1 and would be an out-of-bounds access for every row after the
    // first.
    unsafe {
        let count = (*table.0).NumEntries as usize;
        let base = std::ptr::addr_of!((*table.0).Table) as *const MIB_IF_ROW2;
        for index in 0..count {
            let row = &*base.add(index);
            if row.AccessType == NET_IF_ACCESS_LOOPBACK || row.OperStatus != IfOperStatusUp {
                continue;
            }
            // Each bound filter driver gets a row mirroring its adapter's
            // octets. Counting them multiplies real throughput — measured at
            // exactly 4x on a stock Windows 11 host. See FILTER_INTERFACE_FLAG.
            if row.InterfaceAndOperStatusFlags._bitfield & FILTER_INTERFACE_FLAG != 0 {
                continue;
            }
            rows.push(CountedRow {
                index: row.InterfaceIndex,
                in_octets: row.InOctets,
                out_octets: row.OutOctets,
            });
        }
    }
    Ok(rows)
}

/// Bytes per second between two counter readings, or `None` when the pair
/// cannot be differenced into a throughput.
///
/// Three ways that happens, and all three are genuinely *unknown* rather than
/// zero:
///
/// * **The interface set changed.** The totals sum only interfaces that are
///   currently up, so an adapter joining or leaving moves the sum by its whole
///   accumulated octet count. The decrease case is obvious; the increase case
///   is the dangerous one, because a reconnecting adapter carries its retained
///   counters back into the sum and the naive difference looks like a
///   multi-gigabyte burst in one second. Both are caught here.
/// * **Counters were reset** by a driver reload, showing up as a decrease.
/// * **No time elapsed** between the readings.
///
/// Reporting 0 in any of these would put a point on the operator's chart
/// claiming an idle link, which is a measurement nobody took.
fn rates(previous: &NetCounters, current: &NetCounters) -> Option<(u64, u64)> {
    let elapsed = current.at.saturating_duration_since(previous.at).as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    if previous.interfaces != current.interfaces {
        tracing::info!(
            "the set of live network interfaces changed; this interval's throughput is unknown"
        );
        return None;
    }
    if current.rx_bytes < previous.rx_bytes || current.tx_bytes < previous.tx_bytes {
        tracing::warn!(
            "network counters went backwards; an adapter was reset, so this interval's throughput is unknown"
        );
        return None;
    }
    let rx = ((current.rx_bytes - previous.rx_bytes) as f64 / elapsed).round();
    let tx = ((current.tx_bytes - previous.tx_bytes) as f64 / elapsed).round();
    // `as` on a float saturates at the integer bounds in Rust and cannot be a
    // negative-to-huge wrap, because both operands above are non-negative.
    Some((rx as u64, tx as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_is_total_minus_idle_not_kernel_plus_user() {
        // One second of wall time on a machine that was idle for 3/4 of it.
        let previous = CpuTimes {
            idle: 0,
            kernel: 0,
            user: 0,
        };
        let current = CpuTimes {
            idle: 7_500_000,
            kernel: 7_500_000,
            user: 2_500_000,
        };
        let percent = busy_percent(previous, current).expect("time elapsed");
        assert!(
            (percent - 25.0).abs() < 0.001,
            "expected 25% busy, got {percent}"
        );
    }

    #[test]
    fn a_fully_idle_interval_reports_zero() {
        let previous = CpuTimes {
            idle: 0,
            kernel: 0,
            user: 0,
        };
        let current = CpuTimes {
            idle: 10_000_000,
            kernel: 10_000_000,
            user: 0,
        };
        assert_eq!(busy_percent(previous, current), Some(0.0));
    }

    #[test]
    fn a_fully_busy_interval_reports_one_hundred() {
        let previous = CpuTimes {
            idle: 0,
            kernel: 0,
            user: 0,
        };
        let current = CpuTimes {
            idle: 0,
            kernel: 2_000_000,
            user: 8_000_000,
        };
        assert_eq!(busy_percent(previous, current), Some(100.0));
    }

    #[test]
    fn two_readings_in_the_same_tick_report_unknown_not_idle() {
        let same = CpuTimes {
            idle: 5,
            kernel: 9,
            user: 3,
        };
        assert_eq!(
            busy_percent(same, same),
            None,
            "no elapsed processor time is unknown utilisation, not 0%"
        );
    }

    fn counters(rx: u64, tx: u64, at: Instant, interfaces: &[u32]) -> NetCounters {
        NetCounters {
            rx_bytes: rx,
            tx_bytes: tx,
            at,
            interfaces: interfaces.to_vec(),
        }
    }

    #[test]
    fn a_counter_reset_reports_unknown_rather_than_a_wrapped_spike() {
        let start = Instant::now();
        let previous = counters(1_000_000, 1_000_000, start, &[9]);
        let current = counters(12, 12, start + std::time::Duration::from_secs(1), &[9]);
        assert_eq!(rates(&previous, &current), None);
    }

    #[test]
    fn an_adapter_rejoining_the_sum_is_not_reported_as_a_burst() {
        // The dangerous half of a membership change: Wi-Fi reconnects carrying
        // the 2 GB it transferred before it dropped. The naive difference is a
        // 2 GB/s spike on a link that cannot do that.
        let start = Instant::now();
        let previous = counters(5_000, 5_000, start, &[9]);
        let current = counters(
            2_000_005_000,
            2_000_005_000,
            start + std::time::Duration::from_secs(1),
            &[9, 14],
        );
        assert_eq!(
            rates(&previous, &current),
            None,
            "a set change must read as unknown, not as throughput"
        );
    }

    #[test]
    fn rates_are_per_second_not_per_interval() {
        let start = Instant::now();
        let previous = counters(0, 0, start, &[9]);
        let current = counters(3_000, 6_000, start + std::time::Duration::from_secs(3), &[9]);
        assert_eq!(rates(&previous, &current), Some((1_000, 2_000)));
    }

    #[test]
    fn no_counted_interface_duplicates_another_interfaces_octets() {
        // Regression guard for a measured 4x throughput inflation. Windows
        // creates a pseudo-row per bound lightweight filter driver — "-WFP
        // Native MAC Layer LightWeight Filter-0000" and friends — and each
        // mirrors its adapter's octet counters *exactly*. That exact
        // duplication is the signature of the bug, and it is machine
        // independent in a way that counting rows is not.
        let rows = counted_rows().expect("interface table");
        for (position, row) in rows.iter().enumerate() {
            if row.in_octets == 0 {
                continue;
            }
            for other in &rows[position + 1..] {
                assert_ne!(
                    row.in_octets, other.in_octets,
                    "interfaces {} and {} report identical octet counts, so a filter \
                     pseudo-interface is being summed alongside its adapter",
                    row.index, other.index
                );
            }
        }
    }

    #[test]
    fn every_counted_interface_is_distinct() {
        let rows = counted_rows().expect("interface table");
        let mut indices: Vec<u32> = rows.iter().map(|row| row.index).collect();
        indices.sort_unstable();
        let counted = indices.len();
        indices.dedup();
        assert_eq!(counted, indices.len(), "an interface was counted twice");
    }

    #[test]
    fn the_machine_reports_real_memory() {
        let (used, total) = memory_status().expect("memory status");
        assert!(total > 0, "installed memory must be non-zero");
        assert!(used <= total, "used {used} exceeds total {total}");
    }

    #[test]
    fn at_least_one_fixed_volume_is_found() {
        let volumes = fixed_volumes();
        assert!(
            !volumes.is_empty(),
            "a Windows machine has at least one fixed volume"
        );
        for volume in &volumes {
            assert!(volume.total_bytes > 0, "{} reported no capacity", volume.label);
            assert!(volume.used_bytes <= volume.total_bytes);
        }
    }

    #[test]
    fn the_interface_table_reads_and_frees() {
        let first = net_counters().expect("interface table");
        let second = net_counters().expect("interface table again");
        assert!(
            second.rx_bytes >= first.rx_bytes,
            "octet counters must not go backwards within one test"
        );
    }

    #[test]
    fn a_collector_produces_a_whole_sample() {
        let mut collector = Collector::new();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let sample = collector.sample().expect("sample");
        assert!((0.0..=100.0).contains(&sample.cpu_percent));
        assert!(sample.mem_total_bytes > 0);
        assert!(sample.mem_used_bytes <= sample.mem_total_bytes);
        assert!(!sample.disks.is_empty());
    }
}
