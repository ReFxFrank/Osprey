//! Conversions from sampled values to the generated protocol bodies.
//!
//! Kept apart from both the sampler and the session loop because this is the
//! one place where the parallel-array layout the schema uses has to line up
//! exactly — a length mismatch between `disk_labels` and `disk_used_bytes`
//! would mislabel every volume on the client, and nothing downstream could
//! detect it.

use osprey_proto::{MetricsHistoryBody, MetricsTickBody};
use uuid::Uuid;

use crate::metrics::ring::History;
use crate::metrics::Sample;

/// One live sample as a `metrics.tick` body.
pub fn tick_body(sub: Uuid, sample: &Sample) -> MetricsTickBody {
    let mut disk_labels = Vec::with_capacity(sample.disks.len());
    let mut disk_used_bytes = Vec::with_capacity(sample.disks.len());
    let mut disk_total_bytes = Vec::with_capacity(sample.disks.len());
    for disk in &sample.disks {
        disk_labels.push(disk.label.clone());
        disk_used_bytes.push(disk.used_bytes);
        disk_total_bytes.push(disk.total_bytes);
    }

    MetricsTickBody {
        sub,
        ts: sample.ts_ms,
        cpu_percent: sample.cpu_percent,
        mem_used_bytes: sample.mem_used_bytes,
        mem_total_bytes: sample.mem_total_bytes,
        disk_labels,
        disk_used_bytes,
        disk_total_bytes,
        net_rx_bytes_per_sec: sample.net_rx_bytes_per_sec,
        net_tx_bytes_per_sec: sample.net_tx_bytes_per_sec,
    }
}

/// A stored run as a `metrics.history` body.
///
/// `history` is `None` when the ring has nothing in range, which is an ordinary
/// state on a freshly started service. The body then carries empty arrays and a
/// zero `start_ts` — explicitly no data, which the client renders as an empty
/// chart rather than as a flat line at zero. `mem_total_bytes` is likewise
/// `None` until something has been sampled, because an unknown capacity must
/// not arrive as a measured zero.
pub fn history_body(
    sub: Uuid,
    history: Option<&History>,
    mem_total_bytes: Option<u64>,
) -> MetricsHistoryBody {
    let Some(history) = history else {
        return MetricsHistoryBody {
            sub,
            start_ts: 0,
            interval_ms: crate::metrics::RING_INTERVAL_MS,
            cpu_percent: Vec::new(),
            mem_used_bytes: Vec::new(),
            mem_total_bytes,
            net_rx_bytes_per_sec: Vec::new(),
            net_tx_bytes_per_sec: Vec::new(),
        };
    };

    let len = history.samples.len();
    let mut cpu_percent = Vec::with_capacity(len);
    let mut mem_used_bytes = Vec::with_capacity(len);
    let mut net_rx_bytes_per_sec = Vec::with_capacity(len);
    let mut net_tx_bytes_per_sec = Vec::with_capacity(len);
    for sample in &history.samples {
        cpu_percent.push(sample.cpu_percent);
        mem_used_bytes.push(sample.mem_used_bytes);
        // Only samples with known rates are ever stored (see the engine), so
        // these are `Some` by construction. Should that ever change, the run
        // is truncated at the unknown rather than back-filled with a zero.
        let (Some(rx), Some(tx)) = (sample.net_rx_bytes_per_sec, sample.net_tx_bytes_per_sec)
        else {
            break;
        };
        net_rx_bytes_per_sec.push(rx);
        net_tx_bytes_per_sec.push(tx);
    }
    // Truncating the rate arrays without truncating the others would break the
    // one-entry-per-sample contract the client reads them under.
    let usable = net_rx_bytes_per_sec.len();
    cpu_percent.truncate(usable);
    mem_used_bytes.truncate(usable);

    MetricsHistoryBody {
        sub,
        start_ts: history.start_ts,
        interval_ms: history.interval_ms,
        cpu_percent,
        mem_used_bytes,
        // Capacity is a scalar in the schema, so it comes from the newest
        // sample rather than from any historical one: if a machine gained RAM
        // mid-window the current figure is the one that describes it now.
        mem_total_bytes: history
            .samples
            .last()
            .map_or(mem_total_bytes, |s| Some(s.mem_total_bytes)),
        net_rx_bytes_per_sec,
        net_tx_bytes_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{DiskUsage, RING_INTERVAL_MS};

    fn sample(ts_ms: i64) -> Sample {
        Sample {
            ts_ms,
            cpu_percent: 42.5,
            mem_used_bytes: 8,
            mem_total_bytes: 16,
            disks: vec![
                DiskUsage {
                    label: "C:".to_owned(),
                    used_bytes: 1,
                    total_bytes: 2,
                },
                DiskUsage {
                    label: "D:".to_owned(),
                    used_bytes: 3,
                    total_bytes: 4,
                },
            ],
            net_rx_bytes_per_sec: Some(5),
            net_tx_bytes_per_sec: Some(6),
        }
    }

    #[test]
    fn the_disk_arrays_stay_parallel_and_ordered() {
        let body = tick_body(Uuid::nil(), &sample(1_000));
        assert_eq!(body.disk_labels.len(), body.disk_used_bytes.len());
        assert_eq!(body.disk_labels.len(), body.disk_total_bytes.len());
        assert_eq!(body.disk_labels, ["C:", "D:"]);
        assert_eq!(body.disk_used_bytes, [1, 3]);
        assert_eq!(body.disk_total_bytes, [2, 4]);
    }

    #[test]
    fn a_tick_carries_the_sample_clock_not_the_send_clock() {
        let body = tick_body(Uuid::nil(), &sample(1_700_000_000_000));
        assert_eq!(body.ts, 1_700_000_000_000);
    }

    #[test]
    fn an_absent_history_is_empty_rather_than_zero_filled() {
        let body = history_body(Uuid::nil(), None, Some(16));
        assert!(body.cpu_percent.is_empty());
        assert!(body.mem_used_bytes.is_empty());
        assert!(body.net_rx_bytes_per_sec.is_empty());
        assert!(body.net_tx_bytes_per_sec.is_empty());
        assert_eq!(body.start_ts, 0);
        assert_eq!(
            body.mem_total_bytes,
            Some(16),
            "capacity is known even with no history"
        );
    }

    #[test]
    fn unknown_installed_memory_is_absent_rather_than_zero() {
        let body = history_body(Uuid::nil(), None, None);
        assert_eq!(
            body.mem_total_bytes, None,
            "a zero here would be indistinguishable from a real reading"
        );
    }

    #[test]
    fn an_unknown_rate_is_absent_on_a_tick_rather_than_zero() {
        let mut unknown = sample(1_000);
        unknown.net_rx_bytes_per_sec = None;
        unknown.net_tx_bytes_per_sec = None;
        let body = tick_body(Uuid::nil(), &unknown);
        assert_eq!(body.net_rx_bytes_per_sec, None);
        assert_eq!(body.net_tx_bytes_per_sec, None);
        // The rest of the sample is still a real measurement and must survive.
        assert_eq!(body.cpu_percent, 42.5);
        assert_eq!(body.mem_total_bytes, 16);
    }

    #[test]
    fn every_history_array_has_one_entry_per_sample() {
        let history = History {
            start_ts: 1_000,
            interval_ms: RING_INTERVAL_MS,
            samples: vec![sample(1_000), sample(31_000), sample(61_000)],
        };
        let body = history_body(Uuid::nil(), Some(&history), None);
        assert_eq!(body.cpu_percent.len(), 3);
        assert_eq!(body.mem_used_bytes.len(), 3);
        assert_eq!(body.net_rx_bytes_per_sec.len(), 3);
        assert_eq!(body.net_tx_bytes_per_sec.len(), 3);
        assert_eq!(body.start_ts, 1_000);
        assert_eq!(body.interval_ms, RING_INTERVAL_MS);
    }

    #[test]
    fn a_decimated_interval_is_carried_through_verbatim() {
        // The client multiplies this by the sample index; passing the ring's
        // native cadence instead would compress a decimated chart 6x.
        let history = History {
            start_ts: 0,
            interval_ms: RING_INTERVAL_MS * 6,
            samples: vec![sample(0), sample(180_000)],
        };
        let body = history_body(Uuid::nil(), Some(&history), None);
        assert_eq!(body.interval_ms, RING_INTERVAL_MS * 6);
    }
}
