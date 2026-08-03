//! M-01: whole-machine telemetry.
//!
//! Three pieces, deliberately separated: [`collect`] reads the platform's
//! counters, [`ring`] keeps 24 h of them, and [`engine`] owns the sampling
//! thread and the subscriber it feeds.
//!
//! ## Why the ring's cadence is fixed at 30 s regardless of the live rate
//!
//! `metrics.history` locates every sample as `start_ts + N * interval_ms`
//! rather than carrying a timestamp array, because a per-sample timestamp
//! would roughly double a backfill that already has to fit inside one
//! session message. That only works if the stored cadence is constant — so
//! the live 1 Hz stream is *pushed* to the subscriber and only every 30 s
//! sample is *stored*. Subscribing does not change the shape of history.

pub mod collect;
pub mod engine;
pub mod ring;
pub mod wire;

pub use engine::{MetricsEngine, Subscription};
pub use ring::{History, RingBuffer, RING_CAPACITY, RING_INTERVAL_MS};

/// One volume's usage. Reported per tick rather than per history sample:
/// disk usage moves too slowly to chart and would triple the backfill size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskUsage {
    /// Volume label as the operator sees it, e.g. `C:`.
    pub label: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// One whole-machine observation.
///
/// Every field is a measured value. A counter the platform does not expose is
/// absent from the type entirely rather than defaulted — CLAUDE.md rule 9
/// forbids a plausible-looking zero, and a chart drawn from a fabricated zero
/// is indistinguishable from a real idle machine.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Wall clock at sampling, milliseconds since the Unix epoch.
    pub ts_ms: i64,
    /// Whole-machine utilisation across all logical processors, 0–100.
    pub cpu_percent: f64,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub disks: Vec<DiskUsage>,
    /// Bytes per second since the previous reading, aggregated over the
    /// machine's real interfaces.
    ///
    /// `None` means *unknown for this interval*, which is a different claim
    /// from zero: the set of interfaces changed, or an adapter's counters were
    /// reset, so the difference between the two readings describes nothing
    /// real. Reporting 0 there would be indistinguishable from an idle link,
    /// which is the fabricated value CLAUDE.md rule 9 forbids.
    pub net_rx_bytes_per_sec: Option<u64>,
    pub net_tx_bytes_per_sec: Option<u64>,
}

/// Why a sample could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// The platform has no implementation. Non-Windows builds exist so the
    /// crate compiles and tests run in CI; they never pretend to have data.
    #[error("metrics collection is not implemented on this platform")]
    Unsupported,
    /// Rates are differences between two readings, and the first reading of a
    /// counter has nothing to difference against. Reported rather than
    /// answered with a zero that would be indistinguishable from a genuinely
    /// idle machine.
    #[error("no baseline reading yet; the next sample will have one")]
    NoBaseline,
    #[error("{call} failed: {detail}")]
    Platform { call: &'static str, detail: String },
}

/// Milliseconds since the Unix epoch.
///
/// Shared with the session layer's notion of "now"; a clock before 1970 is
/// advisory-only nonsense rather than a reason to fail a sample.
pub fn now_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
