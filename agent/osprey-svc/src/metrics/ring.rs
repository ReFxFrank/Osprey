//! The 24 h history ring and the decimation that makes it fit one message.

use std::collections::VecDeque;

use crate::metrics::Sample;

/// Spacing between stored samples. Also the `interval_ms` an undecimated
/// `metrics.history` reports.
pub const RING_INTERVAL_MS: u32 = 30_000;

/// 24 h at [`RING_INTERVAL_MS`] (brief M-01).
pub const RING_CAPACITY: usize = 2_880;

/// Upper bound on the samples one `metrics.history` may carry.
///
/// The session caps a reassembled message at 64 KiB. A history sample encodes
/// as four JSON numbers — cpu, memory, rx, tx — which is under 40 bytes
/// typically and about 70 in the worst case where every integer is 20 digits.
/// 512 samples is therefore ~36 KB worst case, comfortably inside the cap with
/// room for the envelope and the disk-free arrays. A full 24 h ring exceeds
/// this by 5.6×, so decimation is the normal path, not an edge case.
pub const MAX_HISTORY_SAMPLES: usize = 512;

/// Widest spacing two samples may have and still be declared consecutive at
/// [`RING_INTERVAL_MS`].
///
/// Sleep, hibernation and a service restart all leave a hole. Interpolating
/// across one would invent data; emitting a sentinel would need a value that
/// `u64` does not have. So a hole simply ends the run — see
/// [`RingBuffer::history`].
const MAX_STEP_MS: i64 = (RING_INTERVAL_MS as i64) * 3 / 2;

/// Narrowest spacing, for the same reason in the other direction.
///
/// The returned run is described by `start_ts + N * interval_ms` with no
/// per-sample timestamps, so a client cannot detect samples that were stored
/// closer together than the interval claims — it would just plot them at the
/// wrong times. Bounding the step on *both* sides makes the fixed-cadence
/// contract something this function verifies rather than something it assumes.
const MIN_STEP_MS: i64 = (RING_INTERVAL_MS as i64) / 2;

/// A contiguous, fixed-cadence run of samples ready to become a
/// `metrics.history` body.
#[derive(Debug, Clone, PartialEq)]
pub struct History {
    /// Timestamp of `samples[0]`.
    pub start_ts: i64,
    /// Spacing after decimation. Sample N is at `start_ts + N * interval_ms`.
    pub interval_ms: u32,
    pub samples: Vec<Sample>,
}

/// Fixed-capacity history, oldest evicted first.
#[derive(Debug)]
pub struct RingBuffer {
    samples: VecDeque<Sample>,
    capacity: usize,
}

impl RingBuffer {
    pub fn new() -> Self {
        Self::with_capacity(RING_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity.min(RING_CAPACITY)),
            capacity: capacity.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn push(&mut self, sample: Sample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// The most recent `backfill_seconds` of history, as one contiguous run.
    ///
    /// Walks backwards from the newest sample and stops at the first gap, so
    /// the returned run always satisfies the fixed-cadence contract the
    /// `metrics.history` body depends on. A client that asks for 24 h across a
    /// laptop's overnight sleep therefore gets everything since it woke, which
    /// is honest, rather than a chart with an invented flat line through the
    /// night.
    ///
    /// `None` when nothing is in range: the caller answers with empty arrays
    /// rather than an error, because "no history yet" is an ordinary state on
    /// a service that just started.
    pub fn history(&self, backfill_seconds: u32, now_ms: i64) -> Option<History> {
        if backfill_seconds == 0 {
            return None;
        }
        let horizon = now_ms.saturating_sub(i64::from(backfill_seconds).saturating_mul(1_000));

        let mut run: Vec<&Sample> = Vec::new();
        for sample in self.samples.iter().rev() {
            if sample.ts_ms < horizon {
                break;
            }
            if let Some(previous) = run.last() {
                let step = previous.ts_ms.saturating_sub(sample.ts_ms);
                if !(MIN_STEP_MS..=MAX_STEP_MS).contains(&step) {
                    break;
                }
            }
            run.push(sample);
        }
        if run.is_empty() {
            return None;
        }
        run.reverse();

        let factor = run.len().div_ceil(MAX_HISTORY_SAMPLES).max(1);
        let samples: Vec<Sample> = run.iter().step_by(factor).map(|s| (*s).clone()).collect();
        let start_ts = samples.first()?.ts_ms;

        Some(History {
            start_ts,
            // The cast cannot overflow in practice: `factor` is bounded by
            // RING_CAPACITY / MAX_HISTORY_SAMPLES, so the product stays far
            // inside u32 — but saturating rather than wrapping, because a
            // wrapped interval would silently mislocate every sample.
            interval_ms: RING_INTERVAL_MS.saturating_mul(u32::try_from(factor).unwrap_or(u32::MAX)),
            samples,
        })
    }

    /// The newest stored sample, if any.
    pub fn latest(&self) -> Option<&Sample> {
        self.samples.back()
    }
}

impl Default for RingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::DiskUsage;

    fn sample_at(ts_ms: i64, cpu: f64) -> Sample {
        Sample {
            ts_ms,
            cpu_percent: cpu,
            mem_used_bytes: 1_000,
            mem_total_bytes: 2_000,
            disks: vec![DiskUsage {
                label: "C:".to_owned(),
                used_bytes: 1,
                total_bytes: 2,
            }],
            net_rx_bytes_per_sec: Some(10),
            net_tx_bytes_per_sec: Some(20),
        }
    }

    /// Fills `count` samples ending at `end_ms`, spaced at the ring cadence.
    fn filled(count: usize, end_ms: i64) -> RingBuffer {
        let mut ring = RingBuffer::new();
        let step = i64::from(RING_INTERVAL_MS);
        for index in (0..count).rev() {
            let offset = step * i64::try_from(index).expect("test index fits");
            ring.push(sample_at(end_ms - offset, index as f64));
        }
        ring
    }

    #[test]
    fn evicts_the_oldest_sample_at_capacity() {
        let mut ring = RingBuffer::with_capacity(3);
        let step = i64::from(RING_INTERVAL_MS);
        for index in 0..5 {
            ring.push(sample_at(i64::from(index) * step, f64::from(index)));
        }
        assert_eq!(ring.len(), 3);
        let newest = 4 * step;
        assert_eq!(ring.latest().expect("non-empty").ts_ms, newest);
        let history = ring.history(3_600, newest).expect("history");
        assert_eq!(history.samples.len(), 3, "only the retained window survives");
        assert_eq!(history.start_ts, 2 * step);
    }

    #[test]
    fn samples_stored_closer_than_the_declared_cadence_end_the_run() {
        // The failure this guards is silent: the body has no per-sample
        // timestamps, so a run stored at 28 s but declared at 30 s would just
        // plot every point at the wrong time with nothing to detect it.
        let mut ring = RingBuffer::new();
        let step = i64::from(RING_INTERVAL_MS);
        ring.push(sample_at(0, 1.0));
        ring.push(sample_at(step, 1.0));
        // Then a burst far tighter than the declared interval.
        ring.push(sample_at(step + 1_000, 2.0));
        ring.push(sample_at(step + 2_000, 2.0));

        let history = ring.history(86_400, step + 2_000).expect("history");
        assert_eq!(
            history.samples.len(),
            1,
            "an off-cadence run must not be declared at the ring interval"
        );
    }

    #[test]
    fn an_empty_ring_has_no_history() {
        assert!(RingBuffer::new().history(3_600, 1_000).is_none());
    }

    #[test]
    fn a_zero_backfill_request_returns_nothing() {
        let ring = filled(10, 1_000_000);
        assert!(ring.history(0, 1_000_000).is_none());
    }

    #[test]
    fn history_is_chronological_and_starts_at_the_first_sample() {
        let now = 10_000_000;
        let ring = filled(10, now);
        let history = ring.history(3_600, now).expect("history");
        assert_eq!(history.interval_ms, RING_INTERVAL_MS);
        assert_eq!(history.samples.len(), 10);
        assert_eq!(history.start_ts, now - i64::from(RING_INTERVAL_MS) * 9);
        for (index, sample) in history.samples.iter().enumerate() {
            let expected = history.start_ts
                + i64::from(history.interval_ms) * i64::try_from(index).expect("fits");
            assert_eq!(sample.ts_ms, expected, "sample {index} is off-cadence");
        }
    }

    #[test]
    fn the_backfill_window_bounds_what_is_returned() {
        let now = 10_000_000;
        let ring = filled(100, now);
        // 5 minutes at a 30 s cadence is 10 samples, plus the one exactly on
        // the horizon.
        let history = ring.history(300, now).expect("history");
        assert!(
            history.samples.len() <= 11,
            "returned {} samples for a 5-minute window",
            history.samples.len()
        );
        assert!(history.start_ts >= now - 300_000);
    }

    #[test]
    fn a_gap_ends_the_run_rather_than_being_interpolated() {
        let mut ring = RingBuffer::new();
        let step = i64::from(RING_INTERVAL_MS);
        // Three samples, then a two-hour hole (a sleeping laptop), then three.
        for index in 0..3 {
            ring.push(sample_at(index * step, 1.0));
        }
        let after_gap = 3 * step + 7_200_000;
        for index in 0..3 {
            ring.push(sample_at(after_gap + index * step, 2.0));
        }

        let history = ring.history(86_400, after_gap + 2 * step).expect("history");
        assert_eq!(
            history.samples.len(),
            3,
            "the run must stop at the hole, not span it"
        );
        assert_eq!(history.start_ts, after_gap);
        assert!(
            history.samples.iter().all(|s| s.cpu_percent == 2.0),
            "only post-gap samples belong to the newest run"
        );
    }

    #[test]
    fn a_full_day_is_decimated_to_fit_one_message() {
        let now = 100_000_000;
        let ring = filled(RING_CAPACITY, now);
        let history = ring.history(86_400, now).expect("history");

        assert!(
            history.samples.len() <= MAX_HISTORY_SAMPLES,
            "{} samples exceeds the per-message bound",
            history.samples.len()
        );
        // The reported interval must describe the decimated spacing, or every
        // sample after the first is plotted at the wrong time.
        let factor = RING_CAPACITY.div_ceil(MAX_HISTORY_SAMPLES);
        assert_eq!(
            history.interval_ms,
            RING_INTERVAL_MS * u32::try_from(factor).expect("small factor")
        );
        let observed = history.samples[1].ts_ms - history.samples[0].ts_ms;
        assert_eq!(
            observed,
            i64::from(history.interval_ms),
            "reported interval must match the real spacing"
        );
    }

    #[test]
    fn a_decimated_history_still_spans_the_whole_window() {
        let now = 100_000_000;
        let ring = filled(RING_CAPACITY, now);
        let history = ring.history(86_400, now).expect("history");
        let last = history.samples.last().expect("non-empty");
        let span = last.ts_ms - history.start_ts;
        // Decimation drops at most `factor - 1` samples off the end, so the
        // covered span must still be within one decimated interval of 24 h.
        assert!(
            span >= 86_400_000 - i64::from(history.interval_ms) * 2,
            "decimation lost the tail: spanned {span} ms"
        );
    }
}
