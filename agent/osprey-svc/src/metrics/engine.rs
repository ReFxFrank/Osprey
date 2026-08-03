//! The sampling thread and the subscriptions it feeds.
//!
//! One thread samples for the whole machine no matter how many controllers are
//! watching, because the counters are whole-machine values and sampling them
//! twice would cost twice as much to learn the same number.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::metrics::collect::Collector;
use crate::metrics::ring::{History, RingBuffer, RING_INTERVAL_MS};
use crate::metrics::{now_ms, Sample};

/// Cadence while at least one controller is subscribed (brief M-01).
pub const LIVE_INTERVAL: Duration = Duration::from_secs(1);
/// Cadence with nobody watching. This is what keeps idle CPU inside the gate's
/// 1% budget: an unwatched agent wakes twice a minute, not sixty times.
pub const IDLE_INTERVAL: Duration = Duration::from_secs(30);

/// How many ticks may queue for one subscriber before the oldest are dropped.
///
/// Metrics are lossy by nature — a missed tick is one missing point on a chart
/// that is about to be redrawn — so a slow consumer must not be allowed to grow
/// the sender's memory. Four is two seconds of slack at the live cadence.
const SUBSCRIBER_QUEUE_DEPTH: usize = 4;

/// Shortest interval between two platform reads.
///
/// Two guarantees. First, `GetSystemTimes` only advances on the ~15.6 ms system
/// tick, so two reads closer than that yield identical counters and no
/// utilisation to report. Second, `subscribe` wakes the sampler immediately, so
/// without a floor a peer could set the sampling rate by re-subscribing in a
/// loop and make the agent call into the platform as fast as it liked.
const MIN_SAMPLE_SPACING: Duration = Duration::from_millis(250);

/// A controller's live view of the stream.
///
/// Dropping it unsubscribes: the engine notices the disconnected channel on its
/// next tick and stops counting this subscriber, which is what returns an idle
/// agent to the slow cadence.
pub struct Subscription {
    receiver: Receiver<Sample>,
}

impl Subscription {
    /// Every sample queued since the last call, oldest first.
    ///
    /// Non-blocking by design: the caller is a session thread that must not
    /// wait on metrics while a controller might be sending it a request.
    pub fn drain(&self) -> Vec<Sample> {
        self.receiver.try_iter().collect()
    }
}

#[derive(Default)]
struct Shared {
    subscribers: Vec<SyncSender<Sample>>,
    ring: RingBuffer,
    running: bool,
    /// Set once when collection is unavailable, so an unsupported platform
    /// logs one line rather than one per sample forever.
    reported_failure: bool,
}

/// Owns the sampler thread. Dropping it stops the thread and joins it.
pub struct MetricsEngine {
    shared: Arc<(Mutex<Shared>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl MetricsEngine {
    /// Start sampling.
    pub fn start() -> Self {
        let shared = Arc::new((
            Mutex::new(Shared {
                running: true,
                ..Shared::default()
            }),
            Condvar::new(),
        ));
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("osprey-metrics".to_owned())
            .spawn(move || run_sampler(&worker_shared))
            .ok();
        if worker.is_none() {
            tracing::error!("could not spawn the metrics sampler; metrics will be unavailable");
        }
        Self { shared, worker }
    }

    /// Register a live subscriber and wake the sampler onto the fast cadence.
    pub fn subscribe(&self) -> Subscription {
        let (sender, receiver) = sync_channel(SUBSCRIBER_QUEUE_DEPTH);
        let (lock, condvar) = &*self.shared;
        if let Ok(mut shared) = lock.lock() {
            shared.subscribers.push(sender);
        }
        // Without this the first live sample could be up to IDLE_INTERVAL away,
        // so a controller would stare at an empty chart for thirty seconds.
        condvar.notify_all();
        Subscription { receiver }
    }

    /// The most recent `backfill_seconds` of stored history.
    pub fn history(&self, backfill_seconds: u32) -> Option<History> {
        let (lock, _) = &*self.shared;
        let shared = lock.lock().ok()?;
        shared.ring.history(backfill_seconds, now_ms())
    }

    /// Installed physical memory from the newest stored sample.
    ///
    /// `metrics.history` carries capacity as a scalar, so a backfill that is
    /// empty or decimated still needs a figure from somewhere. `None` means
    /// nothing has ever been sampled — the client then knows the value is
    /// unknown rather than being handed a zero.
    pub fn latest_total_memory(&self) -> Option<u64> {
        let (lock, _) = &*self.shared;
        let shared = lock.lock().ok()?;
        shared.ring.latest().map(|sample| sample.mem_total_bytes)
    }

    /// Samples currently held in the ring. Diagnostics and tests.
    pub fn stored_samples(&self) -> usize {
        let (lock, _) = &*self.shared;
        lock.lock().map(|shared| shared.ring.len()).unwrap_or(0)
    }
}

impl Drop for MetricsEngine {
    fn drop(&mut self) {
        {
            let (lock, condvar) = &*self.shared;
            if let Ok(mut shared) = lock.lock() {
                shared.running = false;
            }
            condvar.notify_all();
        }
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                tracing::error!("the metrics sampler thread panicked");
            }
        }
    }
}

fn run_sampler(shared: &Arc<(Mutex<Shared>, Condvar)>) {
    let (lock, condvar) = &**shared;
    let mut collector = Collector::new();
    let mut next_ring_due: Option<i64> = None;
    let mut last_sampled_at: Option<std::time::Instant> = None;

    loop {
        // The interval is read and the wait entered under one continuous hold
        // of the lock. Releasing it in between would drop a `subscribe` that
        // landed in the gap: the notify would fire before the wait began, and
        // the new subscriber would sit on the idle cadence for thirty seconds.
        let Ok(guard) = lock.lock() else {
            return;
        };
        if !guard.running {
            return;
        }
        let interval = if guard.subscribers.is_empty() {
            IDLE_INTERVAL
        } else {
            LIVE_INTERVAL
        };
        let Ok((guard, _)) = condvar.wait_timeout(guard, interval) else {
            return;
        };
        if !guard.running {
            return;
        }
        // Sampling calls into the platform and can block; holding the lock
        // across it would stall every `subscribe` and `history` call.
        drop(guard);

        // A `subscribe` notify can wake the loop moments after the last read.
        if let Some(previous) = last_sampled_at {
            let since = previous.elapsed();
            if since < MIN_SAMPLE_SPACING {
                std::thread::sleep(MIN_SAMPLE_SPACING - since);
            }
        }
        last_sampled_at = Some(std::time::Instant::now());

        match collector.sample() {
            Ok(sample) => deliver(lock, &sample, &mut next_ring_due),
            Err(err) => {
                let Ok(mut shared) = lock.lock() else {
                    return;
                };
                if !shared.reported_failure {
                    shared.reported_failure = true;
                    tracing::warn!(error = %err, "metrics collection failed; no samples will be recorded until it recovers");
                }
            }
        }
    }
}

/// Push to every live subscriber and, when due, into the ring.
///
/// Storing is governed by an absolute grid rather than by the gap since the
/// last stored sample: `next_due` advances by exactly one interval each time,
/// so sample N lands within one sampler period of `first_ts + N * interval`
/// however the wakeups jitter. Advancing by "now + interval" instead would let
/// the stored cadence drift away from the `interval_ms` that
/// `metrics.history` declares — and since that body carries no per-sample
/// timestamps, nothing downstream could ever detect the drift.
fn deliver(lock: &Mutex<Shared>, sample: &Sample, next_ring_due: &mut Option<i64>) {
    let Ok(mut shared) = lock.lock() else {
        return;
    };
    if shared.reported_failure {
        shared.reported_failure = false;
        tracing::info!("metrics collection recovered");
    }

    // Retain only channels whose receiver is still alive. A full queue is not a
    // dead subscriber — it is a busy one — so only Disconnected drops it.
    shared
        .subscribers
        .retain(|sender| match sender.try_send(sample.clone()) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        });

    // A sample whose throughput is unknown cannot go into history: the body's
    // arrays have one entry per sample with no way to mark one absent, so
    // storing it would force a fabricated number into the backfill. It still
    // reaches live subscribers above, where the tick's optional fields can say
    // "unknown" honestly.
    if sample.net_rx_bytes_per_sec.is_none() || sample.net_tx_bytes_per_sec.is_none() {
        return;
    }

    let interval = i64::from(RING_INTERVAL_MS);
    match next_ring_due {
        None => {
            shared.ring.push(sample.clone());
            *next_ring_due = Some(sample.ts_ms.saturating_add(interval));
        }
        Some(due) if sample.ts_ms >= *due => {
            shared.ring.push(sample.clone());
            // Snap forward rather than adding once: after a sleep or a long
            // collection outage the grid may be many intervals behind, and a
            // single addition would then store every sample until it caught up.
            let mut next = *due;
            while next <= sample.ts_ms {
                next = next.saturating_add(interval);
            }
            *next_ring_due = Some(next);
        }
        Some(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine only stores samples the platform actually produced, so on a
    /// platform without a collector these assert the honest-empty behaviour and
    /// on Windows they assert real sampling. Both are correct outcomes; what is
    /// never correct is a fabricated sample, so nothing here injects one.
    #[test]
    fn an_engine_starts_and_stops_cleanly() {
        let engine = MetricsEngine::start();
        drop(engine);
    }

    #[test]
    fn a_subscription_outlives_a_drain_and_unsubscribes_on_drop() {
        let engine = MetricsEngine::start();
        let subscription = engine.subscribe();
        // Draining an idle subscription must not block or panic.
        let _ = subscription.drain();
        drop(subscription);
    }

    #[test]
    fn history_of_an_empty_ring_is_absent_rather_than_zeroed() {
        let engine = MetricsEngine::start();
        assert!(
            engine.history(0).is_none(),
            "a zero-length backfill has no history"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_live_cadence_produces_samples_on_windows() {
        let engine = MetricsEngine::start();
        let subscription = engine.subscribe();
        // Three live intervals is generous slack for a one-second cadence.
        std::thread::sleep(LIVE_INTERVAL * 3);
        let samples = subscription.drain();
        assert!(
            !samples.is_empty(),
            "the sampler produced nothing in three live intervals"
        );
        let first = &samples[0];
        assert!(
            first.mem_total_bytes > 0,
            "installed memory must be a real value"
        );
        assert!(
            (0.0..=100.0).contains(&first.cpu_percent),
            "cpu {} is outside 0-100",
            first.cpu_percent
        );
    }
}
