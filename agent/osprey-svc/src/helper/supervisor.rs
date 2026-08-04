//! Keeps exactly one helper alive in whichever session the user is signed in to.
//!
//! Three things it has to get right, and the P1 gate measures two of them:
//!
//! * **Respawn on crash, within 3 seconds.** Killing the helper from Task
//!   Manager must be indistinguishable from it never having died.
//! * **Follow the session.** Log out and the helper's session is gone; log back
//!   in — possibly as a different user, possibly a different session id — and a
//!   helper belongs there again. Fast user switching is the same event twice.
//! * **Back off when it is crash-looping**, so a helper that dies on startup
//!   does not get relaunched forever at full speed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use crate::helper::{
    active_console_session, spawn_into_active_session, ProcessHandle, HEALTHY_AFTER, LIVENESS_POLL,
    RESPAWN_BASE_DELAY, RESPAWN_MAX_DELAY,
};

/// Live view of the helper, so its state is observable rather than only
/// loggable — the gate has to see a respawn happen, and a controller will want
/// to know whether the user's session has a helper in it.
#[derive(Debug, Default)]
pub struct HelperStatus {
    running: AtomicBool,
    starts: std::sync::atomic::AtomicU64,
    session: std::sync::atomic::AtomicU32,
}

impl HelperStatus {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// How many helpers have been started since the service came up. A respawn
    /// is this going up — which is what distinguishes "never died" from "died
    /// and came back".
    pub fn starts(&self) -> u64 {
        self.starts.load(Ordering::Relaxed)
    }

    /// The session the current helper is in, or 0 if there is none.
    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Relaxed)
    }
}

/// Start supervising. Returns `None` if the thread could not be created.
pub fn spawn(
    helper_exe: PathBuf,
    running: Arc<AtomicBool>,
    status: Arc<HelperStatus>,
) -> Option<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("osprey-helper-sup".to_owned())
        .spawn(move || supervise(&helper_exe, &running, &status))
        .map_err(|err| tracing::error!(error = %err, "could not start the helper supervisor"))
        .ok()
}

fn supervise(helper_exe: &std::path::Path, running: &AtomicBool, status: &HelperStatus) {
    let mut child: Option<ProcessHandle> = None;
    let mut delay = RESPAWN_BASE_DELAY;
    let mut started_at: Option<Instant> = None;
    let mut retry_at: Option<Instant> = None;

    while running.load(Ordering::Relaxed) {
        let session = active_console_session();

        // 1. Has the session gone, or changed underneath the helper?
        if let Some(live) = &child {
            let followed = session == Some(live.session());
            if !followed {
                // Logging out kills the helper's session and with it the
                // process; a fast user switch moves the console to a different
                // session id. Either way this handle is stale.
                tracing::info!(
                    pid = live.pid(),
                    from = live.session(),
                    to = ?session,
                    "the console session changed; the helper no longer belongs to it"
                );
                child = None;
                started_at = None;
                status.running.store(false, Ordering::Relaxed);
                status.session.store(0, Ordering::Relaxed);
                // A session change is not a crash, so the next start is prompt.
                delay = RESPAWN_BASE_DELAY;
                retry_at = None;
            }
        }

        // 2. Has it exited?
        if let Some(live) = &child {
            match live.try_exit_code() {
                Ok(Some(code)) => {
                    let lasted = started_at.map(|at| at.elapsed()).unwrap_or_default();
                    tracing::warn!(
                        pid = live.pid(),
                        exit_code = code,
                        lasted_ms = lasted.as_millis(),
                        "the helper exited"
                    );
                    // Only a helper that lasted counts as healthy. Otherwise a
                    // process that dies on startup would reset the backoff
                    // every time and the ceiling would never engage.
                    delay = if lasted >= HEALTHY_AFTER {
                        RESPAWN_BASE_DELAY
                    } else {
                        (delay * 2).min(RESPAWN_MAX_DELAY)
                    };
                    child = None;
                    started_at = None;
                    status.running.store(false, Ordering::Relaxed);
                    status.session.store(0, Ordering::Relaxed);
                    retry_at = Some(Instant::now() + delay);
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(error = %err, "could not check on the helper; assuming it is gone");
                    child = None;
                    started_at = None;
                    status.running.store(false, Ordering::Relaxed);
                    retry_at = Some(Instant::now() + delay);
                }
            }
        }

        // 3. Start one if there should be one and there is not.
        if child.is_none() && session.is_some() {
            let due = retry_at.map(|at| Instant::now() >= at).unwrap_or(true);
            if due {
                match spawn_into_active_session(helper_exe, "run") {
                    Ok(handle) => {
                        tracing::info!(
                            pid = handle.pid(),
                            session = handle.session(),
                            "started the session helper"
                        );
                        status.running.store(true, Ordering::Relaxed);
                        status.session.store(handle.session(), Ordering::Relaxed);
                        status.starts.fetch_add(1, Ordering::Relaxed);
                        started_at = Some(Instant::now());
                        child = Some(handle);
                        retry_at = None;
                    }
                    Err(err) => {
                        // Expected at the sign-in screen and during a switch,
                        // so this is a warning rather than an error, and the
                        // backoff keeps it from filling the log.
                        tracing::warn!(error = %err, "could not start the session helper");
                        delay = (delay * 2).min(RESPAWN_MAX_DELAY);
                        retry_at = Some(Instant::now() + delay);
                    }
                }
            }
        }

        std::thread::sleep(LIVENESS_POLL);
    }

    // The service is stopping. The helper is left to exit with its session
    // rather than being killed: it holds no state worth a forced teardown, and
    // terminating a process in the user's session on service stop is more
    // violence than the situation needs.
    if let Some(live) = child {
        tracing::info!(pid = live.pid(), "leaving the helper to its session");
    }
    status.running.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_backoff_ceiling_is_reached_by_doubling_and_never_exceeded() {
        let mut delay = RESPAWN_BASE_DELAY;
        for _ in 0..20 {
            delay = (delay * 2).min(RESPAWN_MAX_DELAY);
            assert!(delay <= RESPAWN_MAX_DELAY);
        }
        assert_eq!(delay, RESPAWN_MAX_DELAY);
    }

    #[test]
    fn the_first_respawn_fits_inside_the_gate_budget() {
        // The gate allows 3 seconds between a kill and the replacement being
        // up. One poll plus the first delay has to leave room for the spawn
        // itself.
        let worst_case = LIVENESS_POLL + RESPAWN_BASE_DELAY;
        assert!(
            worst_case < Duration::from_secs(1),
            "detection plus first backoff is {worst_case:?}, too close to the 3s budget"
        );
    }

    #[test]
    fn a_supervisor_starts_and_stops_without_a_session() {
        // On CI there is no interactive session; the supervisor must idle
        // rather than spin or panic.
        let running = Arc::new(AtomicBool::new(true));
        let status = Arc::new(HelperStatus::default());
        let handle = spawn(
            PathBuf::from("osprey-helper-does-not-exist.exe"),
            Arc::clone(&running),
            Arc::clone(&status),
        )
        .expect("spawn the supervisor");
        std::thread::sleep(LIVENESS_POLL * 3);
        assert!(!status.is_running());
        running.store(false, Ordering::Relaxed);
        handle.join().expect("join the supervisor");
    }
}
