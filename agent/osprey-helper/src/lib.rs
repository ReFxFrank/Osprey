//! The user-session helper.
//!
//! Everything visual or input-related in Osprey lives here, because
//! `osprey-svc` runs in Session 0 with no desktop and never may (brief §9.1).
//! P1 builds only the part that has to exist first: a process in the user's
//! session that the service starts, supervises and can talk to.
//!
//! The screen capture (P4) and `SendInput` (P6) that will make this crate
//! interesting are deliberately absent rather than stubbed.

#![forbid(unsafe_op_in_unsafe_fn)]
// This process is reachable from the service, which is reachable from a remote
// peer, so the same no-panic posture applies here as everywhere else.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::time::Duration;

use anyhow::Result;

#[cfg(windows)]
mod pipe;

/// How long to wait between attempts to reach the service.
///
/// The helper is started *by* the service, so the pipe is normally already
/// listening — but a helper that outlives a service restart should reattach
/// rather than exit and rely on being noticed.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Attach to the service and stay resident until it goes away for good.
pub fn run() -> Result<()> {
    tracing::info!("session helper starting");

    #[cfg(windows)]
    {
        pipe::serve(RECONNECT_DELAY)
    }

    #[cfg(not(windows))]
    {
        // Not an error: the crate exists on other platforms so the workspace
        // builds and its tests run, and saying so beats pretending to attach.
        tracing::warn!("the session helper only does anything on Windows");
        Ok(())
    }
}
