//! The user-session helper: launching it, supervising it, talking to it.
//!
//! A Windows service runs in Session 0 with no desktop, so it can never draw a
//! window, capture a screen or inject input (brief §9.1). Everything visual
//! therefore lives in `osprey-helper`, a process running as the logged-in user
//! in their session — and the service's job is to put it there and keep it
//! there.
//!
//! In P1 the helper deliberately does nothing but exist and stay connected.
//! Capture arrives at P4 and input at P6; a stub tray or a fake capture surface
//! here would be exactly the plausible-looking fiction that makes a phase gate
//! meaningless.

use std::time::Duration;

#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod spawn;
#[cfg(windows)]
pub use pipe::{HelperPipeServer, PIPE_NAME};
#[cfg(windows)]
pub use spawn::{active_console_session, spawn_into_active_session, ProcessHandle};

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use unsupported::{active_console_session, spawn_into_active_session, ProcessHandle};

pub mod supervisor;

/// Where the helper executable sits relative to the service.
///
/// A sibling of the service binary, deliberately: an installed Osprey is one
/// directory, and resolving the helper by searching `PATH` would let anything
/// that can write a `PATH` directory choose what the SYSTEM service launches
/// into the user's session.
pub fn helper_executable() -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;
    let service = std::env::current_exe().context("could not locate the agent executable")?;
    let directory = service
        .parent()
        .context("the agent executable has no parent directory")?;
    Ok(directory.join(if cfg!(windows) {
        "osprey-helper.exe"
    } else {
        "osprey-helper"
    }))
}

/// How often the supervisor checks whether the helper is still alive.
///
/// The P1 gate requires a killed helper back within 3 s, so the poll plus the
/// first backoff step has to fit inside that with room to spare.
pub const LIVENESS_POLL: Duration = Duration::from_millis(250);

/// Delay before the first respawn. Deliberately short: the overwhelmingly
/// common cause of a helper exiting is a one-off crash, not a persistent fault.
pub const RESPAWN_BASE_DELAY: Duration = Duration::from_millis(250);

/// Ceiling on the respawn delay once a helper is crash-looping.
///
/// The brief calls for backoff specifically for this case: a helper that dies
/// on startup every time would otherwise be relaunched forever at full speed,
/// which burns the user's CPU and fills the log faster than anyone can read it.
pub const RESPAWN_MAX_DELAY: Duration = Duration::from_secs(30);

/// How long a helper must survive before it counts as healthy.
///
/// Without this, a helper that starts and immediately dies would reset the
/// backoff on every attempt and the crash-loop ceiling would never engage.
pub const HEALTHY_AFTER: Duration = Duration::from_secs(20);
