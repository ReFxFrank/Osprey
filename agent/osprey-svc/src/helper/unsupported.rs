//! Helper launching on platforms with no sessions to launch into.
//!
//! Windows is the only agent platform (brief §2). These exist so the crate
//! builds and its tests run on the Linux CI host, and they report why rather
//! than pretending to have started something.

use std::path::Path;

use anyhow::{bail, Result};

pub struct ProcessHandle;

impl ProcessHandle {
    pub fn pid(&self) -> u32 {
        0
    }

    pub fn session(&self) -> u32 {
        0
    }

    pub fn try_exit_code(&self) -> Result<Option<u32>> {
        bail!("there is no helper process on this platform")
    }
}

/// Always `None`: there are no Windows console sessions here.
pub fn active_console_session() -> Option<u32> {
    None
}

pub fn spawn_into_active_session(_exe: &Path, _args: &str) -> Result<ProcessHandle> {
    bail!("launching a session helper requires Windows")
}
