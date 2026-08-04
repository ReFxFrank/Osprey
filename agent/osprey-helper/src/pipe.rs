//! The helper's end of the service pipe.
//!
//! The service owns the pipe and its DACL; this side only opens it. Nothing
//! here trusts the pipe's *contents* — but the DACL means only SYSTEM,
//! Administrators and the interactive user can have written them, which is a
//! stronger statement than anything the helper could check for itself.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::Duration;

use anyhow::{Context, Result};
use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
};

/// Must match `osprey_svc::helper::PIPE_NAME`.
const PIPE_NAME: &str = r"\\.\pipe\osprey-helper";

/// Largest message either side will send.
const MAX_MESSAGE: usize = 8 * 1024;

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Connect, greet, and stay attached until the service closes the pipe.
///
/// Returns only when the helper should exit. A closed pipe means the service
/// stopped; the helper then waits and tries again, because the service
/// restarting should not require the user to log out and back in to get a
/// helper.
pub fn serve(reconnect_delay: Duration) -> Result<()> {
    loop {
        match attach() {
            Ok(()) => tracing::info!("the service closed the helper pipe"),
            Err(err) => tracing::warn!(error = %err, "could not attach to the service"),
        }
        std::thread::sleep(reconnect_delay);
    }
}

/// One attachment, from connect to close.
fn attach() -> Result<()> {
    let name = wide(PIPE_NAME);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("could not open {PIPE_NAME}"))?;
    // SAFETY: a valid handle, owned from here.
    let pipe = unsafe { Owned::new(handle) };

    tracing::info!("attached to the service");
    write_message(*pipe, b"hello")?;

    let mut buffer = vec![0u8; MAX_MESSAGE];
    loop {
        let Some(message) = read_message(*pipe, &mut buffer)? else {
            // A zero-length read is the service closing its end.
            return Ok(());
        };
        // P1 defines no commands. Logging what arrived beats discarding it
        // silently, and the message set grows with the phases that need it.
        tracing::debug!(bytes = message.len(), "message from the service");
    }
}

fn write_message(pipe: HANDLE, payload: &[u8]) -> Result<()> {
    let mut written = 0u32;
    // SAFETY: `pipe` is live and `payload` outlives the call.
    unsafe { WriteFile(pipe, Some(payload), Some(&mut written), None) }
        .context("could not write to the service pipe")?;
    Ok(())
}

/// `Ok(None)` when the service closed its end.
fn read_message(pipe: HANDLE, buffer: &mut [u8]) -> Result<Option<&[u8]>> {
    let mut read = 0u32;
    // SAFETY: `pipe` is live and `buffer` outlives the call.
    unsafe { ReadFile(pipe, Some(buffer), Some(&mut read), None) }
        .context("could not read from the service pipe")?;
    if read == 0 {
        return Ok(None);
    }
    let end = usize::try_from(read).unwrap_or(buffer.len()).min(buffer.len());
    Ok(Some(&buffer[..end]))
}
