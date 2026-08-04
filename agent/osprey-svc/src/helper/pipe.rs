//! The service's end of the helper pipe.
//!
//! The brief calls for a "SYSTEM-only DACL". Read literally that would lock out
//! the helper, which runs as the logged-in user — so what ships is: full
//! control for SYSTEM and Administrators, and read/write for the *interactive*
//! user only. Nothing over the network can reach it, no service account can,
//! and no other desktop session can.
//!
//! Two shapes here are not what a C programmer expects. `CreateNamedPipeW`
//! returns a bare `HANDLE` rather than a `Result`, so failure arrives as
//! `INVALID_HANDLE_VALUE` and must be checked. And `ConnectNamedPipe` reports
//! `ERROR_PIPE_CONNECTED` when a client won the race between creation and the
//! connect call — that is success, and treating it as failure would drop
//! roughly every fast helper start.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use anyhow::{bail, Context, Result};
use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

/// Where the helper looks for the service.
pub const PIPE_NAME: &str = r"\\.\pipe\osprey-helper";

/// `D:P` protects the DACL from inheritance; `SY` is SYSTEM, `BA` the built-in
/// Administrators, and `IU` interactive users — the only ones who could be
/// running the helper.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// One message may not exceed this. The helper protocol is a handful of short
/// control messages; anything larger is a bug or an attack.
const MAX_MESSAGE: usize = 8 * 1024;
const PIPE_BUFFER: u32 = 16 * 1024;

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// A security descriptor built from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: the descriptor was LocalAlloc'd by the conversion below
            // and is freed exactly once.
            unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
        }
    }
}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let text = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `text` is NUL-terminated and outlives the call; `descriptor`
        // receives an owned allocation.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .context("could not build the helper pipe's security descriptor")?;
        Ok(Self(descriptor))
    }
}

/// The listening end of the helper pipe.
pub struct HelperPipeServer {
    pipe: Owned<HANDLE>,
    /// Kept alive for as long as the pipe: the descriptor is referenced by the
    /// SECURITY_ATTRIBUTES handed to `CreateNamedPipeW`.
    _descriptor: SecurityDescriptor,
}

impl HelperPipeServer {
    /// Create the pipe instance and start listening.
    pub fn create() -> Result<Self> {
        let descriptor = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>())
                .context("SECURITY_ATTRIBUTES is larger than a u32")?,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };

        let name = wide(PIPE_NAME);
        // SAFETY: `name` is NUL-terminated and `attributes` outlives the call.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                // One instance: there is exactly one interactive session to
                // serve, and a second connection would be something else
                // pretending to be the helper.
                1,
                PIPE_BUFFER,
                PIPE_BUFFER,
                0,
                Some(&attributes),
            )
        };
        // Bare HANDLE, not a Result: failure is a sentinel value.
        if handle.is_invalid() {
            bail!(
                "could not create {PIPE_NAME}: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: a valid handle this type now owns.
        let pipe = unsafe { Owned::new(handle) };

        Ok(Self {
            pipe,
            _descriptor: descriptor,
        })
    }

    /// Block until the helper connects.
    pub fn accept(&self) -> Result<()> {
        // SAFETY: `pipe` is a live listening pipe.
        match unsafe { ConnectNamedPipe(*self.pipe, None) } {
            Ok(()) => Ok(()),
            // Not a failure: the client connected in the window between
            // creation and this call.
            Err(err) if err.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(()),
            Err(err) => Err(err).context("waiting for the helper to connect failed"),
        }
    }

    /// Release the current client so a replacement helper can connect.
    pub fn disconnect(&self) {
        // SAFETY: `pipe` is live; disconnecting an unconnected pipe is
        // harmless.
        if let Err(err) = unsafe { DisconnectNamedPipe(*self.pipe) } {
            tracing::debug!(error = %err, "the helper pipe did not disconnect cleanly");
        }
    }

    /// Read one message from the connected helper.
    ///
    /// `Ok(None)` means the helper closed its end, which is the ordinary way an
    /// attachment ends when the user logs out.
    // The lifetime is explicit because it cannot be elided correctly here:
    // elision would tie the returned slice to `&self` rather than to the
    // caller's buffer, which is where the bytes actually live.
    pub fn read_message<'a>(&self, buffer: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
        let mut read = 0u32;
        // SAFETY: the pipe is live and `buffer` outlives the call.
        unsafe { ReadFile(*self.pipe, Some(buffer), Some(&mut read), None) }
            .context("could not read from the helper pipe")?;
        if read == 0 {
            return Ok(None);
        }
        let end = usize::try_from(read).unwrap_or(buffer.len()).min(buffer.len());
        Ok(Some(&buffer[..end]))
    }

    pub fn raw(&self) -> HANDLE {
        *self.pipe
    }

    pub const fn max_message() -> usize {
        MAX_MESSAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sddl_grants_exactly_the_three_intended_trustees() {
        // Parsing proves the string is well formed; the trustees are asserted
        // literally because a typo here would silently widen access to the
        // pipe the service accepts commands on.
        SecurityDescriptor::from_sddl(PIPE_SDDL).expect("the pipe SDDL must parse");
        assert!(PIPE_SDDL.starts_with("D:P"), "the DACL must not be inheritable");
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"), "SYSTEM needs full control");
        assert!(PIPE_SDDL.contains("(A;;GA;;;BA)"), "Administrators need full control");
        assert!(
            PIPE_SDDL.contains("(A;;GRGW;;;IU)"),
            "the interactive user needs read/write to connect at all"
        );
        assert_eq!(
            PIPE_SDDL.matches("(A;").count(),
            3,
            "exactly three trustees were intended: {PIPE_SDDL}"
        );
        assert!(
            !PIPE_SDDL.contains(";WD)") && !PIPE_SDDL.contains(";AU)"),
            "Everyone and Authenticated Users must never appear: {PIPE_SDDL}"
        );
    }

    #[test]
    fn a_malformed_descriptor_is_a_typed_error() {
        assert!(SecurityDescriptor::from_sddl("not sddl at all").is_err());
    }

    #[test]
    fn the_pipe_can_be_created_and_dropped() {
        let server = HelperPipeServer::create().expect("create the pipe");
        assert!(!server.raw().is_invalid());
        // A second server on the same name must be refused: one instance only,
        // so nothing can race the helper for the connection.
        let second = HelperPipeServer::create();
        assert!(second.is_err(), "a second pipe instance must not be allowed");
    }
}
