//! Launching a process from Session 0 into the interactive user's session.
//!
//! Every symbol here was read from the vendored `windows` 0.62 source before
//! use. Three shapes are not what they look like:
//!
//! * `WTSGetActiveConsoleSessionId` lives under `System::RemoteDesktop` even
//!   though it links `kernel32`, and returns a bare `u32` — failure is a
//!   sentinel value, not an error.
//! * `CreateProcessAsUserW` is gated on the `Win32_Security` feature *as well
//!   as* `Win32_System_Threading`; enabling only the latter makes the function
//!   silently not exist.
//! * The token `WTSQueryUserToken` hands back is an impersonation token and
//!   cannot start a process. It has to be duplicated into a *primary* token
//!   first.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use windows::core::{Owned, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    DETACHED_PROCESS, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTUPINFOW,
};

/// What `WTSGetActiveConsoleSessionId` reports when no session is attached to
/// the physical console — at the sign-in screen, or on a machine whose console
/// session is being switched.
///
/// TODO(frank): this sentinel comes from the documented contract rather than
/// from the windows-rs source, which carries no constant for it. Confirm it
/// against a headless boot before the P1 gate is signed off.
const NO_ACTIVE_SESSION: u32 = 0xFFFF_FFFF;

/// The interactive window station and desktop.
///
/// Session 0's own desktop is not it: a helper started there would run, draw
/// nothing anyone can see, and be invisible to the user whose machine it is.
const INTERACTIVE_DESKTOP: &str = "winsta0\\default";

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// The session a user is signed in to at the physical console, if any.
pub fn active_console_session() -> Option<u32> {
    // SAFETY: no arguments and no out-parameters.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == NO_ACTIVE_SESSION {
        None
    } else {
        Some(session)
    }
}

/// An owned handle to a live child process.
///
/// The initial thread handle is deliberately absent: the supervisor never
/// resumes or waits on it, and holding it would keep a thread object alive for
/// the helper's entire lifetime.
pub struct ProcessHandle {
    process: Owned<HANDLE>,
    pid: u32,
    session: u32,
}

// SAFETY: a process handle is a kernel object reference with no thread
// affinity, and the supervisor moves it between its own threads.
unsafe impl Send for ProcessHandle {}

impl ProcessHandle {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn session(&self) -> u32 {
        self.session
    }

    /// `Ok(None)` while the helper is alive, `Ok(Some(code))` once it has
    /// exited. The zero timeout makes this a poll rather than a block.
    pub fn try_exit_code(&self) -> Result<Option<u32>> {
        // SAFETY: `process` is a live handle owned by this value.
        let waited = unsafe { WaitForSingleObject(*self.process, 0) };
        if waited == WAIT_TIMEOUT {
            return Ok(None);
        }
        if waited != WAIT_OBJECT_0 {
            bail!("waiting on helper process {} failed: {waited:?}", self.pid);
        }
        let mut code = 0u32;
        // SAFETY: the process has signalled, so its exit code is final.
        unsafe { GetExitCodeProcess(*self.process, &mut code) }
            .context("could not read the helper exit code")?;
        Ok(Some(code))
    }
}

/// A `CreateEnvironmentBlock` allocation, released on drop.
struct EnvironmentBlock(*mut core::ffi::c_void);

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful CreateEnvironmentBlock and
        // is destroyed exactly once, here.
        if let Err(err) = unsafe { DestroyEnvironmentBlock(self.0) } {
            tracing::warn!(error = %err, "leaked a user environment block");
        }
    }
}

/// Launch `exe` in the interactive console session, with the signed-in user's
/// token and environment.
pub fn spawn_into_active_session(exe: &Path, args: &str) -> Result<ProcessHandle> {
    let Some(session) = active_console_session() else {
        bail!("no interactive console session is attached");
    };

    let mut raw_token = HANDLE::default();
    // SAFETY: `raw_token` is a valid out-slot. This needs SeTcbPrivilege, which
    // a LocalSystem service holds and an ordinary process does not.
    unsafe { WTSQueryUserToken(session, &mut raw_token) }
        .with_context(|| format!("could not obtain the user token for session {session}"))?;
    // SAFETY: the call succeeded, so the handle is ours to close.
    let user_token = unsafe { Owned::new(raw_token) };

    let mut raw_primary = HANDLE::default();
    // SAFETY: `user_token` is live and `raw_primary` is a valid out-slot.
    unsafe {
        DuplicateTokenEx(
            *user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            None,
            SecurityImpersonation,
            // A process can only be started from a *primary* token; the one
            // WTSQueryUserToken returns is for impersonation.
            TokenPrimary,
            &mut raw_primary,
        )
    }
    .context("could not duplicate the session token into a primary token")?;
    // SAFETY: the call succeeded, so the handle is ours to close.
    let primary = unsafe { Owned::new(raw_primary) };

    let mut raw_env: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `raw_env` is a valid out-slot and `primary` is a live token.
    unsafe { CreateEnvironmentBlock(&mut raw_env, Some(*primary), false) }
        .context("could not build the user environment block")?;
    let environment = EnvironmentBlock(raw_env);

    let exe_wide = wide(exe.as_os_str());
    // Owned and mutable because CreateProcessAsUserW may write into it, and it
    // must carry argv[0] — the API does not prepend the executable itself.
    let mut command_line = wide(OsStr::new(&format!("\"{}\" {args}", exe.display())));
    let mut desktop = wide(OsStr::new(INTERACTIVE_DESKTOP));

    let startup = STARTUPINFOW {
        cb: u32::try_from(core::mem::size_of::<STARTUPINFOW>())
            .context("STARTUPINFOW is larger than a u32")?,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();

    // SAFETY: every pointer outlives the call and `startup.cb` matches the
    // struct's size.
    unsafe {
        CreateProcessAsUserW(
            Some(*primary),
            PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            // DETACHED_PROCESS so the helper never inherits or opens a console;
            // it is a background process in the user's session, not a program
            // they launched.
            CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | NORMAL_PRIORITY_CLASS,
            Some(environment.0),
            PCWSTR::null(),
            &startup,
            &mut info,
        )
    }
    .with_context(|| format!("could not launch {} in session {session}", exe.display()))?;

    // SAFETY: the call succeeded, so both handles are ours. The thread handle
    // is closed at once; the process handle is what the supervisor watches.
    let process = unsafe { Owned::new(info.hProcess) };
    drop(unsafe { Owned::new(info.hThread) });

    Ok(ProcessHandle {
        process,
        pid: info.dwProcessId,
        session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_session_is_reported_consistently() {
        // Whatever this machine's state, two reads in a row must agree — and
        // the answer must never be the sentinel dressed up as a real session.
        let first = active_console_session();
        let second = active_console_session();
        assert_eq!(first, second);
        assert_ne!(first, Some(NO_ACTIVE_SESSION));
    }

    #[test]
    fn spawning_without_the_tcb_privilege_fails_cleanly() {
        // The test process is not LocalSystem, so WTSQueryUserToken is refused.
        // What matters is that it is a typed error naming the step, not a panic
        // and not a silently dead helper.
        let outcome = spawn_into_active_session(Path::new("C:\\Windows\\System32\\cmd.exe"), "");
        let Err(err) = outcome else {
            // Running elevated as SYSTEM would legitimately succeed; do not
            // fail the suite for having more privilege than expected.
            return;
        };
        let text = format!("{err:#}");
        assert!(
            text.contains("user token") || text.contains("console session"),
            "unexpected failure: {text}"
        );
    }
}
