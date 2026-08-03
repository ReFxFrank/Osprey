//! The access-control boundary protecting the sealed device keys.
//!
//! DPAPI with machine scope is at-rest obfuscation and nothing more: any local
//! process can call `CryptUnprotectData` on the blob. The filesystem ACL on
//! `%ProgramData%\Osprey` is therefore the *actual* boundary, which is why it
//! is established here in code with a typed result rather than by shelling out
//! to `icacls.exe`. A security boundary established through a localised,
//! exit-code-only text interface is one whose failures cannot be distinguished
//! from its successes.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

/// A well-known SID in a caller-owned buffer.
///
/// `CreateWellKnownSid` writes into this and needs no matching free, unlike
/// `AllocateAndInitializeSid`, which would also require spelling out the
/// authority and sub-authorities of "Administrators" by hand — three more
/// chances to get a security-critical constant wrong for no benefit.
struct SidBuffer {
    bytes: [u8; SECURITY_MAX_SID_SIZE as usize],
}

impl SidBuffer {
    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        let mut buffer = SidBuffer {
            bytes: [0u8; SECURITY_MAX_SID_SIZE as usize],
        };
        let mut len = SECURITY_MAX_SID_SIZE;
        // SAFETY: the buffer is SECURITY_MAX_SID_SIZE bytes, the documented
        // upper bound for any well-known SID, and `len` is an in/out parameter
        // describing exactly that capacity.
        unsafe {
            CreateWellKnownSid(kind, None, Some(PSID(buffer.bytes.as_mut_ptr().cast())), &mut len)
        }
        .context("could not build a well-known SID")?;
        Ok(buffer)
    }

    fn psid(&mut self) -> PSID {
        PSID(self.bytes.as_mut_ptr().cast())
    }
}

/// Replace the DACL on `dir` with Administrators + SYSTEM, full control, and
/// disconnect it from the parent's inheritable entries.
///
/// Two things worth knowing about the effect:
///
/// * It applies immediately to existing children, not just to the directory —
///   the inheritable ACEs propagate on the spot. Anything the user-session
///   helper needs to read therefore must not live under this root, or must be
///   given its own explicit entry.
/// * It is idempotent. `SET_ACCESS` replaces rather than accumulates, so
///   running the installer twice leaves the same two entries.
pub fn harden_data_dir(dir: &Path) -> Result<()> {
    let mut administrators = SidBuffer::well_known(WinBuiltinAdministratorsSid)?;
    let mut system = SidBuffer::well_known(WinLocalSystemSid)?;

    let inheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let entry_for = |sid: PSID| EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            // Typed `PWSTR` but reinterpreted as a `PSID` because TrusteeForm
            // says so. The compiler cannot catch a mix-up here.
            ptstrName: PWSTR(sid.0.cast()),
        },
    };
    let entries = [entry_for(administrators.psid()), entry_for(system.psid())];

    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `entries`, and the SID buffers they point into, outlive this
    // call; `acl` receives a LocalAlloc'd allocation this function owns.
    unsafe { SetEntriesInAclW(Some(&entries), None, &mut acl) }
        .ok()
        .context("could not build the access control list")?;

    let path: Vec<u16> = wide(dir.as_os_str());
    // SAFETY: `acl` is valid until the LocalFree below, and `path` is
    // NUL-terminated.
    let outcome = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            // PROTECTED_ is a modifier and does nothing on its own: it is what
            // severs inheritance from the parent, and it must be combined with
            // the DACL flag that says which part is being replaced.
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };

    // Freed on the failure path too: an early `?` above the free would leak the
    // allocation every time the call failed.
    // SAFETY: `acl` came from a successful SetEntriesInAclW and is freed once.
    unsafe { LocalFree(Some(HLOCAL(acl.cast()))) };

    outcome
        .ok()
        .with_context(|| format!("could not set the access control list on {}", dir.display()))
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    //! These mutate real filesystem ACLs, so they are opt-in like
    //! `mdns_discovery` and `relay_live`:
    //!
    //! ```text
    //! cargo test -p osprey-svc --lib service::acl -- --ignored --nocapture
    //! ```
    //!
    //! Two reasons they are not part of the default run. A hardened directory
    //! is deliberately *unwritable* by the unelevated account that created it —
    //! that is the boundary doing its job — so the temporary directory can no
    //! longer be deleted and every run would leave one behind. And the outcome
    //! depends on the caller's token: elevated, SYSTEM and plain-user runs each
    //! see different access afterwards, so an assertion about access would be
    //! asserting the environment rather than the code. The SDDL check below
    //! sidesteps that by reading the resulting DACL rather than exercising it.

    use super::*;

    /// The security descriptor in SDDL form, whose SID abbreviations (`BA`,
    /// `SY`) and flags are locale-independent — unlike `icacls` output, which
    /// prints translated account names.
    fn sddl(dir: &Path) -> String {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Acl -LiteralPath '{}').Sddl", dir.display()),
            ])
            .output()
            .expect("read the security descriptor");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    #[test]
    #[ignore = "mutates a real filesystem ACL; see the module docs"]
    fn the_resulting_dacl_is_exactly_administrators_and_system_and_is_protected() {
        let dir = tempfile::tempdir().expect("tempdir");
        harden_data_dir(dir.path()).expect("harden");

        let descriptor = sddl(dir.path());
        let dacl = descriptor
            .split_once("D:")
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default();

        assert!(
            dacl.starts_with('P'),
            "the DACL must be protected so parent permissions stop being inherited: {descriptor}"
        );
        assert!(
            dacl.contains(";BA)"),
            "Administrators must have an entry: {descriptor}"
        );
        assert!(
            dacl.contains(";SY)"),
            "SYSTEM must have an entry: {descriptor}"
        );
        assert_eq!(
            dacl.matches("(A;").count(),
            2,
            "exactly two allow entries were expected, found: {descriptor}"
        );
    }

    #[test]
    #[ignore = "mutates a real filesystem ACL; see the module docs"]
    fn hardening_is_idempotent_and_reports_a_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Applied twice on purpose: SET_ACCESS replaces, so a second install
        // must not accumulate entries or fail.
        harden_data_dir(dir.path()).expect("first hardening");
        harden_data_dir(dir.path()).expect("second hardening");

        let missing = dir.path().join("does-not-exist");
        let err = harden_data_dir(&missing).expect_err("a missing path must be a typed error");
        assert!(
            err.to_string().contains("could not set the access control list"),
            "unexpected error: {err}"
        );
    }

}
