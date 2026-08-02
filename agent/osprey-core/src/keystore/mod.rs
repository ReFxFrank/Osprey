//! Sealed storage for private key material.
//!
//! ## Why DPAPI is not the security boundary
//!
//! `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE` derives its key from
//! machine state, which means *any* code running on the box — including an
//! unprivileged process — can call `CryptUnprotectData` on the blob and get the
//! plaintext back. DPAPI therefore buys at-rest obfuscation against someone who
//! walks off with the disk, and nothing else. **The filesystem ACL on
//! `%ProgramData%\Osprey\` is the actual access-control boundary** (P0 execution
//! plan §2 #1): Administrators + SYSTEM in P0, tightened to the service account
//! in P1. Machine scope is mandatory rather than convenient — the per-user
//! default would seal the key to the interactive user in P0 and leave it
//! permanently unreadable by the SYSTEM service in P1, silently stranding the
//! device's identity (plan §2 #10).

use crate::error::KeystoreError;

#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
pub use dpapi::DpapiKeystore;

// The dev backend does not encrypt. Compiling it out on Windows makes it
// impossible to select accidentally on the platform that has real protection,
// which is stronger than a runtime check that someone can flip.
#[cfg(not(windows))]
mod dev_file;
#[cfg(not(windows))]
pub use dev_file::DevFileKeystore;

/// Backing store for the device's private keys.
///
/// Implemented exactly twice: DPAPI on Windows (the shipping path) and a
/// 0600-permission file on Unix (so the crypto is testable in CI, where no
/// Windows host exists).
pub trait Keystore {
    /// Seal `plaintext` under `label`, replacing any existing entry.
    fn store(&self, label: &str, plaintext: &[u8]) -> Result<(), KeystoreError>;

    /// Unseal the entry, or `None` if it has never been written.
    fn load(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError>;

    /// Remove the entry. Removing a missing entry succeeds.
    fn delete(&self, label: &str) -> Result<(), KeystoreError>;
}

/// Labels become filenames, so they are restricted rather than sanitised — a
/// caller passing `../../config` should get an error, not a surprising path.
fn check_label(label: &str) -> Result<(), KeystoreError> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(KeystoreError::UnsafeLabel(label.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::check_label;

    #[test]
    fn rejects_path_traversal_labels() {
        assert!(check_label("device-identity").is_ok());
        assert!(check_label("../../etc/passwd").is_err());
        assert!(check_label("").is_err());
        assert!(check_label("has space").is_err());
    }
}
