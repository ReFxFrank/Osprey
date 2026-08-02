//! **Development-only** keystore: plaintext files with 0600 permissions.
//!
//! This backend performs no encryption at all and says so rather than
//! pretending otherwise (CLAUDE.md rule 9 — no plausible fake on a shipping
//! path). It exists so the Noise/identity layer is testable on Linux CI, where
//! DPAPI does not exist. It is `#[cfg(not(windows))]`, so it cannot be selected
//! on the platform Osprey actually ships to.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::KeystoreError;
use crate::keystore::{check_label, Keystore};

/// Owner-only file mode. Anything wider and a second local account can read the
/// device's private keys straight off disk.
const OWNER_ONLY_FILE: u32 = 0o600;
const OWNER_ONLY_DIR: u32 = 0o700;

pub struct DevFileKeystore {
    dir: PathBuf,
}

impl DevFileKeystore {
    /// Create (or adopt) `dir` as the key directory, forcing 0700 on it.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(OWNER_ONLY_DIR))?;
        Ok(Self { dir })
    }

    fn path(&self, label: &str) -> Result<PathBuf, KeystoreError> {
        check_label(label)?;
        Ok(self.dir.join(format!("{label}.key")))
    }
}

impl Keystore for DevFileKeystore {
    fn store(&self, label: &str, plaintext: &[u8]) -> Result<(), KeystoreError> {
        let path = self.path(label)?;
        // Written to a sibling then renamed so an interrupted write cannot leave
        // a truncated key file where a valid one used to be.
        let tmp = path.with_extension("key.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(OWNER_ONLY_FILE)
            .open(&tmp)?;
        file.write_all(plaintext)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn load(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let path = self.path(label)?;
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    fn delete(&self, label: &str) -> Result<(), KeystoreError> {
        let path = self.path(label)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_mode_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = DevFileKeystore::open(dir.path()).expect("open keystore");
        ks.store("device-identity", b"secret").expect("store");
        let meta = fs::metadata(dir.path().join("device-identity.key")).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, OWNER_ONLY_FILE);
    }
}
