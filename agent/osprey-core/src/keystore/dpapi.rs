//! Windows keystore: DPAPI-sealed blobs under the Osprey data directory.
//!
//! See the module docs on [`crate::keystore`] for why the ACL, not DPAPI, is the
//! security boundary, and why `CRYPTPROTECT_LOCAL_MACHINE` is mandatory.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::ptr;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroize;

use crate::error::KeystoreError;
use crate::keystore::{check_label, Keystore};

pub struct DpapiKeystore {
    dir: PathBuf,
}

impl DpapiKeystore {
    /// Adopt `dir` as the sealed-key directory.
    ///
    /// The directory ACL is *not* set here: it is applied once at install time
    /// by the elevated installer, because the P0 console agent runs
    /// unelevated and must fail loudly rather than silently widen permissions
    /// it inherited.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, label: &str) -> Result<PathBuf, KeystoreError> {
        check_label(label)?;
        Ok(self.dir.join(format!("{label}.dpapi")))
    }
}

/// Owns a `CRYPT_INTEGER_BLOB` allocated by DPAPI so the `LocalFree` happens on
/// every exit path, including the error paths.
struct DpapiBlob(CRYPT_INTEGER_BLOB);

impl DpapiBlob {
    fn as_slice(&self) -> &[u8] {
        if self.0.pbData.is_null() || self.0.cbData == 0 {
            return &[];
        }
        // SAFETY: DPAPI guarantees pbData points to cbData readable bytes until
        // LocalFree, which only happens in this type's Drop.
        unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
    }
}

impl Drop for DpapiBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // On the unseal path this buffer holds the device's private keys,
            // so it is wiped before the allocator is free to hand it out again.
            // SAFETY: same validity argument as `as_slice`.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
            }
            // SAFETY: pbData came from a successful CryptProtectData /
            // CryptUnprotectData call, which allocates with LocalAlloc.
            let unfreed = unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
            if !unfreed.0.is_null() {
                // A leak, not a correctness problem, but it must not be silent.
                tracing::error!("LocalFree did not release a DPAPI blob");
            }
            self.0.pbData = ptr::null_mut();
            self.0.cbData = 0;
        }
    }
}

fn input_blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        // DPAPI does not write through this pointer on the input side.
        pbData: data.as_ptr().cast_mut(),
    }
}

fn protect(plaintext: &[u8]) -> Result<DpapiBlob, KeystoreError> {
    let input = input_blob(plaintext);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: both blobs are valid for the duration of the call; `input` borrows
    // `plaintext`, and `output` is populated by DPAPI and owned by DpapiBlob.
    unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    }
    .map_err(|e| KeystoreError::Platform(format!("CryptProtectData: {e}")))?;
    Ok(DpapiBlob(output))
}

fn unprotect(sealed: &[u8]) -> Result<DpapiBlob, KeystoreError> {
    let input = input_blob(sealed);
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as above.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    }
    .map_err(|_| KeystoreError::Unseal)?;
    Ok(DpapiBlob(output))
}

impl Keystore for DpapiKeystore {
    fn store(&self, label: &str, plaintext: &[u8]) -> Result<(), KeystoreError> {
        let path = self.path(label)?;
        let sealed = protect(plaintext)?;
        let tmp = path.with_extension("dpapi.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(sealed.as_slice())?;
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
        let mut sealed = Vec::new();
        file.read_to_end(&mut sealed)?;
        let plain = unprotect(&sealed)?;
        Ok(Some(plain.as_slice().to_vec()))
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
