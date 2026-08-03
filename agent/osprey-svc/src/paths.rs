//! Where the agent keeps its keys, its pin store, and its audit log.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Sealed private key material, one file per keystore label.
pub const KEYS_SUBDIR: &str = "keys";
/// Append-only JSONL audit files, one per UTC day (brief §6.4).
pub const AUDIT_SUBDIR: &str = "audit";
/// Diagnostic logs. Distinct from `audit/`, which is a security record the
/// operator may not delete; these are ordinary troubleshooting output and exist
/// because a Windows service has no console for `tracing` to write to.
pub const LOGS_SUBDIR: &str = "logs";
/// Device id, relay credentials, and the pinned-peer list.
pub const STATE_FILE: &str = "state.json";

/// Root of the agent's on-disk state.
///
/// On Windows this is fixed at `%ProgramData%\Osprey` with no override. The
/// filesystem ACL there is the real access-control boundary for the sealed keys
/// (DPAPI machine scope is readable by any local process), so an environment
/// variable that could redirect the keystore somewhere world-writable would
/// dissolve the only boundary that exists.
#[cfg(windows)]
pub fn data_dir() -> Result<PathBuf> {
    let program_data = std::env::var_os("ProgramData")
        .context("ProgramData is not set; cannot locate the Osprey data directory")?;
    Ok(PathBuf::from(program_data).join("Osprey"))
}

/// Root of the agent's on-disk state.
///
/// `OSPREY_DATA_DIR` is honoured only off Windows, where the keystore is the
/// explicitly non-encrypting dev backend and there is no shipping deployment to
/// weaken.
#[cfg(not(windows))]
pub fn data_dir() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("OSPREY_DATA_DIR") {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state_home).join("osprey"));
    }
    let home = std::env::var_os("HOME")
        .context("neither OSPREY_DATA_DIR, XDG_STATE_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/state/osprey"))
}

/// The three subtrees the agent needs, created if absent.
#[derive(Debug, Clone)]
pub struct DataLayout {
    pub root: PathBuf,
    pub keys: PathBuf,
    pub audit: PathBuf,
    pub logs: PathBuf,
    pub state: PathBuf,
}

impl DataLayout {
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            keys: root.join(KEYS_SUBDIR),
            audit: root.join(AUDIT_SUBDIR),
            logs: root.join(LOGS_SUBDIR),
            state: root.join(STATE_FILE),
            root,
        }
    }

    /// Resolve the platform data directory and create the subtrees.
    pub fn create_default() -> Result<Self> {
        let layout = Self::under(data_dir()?);
        layout.create()?;
        Ok(layout)
    }

    pub fn create(&self) -> Result<()> {
        for dir in [&self.root, &self.keys, &self.audit, &self.logs] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("could not create {}", dir.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_places_every_artefact_under_one_root() {
        let layout = DataLayout::under("/var/osprey");
        assert_eq!(layout.keys, PathBuf::from("/var/osprey/keys"));
        assert_eq!(layout.audit, PathBuf::from("/var/osprey/audit"));
        assert_eq!(layout.logs, PathBuf::from("/var/osprey/logs"));
        assert_eq!(layout.state, PathBuf::from("/var/osprey/state.json"));
    }

    #[test]
    fn diagnostics_never_share_a_directory_with_the_audit_record() {
        // Brief §6.4: the audit log is not deletable from the client. Keeping
        // rotatable diagnostics out of that directory is what lets a future
        // log-cleanup task exist without it being able to touch the record.
        let layout = DataLayout::under("/var/osprey");
        assert_ne!(layout.logs, layout.audit);
    }

    #[test]
    fn create_makes_every_subtree() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let layout = DataLayout::under(tmp.path().join("nested"));
        layout.create().expect("create");
        assert!(layout.keys.is_dir());
        assert!(layout.audit.is_dir());
        assert!(layout.logs.is_dir());
    }
}
