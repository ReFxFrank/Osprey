//! Append-only JSONL audit log.
//!
//! Pairing is the highest-privilege action Osprey performs — it grants a device
//! full control of the machine — so pairing success, pairing failure and unpair
//! are audited from P0 onward (P0 execution plan §2 #14; the brief's §6.4 list
//! omitted them).
//!
//! "Append-only" is enforced by construction: this type exposes no truncate, no
//! rewrite and no delete, and every write opens the day's file with
//! `append(true)`. There is deliberately no client-reachable path that removes a
//! line, which is why the log is not user-suppressible.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::identity::Fingerprint;
use crate::pairing::PairingFailureReason;

/// Which side asked for an unpair, so a revocation can be traced back.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnpairInitiator {
    /// Operator acted at the host (physical access).
    Host,
    /// Signed `pair.revoke` arrived over the authenticated channel.
    Peer,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    PairingSucceeded {
        account_id: String,
        device_id: String,
        /// Fingerprint of the peer's *identity* key — the durable pin, and the
        /// value shown to the human at the host for out-of-band comparison.
        peer_fingerprint: Fingerprint,
        #[serde(with = "crate::hex32")]
        peer_noise_static: [u8; 32],
    },
    PairingFailed {
        account_id: String,
        device_id: String,
        reason: PairingFailureReason,
        /// Human-readable detail. Never contains the pairing secret.
        detail: String,
    },
    Unpaired {
        account_id: String,
        device_id: String,
        peer_fingerprint: Fingerprint,
        initiated_by: UnpairInitiator,
    },
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    ts: String,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

pub struct AuditLog {
    dir: PathBuf,
    // Serialises writers in-process. `O_APPEND` already prevents interleaving
    // across processes for writes this small; the mutex removes the same risk
    // between the agent's own threads without depending on that guarantee.
    write_lock: Mutex<()>,
}

impl AuditLog {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(Error::Audit)?;
        Ok(Self {
            dir,
            write_lock: Mutex::new(()),
        })
    }

    /// Path of the file the next record would land in.
    pub fn current_file(&self) -> PathBuf {
        self.path_for(OffsetDateTime::now_utc())
    }

    fn path_for(&self, now: OffsetDateTime) -> PathBuf {
        let date = now.date();
        self.dir.join(format!(
            "{:04}-{:02}-{:02}.jsonl",
            date.year(),
            u8::from(date.month()),
            date.day()
        ))
    }

    /// Append one event. Failure to audit is returned, never swallowed: a
    /// caller that cannot record a pairing must not proceed with it.
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let ts = now
            .format(&Rfc3339)
            .map_err(|e| Error::Audit(std::io::Error::other(e)))?;
        let mut line = serde_json::to_vec(&AuditRecord { ts, event })
            .map_err(|e| Error::Audit(std::io::Error::other(e)))?;
        line.push(b'\n');

        let path = self.path_for(now);
        let guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(Error::Audit)?;
        file.write_all(&line).map_err(Error::Audit)?;
        file.sync_data().map_err(Error::Audit)?;
        drop(guard);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_append_one_line_each() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::open(dir.path()).expect("open");
        let event = AuditEvent::Unpaired {
            account_id: "acct".into(),
            device_id: "dev".into(),
            peer_fingerprint: Fingerprint::of_identity(&[1u8; 32]),
            initiated_by: UnpairInitiator::Host,
        };
        log.record(&event).expect("first");
        log.record(&event).expect("second");
        let body = fs::read_to_string(log.current_file()).expect("read back");
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("\"event\":\"unpaired\""));
        assert!(body.contains("\"initiated_by\":\"host\""));
    }
}
