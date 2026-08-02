//! Applying a peer-signed `pair.revoke` to this host's pin store.
//!
//! The other half of "unpair works from both sides" (P0 execution plan §3, task
//! D3). `commands::unpair` is the operator standing at the machine; this is the
//! operator holding the phone, who has no physical access and therefore signs a
//! revocation instead.
//!
//! [`osprey_core::pairing::verify_revocation`] decides whether the message is
//! genuine. This module owns what happens next, and the order is the security
//! property, exactly as it is in `commands::unpair`:
//!
//! 1. the nonce is recorded, so a replay is refused even if step 2 crashes;
//! 2. the pin is removed from the local store and the store is fsynced;
//! 3. the unpair is audited as [`UnpairInitiator::Peer`];
//! 4. the caller hangs up.
//!
//! The relay is not consulted and gets no veto — it is not even on the path for
//! a LAN session, and a compromised one must not be able to keep a device paired
//! against its owner's instruction.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use osprey_core::audit::{AuditLog, UnpairInitiator};
use osprey_core::identity::{Fingerprint, PinnedPeer};
use osprey_core::pairing::{
    self, PairingContext, Revocation, RevocationCheck, RevocationRejection, REVOKE_CLOCK_WINDOW,
};
use osprey_proto::{ErrorCode, PairRevokeBody};
use uuid::Uuid;

use crate::registry::SessionRegistry;
use crate::state::{HostState, PeerSelector};

/// Why a revocation did not take effect.
#[derive(Debug)]
pub enum RevocationRefusal {
    /// The message itself was refused. Nothing was written.
    Rejected(RevocationRejection),
    /// The message verified but the host could not act on it. The pairing is
    /// unchanged, and the peer is told so rather than being left to assume it
    /// was unpaired.
    NotApplied(anyhow::Error),
}

impl RevocationRefusal {
    /// Wire error class. A rejected replay is a `conflict` rather than an
    /// `unauthorized`: the signature was good, the message is simply spent.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Rejected(RevocationRejection::Malformed) => ErrorCode::BadRequest,
            Self::Rejected(RevocationRejection::ReplayedNonce) => ErrorCode::Conflict,
            Self::Rejected(_) => ErrorCode::Unauthorized,
            Self::NotApplied(_) => ErrorCode::Internal,
        }
    }

    /// Text safe to put on the wire. Host paths and io detail stay in the log.
    pub fn wire_message(&self) -> String {
        match self {
            Self::Rejected(reason) => format!("pair.revoke refused: {reason}"),
            Self::NotApplied(_) => "the revocation could not be applied at the host".to_owned(),
        }
    }
}

impl std::fmt::Display for RevocationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) => write!(f, "rejected: {reason}"),
            Self::NotApplied(err) => write!(f, "not applied: {err:#}"),
        }
    }
}

/// A revocation that took effect.
#[derive(Debug)]
pub struct AppliedRevocation {
    /// The peer that is no longer pinned.
    pub fingerprint: Fingerprint,
    /// The pin is gone whether or not the audit line landed, so an audit failure
    /// cannot undo the revocation and must not be reported as one. It is
    /// surfaced here instead of dropped: revocation happened, the record of it
    /// did not, and the operator needs to know which.
    pub audit_error: Option<osprey_core::Error>,
}

/// Everything a session thread needs to act on a `pair.revoke`.
///
/// Built once per `run` and shared by reference across session threads.
pub struct RevocationHandler<'a> {
    state_path: PathBuf,
    audit: &'a AuditLog,
    registry: &'a Arc<SessionRegistry>,
    host_device_id: Uuid,
    context: PairingContext,
    /// Serialises the read-modify-write of `state.json` between session threads.
    /// The P0 console `unpair` is a *separate process* and is outside this lock;
    /// that residual is inherent to P0's two-process model and closes at P1,
    /// when the service owns both paths.
    write_lock: Mutex<()>,
}

impl<'a> RevocationHandler<'a> {
    pub fn new(
        state_path: &Path,
        audit: &'a AuditLog,
        registry: &'a Arc<SessionRegistry>,
        host_device_id: Uuid,
        context: PairingContext,
    ) -> Self {
        Self {
            state_path: state_path.to_path_buf(),
            audit,
            registry,
            host_device_id,
            context,
            write_lock: Mutex::new(()),
        }
    }

    /// Verify a revocation and, if it holds, remove the peer's pin.
    pub fn apply(
        &self,
        body: &PairRevokeBody,
        peer: &PinnedPeer,
        peer_device_id: Uuid,
    ) -> Result<AppliedRevocation, RevocationRefusal> {
        let now_ms = crate::session::now_ms();
        let nonce = pairing::verify_revocation(
            &Revocation {
                issuer_device_id: *body.issuer_device_id.as_bytes(),
                revoked_device_id: *body.revoked_device_id.as_bytes(),
                issued_at_ms: body.issued_at,
                nonce: &body.nonce,
                signature: &body.signature,
            },
            &RevocationCheck {
                peer,
                peer_device_id: *peer_device_id.as_bytes(),
                host_device_id: *self.host_device_id.as_bytes(),
                now_ms,
            },
        )
        .map_err(RevocationRefusal::Rejected)?;

        let window_ms = i64::try_from(REVOKE_CLOCK_WINDOW.as_millis())
            .map_err(|_| RevocationRefusal::Rejected(RevocationRejection::StaleClock))?;

        let guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = self.remove_pin(peer, &nonce, body.issued_at, now_ms, window_ms);
        drop(guard);
        result
    }

    /// Hang up on every other live session with this peer.
    ///
    /// The pin is already gone, so the revocation watcher would close them
    /// within its poll interval regardless; doing it here makes "immediate"
    /// (brief §6.1) literal rather than approximate.
    pub fn close_peer_sessions(&self, peer: &PinnedPeer) -> usize {
        self.registry.revoke_identity(&peer.fingerprint())
    }

    fn remove_pin(
        &self,
        peer: &PinnedPeer,
        nonce: &[u8; 32],
        issued_at_ms: i64,
        now_ms: i64,
        window_ms: i64,
    ) -> Result<AppliedRevocation, RevocationRefusal> {
        let mut state = HostState::load(&self.state_path).map_err(RevocationRefusal::NotApplied)?;

        // Recorded before the pin is touched: if the process dies between the
        // two, the worst case is a revocation that must be re-issued, not a
        // revocation that can be replayed after the operator re-pairs.
        let fresh = state
            .consume_revocation_nonce(nonce, issued_at_ms, now_ms, window_ms)
            .map_err(RevocationRefusal::NotApplied)?;
        if !fresh {
            return Err(RevocationRefusal::Rejected(
                RevocationRejection::ReplayedNonce,
            ));
        }

        let fingerprint = peer.fingerprint();
        let selector = PeerSelector::FingerprintPrefix(fingerprint.to_string());
        let removed = state
            .remove_peers(&selector)
            .map_err(RevocationRefusal::NotApplied)?;
        if removed.is_empty() {
            // The pin went away between the handshake and here — a local
            // `unpair` won the race. The peer's stated goal already holds.
            tracing::info!(
                fingerprint = %fingerprint.short(),
                "pair.revoke named a peer that was already unpinned"
            );
        }

        let audit_error =
            pairing::record_unpair(self.audit, &self.context, peer, UnpairInitiator::Peer).err();

        Ok(AppliedRevocation {
            fingerprint,
            audit_error,
        })
    }
}
