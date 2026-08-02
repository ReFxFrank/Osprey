//! Pairing: the one enrolment path, and the only one there will ever be.

mod flow;
mod qr;
mod revoke;
mod secret;

pub use flow::{initiate, record_unpair, respond, PairingOutcome};
pub use qr::{QrPayload, QR_PAYLOAD_VERSION};
pub use revoke::{
    revocation_signing_bytes, verify_revocation, Revocation, RevocationCheck, RevocationRejection,
    REVOKE_CLOCK_WINDOW, REVOKE_CONTEXT, REVOKE_NONCE_LEN,
};
pub use secret::{PairingOffer, PairingSecret, RoutingId, DEFAULT_PAIRING_TTL, PAIRING_SECRET_LEN};

use serde::Serialize;

/// Why a pairing attempt was refused. Every variant is an audited outcome, not
/// a log line — a rejected pairing is a security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingFailureReason {
    /// The offer's validity window had passed.
    Expired,
    /// The offer had already been used. Single-use is enforced at the host
    /// because the relay is untrusted and cannot be asked to enforce it.
    Replayed,
    /// A handshake message failed to decrypt or authenticate — tampering, a
    /// wrong pattern, or a peer that never held the QR secret.
    HandshakeRejected,
    /// The handshake completed but the peer could not produce a confirmation
    /// under the pairing secret. In `IKpsk2` the responder cannot detect a PSK
    /// mismatch any earlier than this.
    PskMismatch,
    /// The peer's Noise static was not cross-signed by the identity key it
    /// claimed.
    BadSignature,
    /// The cross-signed static did not match the static the handshake actually
    /// used — an attempt to have one key vouched for and another key used.
    StaticMismatch,
    /// The peer is not the device named in the QR.
    PeerIdentityMismatch,
    /// A payload inside the encrypted channel did not parse.
    MalformedPayload,
    /// Connection-level failure before a verdict could be reached.
    Transport,
}

/// Identifiers recorded alongside every pairing audit entry.
#[derive(Debug, Clone)]
pub struct PairingContext {
    pub account_id: String,
    pub device_id: String,
}

impl PairingContext {
    pub fn new(account_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            device_id: device_id.into(),
        }
    }
}
