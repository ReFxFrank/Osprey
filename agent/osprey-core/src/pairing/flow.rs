//! The pairing exchange, with auditing welded to the control flow.
//!
//! Both drivers return through a single point that records the outcome, so
//! there is no path — success or failure — that can forget to audit. That is
//! deliberate: the audit entry *is* the security control, and an "add the log
//! line at the call site" design fails open the first time someone adds an
//! early return.
//!
//! ## Why a post-handshake confirmation exists
//!
//! In `IKpsk2` the PSK is mixed into the *second* message. The responder writes
//! that message and reaches transport mode without ever learning whether the
//! initiator holds the same PSK; only the initiator's decryption of message two
//! depends on it. So the agent must not pin anything until it has decrypted one
//! transport-mode message from the peer. That first message is the confirmation
//! below, and a wrong PSK fails there — closed, and audited.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, AuditLog, UnpairInitiator};
use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, PinnedPeer, PublicIdentity};
use crate::noise::{Handshake, HandshakeConfig, NoiseSession, Pattern, Role};
use crate::pairing::secret::PairingOffer;
use crate::pairing::{PairingContext, PairingFailureReason, QrPayload};

const CONFIRM_TAG: &[u8] = b"osprey/pair/confirm/v1";
const ACCEPT_TAG: &[u8] = b"osprey/pair/accept/v1";

/// Identity bundle exchanged inside the encrypted handshake payloads.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityMessage {
    identity: PublicIdentity,
}

/// A completed pairing: the peer to pin, and the live channel to it.
#[derive(Debug)]
pub struct PairingOutcome {
    pub peer: PinnedPeer,
    pub session: NoiseSession,
}

type Attempt<T> = std::result::Result<T, (PairingFailureReason, Error)>;

/// Flatten an error chain into one audit-safe line. No Osprey error's `Display`
/// carries key material or the pairing secret.
fn detail(err: &Error) -> String {
    let mut out = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

fn finish(
    audit: &AuditLog,
    context: &PairingContext,
    attempt: Attempt<PairingOutcome>,
) -> Result<PairingOutcome> {
    match attempt {
        Ok(outcome) => {
            audit.record(&AuditEvent::PairingSucceeded {
                account_id: context.account_id.clone(),
                device_id: context.device_id.clone(),
                peer_fingerprint: outcome.peer.fingerprint(),
                peer_noise_static: outcome.peer.noise_static_pub,
            })?;
            Ok(outcome)
        }
        Err((reason, err)) => {
            audit.record(&AuditEvent::PairingFailed {
                account_id: context.account_id.clone(),
                device_id: context.device_id.clone(),
                reason,
                detail: detail(&err),
            })?;
            Err(err)
        }
    }
}

/// Check that the bundle a peer sent is internally sound *and* describes the
/// static the handshake actually authenticated.
fn pin_from_handshake(
    message: &[u8],
    session: &NoiseSession,
) -> Attempt<(PinnedPeer, PublicIdentity)> {
    let parsed: IdentityMessage = serde_json::from_slice(message).map_err(|e| {
        (
            PairingFailureReason::MalformedPayload,
            Error::PairingDecode(e),
        )
    })?;
    let peer = PinnedPeer::pin(&parsed.identity)
        .map_err(|e| (PairingFailureReason::BadSignature, e))?;
    if !peer.matches_handshake_static(session.remote_static()) {
        return Err((PairingFailureReason::StaticMismatch, Error::UnpinnedPeer));
    }
    Ok((peer, parsed.identity))
}

fn encode_identity(identity: &DeviceIdentity) -> Attempt<Vec<u8>> {
    serde_json::to_vec(&IdentityMessage {
        identity: identity.public().clone(),
    })
    .map_err(|e| {
        (
            PairingFailureReason::MalformedPayload,
            Error::PairingEncode(e),
        )
    })
}

/// Host side. Accepts one pairing attempt on `stream`, consuming `offer`.
pub fn respond<S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    offer: &mut PairingOffer,
    context: &PairingContext,
    audit: &AuditLog,
) -> Result<PairingOutcome> {
    let attempt = respond_inner(stream, identity, offer, context);
    finish(audit, context, attempt)
}

fn respond_inner<S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    offer: &mut PairingOffer,
    _context: &PairingContext,
) -> Attempt<PairingOutcome> {
    if offer.is_consumed() {
        return Err((
            PairingFailureReason::Replayed,
            Error::HandshakeConfig("pairing offer already used"),
        ));
    }
    if offer.is_expired() {
        return Err((
            PairingFailureReason::Expired,
            Error::HandshakeConfig("pairing offer expired"),
        ));
    }

    let local_static = identity.noise_static_secret();
    let handshake = Handshake::new(HandshakeConfig {
        pattern: Pattern::Pairing,
        role: Role::Responder,
        local_static: &local_static,
        remote_static: None,
        psk: Some(offer.secret()),
    })
    .map_err(|e| (PairingFailureReason::HandshakeRejected, e))?;

    let reply = encode_identity(identity)?;
    let (mut session, request) = handshake
        .run_responder(stream, &reply)
        .map_err(classify_handshake)?;

    let (peer, _) = pin_from_handshake(&request, &session)?;

    // First transport-mode message: this is where a wrong PSK finally shows up.
    let confirm = session
        .recv(stream)
        .map_err(|e| (PairingFailureReason::PskMismatch, e))?
        .ok_or((
            PairingFailureReason::PskMismatch,
            Error::TruncatedFrame { got: 0, want: 2 },
        ))?;
    if confirm != CONFIRM_TAG {
        return Err((
            PairingFailureReason::MalformedPayload,
            Error::HandshakeConfig("peer sent an unexpected pairing confirmation"),
        ));
    }
    offer.consume();

    session
        .send(ACCEPT_TAG, stream)
        .map_err(|e| (PairingFailureReason::Transport, e))?;

    Ok(PairingOutcome { peer, session })
}

/// Controller side. Runs the scanning device's half against a scanned QR.
pub fn initiate<S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    qr: &QrPayload,
    audit: &AuditLog,
) -> Result<PairingOutcome> {
    let context = PairingContext::new(qr.account_id.clone(), qr.device_id.clone());
    let attempt = initiate_inner(stream, identity, qr);
    finish(audit, &context, attempt)
}

fn initiate_inner<S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    qr: &QrPayload,
) -> Attempt<PairingOutcome> {
    // The QR is the trust anchor, so its cross-certificate is checked before a
    // single byte goes on the wire.
    let expected = PinnedPeer::pin(&qr.agent_identity)
        .map_err(|e| (PairingFailureReason::BadSignature, e))?;

    let local_static = identity.noise_static_secret();
    let handshake = Handshake::new(HandshakeConfig {
        pattern: Pattern::Pairing,
        role: Role::Initiator,
        local_static: &local_static,
        remote_static: Some(&expected.noise_static_pub),
        psk: Some(&qr.pairing_secret),
    })
    .map_err(|e| (PairingFailureReason::HandshakeRejected, e))?;

    let hello = encode_identity(identity)?;
    let (mut session, response) = handshake
        .run_initiator(stream, &hello)
        .map_err(classify_handshake)?;

    let (peer, _) = pin_from_handshake(&response, &session)?;
    if peer != expected {
        return Err((
            PairingFailureReason::PeerIdentityMismatch,
            Error::UnpinnedPeer,
        ));
    }

    session
        .send(CONFIRM_TAG, stream)
        .map_err(|e| (PairingFailureReason::Transport, e))?;
    let accept = session
        .recv(stream)
        .map_err(|e| (PairingFailureReason::Transport, e))?
        .ok_or((
            PairingFailureReason::Transport,
            Error::TruncatedFrame { got: 0, want: 2 },
        ))?;
    if accept != ACCEPT_TAG {
        return Err((
            PairingFailureReason::MalformedPayload,
            Error::HandshakeConfig("host sent an unexpected pairing acceptance"),
        ));
    }

    Ok(PairingOutcome { peer, session })
}

/// A read-stage handshake failure is a forged or tampered message; anything else
/// on that path is a transport problem.
fn classify_handshake(err: Error) -> (PairingFailureReason, Error) {
    match &err {
        Error::Handshake { .. } | Error::TransportAuth(_) => {
            (PairingFailureReason::HandshakeRejected, err)
        }
        _ => (PairingFailureReason::Transport, err),
    }
}

/// Record an unpair. Removing the local pin is the caller's job; this is the
/// non-suppressible half of it.
pub fn record_unpair(
    audit: &AuditLog,
    context: &PairingContext,
    peer: &PinnedPeer,
    initiated_by: UnpairInitiator,
) -> Result<()> {
    audit.record(&AuditEvent::Unpaired {
        account_id: context.account_id.clone(),
        device_id: context.device_id.clone(),
        peer_fingerprint: peer.fingerprint(),
        initiated_by,
    })
}
