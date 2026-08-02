//! Verification of a peer-issued `pair.revoke`.
//!
//! This is the client's half of "unpair works from both sides" (P0 execution
//! plan §3, task D3). The operator standing at the host removes a pin with the
//! console `unpair`; the operator holding the phone cannot, so the phone signs a
//! revocation under its pinned identity key and sends it inside the already
//! authenticated Noise channel.
//!
//! Everything here is verification only: it decides whether a revocation is
//! genuine, fresh and addressed to this pairing. Removing the pin, auditing it
//! and closing the session are the caller's job, because they touch host state
//! this crate deliberately does not own.
//!
//! Three separate properties have to hold, and none of them implies the others:
//!
//! * **authenticity** — the signature verifies under the *pinned* identity key,
//!   not under any key carried in the message;
//! * **freshness** — `issued_at` is inside the receiver's clock window, so a
//!   revocation captured long ago cannot be presented as current;
//! * **single use** — the nonce has not been accepted before, so a revocation
//!   captured *inside* the window cannot be replayed after a re-pairing.
//!
//! The nonce store the caller keeps only has to cover the clock window: outside
//! it, freshness already rejects the message.

use std::fmt;
use std::time::Duration;

use crate::identity::{verify_identity_signature, PinnedPeer};

/// Domain separator for a signed unpair, as specified in `proto/messages.toml`.
pub const REVOKE_CONTEXT: &[u8] = b"osprey/pair.revoke/v1";

/// Anti-replay nonce length, fixed by the protocol.
pub const REVOKE_NONCE_LEN: usize = 32;

/// Ed25519 signature length.
const REVOKE_SIGNATURE_LEN: usize = 64;

/// How far `issued_at` may sit either side of the receiver's clock.
///
/// TODO(frank): this window is also the retention period the nonce store has to
/// cover, and it must match what the iOS client allows for its own clock drift.
/// Five minutes is what this build enforces; decide whether the phone (which can
/// be offline for days and resyncs its clock on reconnect) needs a wider window,
/// or whether the revocation should instead carry a host-issued challenge and
/// drop the clock dependency entirely. Both ends must agree before an iOS-issued
/// revocation can be accepted in the field.
pub const REVOKE_CLOCK_WINDOW: Duration = Duration::from_secs(300);

/// Why a `pair.revoke` was refused. Every variant is an audited security
/// outcome, not a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationRejection {
    /// `nonce` or `signature` is not the length the protocol fixes.
    Malformed,
    /// The revocation names an issuer other than the peer on this session.
    WrongIssuer,
    /// The revocation targets a device that is neither end of this pairing.
    UnrelatedTarget,
    /// `issued_at` is outside the receiver's clock window.
    StaleClock,
    /// The signature does not verify under the peer's *pinned* identity key.
    BadSignature,
    /// This nonce has already been accepted.
    ReplayedNonce,
}

impl fmt::Display for RevocationRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Malformed => "nonce or signature has the wrong length",
            Self::WrongIssuer => "issuer is not the device on this session",
            Self::UnrelatedTarget => "revoked device is not part of this pairing",
            Self::StaleClock => "issued_at is outside the accepted clock window",
            Self::BadSignature => "signature does not verify under the pinned identity key",
            Self::ReplayedNonce => "this revocation nonce has already been used",
        };
        f.write_str(s)
    }
}

/// The exact byte string a `pair.revoke` signature covers.
///
/// Fixed-width and unambiguous: every field has a constant length, so no two
/// distinct revocations can produce the same message.
pub fn revocation_signing_bytes(
    issuer_device_id: &[u8; 16],
    revoked_device_id: &[u8; 16],
    issued_at_ms: i64,
    nonce: &[u8; REVOKE_NONCE_LEN],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(REVOKE_CONTEXT.len() + 16 + 16 + 8 + REVOKE_NONCE_LEN);
    message.extend_from_slice(REVOKE_CONTEXT);
    message.extend_from_slice(issuer_device_id);
    message.extend_from_slice(revoked_device_id);
    message.extend_from_slice(&issued_at_ms.to_be_bytes());
    message.extend_from_slice(nonce);
    message
}

/// A `pair.revoke` as it arrived, with the two variable-length fields still
/// unvalidated.
#[derive(Debug, Clone, Copy)]
pub struct Revocation<'a> {
    pub issuer_device_id: [u8; 16],
    pub revoked_device_id: [u8; 16],
    pub issued_at_ms: i64,
    pub nonce: &'a [u8],
    pub signature: &'a [u8],
}

/// What the receiver knows independently of the message.
#[derive(Debug, Clone, Copy)]
pub struct RevocationCheck<'a> {
    /// The peer's pin, as loaded from the host's own store. The identity key
    /// used for verification comes from here and nowhere else.
    pub peer: &'a PinnedPeer,
    /// The device id the peer announced in `hello` on this session.
    pub peer_device_id: [u8; 16],
    /// This host's own device id.
    pub host_device_id: [u8; 16],
    /// Receiver's clock, milliseconds since the Unix epoch.
    pub now_ms: i64,
}

/// Verify a revocation, returning the nonce the caller must record before acting.
///
/// Returning the nonce rather than checking it here is deliberate: the store
/// that answers "have I seen this?" is persistent host state, and it must not be
/// written until the signature has been checked, or an unauthenticated peer
/// could fill it.
pub fn verify_revocation(
    revocation: &Revocation<'_>,
    check: &RevocationCheck<'_>,
) -> Result<[u8; REVOKE_NONCE_LEN], RevocationRejection> {
    let nonce = <[u8; REVOKE_NONCE_LEN]>::try_from(revocation.nonce)
        .map_err(|_| RevocationRejection::Malformed)?;
    let signature = <[u8; REVOKE_SIGNATURE_LEN]>::try_from(revocation.signature)
        .map_err(|_| RevocationRejection::Malformed)?;

    if revocation.issuer_device_id != check.peer_device_id {
        return Err(RevocationRejection::WrongIssuer);
    }
    // Either end of a pairing may revoke either side of it, but the only action
    // this host can take is to drop its own pin of the peer — so a revocation
    // naming some third device is refused rather than silently treated as one of
    // the two cases that do make sense here.
    if revocation.revoked_device_id != revocation.issuer_device_id
        && revocation.revoked_device_id != check.host_device_id
    {
        return Err(RevocationRejection::UnrelatedTarget);
    }

    let window_ms = i64::try_from(REVOKE_CLOCK_WINDOW.as_millis())
        .map_err(|_| RevocationRejection::StaleClock)?;
    let drift = check.now_ms.saturating_sub(revocation.issued_at_ms);
    if drift.saturating_abs() > window_ms {
        return Err(RevocationRejection::StaleClock);
    }

    let message = revocation_signing_bytes(
        &revocation.issuer_device_id,
        &revocation.revoked_device_id,
        revocation.issued_at_ms,
        &nonce,
    );
    verify_identity_signature(&check.peer.identity_pub, &message, &signature)
        .map_err(|_| RevocationRejection::BadSignature)?;

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    struct Peers {
        issuer: DeviceIdentity,
        pin: PinnedPeer,
        peer_device_id: [u8; 16],
        host_device_id: [u8; 16],
    }

    fn peers() -> Peers {
        let issuer = DeviceIdentity::generate();
        let pin = PinnedPeer::pin(issuer.public()).expect("pin");
        Peers {
            issuer,
            pin,
            peer_device_id: [7u8; 16],
            host_device_id: [9u8; 16],
        }
    }

    fn signed(peers: &Peers, revoked: [u8; 16], issued_at_ms: i64, nonce: [u8; 32]) -> [u8; 64] {
        peers.issuer.sign(&revocation_signing_bytes(
            &peers.peer_device_id,
            &revoked,
            issued_at_ms,
            &nonce,
        ))
    }

    #[test]
    fn a_correctly_signed_revocation_is_accepted() {
        let peers = peers();
        let nonce = [4u8; 32];
        let signature = signed(&peers, peers.host_device_id, 1_000, nonce);
        let accepted = verify_revocation(
            &Revocation {
                issuer_device_id: peers.peer_device_id,
                revoked_device_id: peers.host_device_id,
                issued_at_ms: 1_000,
                nonce: &nonce,
                signature: &signature,
            },
            &RevocationCheck {
                peer: &peers.pin,
                peer_device_id: peers.peer_device_id,
                host_device_id: peers.host_device_id,
                now_ms: 1_000,
            },
        )
        .expect("a genuine revocation must verify");
        assert_eq!(accepted, nonce);
    }

    #[test]
    fn a_revocation_signed_by_another_identity_is_refused() {
        let peers = peers();
        let impostor = DeviceIdentity::generate();
        let nonce = [5u8; 32];
        let signature = impostor.sign(&revocation_signing_bytes(
            &peers.peer_device_id,
            &peers.host_device_id,
            2_000,
            &nonce,
        ));
        let result = verify_revocation(
            &Revocation {
                issuer_device_id: peers.peer_device_id,
                revoked_device_id: peers.host_device_id,
                issued_at_ms: 2_000,
                nonce: &nonce,
                signature: &signature,
            },
            &RevocationCheck {
                peer: &peers.pin,
                peer_device_id: peers.peer_device_id,
                host_device_id: peers.host_device_id,
                now_ms: 2_000,
            },
        );
        assert_eq!(result, Err(RevocationRejection::BadSignature));
    }

    #[test]
    fn a_stale_or_future_issued_at_is_refused() {
        let peers = peers();
        let nonce = [6u8; 32];
        let window_ms = REVOKE_CLOCK_WINDOW.as_millis() as i64;
        for issued_at_ms in [-window_ms - 1, window_ms + 1] {
            let signature = signed(&peers, peers.host_device_id, issued_at_ms, nonce);
            let result = verify_revocation(
                &Revocation {
                    issuer_device_id: peers.peer_device_id,
                    revoked_device_id: peers.host_device_id,
                    issued_at_ms,
                    nonce: &nonce,
                    signature: &signature,
                },
                &RevocationCheck {
                    peer: &peers.pin,
                    peer_device_id: peers.peer_device_id,
                    host_device_id: peers.host_device_id,
                    now_ms: 0,
                },
            );
            assert_eq!(result, Err(RevocationRejection::StaleClock));
        }
    }

    #[test]
    fn a_revocation_naming_a_third_device_is_refused() {
        let peers = peers();
        let nonce = [8u8; 32];
        let stranger = [42u8; 16];
        let signature = signed(&peers, stranger, 0, nonce);
        let result = verify_revocation(
            &Revocation {
                issuer_device_id: peers.peer_device_id,
                revoked_device_id: stranger,
                issued_at_ms: 0,
                nonce: &nonce,
                signature: &signature,
            },
            &RevocationCheck {
                peer: &peers.pin,
                peer_device_id: peers.peer_device_id,
                host_device_id: peers.host_device_id,
                now_ms: 0,
            },
        );
        assert_eq!(result, Err(RevocationRejection::UnrelatedTarget));
    }

    #[test]
    fn a_short_nonce_is_refused_before_any_signature_work() {
        let peers = peers();
        let result = verify_revocation(
            &Revocation {
                issuer_device_id: peers.peer_device_id,
                revoked_device_id: peers.host_device_id,
                issued_at_ms: 0,
                nonce: &[1u8; 16],
                signature: &[0u8; 64],
            },
            &RevocationCheck {
                peer: &peers.pin,
                peer_device_id: peers.peer_device_id,
                host_device_id: peers.host_device_id,
                now_ms: 0,
            },
        );
        assert_eq!(result, Err(RevocationRejection::Malformed));
    }

    #[test]
    fn the_signed_bytes_are_the_documented_construction() {
        let message =
            revocation_signing_bytes(&[1u8; 16], &[2u8; 16], 0x0102_0304_0506_0708, &[3u8; 32]);
        assert_eq!(message.len(), REVOKE_CONTEXT.len() + 16 + 16 + 8 + 32);
        assert!(message.starts_with(REVOKE_CONTEXT));
        let issued_at_offset = REVOKE_CONTEXT.len() + 32;
        assert_eq!(
            &message[issued_at_offset..issued_at_offset + 8],
            &[1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
