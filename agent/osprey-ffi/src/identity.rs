//! Identity bundles: what the phone signs, what it verifies, what it pins.
//!
//! The phone's root of trust is a P-256 key in the Secure Enclave. It never
//! exports, so Rust never sees it: Swift asks [`cross_certificate_bytes`] for
//! the exact message to sign, signs it with `SecKeyCreateSignature`, and hands
//! the DER signature back inside a [`PeerIdentity`]. Everything on this side is
//! verification and encoding.

use osprey_core::identity::{
    cross_certificate_bytes as core_cross_certificate_bytes, verify_cross_signature, Fingerprint,
    PublicIdentity,
};
use osprey_proto::IdentityAlgorithm;
use serde::{Deserialize, Serialize};

use crate::error::{key32, OspreyError, Result};

/// The identity bundle exchanged inside the encrypted handshake payloads.
///
/// This mirrors the private `IdentityMessage` in `osprey_core::pairing::flow`.
/// Only the one-field wrapper is restated — the inner encoding is
/// `PublicIdentity`'s own `serde` implementation, so the hex-vs-base64 and
/// field-name decisions have exactly one definition. `tests/pairing_interop.rs`
/// drives a real `osprey_core::pairing::respond` against this encoder, so a
/// divergence fails a test rather than a first pairing on a phone.
#[derive(Serialize, Deserialize)]
struct IdentityEnvelope {
    identity: PublicIdentity,
}

/// A device's pinned public material.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PeerIdentity {
    /// Wire spelling of the identity algorithm: `"ed25519"` or `"p256"`.
    pub identity_algorithm: String,
    /// 32 bytes for Ed25519; 65 bytes of uncompressed SEC1 point for P-256.
    pub identity_pub: Vec<u8>,
    /// The X25519 Noise static this identity vouches for. Always 32 bytes.
    pub noise_static_pub: Vec<u8>,
    /// 64 raw bytes for Ed25519; variable-length ASN.1 DER for P-256.
    pub noise_static_sig: Vec<u8>,
}

impl TryFrom<&PeerIdentity> for PublicIdentity {
    type Error = OspreyError;

    fn try_from(value: &PeerIdentity) -> Result<Self> {
        Ok(PublicIdentity {
            identity_algorithm: IdentityAlgorithm::from(value.identity_algorithm.clone()),
            identity_pub: value.identity_pub.clone(),
            noise_static_pub: key32("noise static public key", &value.noise_static_pub)?,
            noise_static_sig: value.noise_static_sig.clone(),
        })
    }
}

impl From<&PublicIdentity> for PeerIdentity {
    fn from(value: &PublicIdentity) -> Self {
        Self {
            identity_algorithm: value.identity_algorithm.as_str().to_string(),
            identity_pub: value.identity_pub.clone(),
            noise_static_pub: value.noise_static_pub.to_vec(),
            noise_static_sig: value.noise_static_sig.clone(),
        }
    }
}

/// A pinned identity's fingerprint, in both the forms the UI needs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityFingerprint {
    /// Full 32-byte SHA-256, lowercase hex.
    pub hex: String,
    /// First 8 bytes grouped in pairs, for reading aloud at pairing.
    pub short: String,
}

impl From<Fingerprint> for IdentityFingerprint {
    fn from(value: Fingerprint) -> Self {
        Self {
            hex: value.to_string(),
            short: value.short(),
        }
    }
}

/// The exact bytes an identity key must sign to vouch for a Noise static.
///
/// Swift must never construct this string itself. `proto/messages.toml`
/// documents a different construction than the agent implements, and a phone
/// that signs the documented one fails every pairing with a signature error that
/// looks like a key-management bug. Asking Rust removes the possibility.
#[uniffi::export]
pub fn cross_certificate_bytes(identity_pub: Vec<u8>, noise_static_pub: Vec<u8>) -> Result<Vec<u8>> {
    let static_pub = key32("noise static public key", &noise_static_pub)?;
    Ok(core_cross_certificate_bytes(&identity_pub, &static_pub))
}

/// Verify that `identity`'s Noise static really was cross-signed by its identity
/// key. This is how the phone checks the *agent*'s Ed25519 cross-certificate,
/// and how it re-checks its own bundle before sending it.
#[uniffi::export]
pub fn verify_identity_bundle(identity: PeerIdentity) -> Result<()> {
    let public = PublicIdentity::try_from(&identity)?;
    verify_cross_signature(
        &public.identity_algorithm,
        &public.identity_pub,
        &public.noise_static_pub,
        &public.noise_static_sig,
    )?;
    Ok(())
}

/// The fingerprint of a device identity: what the operator compares at pairing
/// and what the audit log records. Hashes the algorithm alongside the key, so
/// the same key bytes under two algorithms are two different devices.
#[uniffi::export]
pub fn identity_fingerprint(identity: PeerIdentity) -> Result<IdentityFingerprint> {
    let public = PublicIdentity::try_from(&identity)?;
    Ok(public.fingerprint().into())
}

/// Encode the identity bundle the phone sends as its first handshake payload.
#[uniffi::export]
pub fn encode_identity_message(identity: PeerIdentity) -> Result<Vec<u8>> {
    let public = PublicIdentity::try_from(&identity)?;
    serde_json::to_vec(&IdentityEnvelope { identity: public }).map_err(|e| {
        OspreyError::PayloadEncode {
            detail: e.to_string(),
        }
    })
}

/// Decode the agent's identity bundle from its handshake reply, verifying the
/// cross-certificate before returning it. A bundle that does not verify is
/// refused here so no caller can skip the check.
#[uniffi::export]
pub fn decode_identity_message(message: Vec<u8>) -> Result<PeerIdentity> {
    let envelope: IdentityEnvelope =
        serde_json::from_slice(&message).map_err(|e| OspreyError::PayloadDecode {
            detail: e.to_string(),
        })?;
    envelope.identity.verify_self_consistent()?;
    Ok(PeerIdentity::from(&envelope.identity))
}

/// The plaintext the phone sends as its first *transport* message once pairing's
/// handshake completes.
///
/// `IKpsk2` mixes the PSK into the second message, so the agent reaches
/// transport mode without ever learning whether the phone held the same secret.
/// This message is where a wrong PSK finally fails, which is why the agent pins
/// nothing until it decrypts it.
#[uniffi::export]
pub fn pair_confirm_tag() -> Vec<u8> {
    b"osprey/pair/confirm/v1".to_vec()
}

/// The agent's reply to [`pair_confirm_tag`]. The phone must compare against
/// this exactly before treating the pairing as complete.
#[uniffi::export]
pub fn pair_accept_tag() -> Vec<u8> {
    b"osprey/pair/accept/v1".to_vec()
}
