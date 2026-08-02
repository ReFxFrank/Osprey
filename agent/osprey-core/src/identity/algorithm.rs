//! Verification of a *peer's* hardware identity signatures, one arm per
//! algorithm.
//!
//! This device's own identity is Ed25519 and always will be (brief §6.1), but
//! the peer that matters most — an iPhone — roots its trust in a P-256 key in
//! the Secure Enclave, because the Enclave has no Ed25519. So verification, and
//! only verification, is algorithm-agnostic.
//!
//! ## Interoperating with the Secure Enclave
//!
//! Two encoding details decide whether this works against a real iPhone, and
//! both fail silently as "signature does not verify" if they are wrong:
//!
//! * `SecKeyCopyExternalRepresentation` exports a P-256 public key as an X9.63
//!   **uncompressed point** — `0x04 ‖ X(32) ‖ Y(32)`, 65 bytes. Not DER, not
//!   SPKI, no algorithm identifier.
//! * `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` hashes the
//!   message with SHA-256 *itself* and returns an **ASN.1 DER** `SEQUENCE` of
//!   two `INTEGER`s, whose length varies (typically 70–72 bytes, and shorter
//!   when a leading zero byte drops out). The fixed-width `r ‖ s` form must not
//!   be used to parse it.
//!
//! The RustCrypto `Verifier` impl used below hashes with SHA-256 as well, which
//! is what makes it the counterpart of `…MessageX962SHA256` rather than of the
//! pre-hashed `…DigestX962SHA256`.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use osprey_proto::IdentityAlgorithm;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key};

use crate::error::{CrossSignatureFailure, Error, Result};

/// Ed25519 public keys are exactly this long.
const ED25519_KEY_LEN: usize = 32;

/// Ed25519 signatures are exactly this long.
const ED25519_SIGNATURE_LEN: usize = 64;

/// An X9.63 uncompressed P-256 point: the `0x04` tag plus two 32-byte
/// coordinates.
const P256_UNCOMPRESSED_KEY_LEN: usize = 65;

/// SEC1 tag byte for an uncompressed point.
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

/// Longest signature any supported algorithm produces, plus headroom.
///
/// A DER ECDSA signature over P-256 tops out at 72 bytes. The cap is here so a
/// peer cannot make the verifier walk a multi-megabyte buffer before rejecting
/// it; the framing layer bounds a whole message, but not one field inside it.
const MAX_SIGNATURE_LEN: usize = 128;

/// Verify `signature` over `message` under a peer's identity key.
///
/// `algorithm` is taken from the peer's pin (or, at first sight, from the bundle
/// being validated) — never inferred from the key length, because inference is
/// how a verifier ends up choosing the algorithm an attacker prefers.
pub fn verify_identity_signature(
    algorithm: &IdentityAlgorithm,
    identity_pub: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() > MAX_SIGNATURE_LEN {
        return Err(Error::CrossSignature(CrossSignatureFailure::Malformed));
    }
    match algorithm {
        IdentityAlgorithm::Ed25519 => verify_ed25519(identity_pub, message, signature),
        IdentityAlgorithm::P256 => verify_p256(identity_pub, message, signature),
        // Accepting a signature under an algorithm this build cannot check would
        // pin a peer on evidence it never examined.
        IdentityAlgorithm::Unknown(raw) => Err(Error::CrossSignature(
            CrossSignatureFailure::UnsupportedAlgorithm(raw.clone()),
        )),
    }
}

fn verify_ed25519(identity_pub: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key_bytes = <[u8; ED25519_KEY_LEN]>::try_from(identity_pub)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))?;
    let key = Ed25519Key::from_bytes(&key_bytes)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))?;
    let sig_bytes = <[u8; ED25519_SIGNATURE_LEN]>::try_from(signature)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::Malformed))?;
    let sig = Ed25519Signature::from_bytes(&sig_bytes);
    // Fully qualified because both dalek and p256 verify through the same
    // `signature::Verifier` trait; importing it once would silently make one
    // arm depend on the other crate's re-export.
    ed25519_dalek::Verifier::verify(&key, message, &sig)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::NotSignedByIdentity))
}

fn verify_p256(identity_pub: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    // Only the uncompressed encoding is admitted, even though SEC1 also defines
    // a 33-byte compressed form that `from_sec1_bytes` would happily accept.
    // The raw key bytes are what gets pinned, fingerprinted and byte-compared,
    // so allowing two encodings of one key would produce two different pins for
    // one device and make "is this the peer I pinned?" answer no.
    if identity_pub.len() != P256_UNCOMPRESSED_KEY_LEN
        || identity_pub.first() != Some(&SEC1_UNCOMPRESSED_TAG)
    {
        return Err(Error::CrossSignature(CrossSignatureFailure::BadIdentityKey));
    }
    let key = p256::PublicKey::from_sec1_bytes(identity_pub)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))?;
    let sig = P256Signature::from_der(signature)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::Malformed))?;
    p256::ecdsa::signature::Verifier::verify(&P256Key::from(&key), message, &sig)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::NotSignedByIdentity))
}

/// How long a public key must be for `algorithm`, or `None` if the algorithm is
/// not one this build knows.
///
/// Used to reject a bundle whose key length cannot belong to the algorithm it
/// claims, before any signature work happens.
pub fn expected_key_len(algorithm: &IdentityAlgorithm) -> Option<usize> {
    match algorithm {
        IdentityAlgorithm::Ed25519 => Some(ED25519_KEY_LEN),
        IdentityAlgorithm::P256 => Some(P256_UNCOMPRESSED_KEY_LEN),
        IdentityAlgorithm::Unknown(_) => None,
    }
}
