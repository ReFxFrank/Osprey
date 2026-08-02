//! P-256 peer verification: the agent's half of pairing with an iPhone.
//!
//! The phone's root of trust is a P-256 key in the Secure Enclave, so the agent
//! must verify an ECDSA cross-signature it can never produce itself. Everything
//! here is written against the two Apple encodings that actually decide whether
//! this interoperates, because both fail as a plain "does not verify" when they
//! are wrong:
//!
//! * `SecKeyCopyExternalRepresentation` → X9.63 uncompressed point, 65 bytes.
//! * `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` → ASN.1 DER,
//!   variable length, message hashed with SHA-256 by the framework.

use osprey_core::error::{CrossSignatureFailure, Error};
use osprey_core::identity::{
    cross_certificate_bytes, verify_cross_signature, verify_identity_signature, DeviceIdentity,
    Fingerprint, PinnedPeer, PublicIdentity,
};
use osprey_core::pairing::{
    revocation_signing_bytes, verify_revocation, Revocation, RevocationCheck, RevocationRejection,
};
use osprey_proto::IdentityAlgorithm;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

/// A stand-in for a Secure Enclave: the same public encoding and the same
/// signature encoding, with the private half in software so a test can drive it.
struct EnclavePeer {
    signing: SigningKey,
    public: PublicIdentity,
}

impl EnclavePeer {
    fn generate(noise_static_pub: [u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::random(&mut OsRng), noise_static_pub)
    }

    fn from_signing_key(signing: SigningKey, noise_static_pub: [u8; 32]) -> Self {
        let identity_pub = sec1_public(&signing);
        let message = cross_certificate_bytes(&identity_pub, &noise_static_pub);
        let public = PublicIdentity {
            identity_algorithm: IdentityAlgorithm::P256,
            identity_pub,
            noise_static_pub,
            noise_static_sig: der_sign(&signing, &message),
        };
        Self { signing, public }
    }

    /// Re-sign an arbitrary static, as the phone would after rotating its Noise
    /// key without touching the Enclave key.
    fn certify(&self, noise_static_pub: [u8; 32]) -> PublicIdentity {
        let message = cross_certificate_bytes(&self.public.identity_pub, &noise_static_pub);
        PublicIdentity {
            identity_algorithm: IdentityAlgorithm::P256,
            identity_pub: self.public.identity_pub.clone(),
            noise_static_pub,
            noise_static_sig: der_sign(&self.signing, &message),
        }
    }
}

fn sec1_public(signing: &SigningKey) -> Vec<u8> {
    PublicKey::from(VerifyingKey::from(signing))
        .to_sec1_bytes()
        .to_vec()
}

/// Sign exactly as `.ecdsaSignatureMessageX962SHA256` does: SHA-256 over the
/// message, DER-encoded output.
fn der_sign(signing: &SigningKey, message: &[u8]) -> Vec<u8> {
    let sig: Signature = signing.sign(message);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn a_genuine_p256_cross_signature_verifies() {
    let peer = EnclavePeer::generate([0x11; 32]);
    assert_eq!(peer.public.identity_pub.len(), 65);
    assert_eq!(peer.public.identity_pub[0], 0x04);
    // DER is variable-length; asserting anything but a range would bake in one
    // sample's leading-zero luck.
    assert!((8..=72).contains(&peer.public.noise_static_sig.len()));

    peer.public
        .verify_self_consistent()
        .expect("a Secure-Enclave-shaped bundle must verify");
    PinnedPeer::pin(&peer.public).expect("and must be pinnable");
}

#[test]
fn a_p256_signature_from_a_different_key_is_rejected() {
    let real = EnclavePeer::generate([0x22; 32]);
    let impostor = EnclavePeer::generate([0x22; 32]);

    let mut forged = real.public.clone();
    forged.noise_static_sig = impostor.public.noise_static_sig.clone();
    assert!(matches!(
        forged.verify_self_consistent(),
        Err(Error::CrossSignature(
            CrossSignatureFailure::NotSignedByIdentity
        ))
    ));

    // The other half of the substitution: the impostor's key vouching for its
    // own static, presented under the real device's identity key.
    let err = verify_cross_signature(
        &IdentityAlgorithm::P256,
        &real.public.identity_pub,
        &impostor.public.noise_static_pub,
        &impostor.public.noise_static_sig,
    )
    .expect_err("a foreign P-256 signature must not verify");
    assert!(matches!(
        err,
        Error::CrossSignature(CrossSignatureFailure::NotSignedByIdentity)
    ));
}

#[test]
fn a_malformed_der_signature_is_a_typed_error_not_a_panic() {
    let peer = EnclavePeer::generate([0x33; 32]);
    let good = peer.public.noise_static_sig.clone();

    // Every truncation, including the empty one.
    for cut in 0..good.len() {
        let mut broken = peer.public.clone();
        broken.noise_static_sig = good[..cut].to_vec();
        assert!(
            matches!(
                broken.verify_self_consistent(),
                Err(Error::CrossSignature(_))
            ),
            "truncation to {cut} bytes must be a typed error"
        );
    }

    // Every single-byte flip, which walks the DER tags, lengths and both
    // integers rather than only the parts a hand-picked sample would touch.
    for index in 0..good.len() {
        let mut broken = peer.public.clone();
        broken.noise_static_sig = good.clone();
        broken.noise_static_sig[index] ^= 0x80;
        assert!(
            matches!(
                broken.verify_self_consistent(),
                Err(Error::CrossSignature(_))
            ),
            "flipping byte {index} must be a typed error"
        );
    }

    // A signature longer than any supported algorithm produces is refused
    // before parsing, so a peer cannot make the verifier walk a large buffer.
    let mut oversized = peer.public.clone();
    oversized.noise_static_sig = vec![0x30; 4096];
    assert!(matches!(
        oversized.verify_self_consistent(),
        Err(Error::CrossSignature(CrossSignatureFailure::Malformed))
    ));
}

#[test]
fn a_malformed_p256_identity_key_is_a_typed_error_not_a_panic() {
    let peer = EnclavePeer::generate([0x44; 32]);
    let good = peer.public.identity_pub.clone();

    for index in 0..good.len() {
        let mut broken = peer.public.clone();
        broken.identity_pub = good.clone();
        broken.identity_pub[index] ^= 0x01;
        assert!(
            matches!(
                broken.verify_self_consistent(),
                Err(Error::CrossSignature(_))
            ),
            "flipping key byte {index} must be a typed error"
        );
    }

    for len in [0usize, 1, 32, 64, 66, 200] {
        let mut broken = peer.public.clone();
        broken.identity_pub = vec![0x04; len];
        assert!(matches!(
            broken.verify_self_consistent(),
            Err(Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))
        ));
    }
}

#[test]
fn a_compressed_p256_key_is_refused_so_a_pin_has_one_encoding() {
    let peer = EnclavePeer::generate([0x55; 32]);
    let compressed = PublicKey::from(VerifyingKey::from(&peer.signing))
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(compressed.len(), 33);

    // The same key, and SEC1 would accept it — but the raw bytes are what gets
    // pinned and byte-compared, so admitting a second encoding would make one
    // device produce two different pins.
    let message = cross_certificate_bytes(&compressed, &peer.public.noise_static_pub);
    let bundle = PublicIdentity {
        identity_algorithm: IdentityAlgorithm::P256,
        identity_pub: compressed,
        noise_static_pub: peer.public.noise_static_pub,
        noise_static_sig: der_sign(&peer.signing, &message),
    };
    assert!(matches!(
        bundle.verify_self_consistent(),
        Err(Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))
    ));
}

#[test]
fn an_ed25519_bundle_relabelled_p256_is_rejected() {
    let ed = DeviceIdentity::generate();
    let mut relabelled = ed.public().clone();
    relabelled.identity_algorithm = IdentityAlgorithm::P256;
    assert!(matches!(
        relabelled.verify_self_consistent(),
        Err(Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))
    ));
}

#[test]
fn a_p256_bundle_relabelled_ed25519_is_rejected() {
    let peer = EnclavePeer::generate([0x66; 32]);
    let mut relabelled = peer.public.clone();
    relabelled.identity_algorithm = IdentityAlgorithm::Ed25519;
    assert!(matches!(
        relabelled.verify_self_consistent(),
        Err(Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))
    ));
}

#[test]
fn an_ed25519_raw_signature_offered_for_a_p256_key_is_rejected() {
    // Both fields the right length for *some* algorithm, but not for the one
    // named — the case the per-algorithm key-length check alone cannot catch.
    let ed = DeviceIdentity::generate();
    let peer = EnclavePeer::generate([0x77; 32]);
    let mut mixed = peer.public.clone();
    mixed.noise_static_sig = ed.public().noise_static_sig.clone();
    assert_eq!(mixed.noise_static_sig.len(), 64);
    assert!(matches!(
        mixed.verify_self_consistent(),
        Err(Error::CrossSignature(CrossSignatureFailure::Malformed))
    ));
}

#[test]
fn an_unknown_identity_algorithm_is_a_typed_error_not_a_silent_accept() {
    let peer = EnclavePeer::generate([0x88; 32]);
    let mut future = peer.public.clone();
    future.identity_algorithm = IdentityAlgorithm::Unknown("ed448".to_owned());

    let err = future
        .verify_self_consistent()
        .expect_err("an unverifiable algorithm must never be accepted");
    match err {
        Error::CrossSignature(CrossSignatureFailure::UnsupportedAlgorithm(raw)) => {
            assert_eq!(raw, "ed448", "the refused value must reach the audit line");
        }
        other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
    }
    assert!(PinnedPeer::pin(&future).is_err());
}

#[test]
fn a_p256_peer_pins_rotates_and_re_verifies() {
    let peer = EnclavePeer::generate([0x99; 32]);
    let mut pin = PinnedPeer::pin(&peer.public).expect("pin");
    assert_eq!(pin.identity_algorithm, IdentityAlgorithm::P256);
    let fingerprint = pin.fingerprint();
    pin.verify().expect("a fresh pin must re-verify");

    let rotated = peer.certify([0xaa; 32]);
    pin.accept_static(&rotated)
        .expect("a rotation signed by the pinned Enclave key is accepted");
    assert_eq!(pin.noise_static_pub, [0xaa; 32]);
    assert_eq!(
        pin.fingerprint(),
        fingerprint,
        "rotation must not change the durable identity fingerprint"
    );

    // A rotation offered by a different Enclave key, and one offered under a
    // different algorithm, are both refused before any signature work.
    let attacker = EnclavePeer::generate([0xbb; 32]);
    assert!(matches!(
        pin.accept_static(&attacker.public),
        Err(Error::UnpinnedPeer)
    ));
    let mut relabelled = rotated.clone();
    relabelled.identity_algorithm = IdentityAlgorithm::Ed25519;
    assert!(matches!(
        pin.accept_static(&relabelled),
        Err(Error::UnpinnedPeer)
    ));
    assert_eq!(pin.noise_static_pub, [0xaa; 32]);
}

#[test]
fn a_p256_pin_survives_the_json_round_trip_the_state_file_uses() {
    let peer = EnclavePeer::generate([0xcc; 32]);
    let pin = PinnedPeer::pin(&peer.public).expect("pin");
    let text = serde_json::to_string(&pin).expect("encode");
    assert!(text.contains("\"p256\""), "algorithm must be on the wire");
    let back: PinnedPeer = serde_json::from_str(&text).expect("decode");
    assert_eq!(back, pin);
    back.verify().expect("a reloaded P-256 pin must re-verify");
}

#[test]
fn an_ed25519_and_a_p256_peer_never_share_a_fingerprint() {
    let key = vec![0x04u8; 65];
    let ed = Fingerprint::of_identity(&IdentityAlgorithm::Ed25519, &key);
    let p256 = Fingerprint::of_identity(&IdentityAlgorithm::P256, &key);
    assert_ne!(ed, p256, "the algorithm must be inside the fingerprint");
}

#[test]
fn a_p256_revocation_verifies_and_a_forged_one_does_not() {
    let peer = EnclavePeer::generate([0xdd; 32]);
    let pin = PinnedPeer::pin(&peer.public).expect("pin");
    let peer_device_id = [7u8; 16];
    let host_device_id = [9u8; 16];
    let nonce = [4u8; 32];

    let message = revocation_signing_bytes(&peer_device_id, &host_device_id, 1_000, &nonce);
    let signature = der_sign(&peer.signing, &message);
    // The revocation signature is DER and therefore not 64 bytes; a fixed-width
    // length check here would refuse every genuine iPhone unpair.
    assert_ne!(signature.len(), 64);

    let check = RevocationCheck {
        peer: &pin,
        peer_device_id,
        host_device_id,
        now_ms: 1_000,
    };
    let accepted = verify_revocation(
        &Revocation {
            issuer_device_id: peer_device_id,
            revoked_device_id: host_device_id,
            issued_at_ms: 1_000,
            nonce: &nonce,
            signature: &signature,
        },
        &check,
    )
    .expect("a genuine Secure-Enclave revocation must verify");
    assert_eq!(accepted, nonce);

    let impostor = EnclavePeer::generate([0xee; 32]);
    let forged = der_sign(&impostor.signing, &message);
    let result = verify_revocation(
        &Revocation {
            issuer_device_id: peer_device_id,
            revoked_device_id: host_device_id,
            issued_at_ms: 1_000,
            nonce: &nonce,
            signature: &forged,
        },
        &check,
    );
    assert_eq!(result, Err(RevocationRejection::BadSignature));
}

// ---------------------------------------------------------------------------
// Fixed vectors
// ---------------------------------------------------------------------------
//
// Everything above generates its own keys, so a refactor that changed the signed
// byte string on both the signing and verifying side would still pass. These
// pin the construction itself against values computed once and written down, so
// such a change shows up as a failing test rather than as an iPhone that
// silently stops pairing.

/// A fixed, non-random P-256 scalar. Test material only — never a device key.
const FIXED_SCALAR: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// X9.63 uncompressed public point for [`FIXED_SCALAR`].
const FIXED_PUBLIC_HEX: &str = "04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f\
                                4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";

const FIXED_NOISE_STATIC: [u8; 32] = [0x5a; 32];

/// `"osprey/cross-cert/noise-static/v1" ‖ identity_pub[65] ‖ noise_static[32]`.
const FIXED_MESSAGE_HEX: &str =
    "6f73707265792f63726f73732d636572742f6e6f6973652d7374617469632f7631\
                                 04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f\
                                 4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354\
                                 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// DER ECDSA signature over [`FIXED_MESSAGE_HEX`] under [`FIXED_SCALAR`].
const FIXED_SIGNATURE_HEX: &str = "304502201e408279464b8cd0ceb732e011be4a8f192e4a3006b046068a19479\
                                   84100c06c022100e943e1c5d562047c51526e95e12a9c5e42f617c1afcce54f5\
                                   95b4d4d48949e99";

fn unspaced(hex_with_layout: &str) -> Vec<u8> {
    let compact: String = hex_with_layout
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    hex::decode(compact).expect("fixed vector must be valid hex")
}

#[test]
fn the_p256_signed_byte_string_matches_a_fixed_vector() {
    let public = unspaced(FIXED_PUBLIC_HEX);
    assert_eq!(public.len(), 65);
    assert_eq!(
        public,
        sec1_public(&SigningKey::from_slice(&FIXED_SCALAR).expect("fixed scalar")),
        "the recorded public point no longer matches the recorded scalar"
    );

    let message = cross_certificate_bytes(&public, &FIXED_NOISE_STATIC);
    assert_eq!(
        message,
        unspaced(FIXED_MESSAGE_HEX),
        "the cross-certificate byte string changed; every paired iPhone would \
         stop verifying, so this is a protocol break, not a test failure"
    );
    assert_eq!(message.len(), 33 + 65 + 32);
}

#[test]
fn a_fixed_der_signature_verifies_end_to_end() {
    let public = unspaced(FIXED_PUBLIC_HEX);
    let signature = unspaced(FIXED_SIGNATURE_HEX);
    verify_cross_signature(
        &IdentityAlgorithm::P256,
        &public,
        &FIXED_NOISE_STATIC,
        &signature,
    )
    .expect("the recorded signature must still verify");

    // The same signature over a different static must not.
    let mut other_static = FIXED_NOISE_STATIC;
    other_static[0] ^= 0x01;
    assert!(matches!(
        verify_cross_signature(&IdentityAlgorithm::P256, &public, &other_static, &signature),
        Err(Error::CrossSignature(
            CrossSignatureFailure::NotSignedByIdentity
        ))
    ));
}

#[test]
fn the_ed25519_signed_byte_string_is_unchanged_by_the_algorithm_split() {
    let identity = DeviceIdentity::generate();
    let public = identity.public();
    let message = cross_certificate_bytes(&public.identity_pub, &public.noise_static_pub);
    assert!(message.starts_with(b"osprey/cross-cert/noise-static/v1"));
    assert_eq!(message.len(), 33 + 32 + 32);
    verify_identity_signature(
        &IdentityAlgorithm::Ed25519,
        &public.identity_pub,
        &message,
        &public.noise_static_sig,
    )
    .expect("the Ed25519 construction must be byte-identical to before");
}
