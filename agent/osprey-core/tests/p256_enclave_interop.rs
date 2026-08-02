//! Encoding-level regression tests for Secure Enclave interop.
//!
//! These pin properties of the *wire encodings Apple actually emits*, which is
//! the one part of the cross-signature path that cannot be exercised here: no
//! Secure Enclave exists on a build machine, so a mistake in this area surfaces
//! for the first time on a physical iPhone, as nothing more diagnostic than
//! "signature invalid".
//!
//! The high-S case below is the reason this file exists.

use osprey_core::error::Error;
use osprey_core::identity::{cross_certificate_bytes, verify_cross_signature};
use osprey_proto::IdentityAlgorithm;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::scalar::IsHigh;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NonZeroScalar, PublicKey};

/// Apple exports P-256 public keys as X9.63 uncompressed points, which is what
/// `SecKeyCopyExternalRepresentation` and CryptoKit's `x963Representation`
/// produce: `0x04 || X(32) || Y(32)`.
fn x963(signing: &SigningKey) -> Vec<u8> {
    PublicKey::from(VerifyingKey::from(signing))
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// Apple's ECDSA does **not** normalise S into the low half of the curve order,
/// and `(r, n - s)` is an equally valid signature over the same message. So
/// roughly half of all real Secure Enclave signatures carry a high S.
///
/// RustCrypto normalises when *signing*, which means an implementation that
/// only ever tests against its own signatures will never see a high-S value and
/// will look correct right up until it meets a real iPhone — at which point it
/// fails about half the time, non-deterministically. Hence flipping S by hand.
#[test]
fn high_s_signatures_are_accepted_because_apple_does_not_normalise() {
    let mut high = 0usize;

    for i in 0..64u8 {
        let signing = SigningKey::random(&mut OsRng);
        let key = x963(&signing);
        let static_pub = [i; 32];
        let message = cross_certificate_bytes(&key, &static_pub);
        let sig: Signature = signing.sign(&message);

        let r = sig.r();
        let neg_s = -*sig.s().as_ref();
        let neg_s = NonZeroScalar::new(neg_s).expect("n - s is non-zero for a valid signature");
        let flipped = Signature::from_scalars(*r.as_ref(), *neg_s.as_ref())
            .expect("(r, n - s) is a well-formed signature");

        if flipped.s().is_high().unwrap_u8() == 1 {
            high += 1;
        }

        let der = flipped.to_der().as_bytes().to_vec();
        assert!(
            verify_cross_signature(&IdentityAlgorithm::P256, &key, &static_pub, &der).is_ok(),
            "high-S signature rejected on iteration {i}; every real Secure Enclave \
             signature whose S lands in the upper half would fail to verify"
        );
    }

    assert!(high > 0, "the S-flip never produced a high-S value, so this test proved nothing");
}

/// `SecKeyCreateSignature` returns ASN.1 DER. A fixed-width `r || s` signature
/// is the other common ECDSA encoding, and accepting it by accident would mean
/// the parser is guessing rather than enforcing a format.
#[test]
fn fixed_width_raw_signatures_are_rejected_not_reinterpreted() {
    let signing = SigningKey::random(&mut OsRng);
    let key = x963(&signing);
    let static_pub = [7u8; 32];
    let message = cross_certificate_bytes(&key, &static_pub);
    let sig: Signature = signing.sign(&message);

    let raw = sig.to_bytes().to_vec();
    assert_eq!(raw.len(), 64, "P-256 fixed-width form is r||s, 32 bytes each");

    let err = verify_cross_signature(&IdentityAlgorithm::P256, &key, &static_pub, &raw)
        .expect_err("a fixed-width signature must not verify");
    assert!(matches!(err, Error::CrossSignature(_)));
}

/// The public key must be the 65-byte uncompressed form. A compressed point
/// carries the same key, so accepting it would be harmless cryptographically
/// but would mean the length check is not actually enforcing Apple's encoding —
/// and the pinned bytes would then differ between devices.
#[test]
fn compressed_public_keys_are_rejected() {
    let signing = SigningKey::random(&mut OsRng);
    let uncompressed = x963(&signing);
    let static_pub = [3u8; 32];
    let message = cross_certificate_bytes(&uncompressed, &static_pub);
    let sig: Signature = signing.sign(&message);
    let der = sig.to_der().as_bytes().to_vec();

    let compressed = PublicKey::from(VerifyingKey::from(&signing))
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(compressed.len(), 33);

    let err = verify_cross_signature(&IdentityAlgorithm::P256, &compressed, &static_pub, &der)
        .expect_err("a compressed point is not the encoding Apple emits");
    assert!(matches!(err, Error::CrossSignature(_)));
}

/// Truncated and structurally invalid DER must produce a typed error. Signature
/// bytes arrive from a peer, so a panic here would be remotely triggerable —
/// CLAUDE.md rule 2.
#[test]
fn malformed_der_is_a_typed_error_never_a_panic() {
    let signing = SigningKey::random(&mut OsRng);
    let key = x963(&signing);
    let static_pub = [9u8; 32];
    let message = cross_certificate_bytes(&key, &static_pub);
    let sig: Signature = signing.sign(&message);
    let der = sig.to_der().as_bytes().to_vec();

    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x30],
        vec![0x30, 0x7f],
        vec![0u8; 72],
        der[..der.len() / 2].to_vec(),
    ];
    // A trailing byte after a structurally valid signature must not be ignored.
    let mut trailing = der.clone();
    trailing.push(0x00);
    cases.push(trailing);

    for (i, case) in cases.iter().enumerate() {
        let outcome = verify_cross_signature(&IdentityAlgorithm::P256, &key, &static_pub, case);
        assert!(outcome.is_err(), "malformed DER case {i} unexpectedly verified");
    }
}
