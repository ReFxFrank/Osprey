//! Fixtures shared by the bridge tests.
//!
//! Each integration test is its own crate and uses a different subset, so
//! unused-item warnings here are an artefact of the harness.
#![allow(dead_code)]

use osprey_core::identity::{cross_certificate_bytes, DeviceIdentity};
use osprey_core::pairing::{PairingSecret, QrPayload};
use osprey_ffi::PeerIdentity;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::PublicKey;

/// A stand-in for an iPhone: a P-256 identity that cross-signs a software
/// X25519 Noise static, in exactly the two encodings the Security framework
/// produces (`SecKeyCopyExternalRepresentation` → 65-byte X9.63 point,
/// `.ecdsaSignatureMessageX962SHA256` → ASN.1 DER over a SHA-256 digest).
pub struct FakeEnclavePhone {
    pub identity: PeerIdentity,
    /// The X25519 private half. Software, because the Enclave cannot hold one.
    pub noise_static_private: [u8; 32],
}

impl FakeEnclavePhone {
    pub fn generate() -> Self {
        // Borrow a real X25519 keypair from `osprey-core` rather than depending
        // on x25519-dalek here: the Noise static's *provenance* is irrelevant,
        // only that the public half matches the private one snow is handed.
        let x25519 = DeviceIdentity::generate();
        let noise_static_pub = x25519.public().noise_static_pub;
        let signing = SigningKey::random(&mut OsRng);
        let identity_pub = PublicKey::from(VerifyingKey::from(&signing))
            .to_sec1_bytes()
            .to_vec();
        let message = cross_certificate_bytes(&identity_pub, &noise_static_pub);
        let sig: Signature = signing.sign(&message);
        Self {
            identity: PeerIdentity {
                identity_algorithm: "p256".to_string(),
                identity_pub,
                noise_static_pub: noise_static_pub.to_vec(),
                noise_static_sig: sig.to_der().as_bytes().to_vec(),
            },
            noise_static_private: x25519.noise_static_secret(),
        }
    }
}

/// An Ed25519 device bundle, as the Windows agent produces.
pub fn ed25519_identity() -> (PeerIdentity, [u8; 32]) {
    let device = DeviceIdentity::generate();
    let public = device.public();
    (
        PeerIdentity {
            identity_algorithm: public.identity_algorithm.as_str().to_string(),
            identity_pub: public.identity_pub.clone(),
            noise_static_pub: public.noise_static_pub.to_vec(),
            noise_static_sig: public.noise_static_sig.clone(),
        },
        device.noise_static_secret(),
    )
}

/// A QR payload's text plus the secret it carries.
pub fn sample_qr() -> (String, [u8; 32]) {
    let secret = [0x5eu8; 32];
    let agent = DeviceIdentity::generate();
    let payload = QrPayload::new(
        "https://relay.invalid",
        "acct-test",
        "dev-test",
        agent.public().clone(),
        vec!["127.0.0.1:47010".parse().expect("addr")],
        PairingSecret::from_bytes(secret),
    );
    (payload.encode().expect("encode qr"), secret)
}

/// Flip one hex digit of a hex-encoded JSON field, keeping the document valid
/// JSON so the failure lands on the signature check rather than the parser.
pub fn corrupt_hex_field(text: &str, field: &str) -> String {
    let marker = format!("\"{field}\":\"");
    let at = text.find(&marker).expect("field present") + marker.len();
    let mut bytes = text.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).expect("still utf-8")
}
