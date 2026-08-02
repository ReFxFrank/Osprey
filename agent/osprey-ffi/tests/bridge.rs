//! The bridge surface on its own: framing, identity encoding, QR parsing, and
//! the transport's refusal behaviour.

mod common;

use common::{corrupt_hex_field, ed25519_identity, sample_qr, FakeEnclavePhone};
use osprey_core::identity::DeviceIdentity;
use osprey_core::noise::{Handshake, HandshakeConfig, MAX_CHUNK_PAYLOAD_LEN, Pattern, Role};
use osprey_ffi::{
    cross_certificate_bytes, decode_identity_message, encode_identity_message, frame_decode,
    frame_encode, identity_fingerprint, max_chunk_payload_len, noise_max_message_len,
    parse_qr_payload, routing_id_from_secret, CrossSignatureReason, NoiseHandshake,
    NoiseTransport, OspreyError,
};

/// Two connected transports, built through the core's own handshake so the
/// cipher states are real rather than stubbed.
fn transport_pair() -> (NoiseTransport, NoiseTransport) {
    let a = DeviceIdentity::generate();
    let b = DeviceIdentity::generate();
    let a_static = a.noise_static_secret();
    let b_static = b.noise_static_secret();
    let mut initiator = Handshake::new(HandshakeConfig {
        pattern: Pattern::Session,
        role: Role::Initiator,
        local_static: &a_static,
        remote_static: Some(&b.public().noise_static_pub),
        psk: None,
    })
    .expect("initiator");
    let mut responder = Handshake::new(HandshakeConfig {
        pattern: Pattern::Session,
        role: Role::Responder,
        local_static: &b_static,
        remote_static: None,
        psk: None,
    })
    .expect("responder");

    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");

    (
        NoiseTransport::from_session(initiator.into_session().expect("initiator session"), Vec::new()),
        NoiseTransport::from_session(responder.into_session().expect("responder session"), Vec::new()),
    )
}

#[test]
fn a_message_appears_only_once_its_last_byte_has_arrived() {
    let (sender, receiver) = transport_pair();
    let wire = sender.encrypt(b"hello phone".to_vec()).expect("encrypt");
    for (i, byte) in wire.iter().enumerate() {
        receiver.push_bytes(vec![*byte]).expect("push");
        let got = receiver.next_message().expect("decrypt");
        if i + 1 == wire.len() {
            assert_eq!(got.as_deref(), Some(&b"hello phone"[..]));
        } else {
            assert!(got.is_none(), "message appeared after {} bytes", i + 1);
        }
    }
}

#[test]
fn two_messages_in_one_push_are_both_returned() {
    let (sender, receiver) = transport_pair();
    let mut wire = sender.encrypt(b"one".to_vec()).expect("encrypt");
    wire.extend(sender.encrypt(b"two".to_vec()).expect("encrypt"));
    receiver.push_bytes(wire).expect("push");
    assert_eq!(
        receiver.next_message().expect("first").as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        receiver.next_message().expect("second").as_deref(),
        Some(&b"two"[..])
    );
    assert_eq!(receiver.next_message().expect("third"), None);
}

#[test]
fn a_payload_that_exactly_fills_one_chunk_still_round_trips() {
    let (sender, receiver) = transport_pair();
    let payload = vec![0x5au8; MAX_CHUNK_PAYLOAD_LEN];
    let wire = sender.encrypt(payload.clone()).expect("encrypt");
    receiver.push_bytes(wire).expect("push");
    assert_eq!(receiver.next_message().expect("decrypt"), Some(payload));
}

#[test]
fn a_tampered_byte_is_rejected_and_closes_the_session() {
    let (sender, receiver) = transport_pair();
    let mut wire = sender.encrypt(b"authentic".to_vec()).expect("encrypt");
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    receiver.push_bytes(wire).expect("push");
    let err = receiver.next_message().expect_err("must refuse");
    assert!(matches!(err, OspreyError::TransportAuth { .. }), "{err:?}");
    // A Noise session cannot be resynchronised after an authentication failure,
    // so the object must refuse everything afterwards rather than carry on.
    let err = receiver.encrypt(b"anything".to_vec()).expect_err("closed");
    assert!(matches!(err, OspreyError::SessionState { .. }), "{err:?}");
}

#[test]
fn a_peer_that_floods_bytes_is_bounded() {
    let (_sender, receiver) = transport_pair();
    let mut pushed = 0usize;
    let err = loop {
        match receiver.push_bytes(vec![0u8; 4096]) {
            Ok(()) => {
                pushed += 4096;
                assert!(pushed <= 8 * 1024 * 1024, "buffer grew without bound");
            }
            Err(err) => break err,
        }
    };
    assert!(matches!(err, OspreyError::InboundOverflow { .. }), "{err:?}");
    assert!(
        pushed <= 2 * (65535 + 2),
        "the bound should be about two frames, got {pushed}"
    );
}

#[test]
fn framing_helpers_agree_with_the_transport() {
    let framed = frame_encode(b"payload".to_vec()).expect("encode");
    assert_eq!(framed.len(), 2 + 7);
    let scan = frame_decode(framed.clone()).expect("decode");
    assert_eq!(scan.frame.as_deref(), Some(&b"payload"[..]));
    assert_eq!(scan.consumed, framed.len() as u64);
    assert_eq!(noise_max_message_len(), 65535);
    assert_eq!(max_chunk_payload_len(), 65518);
}

#[test]
fn an_identity_bundle_round_trips_through_the_handshake_encoding() {
    let (identity, _) = ed25519_identity();
    let encoded = encode_identity_message(identity.clone()).expect("encode");
    assert_eq!(decode_identity_message(encoded).expect("decode"), identity);
}

#[test]
fn a_p256_bundle_verifies_and_fingerprints() {
    let phone = FakeEnclavePhone::generate();
    assert_eq!(phone.identity.identity_pub.len(), 65);
    assert_eq!(phone.identity.identity_pub[0], 0x04);
    osprey_ffi::verify_identity_bundle(phone.identity.clone()).expect("verify");
    let fingerprint = identity_fingerprint(phone.identity).expect("fingerprint");
    assert_eq!(fingerprint.hex.len(), 64);
    assert_eq!(fingerprint.short.len(), 8 * 2 + 3);
}

#[test]
fn a_forged_cross_signature_is_refused_by_both_the_verifier_and_the_decoder() {
    let (mut identity, _) = ed25519_identity();
    identity.noise_static_pub[0] ^= 0x01;
    let err = osprey_ffi::verify_identity_bundle(identity.clone()).expect_err("must refuse");
    assert!(
        matches!(
            err,
            OspreyError::CrossSignature {
                reason: CrossSignatureReason::NotSignedByIdentity,
                ..
            }
        ),
        "{err:?}"
    );

    let (good, _) = ed25519_identity();
    let encoded = encode_identity_message(good).expect("encode");
    let text = String::from_utf8(encoded).expect("utf-8");
    let forged = corrupt_hex_field(&text, "noise_static_sig");
    let err = decode_identity_message(forged.into_bytes()).expect_err("must refuse");
    assert!(
        matches!(err, OspreyError::CrossSignature { .. }),
        "the decoder must not hand back an unverified bundle: {err:?}"
    );
}

#[test]
fn an_unknown_identity_algorithm_is_named_in_the_refusal() {
    let (mut identity, _) = ed25519_identity();
    identity.identity_algorithm = "dilithium3".to_string();
    let err = osprey_ffi::verify_identity_bundle(identity).expect_err("must refuse");
    assert!(
        matches!(
            err,
            OspreyError::CrossSignature {
                reason: CrossSignatureReason::UnsupportedAlgorithm { ref raw },
                ..
            } if raw == "dilithium3"
        ),
        "{err:?}"
    );
}

#[test]
fn a_wrong_length_key_is_a_typed_error_not_a_panic() {
    let (mut identity, _) = ed25519_identity();
    identity.noise_static_pub.truncate(31);
    let err = osprey_ffi::verify_identity_bundle(identity).expect_err("must refuse");
    assert!(
        matches!(
            err,
            OspreyError::BadKeyLength {
                expected: 32,
                actual: 31,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(routing_id_from_secret(vec![0u8; 31]).is_err());
    assert!(cross_certificate_bytes(vec![0u8; 32], vec![0u8; 31]).is_err());
    assert!(NoiseHandshake::session_initiator(vec![0u8; 31], vec![0u8; 32]).is_err());
    assert!(NoiseHandshake::pairing_initiator(vec![0u8; 32], vec![0u8; 32], vec![0u8; 31]).is_err());
}

#[test]
fn the_signed_message_binds_the_identity_key_and_the_static() {
    let bytes = cross_certificate_bytes(vec![0xAA; 32], vec![0xBB; 32]).expect("bytes");
    assert!(bytes.starts_with(b"osprey/cross-cert/noise-static/v1"));
    assert_eq!(bytes.len(), 33 + 32 + 32);
    assert!(bytes.ends_with(&[0xBB; 32]));
}

#[test]
fn parsing_a_qr_exposes_the_routing_id_but_never_the_secret() {
    let (text, secret) = sample_qr();
    let scanned = parse_qr_payload(text).expect("parse");
    assert_eq!(
        scanned.routing_id(),
        routing_id_from_secret(secret.to_vec()).expect("routing id")
    );
    assert_eq!(scanned.account_id(), "acct-test");
    assert_eq!(scanned.device_id(), "dev-test");
    assert_eq!(scanned.relay_url(), "https://relay.invalid");
    assert_eq!(scanned.lan_hints(), vec!["127.0.0.1:47010".to_string()]);
    assert_eq!(scanned.agent_fingerprint().hex.len(), 64);
}

#[test]
fn a_forged_agent_cross_signature_is_refused_at_parse_time() {
    let (text, _) = sample_qr();
    // `ScannedQr` has no `Debug` on purpose — a scanned payload should never be
    // formattable into a log line — so unwrap the error side explicitly.
    let err = parse_qr_payload(corrupt_hex_field(&text, "noise_static_sig"))
        .err()
        .expect("must refuse");
    assert!(matches!(err, OspreyError::CrossSignature { .. }), "{err:?}");
}

#[test]
fn an_unparseable_qr_is_an_error_not_a_panic() {
    for text in ["", "{", "not json at all", "{\"v\":99}", "\u{feff}{}"] {
        let err = parse_qr_payload(text.to_string()).err().expect("must refuse");
        assert!(
            matches!(
                err,
                OspreyError::PayloadDecode { .. } | OspreyError::UnsupportedQrVersion { .. }
            ),
            "{text:?} gave {err:?}"
        );
    }
}
