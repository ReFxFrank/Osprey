//! Protocol layer round-trip and hostile-input tests (brief §10 rule 13).
//!
//! Two properties are under test. First, every fully defined body survives
//! serialise → deserialise unchanged, so the Rust peer and the generated Swift
//! peer are describing the same wire. Second, every malformed input a remote
//! peer can send produces a typed error — a malformed network message must
//! never panic the service (CLAUDE.md rule 2), and the P0 gate requires a
//! tampered byte to yield a clean logged failure.

use osprey_proto::{
    Body, ByeBody, ByeReason, Capability, Channel, ErrorBody, ErrorCode, Envelope, HelloBody,
    HelloOkBody, IdentityAlgorithm, MessageType, PairConfirmBody, PairRequestBody, PairRevokeBody,
    PingBody, PongBody, ProtoError, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use std::str::FromStr;
use uuid::Uuid;

/// One sample per fully defined message type. A new fully defined type that is
/// not added here makes `every_defined_type_is_sampled` fail.
fn samples() -> Vec<Body> {
    let device = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
    let account = Uuid::from_u128(0x1112_1314_1516_1718_191a_1b1c_1d1e_1f20);
    vec![
        Body::Error(ErrorBody {
            code: ErrorCode::RateLimited,
            message: "too many pairing attempts".to_owned(),
            retryable: true,
        }),
        Body::Hello(HelloBody {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            capabilities: vec![Capability::Metrics, Capability::Files, Capability::Input],
            device_id: device,
            software_version: "0.1.0".to_owned(),
        }),
        Body::HelloOk(HelloOkBody {
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![Capability::Metrics],
            device_id: device,
            software_version: "0.1.0".to_owned(),
            session_id: Uuid::from_u128(7),
        }),
        Body::Ping(PingBody { seq: u64::MAX }),
        Body::Pong(PongBody {
            seq: u64::MAX,
            echo_ts: -1,
        }),
        Body::Bye(ByeBody {
            reason: ByeReason::Unpaired,
            detail: None,
        }),
        Body::Bye(ByeBody {
            reason: ByeReason::ProtocolError,
            detail: Some("frame exceeded the negotiated maximum".to_owned()),
        }),
        Body::PairRequest(PairRequestBody {
            device_id: device,
            identity_algorithm: IdentityAlgorithm::P256,
            identity_public_key: vec![0x04; 65],
            noise_static_public_key: vec![0xab; 32],
            noise_static_signature: vec![0xcd; 64],
            display_name: "Frank's iPhone".to_owned(),
        }),
        Body::PairConfirm(PairConfirmBody {
            device_id: device,
            account_id: account,
            identity_algorithm: IdentityAlgorithm::Ed25519,
            identity_public_key: vec![0x11; 32],
            noise_static_public_key: vec![0x22; 32],
            noise_static_signature: vec![0x33; 64],
            display_name: "WORKSTATION".to_owned(),
            paired_at: 1_738_000_000_000,
        }),
        Body::PairRevoke(PairRevokeBody {
            issuer_device_id: device,
            revoked_device_id: account,
            issued_at: 1_738_000_000_000,
            nonce: vec![0x5a; 32],
            signature: vec![0x77; 64],
        }),
    ]
}

fn envelope_of(body: &Body) -> Envelope {
    match Envelope::new(Uuid::from_u128(42), 1_738_000_000_000, body) {
        Ok(envelope) => envelope,
        Err(err) => panic!("encoding {} failed: {err}", body.message_type()),
    }
}

#[test]
fn every_defined_body_round_trips() {
    for body in samples() {
        let envelope = envelope_of(&body);
        assert_eq!(envelope.v, PROTOCOL_VERSION);
        assert_eq!(envelope.t, body.message_type());

        let json = serde_json::to_string(&envelope).expect("envelope serialises");
        let parsed: Envelope = serde_json::from_str(&json).expect("envelope parses");
        assert_eq!(parsed, envelope, "envelope changed across the wire");

        parsed.check_version().expect("version is in range");
        let decoded = parsed.decode_body().expect("body decodes");
        assert_eq!(decoded, body, "body changed across the wire");
    }
}

#[test]
fn every_defined_type_is_sampled() {
    let mut sampled: Vec<MessageType> = samples().iter().map(Body::message_type).collect();
    sampled.sort_by_key(MessageType::as_str);
    sampled.dedup();

    let decodable: Vec<MessageType> = MessageType::ALL
        .iter()
        .copied()
        .filter(|t| {
            let probe = Envelope {
                v: PROTOCOL_VERSION,
                id: Uuid::nil(),
                t: *t,
                ts: 0,
                body: serde_json::json!({}),
            };
            !matches!(probe.decode_body(), Err(ProtoError::BodyDeferred(_)))
        })
        .collect();

    assert_eq!(
        sampled.len(),
        decodable.len(),
        "message types with a body schema but no round-trip sample: {:?}",
        decodable
            .iter()
            .filter(|t| !sampled.contains(t))
            .collect::<Vec<_>>()
    );
}

#[test]
fn envelope_wire_shape_is_exactly_the_brief() {
    let body = Body::Ping(PingBody { seq: 1 });
    let envelope = envelope_of(&body);
    let value = serde_json::to_value(&envelope).expect("serialises to a value");
    let object = value.as_object().expect("envelope is a JSON object");

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["body", "id", "t", "ts", "v"]);
    assert_eq!(object.get("t").and_then(serde_json::Value::as_str), Some("ping"));
}

#[test]
fn bytes_fields_use_padded_standard_base64() {
    // The iOS peer decodes these with JSONDecoder's .base64 strategy; a
    // different alphabet or missing padding would silently corrupt key material.
    let body = Body::PairRevoke(PairRevokeBody {
        issuer_device_id: Uuid::nil(),
        revoked_device_id: Uuid::nil(),
        issued_at: 0,
        nonce: vec![0xff, 0xfe, 0xfd],
        signature: vec![0x00],
    });
    let envelope = envelope_of(&body);
    assert_eq!(
        envelope.body.get("nonce").and_then(serde_json::Value::as_str),
        Some("//79")
    );
    assert_eq!(
        envelope.body.get("signature").and_then(serde_json::Value::as_str),
        Some("AA==")
    );
}

#[test]
fn unknown_message_type_is_a_clean_error() {
    let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"totally.bogus","ts":0,"body":{}}"#;
    let result: Result<Envelope, _> = serde_json::from_str(json);
    assert!(result.is_err(), "unknown `t` must not deserialise");

    assert_eq!(
        MessageType::from_str("totally.bogus")
            .expect_err("unknown type has no variant")
            .0,
        "totally.bogus"
    );
}

#[test]
fn malformed_input_never_panics() {
    let hostile = [
        "",
        "not json at all",
        "[]",
        "null",
        "{}",
        r#"{"v":1}"#,
        r#"{"v":1,"id":"not-a-uuid","t":"ping","ts":0,"body":{"seq":1}}"#,
        r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"ping","ts":"soon","body":{}}"#,
        r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":123,"ts":0,"body":{}}"#,
        // A tampered byte inside an otherwise valid envelope, which the P0 gate
        // requires to fail cleanly.
        r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"pair.revoke","ts":0,"body":{"issuer_device_id":"00000000-0000-0000-0000-000000000000","revoked_device_id":"00000000-0000-0000-0000-000000000000","issued_at":0,"nonce":"!!not base64!!","signature":"AA=="}}"#,
    ];

    for json in hostile {
        match serde_json::from_str::<Envelope>(json) {
            Ok(envelope) => {
                let outcome = envelope.decode_body();
                assert!(outcome.is_err(), "hostile input decoded successfully: {json}");
            }
            Err(_) => continue,
        }
    }
}

#[test]
fn missing_body_field_reports_the_message_type() {
    let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"hello","ts":0,"body":{"protocol_version":1}}"#;
    let envelope: Envelope = serde_json::from_str(json).expect("envelope parses");
    match envelope.decode_body() {
        Err(ProtoError::MalformedBody { t, .. }) => assert_eq!(t, MessageType::Hello),
        other => panic!("expected MalformedBody, got {other:?}"),
    }
}

#[test]
fn deferred_type_reports_that_its_body_is_undefined() {
    let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"metrics.tick","ts":0,"body":{"cpu":1}}"#;
    let envelope: Envelope = serde_json::from_str(json).expect("envelope parses");
    match envelope.decode_body() {
        Err(ProtoError::BodyDeferred(t)) => assert_eq!(t, MessageType::MetricsTick),
        other => panic!("expected BodyDeferred, got {other:?}"),
    }
}

#[test]
fn out_of_range_envelope_version_is_rejected() {
    let json = r#"{"v":99,"id":"00000000-0000-0000-0000-000000000000","t":"ping","ts":0,"body":{"seq":1}}"#;
    let envelope: Envelope = serde_json::from_str(json).expect("envelope parses");
    match envelope.check_version() {
        Err(ProtoError::UnsupportedVersion { found, .. }) => assert_eq!(found, 99),
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn unknown_enum_values_survive_instead_of_failing_the_message() {
    // Forward compatibility: an older build must read a newer peer's message.
    let json = r#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","t":"error","ts":0,"body":{"code":"quantum_flux","message":"x","retryable":false}}"#;
    let envelope: Envelope = serde_json::from_str(json).expect("envelope parses");
    match envelope.decode_body().expect("body decodes") {
        Body::Error(body) => {
            assert_eq!(body.code, ErrorCode::Unknown("quantum_flux".to_owned()));
            assert_eq!(body.code.as_str(), "quantum_flux");
        }
        other => panic!("expected an error body, got {other:?}"),
    }
}

#[test]
fn unknown_capability_round_trips_verbatim() {
    let body = Body::Hello(HelloBody {
        protocol_version: PROTOCOL_VERSION,
        min_protocol_version: MIN_PROTOCOL_VERSION,
        capabilities: vec![Capability::Unknown("holodeck".to_owned()), Capability::Exec],
        device_id: Uuid::nil(),
        software_version: "0.1.0".to_owned(),
    });
    let envelope = envelope_of(&body);
    let json = serde_json::to_string(&envelope).expect("serialises");
    let parsed: Envelope = serde_json::from_str(&json).expect("parses");
    assert_eq!(parsed.decode_body().expect("decodes"), body);
}

#[test]
fn registry_covers_the_whole_brief_table() {
    assert_eq!(MessageType::ALL.len(), 73);

    for t in MessageType::ALL {
        let wire = t.as_str();
        assert_eq!(
            MessageType::from_str(wire).expect("registry entry parses from its own wire name"),
            *t
        );
        let json = serde_json::to_string(t).expect("message type serialises");
        assert_eq!(json, format!("\"{wire}\""));
    }
}

#[test]
fn only_mouse_and_scroll_are_unreliable() {
    // CLAUDE.md architecture invariant: two data channels, different
    // guarantees, never merged. Encoded in the registry so it is checkable.
    let unreliable: Vec<&str> = MessageType::ALL
        .iter()
        .filter(|t| t.channel() == Channel::Unreliable)
        .map(|t| t.as_str())
        .collect();
    assert_eq!(unreliable, ["input.mouse", "input.scroll"]);
    assert_eq!(MessageType::InputKey.channel(), Channel::Reliable);
}

#[test]
fn lifecycle_messages_need_no_negotiated_capability() {
    for t in [
        MessageType::Error,
        MessageType::Hello,
        MessageType::HelloOk,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Bye,
        MessageType::PairRequest,
        MessageType::PairConfirm,
        MessageType::PairRevoke,
    ] {
        assert_eq!(t.capability(), None, "{t} must not require negotiation");
    }
    assert_eq!(
        MessageType::MetricsTick.capability(),
        Some(Capability::Metrics)
    );
    assert_eq!(
        MessageType::StreamStart.capability(),
        Some(Capability::SessionPlane)
    );
}
