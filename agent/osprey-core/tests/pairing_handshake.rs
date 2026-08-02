//! Gate P0: the pairing handshake, and every way it must fail closed.

mod common;

use common::{audit_lines, tcp_pair, Fixture, ScriptedStream};

use osprey_core::error::{Error, HandshakeStage};
use osprey_core::noise::{write_frame, Handshake, HandshakeConfig, Pattern, Role};
use osprey_core::pairing::{initiate, respond, PairingContext, PairingSecret};

fn context() -> PairingContext {
    PairingContext::new("acct-test", "dev-test")
}

#[test]
fn ikpsk2_pairing_roundtrip_pins_both_sides_and_carries_traffic() {
    let mut fixture = Fixture::new();
    let (mut phone_stream, mut agent_stream) = tcp_pair();
    let ctx = context();

    let phone = &fixture.phone;
    let qr = &fixture.qr;
    let phone_audit = &fixture.phone_audit;
    let agent = &fixture.agent;
    let agent_audit = &fixture.agent_audit;
    let offer = &mut fixture.offer;

    let (host, client) = std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let mut outcome = initiate(&mut phone_stream, phone, qr, phone_audit)?;
            outcome.session.send(b"ping", &mut phone_stream)?;
            let reply = outcome.session.recv(&mut phone_stream)?;
            Ok::<_, Error>((outcome.peer, reply))
        });
        let host = (|| {
            let mut outcome = respond(&mut agent_stream, agent, offer, &ctx, agent_audit)?;
            let request = outcome.session.recv(&mut agent_stream)?;
            outcome.session.send(b"pong", &mut agent_stream)?;
            Ok::<_, Error>((outcome.peer, request))
        })();
        let client = handle.join().expect("phone thread");
        (host, client)
    });

    let (host_peer, request) = host.expect("host pairing");
    let (client_peer, reply) = client.expect("phone pairing");

    assert_eq!(host_peer.identity_pub, fixture.phone.public().identity_pub);
    assert_eq!(
        host_peer.noise_static_pub,
        fixture.phone.public().noise_static_pub
    );
    assert_eq!(
        client_peer.identity_pub,
        fixture.agent.public().identity_pub
    );
    assert_eq!(request.as_deref(), Some(&b"ping"[..]));
    assert_eq!(reply.as_deref(), Some(&b"pong"[..]));

    assert!(fixture.offer.is_consumed(), "offer must be single-use");

    let host_audit = audit_lines(&fixture.agent_audit);
    assert_eq!(host_audit.len(), 1);
    assert!(host_audit[0].contains("\"event\":\"pairing_succeeded\""));
    assert!(
        host_audit[0].contains(&host_peer.fingerprint().to_string()),
        "audit must record the pinned peer fingerprint: {}",
        host_audit[0]
    );

    // Replaying the now-consumed offer must be refused before any handshake.
    let mut replay = ScriptedStream::new(Vec::new());
    let err = respond(
        &mut replay,
        &fixture.agent,
        &mut fixture.offer,
        &ctx,
        &fixture.agent_audit,
    )
    .expect_err("a consumed offer must not pair a second device");
    assert!(matches!(err, Error::HandshakeConfig(_)));
    let host_audit = audit_lines(&fixture.agent_audit);
    assert_eq!(host_audit.len(), 2);
    assert!(host_audit[1].contains("\"reason\":\"replayed\""));
}

#[test]
fn tampered_handshake_byte_is_a_typed_error_and_an_audit_entry_not_a_panic() {
    let mut fixture = Fixture::new();
    let ctx = context();

    let phone_static = fixture.phone.noise_static_secret();
    let mut handshake = Handshake::new(HandshakeConfig {
        pattern: Pattern::Pairing,
        role: Role::Initiator,
        local_static: &phone_static,
        remote_static: Some(&fixture.agent.public().noise_static_pub),
        psk: Some(&fixture.qr.pairing_secret),
    })
    .expect("build initiator");

    let mut message = handshake.write_message(b"hello").expect("write msg1");
    let last = message.len() - 1;
    message[last] ^= 0x01;

    let mut wire = Vec::new();
    write_frame(&mut wire, &message).expect("frame");
    let mut stream = ScriptedStream::new(wire);

    let err = respond(
        &mut stream,
        &fixture.agent,
        &mut fixture.offer,
        &ctx,
        &fixture.agent_audit,
    )
    .expect_err("tampered handshake must fail");

    assert!(
        matches!(
            err,
            Error::Handshake {
                stage: HandshakeStage::Read,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
    assert!(!fixture.offer.is_consumed());

    let lines = audit_lines(&fixture.agent_audit);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"event\":\"pairing_failed\""));
    assert!(lines[0].contains("\"reason\":\"handshake_rejected\""));
}

#[test]
fn every_single_byte_of_the_first_handshake_message_is_authenticated() {
    let fixture = Fixture::new();
    let ctx = context();
    let phone_static = fixture.phone.noise_static_secret();

    for index in 0..96 {
        let mut handshake = Handshake::new(HandshakeConfig {
            pattern: Pattern::Pairing,
            role: Role::Initiator,
            local_static: &phone_static,
            remote_static: Some(&fixture.agent.public().noise_static_pub),
            psk: Some(&fixture.qr.pairing_secret),
        })
        .expect("build initiator");
        let mut message = handshake.write_message(b"hello").expect("write msg1");
        assert!(index < message.len());
        message[index] ^= 0x80;

        let mut wire = Vec::new();
        write_frame(&mut wire, &message).expect("frame");
        let mut stream = ScriptedStream::new(wire);
        let mut offer = osprey_core::pairing::PairingOffer::new(
            PairingSecret::from_bytes(*fixture.qr.pairing_secret.as_bytes()),
            osprey_core::pairing::DEFAULT_PAIRING_TTL,
        );

        let result = respond(
            &mut stream,
            &fixture.agent,
            &mut offer,
            &ctx,
            &fixture.agent_audit,
        );
        assert!(result.is_err(), "byte {index} was not authenticated");
    }
}

#[test]
fn wrong_psk_fails_closed_on_both_sides() {
    let mut fixture =
        Fixture::with_split_secret(PairingSecret::generate(), PairingSecret::generate());
    let (mut phone_stream, mut agent_stream) = tcp_pair();
    let ctx = context();

    let phone = &fixture.phone;
    let qr = &fixture.qr;
    let phone_audit = &fixture.phone_audit;
    let agent = &fixture.agent;
    let agent_audit = &fixture.agent_audit;
    let offer = &mut fixture.offer;

    let (host, client) = std::thread::scope(|scope| {
        let handle = scope.spawn(move || initiate(&mut phone_stream, phone, qr, phone_audit));
        let host = respond(&mut agent_stream, agent, offer, &ctx, agent_audit);
        let client = handle.join().expect("phone thread");
        (host, client)
    });

    let client_err = client.expect_err("phone must reject a host it cannot authenticate");
    assert!(
        matches!(
            client_err,
            Error::Handshake {
                stage: HandshakeStage::Read,
                ..
            }
        ),
        "unexpected phone error: {client_err:?}"
    );
    host.expect_err("host must never pin a peer that failed to prove the PSK");
    assert!(!fixture.offer.is_consumed());

    for lines in [
        audit_lines(&fixture.agent_audit),
        audit_lines(&fixture.phone_audit),
    ] {
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event\":\"pairing_failed\""));
    }
}

#[test]
fn expired_offer_is_refused_before_any_handshake() {
    let mut fixture = Fixture::new();
    fixture.offer = osprey_core::pairing::PairingOffer::new(
        PairingSecret::generate(),
        std::time::Duration::ZERO,
    );
    std::thread::sleep(std::time::Duration::from_millis(2));

    let mut stream = ScriptedStream::new(Vec::new());
    let err = respond(
        &mut stream,
        &fixture.agent,
        &mut fixture.offer,
        &context(),
        &fixture.agent_audit,
    )
    .expect_err("expired offer must be refused");
    assert!(matches!(err, Error::HandshakeConfig(_)));

    let lines = audit_lines(&fixture.agent_audit);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"reason\":\"expired\""));
}
