//! The bridge, driven against the *real* agent responder.
//!
//! This is the test that matters. `osprey-ffi` restates two things that are
//! private inside `osprey-core`: the one-field `{"identity": …}` wrapper the
//! handshake payloads carry, and the `osprey/pair/{confirm,accept}/v1` tags of
//! the post-handshake confirmation. Neither can be imported, and a silent
//! divergence in either would not surface until a phone stood in front of a
//! host and failed to pair with an error that looks like a key problem.
//!
//! So the phone half here is driven entirely through the FFI surface — byte
//! pushes, no shortcuts — against `osprey_core::pairing::respond` running on a
//! real TCP socket. If any of those constants drift, this fails.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use common::FakeEnclavePhone;
use osprey_core::audit::AuditLog;
use osprey_core::identity::DeviceIdentity;
use osprey_core::noise::MAX_CHUNK_PAYLOAD_LEN;
use osprey_core::pairing::{
    respond, PairingContext, PairingOffer, PairingSecret, QrPayload, DEFAULT_PAIRING_TTL,
};
use osprey_ffi::{
    decode_identity_message, encode_identity_message, pair_accept_tag, pair_confirm_tag,
    parse_qr_payload, NoiseHandshake, NoiseTransport, OspreyError,
};

/// A connected loopback pair. Loopback completes the TCP handshake into the
/// backlog, so no accept thread is needed to establish the pair itself.
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nodelay(true).expect("nodelay client");
    server.set_nodelay(true).expect("nodelay server");
    (client, server)
}

/// Feed the handshake from the socket in small reads until it yields a message.
/// Deliberately 7 bytes at a time: a phone gets whatever the kernel had, and the
/// bridge must never mistake a partial frame for a corrupt one.
fn pump_handshake(stream: &mut TcpStream, handshake: &NoiseHandshake) -> Vec<u8> {
    loop {
        if let Some(message) = handshake.read_message().expect("handshake read") {
            return message;
        }
        let mut buf = [0u8; 7];
        let n = stream.read(&mut buf).expect("socket read");
        assert!(n > 0, "peer closed mid-handshake");
        handshake
            .push_bytes(buf[..n].to_vec())
            .expect("push handshake bytes");
    }
}

fn pump_transport(stream: &mut TcpStream, transport: &NoiseTransport) -> Vec<u8> {
    loop {
        if let Some(message) = transport.next_message().expect("transport read") {
            return message;
        }
        let mut buf = [0u8; 7];
        let n = stream.read(&mut buf).expect("socket read");
        assert!(n > 0, "peer closed mid-message");
        transport
            .push_bytes(buf[..n].to_vec())
            .expect("push transport bytes");
    }
}

struct Host {
    agent: DeviceIdentity,
    offer: PairingOffer,
    qr_text: String,
    _dir: tempfile::TempDir,
    audit: AuditLog,
}

/// A host waiting on a pairing offer, with the QR it is displaying.
///
/// `qr_secret` is what the QR carries; `host_secret` is what the host is waiting
/// on. They differ only in the wrong-PSK test.
fn host_with(host_secret: PairingSecret, qr_secret: PairingSecret) -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let agent = DeviceIdentity::generate();
    let qr = QrPayload::new(
        "https://relay.invalid",
        "acct-1",
        "dev-1",
        agent.public().clone(),
        vec!["127.0.0.1:47010".parse().expect("addr")],
        qr_secret,
    );
    let audit = AuditLog::open(dir.path()).expect("audit log");
    Host {
        agent,
        offer: PairingOffer::new(host_secret, DEFAULT_PAIRING_TTL),
        qr_text: qr.encode().expect("encode qr"),
        _dir: dir,
        audit,
    }
}

fn matching_host() -> Host {
    let secret = PairingSecret::generate();
    host_with(secret.clone(), secret)
}

#[test]
fn the_ffi_initiator_pairs_with_the_real_agent_responder() {
    let phone = FakeEnclavePhone::generate();
    let host = matching_host();
    let (mut client, mut server) = tcp_pair();

    let Host {
        agent,
        mut offer,
        qr_text,
        audit,
        _dir,
    } = host;
    let responder = std::thread::spawn(move || {
        let context = PairingContext::new("acct-1", "dev-1");
        let outcome = respond(&mut server, &agent, &mut offer, &context, &audit);
        (outcome, server)
    });

    let scanned = parse_qr_payload(qr_text).expect("parse qr");
    assert_eq!(scanned.account_id(), "acct-1");
    assert_eq!(scanned.routing_id().len(), 32);

    let handshake = scanned
        .start_pairing(phone.noise_static_private.to_vec())
        .expect("start pairing");
    assert!(!handshake.is_handshake_finished().expect("state"));

    let hello = encode_identity_message(phone.identity.clone()).expect("encode identity");
    let msg1 = handshake.write_message(hello).expect("write msg1");
    client.write_all(&msg1).expect("send msg1");
    client.flush().expect("flush");

    let reply = pump_handshake(&mut client, &handshake);
    let agent_identity = decode_identity_message(reply).expect("decode agent identity");
    assert_eq!(
        agent_identity,
        scanned.agent_identity(),
        "the agent must present the identity the QR pinned"
    );
    assert!(handshake.is_handshake_finished().expect("state"));

    let transport = handshake.into_transport().expect("promote");
    assert_eq!(
        transport.remote_static().expect("remote static"),
        agent_identity.noise_static_pub,
        "the handshake must have authenticated the cross-signed static"
    );

    let confirm = transport.encrypt(pair_confirm_tag()).expect("encrypt confirm");
    client.write_all(&confirm).expect("send confirm");
    client.flush().expect("flush");

    let accept = pump_transport(&mut client, &transport);
    assert_eq!(accept, pair_accept_tag());

    let (outcome, mut server) = responder.join().expect("responder thread");
    let outcome = outcome.expect("the agent must accept the pairing");
    assert_eq!(
        outcome.peer.identity_pub, phone.identity.identity_pub,
        "the agent must pin the phone's P-256 identity key"
    );
    assert_eq!(outcome.peer.identity_algorithm.as_str(), "p256");

    // A multi-chunk payload in the phone→agent direction, decoded by the real
    // core reader. Outbound chunking is unaffected by the inbound one-chunk
    // limit, and this is what proves it.
    let mut agent_session = outcome.session;
    let big = vec![0xA7u8; MAX_CHUNK_PAYLOAD_LEN * 2 + 11];
    let wire = transport.encrypt(big.clone()).expect("encrypt large");
    let reader = std::thread::spawn(move || {
        let received = agent_session.recv(&mut server).expect("agent recv");
        (received, agent_session, server)
    });
    client.write_all(&wire).expect("send large");
    client.flush().expect("flush");
    let (received, mut agent_session, mut server) = reader.join().expect("reader thread");
    assert_eq!(received.expect("a message"), big);

    // The reverse direction is the documented limit: the agent's chunker splits
    // a large message, and the bridge refuses it rather than reassembling half.
    agent_session
        .send(&vec![0x3cu8; MAX_CHUNK_PAYLOAD_LEN + 1], &mut server)
        .expect("agent send large");
    let err = loop {
        match transport.next_message() {
            Ok(Some(_)) => panic!("a multi-chunk inbound message must not be accepted"),
            Ok(None) => {
                let mut buf = [0u8; 4096];
                let n = client.read(&mut buf).expect("socket read");
                assert!(n > 0, "peer closed");
                transport.push_bytes(buf[..n].to_vec()).expect("push");
            }
            Err(err) => break err,
        }
    };
    assert!(matches!(err, OspreyError::MessageTooLarge { .. }), "{err:?}");
}

#[test]
fn a_tampered_handshake_reply_is_refused_at_the_read_stage() {
    let phone = FakeEnclavePhone::generate();
    let host = matching_host();
    let (mut client, mut server) = tcp_pair();

    let Host {
        agent,
        mut offer,
        qr_text,
        audit,
        _dir,
    } = host;
    let responder = std::thread::spawn(move || {
        let context = PairingContext::new("acct-1", "dev-1");
        let outcome = respond(&mut server, &agent, &mut offer, &context, &audit);
        // Hold the socket open so the phone's read cannot fail on a closed peer
        // instead of on the tampered bytes.
        (outcome.is_err(), server)
    });

    let scanned = parse_qr_payload(qr_text).expect("parse qr");
    let handshake = scanned
        .start_pairing(phone.noise_static_private.to_vec())
        .expect("start pairing");
    let hello = encode_identity_message(phone.identity.clone()).expect("encode identity");
    client
        .write_all(&handshake.write_message(hello).expect("write msg1"))
        .expect("send msg1");
    client.flush().expect("flush");

    // Read the whole framed reply, flip one ciphertext byte, then push it.
    let mut prefix = [0u8; 2];
    client.read_exact(&mut prefix).expect("length prefix");
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    client.read_exact(&mut body).expect("frame body");
    body[0] ^= 0x01;

    handshake.push_bytes(prefix.to_vec()).expect("push prefix");
    handshake.push_bytes(body).expect("push body");
    let err = handshake.read_message().expect_err("tampering must be refused");
    match err {
        OspreyError::HandshakeRejected { ref stage, .. } => assert_eq!(stage, "read"),
        other => panic!("expected a read-stage rejection, got {other:?}"),
    }

    drop(client);
    let (agent_refused, _server) = responder.join().expect("responder thread");
    assert!(
        agent_refused,
        "the agent must not complete a pairing whose confirmation never arrives"
    );
}

#[test]
fn a_wrong_pairing_secret_fails_the_handshake_rather_than_pinning() {
    let phone = FakeEnclavePhone::generate();
    // The QR carries one secret; the host is waiting on another. `IKpsk2` mixes
    // the PSK into message two, so this fails on the phone's read of the reply —
    // before it has pinned anything or sent a confirmation.
    let host = host_with(PairingSecret::generate(), PairingSecret::generate());
    let (mut client, mut server) = tcp_pair();

    let Host {
        agent,
        mut offer,
        qr_text,
        audit,
        _dir,
    } = host;
    let responder = std::thread::spawn(move || {
        let context = PairingContext::new("acct-1", "dev-1");
        let refused = respond(&mut server, &agent, &mut offer, &context, &audit).is_err();
        (refused, server)
    });

    let scanned = parse_qr_payload(qr_text).expect("parse qr");
    let handshake = scanned
        .start_pairing(phone.noise_static_private.to_vec())
        .expect("start pairing");
    let hello = encode_identity_message(phone.identity.clone()).expect("encode identity");
    client
        .write_all(&handshake.write_message(hello).expect("write msg1"))
        .expect("send msg1");
    client.flush().expect("flush");

    let err = loop {
        match handshake.read_message() {
            Ok(Some(_)) => panic!("a mismatched PSK must not yield a readable reply"),
            Ok(None) => {
                let mut buf = [0u8; 64];
                let n = client.read(&mut buf).expect("socket read");
                assert!(n > 0, "peer closed before the reply");
                handshake.push_bytes(buf[..n].to_vec()).expect("push");
            }
            Err(err) => break err,
        }
    };
    assert!(
        matches!(err, OspreyError::HandshakeRejected { .. }),
        "{err:?}"
    );
    assert!(
        handshake.into_transport().is_err(),
        "an unfinished handshake must not promote to a session"
    );

    drop(client);
    let (refused, _server) = responder.join().expect("responder thread");
    assert!(refused, "the agent must also refuse the pairing");
}

#[test]
fn a_post_pairing_session_handshake_reaches_the_agent_on_pinned_statics() {
    // Pattern::Session carries no PSK: after pairing, the pin is the
    // authentication. Driven against the core's own responder half so the
    // pattern strings on the two sides are proven to agree.
    let phone = FakeEnclavePhone::generate();
    let agent = DeviceIdentity::generate();
    let agent_static_pub = agent.public().noise_static_pub;

    let handshake = NoiseHandshake::session_initiator(
        phone.noise_static_private.to_vec(),
        agent_static_pub.to_vec(),
    )
    .expect("start session handshake");

    let (mut client, mut server) = tcp_pair();
    let responder = std::thread::spawn(move || {
        use osprey_core::noise::{Handshake, HandshakeConfig, Pattern, Role};
        let local = agent.noise_static_secret();
        let state = Handshake::new(HandshakeConfig {
            pattern: Pattern::Session,
            role: Role::Responder,
            local_static: &local,
            remote_static: None,
            psk: None,
        })
        .expect("build responder");
        let (session, request) = state
            .run_responder(&mut server, b"agent-hello")
            .expect("run responder");
        (session, request, server)
    });

    client
        .write_all(&handshake.write_message(b"phone-hello".to_vec()).expect("msg1"))
        .expect("send msg1");
    client.flush().expect("flush");
    let reply = pump_handshake(&mut client, &handshake);
    assert_eq!(reply, b"agent-hello");

    let transport = handshake.into_transport().expect("promote");
    assert_eq!(
        transport.remote_static().expect("remote static"),
        agent_static_pub.to_vec()
    );

    let (mut session, request, mut server) = responder.join().expect("responder thread");
    assert_eq!(request, b"phone-hello");
    assert_eq!(
        session.remote_static(),
        &<[u8; 32]>::try_from(phone.identity.noise_static_pub.as_slice()).expect("32 bytes"),
        "the agent must see the phone's cross-signed static"
    );

    // One round trip in each direction, so the transport keys are proven to
    // agree and not merely to have been derived.
    client
        .write_all(&transport.encrypt(b"ping".to_vec()).expect("encrypt"))
        .expect("send ping");
    client.flush().expect("flush");
    assert_eq!(
        session.recv(&mut server).expect("agent recv").expect("msg"),
        b"ping"
    );
    session.send(b"pong", &mut server).expect("agent send");
    assert_eq!(pump_transport(&mut client, &transport), b"pong");
}
