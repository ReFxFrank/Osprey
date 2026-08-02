//! Gate P0: chunking across the 65535-byte Noise ceiling, and steady-state IK.

mod common;

use std::io::Cursor;
use std::net::TcpStream;

use common::{tcp_pair, Fixture};

use osprey_core::channel;
use osprey_core::error::Error;
use osprey_core::identity::{DeviceIdentity, PinnedPeer};
use osprey_core::noise::{NoiseSession, MAX_CHUNK_PAYLOAD_LEN, NOISE_MAX_PLAINTEXT_LEN};
use osprey_core::pairing::{initiate, respond, PairingContext};

struct Endpoint {
    session: NoiseSession,
    stream: TcpStream,
}

/// Pair over loopback and hand both live sessions back, so transport-level
/// tests start from a real handshake rather than a synthetic one.
fn paired_sessions(fixture: &mut Fixture) -> (Endpoint, Endpoint) {
    let (mut phone_stream, mut agent_stream) = tcp_pair();
    let ctx = PairingContext::new("acct-test", "dev-test");
    let phone = &fixture.phone;
    let qr = &fixture.qr;
    let phone_audit = &fixture.phone_audit;
    let agent = &fixture.agent;
    let agent_audit = &fixture.agent_audit;
    let offer = &mut fixture.offer;

    let (host, client) = std::thread::scope(|scope| {
        let handle = scope.spawn(|| initiate(&mut phone_stream, phone, qr, phone_audit));
        let host = respond(&mut agent_stream, agent, offer, &ctx, agent_audit);
        (host, handle.join().expect("phone thread"))
    });

    let host = host.expect("host pairing");
    let client = client.expect("phone pairing");
    (
        Endpoint {
            session: host.session,
            stream: agent_stream,
        },
        Endpoint {
            session: client.session,
            stream: phone_stream,
        },
    )
}

#[test]
fn payload_larger_than_one_noise_message_chunks_and_reassembles() {
    let mut fixture = Fixture::new();
    let (mut host, mut client) = paired_sessions(&mut fixture);

    // Past NOISE_MAX_PLAINTEXT_LEN (65519) and past two whole chunks, so this
    // covers both the ceiling and multi-chunk reassembly.
    let payload: Vec<u8> = (0..(NOISE_MAX_PLAINTEXT_LEN * 2 + 1234))
        .map(|i| (i % 251) as u8)
        .collect();
    assert!(payload.len() > NOISE_MAX_PLAINTEXT_LEN);
    let expected = payload.clone();

    std::thread::scope(|scope| {
        scope.spawn(move || {
            client
                .session
                .send(&payload, &mut client.stream)
                .expect("send large payload");
        });
        let received = host
            .session
            .recv(&mut host.stream)
            .expect("recv large payload")
            .expect("stream must not close");
        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);
    });
}

#[test]
fn boundary_sizes_round_trip_exactly() {
    let mut fixture = Fixture::new();
    let (mut host, mut client) = paired_sessions(&mut fixture);

    let sizes = [
        0usize,
        1,
        MAX_CHUNK_PAYLOAD_LEN - 1,
        MAX_CHUNK_PAYLOAD_LEN,
        MAX_CHUNK_PAYLOAD_LEN + 1,
        MAX_CHUNK_PAYLOAD_LEN * 2,
        MAX_CHUNK_PAYLOAD_LEN * 2 + 1,
    ];

    std::thread::scope(|scope| {
        scope.spawn(move || {
            for size in sizes {
                let payload = vec![(size % 256) as u8; size];
                client
                    .session
                    .send(&payload, &mut client.stream)
                    .expect("send");
            }
        });
        for size in sizes {
            let received = host
                .session
                .recv(&mut host.stream)
                .expect("recv")
                .expect("open");
            assert_eq!(received.len(), size, "size {size} did not round-trip");
            assert!(received.iter().all(|b| *b == (size % 256) as u8));
        }
    });
}

#[test]
fn a_flipped_ciphertext_byte_on_an_established_session_is_rejected() {
    let mut fixture = Fixture::new();
    let (mut host, mut client) = paired_sessions(&mut fixture);

    let mut wire = Vec::new();
    client
        .session
        .send(b"authentic", &mut wire)
        .expect("encrypt into a buffer");
    let last = wire.len() - 1;
    wire[last] ^= 0x01;

    let err = host
        .session
        .recv(&mut Cursor::new(wire))
        .expect_err("forged transport message must be rejected");
    assert!(
        matches!(err, Error::TransportAuth(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn a_truncated_multi_chunk_message_is_not_accepted_as_complete() {
    let mut fixture = Fixture::new();
    let (mut host, mut client) = paired_sessions(&mut fixture);

    let payload = vec![9u8; MAX_CHUNK_PAYLOAD_LEN + 100];
    let mut wire = Vec::new();
    client
        .session
        .send(&payload, &mut wire)
        .expect("encrypt into a buffer");

    // Drop the final chunk: an attacker cutting a stream short must not have the
    // receiver hand a partial message to the application.
    let first_frame_len = 2 + usize::from(u16::from_be_bytes([wire[0], wire[1]]));
    wire.truncate(first_frame_len);

    let err = host
        .session
        .recv(&mut Cursor::new(wire))
        .expect_err("truncated message must not be accepted");
    assert!(
        matches!(err, Error::TruncatedFrame { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn steady_state_ik_session_uses_the_pinned_statics() {
    let fixture = Fixture::new();
    let phone_pin_of_agent = PinnedPeer::pin(fixture.agent.public()).expect("pin agent");
    let agent_pin_of_phone = PinnedPeer::pin(fixture.phone.public()).expect("pin phone");

    let (mut phone_stream, mut agent_stream) = tcp_pair();
    let phone = &fixture.phone;
    let agent = &fixture.agent;
    let allowed = [agent_pin_of_phone];

    let (host, client) = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let mut session = channel::connect(&mut phone_stream, phone, &phone_pin_of_agent)?;
            session.send(b"ping", &mut phone_stream)?;
            session.recv(&mut phone_stream)
        });
        let host = (|| {
            let (peer, mut session) = channel::accept(&mut agent_stream, agent, &allowed)?;
            let request = session.recv(&mut agent_stream)?;
            session.send(b"pong", &mut agent_stream)?;
            Ok::<_, Error>((peer.identity_pub, request))
        })();
        (host, handle.join().expect("phone thread"))
    });

    let (peer_identity, request) = host.expect("host session");
    assert_eq!(peer_identity, fixture.phone.public().identity_pub);
    assert_eq!(request.as_deref(), Some(&b"ping"[..]));
    assert_eq!(
        client.expect("client session").as_deref(),
        Some(&b"pong"[..])
    );
}

#[test]
fn an_unpinned_peer_is_refused_a_steady_state_session() {
    let fixture = Fixture::new();
    let stranger = DeviceIdentity::generate();
    let agent_pin = PinnedPeer::pin(fixture.agent.public()).expect("pin agent");

    let (mut phone_stream, mut agent_stream) = tcp_pair();
    let agent = &fixture.agent;
    // An empty allow-list is what unpair leaves behind.
    let allowed: [PinnedPeer; 0] = [];

    let (host, _client) = std::thread::scope(|scope| {
        let handle =
            scope.spawn(|| channel::connect(&mut phone_stream, &stranger, &agent_pin).map(|_| ()));
        let host = channel::accept(&mut agent_stream, agent, &allowed).map(|_| ());
        (host, handle.join().expect("phone thread"))
    });

    assert!(matches!(
        host.expect_err("unpinned peer must be refused"),
        Error::UnpinnedPeer
    ));
}
