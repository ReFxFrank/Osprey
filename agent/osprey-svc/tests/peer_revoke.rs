//! Gate P0: the *client* half of "unpair works from both sides".
//!
//! The operator standing at the host has `osprey-svc unpair`. The operator
//! holding the phone has only the authenticated Noise channel, so the phone
//! signs a `pair.revoke` under the identity key the agent pinned at pairing.
//! This suite drives that message against a real `run` loop and asserts what the
//! brief requires of it: the pin is gone, the session is dropped, the revocation
//! is audited as peer-initiated, and the controller cannot reconnect.
//!
//! It also asserts the three ways a revocation must fail — wrong signer, stale
//! clock, replayed nonce — because a `pair.revoke` that is accepted too easily
//! is a remote unpair primitive for anyone who can get a message onto the
//! channel.

mod common;

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::{
    connect_to_hint, free_port, open_session, pair_one_controller, recv_envelope, send_body,
    session_is_usable, wait_for, Paired, SharedSink,
};
use osprey_core::audit::AuditLog;
use osprey_core::channel;
use osprey_core::identity::DeviceIdentity;
use osprey_core::noise::NoiseSession;
use osprey_core::pairing::{revocation_signing_bytes, REVOKE_CLOCK_WINDOW};
use osprey_proto::{Body, ErrorCode, MessageType, PairRevokeBody};
use osprey_svc::commands::run;
use osprey_svc::host::Host;
use osprey_svc::paths::DataLayout;
use osprey_svc::session::now_ms;
use osprey_svc::state::HostState;
use uuid::Uuid;

/// A running agent with one controller paired to it.
struct Agent {
    layout: DataLayout,
    enrolled: Paired,
    controller: DeviceIdentity,
    controller_device_id: Uuid,
    running: Arc<AtomicBool>,
    run_thread: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
    _agent_dir: tempfile::TempDir,
    _controller_dir: tempfile::TempDir,
}

impl Agent {
    fn start() -> Self {
        let agent_dir = tempfile::tempdir().expect("agent tempdir");
        let controller_dir = tempfile::tempdir().expect("controller tempdir");
        let layout = DataLayout::under(agent_dir.path());
        let port = free_port();

        let controller = DeviceIdentity::generate();
        let controller_audit = AuditLog::open(controller_dir.path()).expect("controller audit");
        let enrolled = pair_one_controller(&layout, port, &controller, &controller_audit);

        let running = Arc::new(AtomicBool::new(true));
        let run_thread = {
            let layout = layout.clone();
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                let host = Host::open(layout, "gate-host").expect("reopen host");
                let mut sink = SharedSink::default();
                run::execute(
                    &host,
                    &run::RunOptions {
                        port,
                        ..Default::default()
                    },
                    running,
                    &mut sink,
                )
            })
        };

        Self {
            layout,
            enrolled,
            controller,
            controller_device_id: Uuid::new_v4(),
            running,
            run_thread: Some(run_thread),
            _agent_dir: agent_dir,
            _controller_dir: controller_dir,
        }
    }

    fn connect(&self) -> (NoiseSession, TcpStream) {
        let mut stream = connect_to_hint(&self.enrolled.payload.lan_hints);
        let session = open_session(
            &mut stream,
            &self.controller,
            &self.enrolled.agent_pin,
            self.controller_device_id,
        );
        (session, stream)
    }

    fn pin_count(&self) -> usize {
        HostState::read_peers(&self.layout.state)
            .expect("read pins")
            .len()
    }

    fn audit_text(&self) -> String {
        let log = AuditLog::open(&self.layout.audit).expect("audit");
        std::fs::read_to_string(log.current_file()).expect("read audit log")
    }

    fn stop(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.run_thread.take() {
            handle.join().expect("run thread").expect("run result");
        }
    }
}

/// Build a `pair.revoke` signed by `signer`. Every parameter a test might want
/// to corrupt is explicit, so a bad case differs from the good one in exactly
/// one value.
fn revocation(
    signer: &DeviceIdentity,
    issuer: Uuid,
    revoked: Uuid,
    issued_at: i64,
    nonce: [u8; 32],
) -> PairRevokeBody {
    let signature = signer.sign(&revocation_signing_bytes(
        issuer.as_bytes(),
        revoked.as_bytes(),
        issued_at,
        &nonce,
    ));
    PairRevokeBody {
        issuer_device_id: issuer,
        revoked_device_id: revoked,
        issued_at,
        nonce: nonce.to_vec(),
        signature: signature.to_vec(),
    }
}

/// Send a `pair.revoke` and read the agent's answer.
fn send_revoke(
    session: &mut NoiseSession,
    stream: &mut TcpStream,
    body: &PairRevokeBody,
) -> osprey_proto::Envelope {
    let id = Uuid::new_v4();
    send_body(session, stream, id, &Body::PairRevoke(body.clone()));
    let reply = recv_envelope(session, stream);
    assert_eq!(reply.id, id, "the answer must correlate to the request");
    reply
}

fn error_code(reply: &osprey_proto::Envelope) -> ErrorCode {
    assert_eq!(
        reply.t,
        MessageType::Error,
        "expected an error, got {reply:?}"
    );
    match reply.decode_body().expect("decode error body") {
        Body::Error(body) => body.code,
        other => panic!("expected an error body, got {other:?}"),
    }
}

#[test]
fn a_signed_pair_revoke_unpins_the_peer_closes_the_session_and_is_audited() {
    let agent = Agent::start();
    assert_eq!(agent.pin_count(), 1);
    let (mut session, mut stream) = agent.connect();

    let body = revocation(
        &agent.controller,
        agent.controller_device_id,
        agent.controller_device_id,
        now_ms(),
        [0x5a; 32],
    );
    let reply = send_revoke(&mut session, &mut stream, &body);

    assert_eq!(
        reply.t,
        MessageType::Bye,
        "an accepted revocation is acknowledged with bye, got {reply:?}"
    );
    match reply.decode_body().expect("decode bye") {
        Body::Bye(bye) => assert_eq!(bye.reason, osprey_proto::ByeReason::Unpaired),
        other => panic!("expected a bye body, got {other:?}"),
    }

    assert_eq!(agent.pin_count(), 0, "the pin must be gone from the store");

    // The session the revocation arrived on is dropped, not left open.
    let ended = wait_for("the revoked session to end", || {
        match session.recv(&mut stream) {
            Ok(None) => Some("clean close"),
            Ok(Some(_)) => None,
            Err(_) => Some("reset"),
        }
    });
    assert!(matches!(ended, "clean close" | "reset"));

    let audit = agent.audit_text();
    assert!(
        audit.contains("\"event\":\"unpaired\"") && audit.contains("\"initiated_by\":\"peer\""),
        "a peer-initiated unpair must be audited as such: {audit}"
    );
    assert!(
        audit.contains(&agent.enrolled.paired.fingerprint().to_string()),
        "the audit entry must name the peer that was unpinned: {audit}"
    );

    // The next connection from the same controller is refused, with no relay
    // anywhere in the path.
    let mut retry = connect_to_hint(&agent.enrolled.payload.lan_hints);
    match channel::connect(&mut retry, &agent.controller, &agent.enrolled.agent_pin) {
        Ok(mut revived) => assert!(
            !session_is_usable(&mut revived, &mut retry),
            "a controller that revoked itself must not be readmitted"
        ),
        Err(_) => { /* refused during the handshake, which is also correct */ }
    }

    agent.stop();
}

#[test]
fn a_revocation_signed_by_the_wrong_identity_is_refused_and_the_pairing_survives() {
    let agent = Agent::start();
    let (mut session, mut stream) = agent.connect();

    let impostor = DeviceIdentity::generate();
    let body = revocation(
        &impostor,
        agent.controller_device_id,
        agent.controller_device_id,
        now_ms(),
        [0x11; 32],
    );
    let reply = send_revoke(&mut session, &mut stream, &body);
    assert_eq!(error_code(&reply), ErrorCode::Unauthorized);
    assert_eq!(agent.pin_count(), 1, "the pin must survive a forged revoke");

    // The session is still usable: refusing one bad message must not become a
    // way to hang up on a peer that is still legitimately paired.
    send_body(
        &mut session,
        &mut stream,
        Uuid::new_v4(),
        &Body::Ping(osprey_proto::PingBody { seq: 1 }),
    );
    assert_eq!(
        recv_envelope(&mut session, &mut stream).t,
        MessageType::Pong
    );

    agent.stop();
}

#[test]
fn a_stale_issued_at_is_refused() {
    let agent = Agent::start();
    let (mut session, mut stream) = agent.connect();

    let window_ms = i64::try_from(REVOKE_CLOCK_WINDOW.as_millis()).expect("window fits");
    let body = revocation(
        &agent.controller,
        agent.controller_device_id,
        agent.controller_device_id,
        now_ms() - window_ms - 60_000,
        [0x22; 32],
    );
    let reply = send_revoke(&mut session, &mut stream, &body);
    assert_eq!(error_code(&reply), ErrorCode::Unauthorized);
    assert_eq!(agent.pin_count(), 1, "a stale revoke must not unpin anyone");

    agent.stop();
}

#[test]
fn a_replayed_nonce_is_refused_even_after_the_operator_re_pairs() {
    let agent_dir = tempfile::tempdir().expect("agent tempdir");
    let controller_dir = tempfile::tempdir().expect("controller tempdir");
    let layout = DataLayout::under(agent_dir.path());
    let port = free_port();
    let controller = DeviceIdentity::generate();
    let controller_audit = AuditLog::open(controller_dir.path()).expect("controller audit");
    let controller_device_id = Uuid::new_v4();

    let enrolled = pair_one_controller(&layout, port, &controller, &controller_audit);
    let nonce = [0x33; 32];
    let issued_at = now_ms();
    let body = revocation(
        &controller,
        controller_device_id,
        controller_device_id,
        issued_at,
        nonce,
    );

    // First delivery: accepted, pin gone.
    let running = Arc::new(AtomicBool::new(true));
    let run_thread = {
        let layout = layout.clone();
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let host = Host::open(layout, "gate-host").expect("reopen host");
            let mut sink = SharedSink::default();
            run::execute(
                &host,
                &run::RunOptions {
                    port,
                    ..Default::default()
                },
                running,
                &mut sink,
            )
        })
    };
    {
        let mut stream = connect_to_hint(&enrolled.payload.lan_hints);
        let mut session = open_session(
            &mut stream,
            &controller,
            &enrolled.agent_pin,
            controller_device_id,
        );
        let reply = send_revoke(&mut session, &mut stream, &body);
        assert_eq!(reply.t, MessageType::Bye);
    }
    assert_eq!(HostState::read_peers(&layout.state).expect("pins").len(), 0);
    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");

    // The operator re-pairs the same device at the host. A captured revocation
    // must not be able to undo that: the nonce is what stops it, because
    // `issued_at` is still inside the clock window.
    let repaired = pair_one_controller(&layout, port, &controller, &controller_audit);
    assert_eq!(HostState::read_peers(&layout.state).expect("pins").len(), 1);
    assert!(
        now_ms() - issued_at < i64::try_from(REVOKE_CLOCK_WINDOW.as_millis()).expect("window"),
        "the replay must be attempted while freshness alone would still accept it"
    );

    let running = Arc::new(AtomicBool::new(true));
    let run_thread = {
        let layout = layout.clone();
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let host = Host::open(layout, "gate-host").expect("reopen host");
            let mut sink = SharedSink::default();
            run::execute(
                &host,
                &run::RunOptions {
                    port,
                    ..Default::default()
                },
                running,
                &mut sink,
            )
        })
    };
    let mut stream = connect_to_hint(&repaired.payload.lan_hints);
    let mut session = open_session(
        &mut stream,
        &controller,
        &repaired.agent_pin,
        controller_device_id,
    );
    let reply = send_revoke(&mut session, &mut stream, &body);
    assert_eq!(error_code(&reply), ErrorCode::Conflict);
    assert_eq!(
        HostState::read_peers(&layout.state).expect("pins").len(),
        1,
        "a replayed revocation must not unpin the re-paired controller"
    );

    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");
}
