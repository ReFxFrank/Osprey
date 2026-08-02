//! Gate P0 criteria 1 and 3, as far as they can be met without an iPhone.
//!
//! One process, two real identities, real TCP on loopback, and the same code
//! paths the console binary uses. What this proves:
//!
//! * a pairing QR the agent actually printed carries everything a controller
//!   needs (the payload is scraped back out of the agent's own console output,
//!   not constructed by the test);
//! * `Noise_IKpsk2` pairing completes and the agent pins the controller;
//! * a steady-state `Noise_IK` session on the pinned statics carries an
//!   encrypted `hello`/`ping` and gets `hello.ok`/`pong` back;
//! * `unpair` drops the live session without the relay being involved;
//! * the next connection from the unpaired controller is refused.
//!
//! The peer-initiated half of unpair — a signed `pair.revoke` — is in
//! `peer_revoke.rs`.
//!
//! What this does **not** prove: anything about a real phone, the Secure
//! Enclave, camera capture of the QR, or DPAPI. Those need hardware this suite
//! does not have.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::{
    connect_to_hint, free_port, open_session, pair_one_controller, recv_envelope, send_body,
    session_is_usable, wait_for, SharedSink,
};
use osprey_core::audit::AuditLog;
use osprey_core::channel;
use osprey_core::identity::DeviceIdentity;
use osprey_proto::{Body, MessageType, PingBody};
use osprey_svc::commands::{run, unpair};
use osprey_svc::host::Host;
use osprey_svc::paths::DataLayout;
use osprey_svc::state::PeerSelector;
use uuid::Uuid;

#[test]
fn pair_then_session_then_unpair_blocks_the_next_connection() {
    let agent_dir = tempfile::tempdir().expect("agent tempdir");
    let controller_dir = tempfile::tempdir().expect("controller tempdir");
    let layout = DataLayout::under(agent_dir.path());
    let port = free_port();

    let controller_identity = DeviceIdentity::generate();
    let controller_audit = AuditLog::open(controller_dir.path()).expect("controller audit");
    let controller_device_id = Uuid::new_v4();

    // ---- 1. pairing -------------------------------------------------------
    let enrolled = pair_one_controller(&layout, port, &controller_identity, &controller_audit);

    assert_eq!(
        enrolled.payload.relay_url, "",
        "a lan-only QR must not name a relay"
    );
    assert!(
        !enrolled.payload.lan_hints.is_empty(),
        "the QR must carry at least one address the controller can reach"
    );
    assert_eq!(
        enrolled.paired.pinned.identity_pub,
        controller_identity.public().identity_pub,
        "the agent must pin the controller's identity key"
    );
    assert_eq!(
        enrolled.agent_pin.fingerprint().to_string(),
        enrolled.payload.agent_identity.fingerprint().to_string(),
        "the controller must pin the key it scanned"
    );
    assert!(
        enrolled
            .console
            .text()
            .contains(&enrolled.paired.fingerprint().short()),
        "the agent must display the pinned fingerprint for a human to check"
    );

    // ---- 2. steady-state session -----------------------------------------
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

    let mut stream = connect_to_hint(&enrolled.payload.lan_hints);
    let mut session = open_session(
        &mut stream,
        &controller_identity,
        &enrolled.agent_pin,
        controller_device_id,
    );

    let ping_id = Uuid::new_v4();
    send_body(
        &mut session,
        &mut stream,
        ping_id,
        &Body::Ping(PingBody { seq: 7 }),
    );
    let pong = recv_envelope(&mut session, &mut stream);
    assert_eq!(pong.t, MessageType::Pong);
    assert_eq!(pong.id, ping_id);
    match pong.decode_body().expect("decode pong") {
        Body::Pong(body) => assert_eq!(body.seq, 7),
        other => panic!("expected a pong body, got {other:?}"),
    }

    // ---- 3. unpair, with no relay anywhere in the path --------------------
    let mut sink = SharedSink::default();
    let mut host = Host::open(layout.clone(), "gate-host").expect("reopen host");
    let selector =
        PeerSelector::parse(&enrolled.paired.fingerprint().to_string()).expect("selector");
    let outcome = unpair::execute(&mut host, &selector, None, &mut sink).expect("unpair");
    assert_eq!(outcome.removed.len(), 1);
    assert!(
        outcome.relay_errors.is_empty(),
        "a lan-only unpair must not attempt a relay call"
    );

    // The live session dies because the agent's watcher noticed the pin is
    // gone — nothing told the controller, and no relay was involved.
    let dropped = wait_for("the live session to be dropped", || {
        match session.recv(&mut stream) {
            Ok(None) => Some("clean close"),
            Ok(Some(_)) => None,
            Err(_) => Some("reset"),
        }
    });
    assert!(matches!(dropped, "clean close" | "reset"));

    // ---- 4. the unpaired controller cannot come back ----------------------
    let mut retry = connect_to_hint(&enrolled.payload.lan_hints);
    match channel::connect(&mut retry, &controller_identity, &enrolled.agent_pin) {
        Ok(mut revived) => assert!(
            !session_is_usable(&mut revived, &mut retry),
            "an unpaired controller must not be able to use a session"
        ),
        Err(_) => { /* refused during the handshake, which is also correct */ }
    }

    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");

    // ---- 5. the audit log recorded both privileged events -----------------
    let audit =
        std::fs::read_to_string(AuditLog::open(&layout.audit).expect("audit").current_file())
            .expect("read audit log");
    assert!(
        audit.contains("\"event\":\"pairing_succeeded\""),
        "pairing must be audited: {audit}"
    );
    assert!(
        audit.contains("\"event\":\"unpaired\""),
        "unpair must be audited: {audit}"
    );
    assert!(
        audit.contains(&enrolled.paired.fingerprint().to_string()),
        "the audit entry must name the peer that was pinned"
    );
    assert!(
        audit.contains(&hex::encode(enrolled.paired.pinned.noise_static_pub)),
        "the pairing entry must record the static the handshake authenticated"
    );
}

/// A controller that was never paired is refused, and the refusal costs the
/// agent nothing but a dropped socket.
#[test]
fn an_unknown_controller_is_refused_a_session() {
    let agent_dir = tempfile::tempdir().expect("agent tempdir");
    let controller_dir = tempfile::tempdir().expect("controller tempdir");
    let layout = DataLayout::under(agent_dir.path());
    let port = free_port();

    let paired_controller = DeviceIdentity::generate();
    let controller_audit = AuditLog::open(controller_dir.path()).expect("audit");
    let enrolled = pair_one_controller(&layout, port, &paired_controller, &controller_audit);

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

    let stranger = DeviceIdentity::generate();
    let mut stream = connect_to_hint(&enrolled.payload.lan_hints);
    match channel::connect(&mut stream, &stranger, &enrolled.agent_pin) {
        Ok(mut session) => assert!(
            !session_is_usable(&mut session, &mut stream),
            "an unpinned controller must not be able to use a session"
        ),
        Err(_) => { /* refused during the handshake */ }
    }

    // The paired controller is unaffected by the stranger's attempt.
    let mut good = connect_to_hint(&enrolled.payload.lan_hints);
    let mut session =
        channel::connect(&mut good, &paired_controller, &enrolled.agent_pin).expect("still paired");
    assert!(
        session_is_usable(&mut session, &mut good),
        "the paired controller must still be served"
    );

    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");
}

/// A socket accepted *before* an unpair completes must still be refused.
///
/// The agent snapshots the pin list when a connection is accepted, and the Noise
/// handshake happens after that — so a controller whose TCP connection landed
/// microseconds before `unpair` finishes handshakes against a list that is
/// already out of date. Recovering only on the revocation watcher's next poll
/// would leave a revoked controller served for up to that interval; the agent
/// re-checks the store once the handshake is done instead, which turns the poll
/// interval into a comparison.
///
/// The connection here is opened and left idle across the unpair, which forces
/// exactly that ordering rather than hoping to hit it.
#[test]
fn a_connection_accepted_before_an_unpair_is_refused_after_it() {
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

    // The TCP connection lands, and the agent takes its pin snapshot, before a
    // single Noise byte is written.
    let mut stream = connect_to_hint(&enrolled.payload.lan_hints);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let mut host = Host::open(layout.clone(), "gate-host").expect("reopen host");
    let selector =
        PeerSelector::parse(&enrolled.paired.fingerprint().to_string()).expect("selector");
    let mut sink = SharedSink::default();
    let outcome = unpair::execute(&mut host, &selector, None, &mut sink).expect("unpair");
    assert_eq!(outcome.removed.len(), 1);

    // Only now does the controller handshake, on a socket the agent accepted
    // while it was still pinned.
    match channel::connect(&mut stream, &controller, &enrolled.agent_pin) {
        Ok(mut session) => assert!(
            !session_is_usable(&mut session, &mut stream),
            "a controller unpaired during its handshake must not be served"
        ),
        Err(_) => { /* refused during the handshake, which is also correct */ }
    }

    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");
}
