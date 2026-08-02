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
//! What it does **not** prove: anything about a real phone, the Secure Enclave,
//! camera capture of the QR, or DPAPI. Those need hardware this suite does not
//! have.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use osprey_core::audit::AuditLog;
use osprey_core::channel;
use osprey_core::identity::{DeviceIdentity, PinnedPeer};
use osprey_core::noise::NoiseSession;
use osprey_core::pairing::{self, QrPayload};
use osprey_proto::{
    Body, Envelope, HelloBody, MessageType, PingBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use osprey_svc::commands::{pair, run, unpair};
use osprey_svc::host::Host;
use osprey_svc::paths::DataLayout;
use osprey_svc::session::now_ms;
use osprey_svc::state::PeerSelector;
use uuid::Uuid;

/// A console sink the test can read while the writer is still running.
#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn text(&self) -> String {
        let guard = self.0.lock().expect("sink lock");
        String::from_utf8_lossy(&guard).into_owned()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ask the OS for a free port, then release it.
///
/// `pair` and `run` have to listen on the *same* port for the controller to find
/// the agent twice, and a hard-coded number would collide with a developer's
/// real agent. The gap between release and rebind is a race in principle; in a
/// single-threaded test on loopback it has no other bidder.
fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
    probe.local_addr().expect("probe addr").port()
}

fn wait_for<T>(what: &str, mut attempt: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(value) = attempt() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Pull the QR payload back out of what the agent printed to its console.
fn scrape_payload(console: &SharedSink) -> QrPayload {
    let text = wait_for("the agent to print a pairing payload", || {
        let text = console.text();
        text.lines()
            .find(|line| line.starts_with("{\"v\":"))
            .map(str::to_owned)
    });
    QrPayload::decode(&text).expect("the printed payload should decode")
}

fn connect_to_hint(hints: &[SocketAddr]) -> TcpStream {
    let stream = wait_for("the agent's listener", || {
        hints.iter().find_map(|addr| TcpStream::connect(addr).ok())
    });
    // Without this the controller half of a *refused* session would block
    // forever instead of failing the assertion it is there to make.
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    stream
}

/// Can this controller actually use the session it just negotiated?
///
/// Worth spelling out, because `channel::connect` returning `Ok` is *not* the
/// same as being admitted. `Noise_IK`'s responder writes message two as part of
/// the same call in which it reads message one, so `channel::accept` can only
/// compare the peer's static against its pin after that message is already on
/// the wire. A refused controller therefore completes the handshake and derives
/// keys the agent will never use, and discovers it was refused when the agent
/// hangs up. No plaintext crosses, and the pin still decides — but "the
/// connection was refused" is only observable at the application layer, which is
/// where these tests assert it.
fn session_is_usable(session: &mut NoiseSession, stream: &mut TcpStream) -> bool {
    let envelope = Envelope::new(
        Uuid::new_v4(),
        now_ms(),
        &Body::Hello(HelloBody {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            capabilities: Vec::new(),
            device_id: Uuid::new_v4(),
            software_version: "gate-test".into(),
        }),
    )
    .expect("build envelope");
    let bytes = serde_json::to_vec(&envelope).expect("encode envelope");
    if session.send(&bytes, stream).is_err() {
        return false;
    }
    matches!(session.recv(stream), Ok(Some(_)))
}

fn send_body(session: &mut NoiseSession, stream: &mut TcpStream, id: Uuid, body: &Body) {
    let envelope = Envelope::new(id, now_ms(), body).expect("build envelope");
    let bytes = serde_json::to_vec(&envelope).expect("encode envelope");
    session.send(&bytes, stream).expect("send");
}

fn recv_envelope(session: &mut NoiseSession, stream: &mut TcpStream) -> Envelope {
    let bytes = session.recv(stream).expect("recv").expect("a message");
    serde_json::from_slice(&bytes).expect("decode envelope")
}

/// The controller's half: scan, handshake, pin.
fn controller_pairs(
    identity: &DeviceIdentity,
    audit: &AuditLog,
    payload: &QrPayload,
) -> PinnedPeer {
    let mut stream = connect_to_hint(&payload.lan_hints);
    let outcome =
        pairing::initiate(&mut stream, identity, payload, audit).expect("pairing should succeed");
    outcome.peer
}

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
    let console = SharedSink::default();
    let pairing_thread = {
        let layout = layout.clone();
        let mut console = console.clone();
        std::thread::spawn(move || {
            let mut host = Host::open(layout, "gate-host").expect("open host");
            let options = pair::PairOptions {
                lan_only: true,
                port,
                ttl: Duration::from_secs(30),
                ..pair::PairOptions::default()
            };
            pair::execute(&mut host, &options, &mut console).expect("pairing should succeed")
        })
    };

    let payload = scrape_payload(&console);
    assert_eq!(payload.relay_url, "", "a lan-only QR must not name a relay");
    assert!(
        !payload.lan_hints.is_empty(),
        "the QR must carry at least one address the controller can reach"
    );
    let pinned_agent = controller_pairs(&controller_identity, &controller_audit, &payload);
    let paired = pairing_thread.join().expect("pairing thread");

    assert_eq!(
        paired.pinned.identity_pub,
        controller_identity.public().identity_pub,
        "the agent must pin the controller's identity key"
    );
    assert_eq!(
        pinned_agent.fingerprint().to_string(),
        payload.agent_identity.fingerprint().to_string(),
        "the controller must pin the key it scanned"
    );
    let rendered = console.text();
    assert!(
        rendered.contains(&paired.fingerprint().short()),
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
            run::execute(&host, &run::RunOptions { port }, running, &mut sink)
        })
    };

    let mut stream = connect_to_hint(&payload.lan_hints);
    let mut session =
        channel::connect(&mut stream, &controller_identity, &pinned_agent).expect("ik session");

    let hello_id = Uuid::new_v4();
    send_body(
        &mut session,
        &mut stream,
        hello_id,
        &Body::Hello(HelloBody {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            capabilities: Vec::new(),
            device_id: controller_device_id,
            software_version: "gate-test".into(),
        }),
    );
    let hello_ok = recv_envelope(&mut session, &mut stream);
    assert_eq!(hello_ok.t, MessageType::HelloOk);
    assert_eq!(hello_ok.id, hello_id, "hello.ok must correlate to hello");

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
    let selector = PeerSelector::parse(&paired.fingerprint().to_string()).expect("selector");
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
    let mut retry = connect_to_hint(&payload.lan_hints);
    match channel::connect(&mut retry, &controller_identity, &pinned_agent) {
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
        audit.contains(&paired.fingerprint().to_string()),
        "the audit entry must name the peer that was pinned"
    );
    assert!(
        audit.contains(&hex::encode(paired.pinned.noise_static_pub)),
        "the pairing entry must record the static the handshake authenticated"
    );
}

/// A controller that was never paired is refused, and the refusal costs the
/// agent nothing but a dropped socket.
#[test]
fn an_unknown_controller_is_refused_a_session() {
    let agent_dir = tempfile::tempdir().expect("agent tempdir");
    let layout = DataLayout::under(agent_dir.path());
    let port = free_port();

    // Pair one controller so `run` has something to serve.
    let console = SharedSink::default();
    let paired_controller = DeviceIdentity::generate();
    let controller_dir = tempfile::tempdir().expect("controller tempdir");
    let controller_audit = AuditLog::open(controller_dir.path()).expect("audit");

    let pairing_thread = {
        let layout = layout.clone();
        let mut console = console.clone();
        std::thread::spawn(move || {
            let mut host = Host::open(layout, "gate-host").expect("open host");
            let options = pair::PairOptions {
                lan_only: true,
                port,
                ttl: Duration::from_secs(30),
                ..pair::PairOptions::default()
            };
            pair::execute(&mut host, &options, &mut console).expect("pairing")
        })
    };
    let payload = scrape_payload(&console);
    let pinned_agent = controller_pairs(&paired_controller, &controller_audit, &payload);
    pairing_thread.join().expect("pairing thread");

    let running = Arc::new(AtomicBool::new(true));
    let run_thread = {
        let layout = layout.clone();
        let running = Arc::clone(&running);
        std::thread::spawn(move || {
            let host = Host::open(layout, "gate-host").expect("reopen host");
            let mut sink = SharedSink::default();
            run::execute(&host, &run::RunOptions { port }, running, &mut sink)
        })
    };

    let stranger = DeviceIdentity::generate();
    let mut stream = connect_to_hint(&payload.lan_hints);
    match channel::connect(&mut stream, &stranger, &pinned_agent) {
        Ok(mut session) => assert!(
            !session_is_usable(&mut session, &mut stream),
            "an unpinned controller must not be able to use a session"
        ),
        Err(_) => { /* refused during the handshake */ }
    }

    // The paired controller is unaffected by the stranger's attempt.
    let mut good = connect_to_hint(&payload.lan_hints);
    let mut session =
        channel::connect(&mut good, &paired_controller, &pinned_agent).expect("still paired");
    assert!(
        session_is_usable(&mut session, &mut good),
        "the paired controller must still be served"
    );

    running.store(false, Ordering::Relaxed);
    run_thread.join().expect("run thread").expect("run result");
}
