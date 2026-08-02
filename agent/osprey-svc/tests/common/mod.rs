//! Shared scaffolding for the agent's end-to-end tests.
//!
//! Each integration test binary is its own crate and uses a different subset of
//! these helpers, so unused-item warnings here are an artefact of the harness
//! rather than real dead code.
#![allow(dead_code)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use osprey_core::audit::AuditLog;
use osprey_core::identity::{DeviceIdentity, PinnedPeer};
use osprey_core::noise::NoiseSession;
use osprey_core::pairing::{self, QrPayload};
use osprey_proto::{Body, Envelope, HelloBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use osprey_svc::commands::pair;
use osprey_svc::host::Host;
use osprey_svc::paths::DataLayout;
use osprey_svc::session::now_ms;
use osprey_svc::state::PairedPeer;
use uuid::Uuid;

/// A console sink the test can read while the writer is still running.
#[derive(Clone, Default)]
pub struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    pub fn text(&self) -> String {
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
/// real agent. The gap between release and rebind is a race in principle; on
/// loopback in a test it has no other bidder.
pub fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
    probe.local_addr().expect("probe addr").port()
}

pub fn wait_for<T>(what: &str, mut attempt: impl FnMut() -> Option<T>) -> T {
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
///
/// Only possible because these tests pass `print_payload: true` — the shipping
/// default keeps the secret off stdout entirely, which is the point of the flag.
pub fn scrape_payload(console: &SharedSink) -> QrPayload {
    let text = wait_for("the agent to print a pairing payload", || {
        let text = console.text();
        text.lines()
            .find(|line| line.starts_with("{\"v\":"))
            .map(str::to_owned)
    });
    QrPayload::decode(&text).expect("the printed payload should decode")
}

pub fn connect_to_hint(hints: &[SocketAddr]) -> TcpStream {
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
pub fn session_is_usable(session: &mut NoiseSession, stream: &mut TcpStream) -> bool {
    if send_hello(session, stream, Uuid::new_v4(), Uuid::new_v4()).is_err() {
        return false;
    }
    matches!(session.recv(stream), Ok(Some(_)))
}

fn send_hello(
    session: &mut NoiseSession,
    stream: &mut TcpStream,
    id: Uuid,
    device_id: Uuid,
) -> Result<(), osprey_core::Error> {
    let envelope = Envelope::new(
        id,
        now_ms(),
        &Body::Hello(HelloBody {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            capabilities: Vec::new(),
            device_id,
            software_version: "gate-test".into(),
        }),
    )
    .expect("build envelope");
    let bytes = serde_json::to_vec(&envelope).expect("encode envelope");
    session.send(&bytes, stream)
}

pub fn send_body(session: &mut NoiseSession, stream: &mut TcpStream, id: Uuid, body: &Body) {
    let envelope = Envelope::new(id, now_ms(), body).expect("build envelope");
    let bytes = serde_json::to_vec(&envelope).expect("encode envelope");
    session.send(&bytes, stream).expect("send");
}

pub fn recv_envelope(session: &mut NoiseSession, stream: &mut TcpStream) -> Envelope {
    let bytes = session.recv(stream).expect("recv").expect("a message");
    serde_json::from_slice(&bytes).expect("decode envelope")
}

/// Open a session and complete the `hello`/`hello.ok` exchange.
pub fn open_session(
    stream: &mut TcpStream,
    controller: &DeviceIdentity,
    agent_pin: &PinnedPeer,
    device_id: Uuid,
) -> NoiseSession {
    let mut session =
        osprey_core::channel::connect(stream, controller, agent_pin).expect("ik session");
    let hello_id = Uuid::new_v4();
    send_hello(&mut session, stream, hello_id, device_id).expect("hello");
    let hello_ok = recv_envelope(&mut session, stream);
    assert_eq!(hello_ok.id, hello_id, "hello.ok must correlate to hello");
    session
}

/// The controller's half: scan, handshake, pin.
pub fn controller_pairs(
    identity: &DeviceIdentity,
    audit: &AuditLog,
    payload: &QrPayload,
) -> PinnedPeer {
    let mut stream = connect_to_hint(&payload.lan_hints);
    let outcome =
        pairing::initiate(&mut stream, identity, payload, audit).expect("pairing should succeed");
    outcome.peer
}

/// Everything one paired agent/controller pair needs, with the agent's `pair`
/// run already completed.
pub struct Paired {
    pub payload: QrPayload,
    pub agent_pin: PinnedPeer,
    pub paired: PairedPeer,
    pub console: SharedSink,
}

/// Run the agent's `pair` command on a thread and pair one controller against it.
pub fn pair_one_controller(
    layout: &DataLayout,
    port: u16,
    controller: &DeviceIdentity,
    controller_audit: &AuditLog,
) -> Paired {
    let console = SharedSink::default();
    let thread = {
        let layout = layout.clone();
        let mut console = console.clone();
        std::thread::spawn(move || {
            let mut host = Host::open(layout, "gate-host").expect("open host");
            let options = pair::PairOptions {
                lan_only: true,
                port,
                ttl: Duration::from_secs(30),
                // The test reads the payload back off the agent's own console
                // rather than constructing one, which is only possible because
                // it asked for it here.
                print_payload: true,
                ..pair::PairOptions::default()
            };
            pair::execute(&mut host, &options, &mut console).expect("pairing should succeed")
        })
    };

    let payload = scrape_payload(&console);
    let agent_pin = controller_pairs(controller, controller_audit, &payload);
    let paired = thread.join().expect("pairing thread");
    Paired {
        payload,
        agent_pin,
        paired,
        console,
    }
}
