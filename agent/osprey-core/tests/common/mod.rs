//! Shared fixtures for the trust-spine integration tests.
//!
//! Each integration test is its own crate and uses a different subset of these
//! helpers, so unused-item warnings here are an artefact of the test harness
//! rather than real dead code.
#![allow(dead_code)]

use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};

use osprey_core::audit::AuditLog;
use osprey_core::identity::DeviceIdentity;
use osprey_core::pairing::{PairingOffer, PairingSecret, QrPayload};

/// A connected loopback pair. Loopback completes the TCP handshake into the
/// backlog, so no accept thread is needed to establish the pair itself.
pub fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nodelay(true).expect("nodelay client");
    server.set_nodelay(true).expect("nodelay server");
    (client, server)
}

/// A stream whose reads come from a fixed script and whose writes are captured.
/// Lets a peer be driven deterministically without threads.
pub struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    pub written: Vec<u8>,
}

impl ScriptedStream {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            written: Vec::new(),
        }
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Fixture {
    pub agent: DeviceIdentity,
    pub phone: DeviceIdentity,
    pub offer: PairingOffer,
    pub qr: QrPayload,
    pub agent_audit: AuditLog,
    pub phone_audit: AuditLog,
    _dir: tempfile::TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_secret(PairingSecret::generate())
    }

    /// Build a fixture where the QR carries `qr_secret` but the host is waiting
    /// on `host_secret`, so the two PSKs can be made to disagree.
    pub fn with_split_secret(host_secret: PairingSecret, qr_secret: PairingSecret) -> Self {
        let mut fixture = Self::with_secret(qr_secret);
        fixture.offer = PairingOffer::new(host_secret, osprey_core::pairing::DEFAULT_PAIRING_TTL);
        fixture
    }

    fn with_secret(secret: PairingSecret) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate();
        let qr = QrPayload::new(
            "https://relay.invalid",
            "acct-test",
            "dev-test",
            agent.public().clone(),
            vec!["127.0.0.1:47010".parse().expect("addr")],
            secret.clone(),
        );
        Self {
            agent,
            phone,
            offer: PairingOffer::new(secret, osprey_core::pairing::DEFAULT_PAIRING_TTL),
            qr,
            agent_audit: AuditLog::open(dir.path().join("agent")).expect("agent audit"),
            phone_audit: AuditLog::open(dir.path().join("phone")).expect("phone audit"),
            _dir: dir,
        }
    }
}

/// Every line currently in an audit log.
pub fn audit_lines(log: &AuditLog) -> Vec<String> {
    match std::fs::read_to_string(log.current_file()) {
        Ok(body) => body.lines().map(str::to_string).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("reading audit log: {e}"),
    }
}
