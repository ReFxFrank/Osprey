//! Steady-state protocol handling on an established Noise session.
//!
//! P0 answers exactly two things: `hello` and `ping`. Everything else in the
//! registry is reserved but unimplemented, and says so on the wire with an
//! `unsupported` error rather than being quietly ignored — an ignored request
//! is indistinguishable from a hung host, and the client cannot tell which.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use osprey_core::noise::NoiseSession;
use osprey_proto::{
    Body, ByeBody, Capability, Envelope, ErrorBody, ErrorCode, HelloBody, HelloOkBody, MessageType,
    PongBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use uuid::Uuid;

/// Management-plane messages are small; file chunks arrive at P3 with their own
/// bound. Capping reassembly here means a peer cannot make the agent buffer
/// megabytes before a single field has been validated.
pub const MAX_SESSION_MESSAGE_LEN: usize = 64 * 1024;

/// What the agent reports about itself in `hello.ok`.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub device_id: Uuid,
    pub software_version: String,
}

/// How a served session ended. Both variants are ordinary outcomes; a dropped
/// socket (including one dropped by an unpair) surfaces as an `Err` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// Peer sent `bye`.
    PeerSaidBye,
    /// Peer closed the transport on a message boundary.
    PeerClosed,
}

/// Summary of a completed session, for the caller's log line.
#[derive(Debug, Clone)]
pub struct SessionReport {
    pub end: SessionEnd,
    pub peer_device_id: Uuid,
    pub pings_answered: u64,
}

pub fn now_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_millis()).unwrap_or(i64::MAX),
        // Before 1970 the value is advisory metadata only (the protocol never
        // authenticates on it), so a nonsensical clock yields 0 rather than
        // failing an otherwise valid session.
        Err(_) => 0,
    }
}

fn send<W: Write>(session: &mut NoiseSession, stream: &mut W, id: Uuid, body: &Body) -> Result<()> {
    let envelope = Envelope::new(id, now_ms(), body).context("could not build an envelope")?;
    let bytes = serde_json::to_vec(&envelope).context("could not encode an envelope")?;
    session
        .send(&bytes, stream)
        .context("could not write to the noise session")
}

fn send_error<W: Write>(
    session: &mut NoiseSession,
    stream: &mut W,
    id: Uuid,
    code: ErrorCode,
    message: &str,
    retryable: bool,
) -> Result<()> {
    let body = Body::Error(ErrorBody {
        code,
        message: message.to_owned(),
        retryable,
    });
    send(session, stream, id, &body)
}

/// Receive and parse one envelope. `Ok(None)` is a clean close.
///
/// A body that does not parse is *not* an error here: the envelope's own id and
/// type are still usable, and the caller needs them to answer with a correlated
/// `error` instead of dropping the connection.
fn recv_envelope<S: Read>(session: &mut NoiseSession, stream: &mut S) -> Result<Option<Envelope>> {
    let Some(bytes) = session
        .recv(stream)
        .context("could not read from the noise session")?
    else {
        return Ok(None);
    };
    let envelope: Envelope =
        serde_json::from_slice(&bytes).context("peer sent a malformed envelope")?;
    Ok(Some(envelope))
}

/// The capability set this build implements.
///
/// Empty, and deliberately so: `Capability` is synthesised from the message
/// groups, P0 implements none of them, and advertising one the agent cannot
/// serve would be exactly the plausible-looking fiction CLAUDE.md rule 9
/// forbids. Later phases add entries here as they land.
pub fn capabilities() -> Vec<Capability> {
    Vec::new()
}

/// Run the agent's half of a session to completion.
pub fn serve<S: Read + Write>(
    session: &mut NoiseSession,
    stream: &mut S,
    config: &SessionConfig,
) -> Result<SessionReport> {
    session.set_max_message_len(MAX_SESSION_MESSAGE_LEN);
    let (peer_device_id, hello_id) = read_hello(session, stream)?;

    let session_id = Uuid::new_v4();
    send(
        session,
        stream,
        hello_id,
        &Body::HelloOk(HelloOkBody {
            protocol_version: PROTOCOL_VERSION,
            capabilities: capabilities(),
            device_id: config.device_id,
            software_version: config.software_version.clone(),
            session_id,
        }),
    )?;

    let mut pings_answered = 0u64;
    loop {
        let Some(envelope) = recv_envelope(session, stream)? else {
            return Ok(SessionReport {
                end: SessionEnd::PeerClosed,
                peer_device_id,
                pings_answered,
            });
        };
        match dispatch(session, stream, &envelope, &mut pings_answered)? {
            Some(end) => {
                return Ok(SessionReport {
                    end,
                    peer_device_id,
                    pings_answered,
                })
            }
            None => continue,
        }
    }
}

/// Handle one envelope. `Ok(Some(_))` ends the session.
fn dispatch<S: Read + Write>(
    session: &mut NoiseSession,
    stream: &mut S,
    envelope: &Envelope,
    pings_answered: &mut u64,
) -> Result<Option<SessionEnd>> {
    if let Err(err) = envelope.check_version() {
        send_error(
            session,
            stream,
            envelope.id,
            ErrorCode::VersionMismatch,
            &err.to_string(),
            false,
        )?;
        return Ok(None);
    }

    match envelope.t {
        MessageType::Ping => {
            let body = match envelope.decode_body() {
                Ok(Body::Ping(ping)) => ping,
                Ok(_) | Err(_) => {
                    send_error(
                        session,
                        stream,
                        envelope.id,
                        ErrorCode::BadRequest,
                        "ping body did not match the schema",
                        false,
                    )?;
                    return Ok(None);
                }
            };
            send(
                session,
                stream,
                envelope.id,
                &Body::Pong(PongBody {
                    seq: body.seq,
                    echo_ts: envelope.ts,
                }),
            )?;
            *pings_answered += 1;
            Ok(None)
        }
        MessageType::Bye => {
            // A `bye` whose body is unparseable still ends the session: the peer
            // has said it is leaving, and arguing about the reason field would
            // leave a socket open that nobody is going to use.
            if let Ok(Body::Bye(ByeBody { reason, detail })) = envelope.decode_body() {
                tracing::info!(reason = %reason, detail = ?detail, "peer ended the session");
            }
            Ok(Some(SessionEnd::PeerSaidBye))
        }
        other => {
            send_error(
                session,
                stream,
                envelope.id,
                ErrorCode::Unsupported,
                &format!("`{other}` is reserved but not implemented in this build"),
                false,
            )?;
            Ok(None)
        }
    }
}

/// Read the opening `hello` and negotiate the envelope version.
///
/// Returns the peer's device id and the correlation id `hello.ok` must carry.
fn read_hello<S: Read + Write>(session: &mut NoiseSession, stream: &mut S) -> Result<(Uuid, Uuid)> {
    let envelope =
        recv_envelope(session, stream)?.context("peer closed the session before sending hello")?;
    if envelope.t != MessageType::Hello {
        send_error(
            session,
            stream,
            envelope.id,
            ErrorCode::BadRequest,
            "the first message on a session must be `hello`",
            false,
        )?;
        anyhow::bail!("peer opened with `{}` instead of `hello`", envelope.t);
    }
    let hello: HelloBody = match envelope.decode_body() {
        Ok(Body::Hello(hello)) => hello,
        Ok(_) | Err(_) => {
            send_error(
                session,
                stream,
                envelope.id,
                ErrorCode::BadRequest,
                "hello body did not match the schema",
                false,
            )?;
            anyhow::bail!("peer sent a malformed hello");
        }
    };

    // Overlap test on the two declared ranges, not on the envelope's own `v`:
    // the peer may speak a version it did not use for this first message.
    let ceiling = PROTOCOL_VERSION.min(hello.protocol_version);
    let floor = MIN_PROTOCOL_VERSION.max(hello.min_protocol_version);
    if floor > ceiling {
        send_error(
            session,
            stream,
            envelope.id,
            ErrorCode::VersionMismatch,
            &format!(
                "peer speaks {}..={}, this build speaks {MIN_PROTOCOL_VERSION}..={PROTOCOL_VERSION}",
                hello.min_protocol_version, hello.protocol_version
            ),
            false,
        )?;
        anyhow::bail!("no common protocol version with the peer");
    }
    Ok((hello.device_id, envelope.id))
}
