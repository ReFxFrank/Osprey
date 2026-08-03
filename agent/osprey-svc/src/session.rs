//! Steady-state protocol handling on an established Noise session.
//!
//! P0 answers `hello`, `ping` and `pair.revoke` — the last because a client-side
//! unpair is a Gate P0 criterion and the agent is the only party that can act on
//! one. Everything else in the registry is reserved but unimplemented, and says
//! so on the wire with an `unsupported` error rather than being quietly ignored
//! — an ignored request is indistinguishable from a hung host, and the client
//! cannot tell which.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use osprey_core::identity::PinnedPeer;
use osprey_core::noise::NoiseSession;
use osprey_proto::{
    Body, ByeBody, ByeReason, Capability, Envelope, ErrorBody, ErrorCode, HelloBody, HelloOkBody,
    MessageType, PongBody, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use uuid::Uuid;

use crate::metrics::{wire, MetricsEngine, Subscription};
use crate::pacing::WaitReadable;
use crate::revoke::RevocationHandler;

/// How long the loop blocks waiting for the peer before it looks for metrics to
/// push. Short enough that a 1 Hz stream is not visibly jittered by it.
const TICK_SLICE: Duration = Duration::from_millis(200);

/// The same wait with nobody subscribed. Nothing needs pushing, so the loop
/// only has to wake often enough to notice the idle deadline.
const QUIET_SLICE: Duration = Duration::from_secs(5);

/// A session with no inbound traffic and no live stream for this long is hung
/// up on. `run` also sets this as the socket's read deadline, which bounds a
/// peer that goes silent *mid-message*; this bound covers the ordinary case of
/// a peer that simply stops talking.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a single write may block before the session is abandoned.
///
/// Generous enough to survive a phone on a congested cell, short enough that a
/// peer which has stopped reading cannot pin a thread indefinitely. Pushed
/// ticks make that case reachable without the peer sending anything.
pub const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Management-plane messages are small; file chunks arrive at P3 with their own
/// bound. Capping reassembly here means a peer cannot make the agent buffer
/// megabytes before a single field has been validated.
pub const MAX_SESSION_MESSAGE_LEN: usize = 64 * 1024;

/// What the agent reports about itself in `hello.ok`.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub device_id: Uuid,
    pub software_version: String,
    /// Machine name for the client's device list (amendment A23). `None` when
    /// the platform offers nothing — the field is optional on the wire and the
    /// client falls back to its own label.
    pub display_name: Option<String>,
}

/// The interactive machine name, or `None` if the platform does not say.
///
/// `COMPUTERNAME` is set by Windows itself for every process; `HOSTNAME` is a
/// shell convention and often absent, which is fine — this is display-only.
pub fn machine_display_name() -> Option<String> {
    let var = if cfg!(windows) { "COMPUTERNAME" } else { "HOSTNAME" };
    std::env::var(var).ok().filter(|name| !name.is_empty())
}

/// How a served session ended. Every variant is an ordinary outcome; a dropped
/// socket (including one dropped by a local unpair) surfaces as an `Err`
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// Peer sent `bye`.
    PeerSaidBye,
    /// Peer closed the transport on a message boundary.
    PeerClosed,
    /// Peer sent a valid `pair.revoke`; its pin is gone and so is the session.
    Revoked,
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
/// An entry appears here only once the agent can actually serve every message
/// in that group — advertising one it cannot is exactly the plausible-looking
/// fiction CLAUDE.md rule 9 forbids. `Metrics` earned its place in P1 with
/// `metrics.subscribe`, `metrics.tick` and `metrics.history` all implemented.
pub fn capabilities() -> Vec<Capability> {
    vec![Capability::Metrics]
}

/// Run the agent's half of a session to completion.
///
/// `peer` is the pin this session handshook against; it is the identity key a
/// `pair.revoke` must verify under, and it must come from the host's own store
/// rather than from anything the peer says.
pub fn serve<S: Read + Write + WaitReadable>(
    session: &mut NoiseSession,
    stream: &mut S,
    config: &SessionConfig,
    peer: &PinnedPeer,
    revocation: &RevocationHandler<'_>,
    metrics: &MetricsEngine,
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
            display_name: config.display_name.clone(),
        }),
    )?;

    let mut runtime = Runtime {
        pings_answered: 0,
        stream: None,
        metrics,
    };
    let mut last_activity = Instant::now();

    loop {
        // Ticks first: a sample that arrived while the loop was blocked should
        // reach the controller before the loop blocks again.
        if runtime.push_ticks(session, stream)? {
            last_activity = Instant::now();
        }

        let slice = if runtime.stream.is_some() {
            TICK_SLICE
        } else {
            QUIET_SLICE
        };
        if !stream
            .wait_readable(slice)
            .context("could not wait on the session transport")?
        {
            if last_activity.elapsed() >= SESSION_IDLE_TIMEOUT {
                anyhow::bail!(
                    "no traffic for {} seconds",
                    SESSION_IDLE_TIMEOUT.as_secs()
                );
            }
            continue;
        }

        let Some(envelope) = recv_envelope(session, stream)? else {
            return Ok(SessionReport {
                end: SessionEnd::PeerClosed,
                peer_device_id,
                pings_answered: runtime.pings_answered,
            });
        };
        last_activity = Instant::now();

        let context = DispatchContext {
            peer,
            peer_device_id,
            revocation,
        };
        if let Some(end) = dispatch(session, stream, &envelope, &context, &mut runtime)? {
            return Ok(SessionReport {
                end,
                peer_device_id,
                pings_answered: runtime.pings_answered,
            });
        }
    }
}

/// Per-session mutable state that outlives one dispatched message.
struct Runtime<'a> {
    pings_answered: u64,
    /// The controller's live metrics stream, if it asked for one.
    stream: Option<ActiveStream>,
    metrics: &'a MetricsEngine,
}

/// A `metrics.subscribe` that asked to keep streaming.
struct ActiveStream {
    /// Envelope id of the subscribe, echoed as `sub` on every pushed tick so
    /// the client can ignore ticks from a subscription it has replaced.
    sub_id: Uuid,
    subscription: Subscription,
}

impl Runtime<'_> {
    /// Send every queued sample. Returns whether anything was sent.
    ///
    /// A successful push counts as session activity: a controller watching a
    /// dashboard sends nothing for minutes at a time, and a write that the peer
    /// is no longer reading fails on its own rather than needing a timer to
    /// notice.
    fn push_ticks<S: Read + Write>(
        &mut self,
        session: &mut NoiseSession,
        stream: &mut S,
    ) -> Result<bool> {
        let Some(active) = &self.stream else {
            return Ok(false);
        };
        let samples = active.subscription.drain();
        if samples.is_empty() {
            return Ok(false);
        }
        let sub_id = active.sub_id;
        for sample in &samples {
            let body = Body::MetricsTick(wire::tick_body(sub_id, sample));
            // A pushed tick is uncorrelated: it carries its own envelope id and
            // identifies its stream through `sub`, per the brief's stream model.
            send(session, stream, Uuid::new_v4(), &body)?;
        }
        Ok(true)
    }
}

/// Who this session belongs to, as the host knows it rather than as the peer
/// claims it.
struct DispatchContext<'a> {
    peer: &'a PinnedPeer,
    peer_device_id: Uuid,
    revocation: &'a RevocationHandler<'a>,
}

/// Handle one envelope. `Ok(Some(_))` ends the session.
fn dispatch<S: Read + Write>(
    session: &mut NoiseSession,
    stream: &mut S,
    envelope: &Envelope,
    context: &DispatchContext<'_>,
    runtime: &mut Runtime<'_>,
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
            runtime.pings_answered += 1;
            Ok(None)
        }
        MessageType::MetricsSubscribe => {
            let body = match envelope.decode_body() {
                Ok(Body::MetricsSubscribe(body)) => body,
                Ok(_) | Err(_) => {
                    send_error(
                        session,
                        stream,
                        envelope.id,
                        ErrorCode::BadRequest,
                        "metrics.subscribe body did not match the schema",
                        false,
                    )?;
                    return Ok(None);
                }
            };
            handle_metrics_subscribe(session, stream, envelope.id, &body, runtime)?;
            Ok(None)
        }
        MessageType::PairRevoke => {
            let body = match envelope.decode_body() {
                Ok(Body::PairRevoke(body)) => body,
                Ok(_) | Err(_) => {
                    send_error(
                        session,
                        stream,
                        envelope.id,
                        ErrorCode::BadRequest,
                        "pair.revoke body did not match the schema",
                        false,
                    )?;
                    return Ok(None);
                }
            };
            handle_revoke(session, stream, envelope.id, &body, context)
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

/// Answer a `metrics.subscribe`: backfill now, then stream if asked.
///
/// The correlated answer is a `metrics.history` body — the subscribe *is* the
/// history request, which is what keeps the metrics group at the three message
/// types the registry reserved for it. `stream = false` therefore doubles as
/// both a one-shot query and the unsubscribe.
fn handle_metrics_subscribe<S: Read + Write>(
    session: &mut NoiseSession,
    stream: &mut S,
    id: Uuid,
    body: &osprey_proto::MetricsSubscribeBody,
    runtime: &mut Runtime<'_>,
) -> Result<()> {
    let history = runtime.metrics.history(body.backfill_seconds);
    // Passed through as an Option: nothing has been sampled yet on a service
    // that just started, and the wire says "unknown" rather than "0 bytes".
    let installed = runtime.metrics.latest_total_memory();
    send(
        session,
        stream,
        id,
        &Body::MetricsHistory(wire::history_body(id, history.as_ref(), installed)),
    )?;

    if body.stream {
        // Replacing rather than adding: one stream per session, so a client
        // that re-subscribes cannot silently accumulate feeds it will then see
        // as duplicate ticks.
        runtime.stream = Some(ActiveStream {
            sub_id: id,
            subscription: runtime.metrics.subscribe(),
        });
        tracing::debug!(%id, "metrics stream opened");
    } else if runtime.stream.take().is_some() {
        tracing::debug!(%id, "metrics stream closed at the peer's request");
    }
    Ok(())
}

/// Apply a `pair.revoke`, or tell the peer why it was refused.
///
/// A refusal leaves the session running: a forged or replayed revocation is
/// exactly the case where dropping the connection would let an on-path attacker
/// turn one bad message into a denial of service against a peer that is still
/// legitimately paired.
fn handle_revoke<S: Read + Write>(
    session: &mut NoiseSession,
    stream: &mut S,
    id: Uuid,
    body: &osprey_proto::PairRevokeBody,
    context: &DispatchContext<'_>,
) -> Result<Option<SessionEnd>> {
    let applied = match context
        .revocation
        .apply(body, context.peer, context.peer_device_id)
    {
        Ok(applied) => applied,
        Err(refusal) => {
            tracing::warn!(
                fingerprint = %context.peer.fingerprint().short(),
                refusal = %refusal,
                "refused a pair.revoke"
            );
            send_error(
                session,
                stream,
                id,
                refusal.code(),
                &refusal.wire_message(),
                false,
            )?;
            return Ok(None);
        }
    };

    if let Some(err) = &applied.audit_error {
        tracing::error!(
            error = %err,
            fingerprint = %applied.fingerprint.short(),
            "unpaired on a peer's signed request, but the audit entry could not be written"
        );
    }
    tracing::warn!(
        fingerprint = %applied.fingerprint.short(),
        "peer revoked its pairing; pin removed"
    );

    // The pin is already gone, so this `bye` is a courtesy that tells the peer
    // its revocation landed. It is sent before any socket is shut down, and a
    // failure to send it cannot un-revoke anything.
    if let Err(err) = send(
        session,
        stream,
        id,
        &Body::Bye(ByeBody {
            reason: ByeReason::Unpaired,
            detail: Some("pair.revoke accepted; this device is no longer paired".to_owned()),
        }),
    ) {
        tracing::warn!(error = %err, "could not acknowledge a pair.revoke before hanging up");
    }

    let closed = context.revocation.close_peer_sessions(context.peer);
    if closed > 0 {
        tracing::info!(closed, "closed live sessions for the revoked peer");
    }
    Ok(Some(SessionEnd::Revoked))
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
