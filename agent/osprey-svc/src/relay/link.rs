//! The agent's persistent WebSocket attachment to the relay.
//!
//! The relay is untrusted (brief §6.2), so nothing here interprets a payload:
//! frames carry opaque Noise ciphertext between two paired devices and this
//! module only decides *whether* to stay connected and *when* to come back.
//!
//! ## Liveness is entirely the agent's problem
//!
//! The relay has no server-side heartbeat, no idle reaping and no protocol
//! ping — a half-open socket after a network drop sits in its hub until TCP
//! eventually gives up. So the agent runs its own application-level
//! `{"t":"ping"}` and treats a missing `pong` as a dead link. Without that, a
//! phone on the other side would see an agent the relay still believes is
//! connected, and the P1 gate's "reconnects after a network drop without
//! intervention" would fail silently rather than loudly.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tungstenite::client::ClientRequestBuilder;
use tungstenite::http::Uri;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::{Message, WebSocket};
use uuid::Uuid;

use crate::relay::DeviceToken;

/// How often the agent proves the link is alive.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a `pong` may be outstanding before the link counts as dead.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Longest a socket read blocks before the loop checks its timers.
const READ_SLICE: Duration = Duration::from_millis(500);

/// The relay closes a superseded socket with this code when the same device
/// attaches again. Entirely benign — it is what a reconnect looks like from the
/// old socket's point of view.
const CLOSE_SUPERSEDED: u16 = 4000;
/// The device was revoked. Its token now fails authentication, so retrying is
/// pointless and would hammer the relay with doomed upgrades.
const CLOSE_REVOKED: u16 = 4001;
/// This device kind may not use this endpoint. A configuration error that
/// retrying cannot fix.
const CLOSE_WRONG_ENDPOINT: u16 = 4003;

/// What the agent sends. Mirrors the relay's `parseClientFrame`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "t")]
pub enum Outbound {
    /// Opaque ciphertext for a paired peer.
    #[serde(rename = "relay")]
    Relay { to: Uuid, payload: String },
    #[serde(rename = "ping")]
    Ping,
}

/// What the relay sends back.
///
/// `#[serde(other)]` is deliberate: a relay that learns a new frame type must
/// not be able to kill an older agent's link with it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "t")]
pub enum Inbound {
    #[serde(rename = "relay")]
    Relay { from: Uuid, payload: String },
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error { code: String, message: String },
    #[serde(other)]
    Unknown,
}

/// Why a link ended, and whether coming back makes sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disconnect {
    /// Retry after a backoff: a dropped network, a relay restart, or this
    /// socket being superseded by a newer one.
    Retryable(String),
    /// Do not retry. The credential or the configuration is wrong, and every
    /// attempt would cost the relay a full authentication scan to fail again.
    Terminal(String),
}

impl Disconnect {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Disconnect::Terminal(_))
    }

    fn reason(&self) -> &str {
        match self {
            Disconnect::Retryable(reason) | Disconnect::Terminal(reason) => reason,
        }
    }
}

impl std::fmt::Display for Disconnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

/// Classify a close code the relay sent.
pub fn classify_close(code: u16, reason: &str) -> Disconnect {
    match code {
        CLOSE_REVOKED => Disconnect::Terminal(format!(
            "this device was revoked at the relay ({reason}); it must be paired again"
        )),
        CLOSE_WRONG_ENDPOINT => Disconnect::Terminal(format!(
            "the relay refused this endpoint for an agent device ({reason})"
        )),
        CLOSE_SUPERSEDED => Disconnect::Retryable(
            "a newer socket for this device replaced this one".to_owned(),
        ),
        other => Disconnect::Retryable(format!("the relay closed the link with code {other}")),
    }
}

/// Exponential backoff with jitter, reset by a connection that stays up.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    /// Next delay, then advance.
    ///
    /// Jitter keeps a fleet of agents from retrying in lockstep after a relay
    /// restart. It is deliberately *not* drawn from a cryptographic source:
    /// nothing here is a secret, and pulling a CSPRNG into a retry timer would
    /// be a dependency for its own sake.
    pub fn next_delay(&mut self) -> Duration {
        let exponent = self.attempt.min(16);
        let scaled = self
            .base
            .saturating_mul(2u32.saturating_pow(exponent))
            .min(self.cap);
        self.attempt = self.attempt.saturating_add(1);

        // ±25%, derived from the clock's sub-second noise.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or(0);
        let spread = scaled.as_millis() as u64 / 2;
        let offset = if spread == 0 {
            0
        } else {
            u64::from(nanos) % spread
        };
        let millis = (scaled.as_millis() as u64)
            .saturating_sub(spread / 2)
            .saturating_add(offset);
        Duration::from_millis(millis.max(1))
    }

    /// Called once a link has proved itself, so the next outage starts fast
    /// again instead of inheriting the last one's delay.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Build the `WS`/`WSS` endpoint for the agent attach route from a relay base
/// URL, carrying the bearer token the upgrade must authenticate with.
pub fn agent_request(base_url: &str, token: &DeviceToken) -> Result<ClientRequestBuilder> {
    let trimmed = base_url.trim_end_matches('/');
    let ws = match trimmed.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("http", rest)) => format!("ws://{rest}"),
        Some((scheme @ ("ws" | "wss"), rest)) => format!("{scheme}://{rest}"),
        _ => {
            return Err(anyhow!(
                "relay url `{base_url}` must start with http://, https://, ws:// or wss://"
            ))
        }
    };
    let uri: Uri = format!("{ws}/v1/agent")
        .parse()
        .with_context(|| format!("relay url `{base_url}` is not a valid endpoint"))?;

    // The relay authenticates the HTTP upgrade itself; there is no query-string
    // or first-frame fallback, so a missing header is a 401 rather than a
    // closed socket.
    Ok(ClientRequestBuilder::new(uri)
        .with_header("Authorization", format!("Bearer {}", token.as_str())))
}

/// A live attachment.
pub struct RelayLink<S> {
    socket: WebSocket<S>,
    last_ping: Instant,
    awaiting_pong_since: Option<Instant>,
}

impl<S: std::io::Read + std::io::Write> RelayLink<S> {
    pub fn new(socket: WebSocket<S>) -> Self {
        Self {
            socket,
            last_ping: Instant::now(),
            awaiting_pong_since: None,
        }
    }

    pub fn send(&mut self, frame: &Outbound) -> Result<()> {
        let text = serde_json::to_string(frame).context("could not encode a relay frame")?;
        self.socket
            .send(Message::Text(text.into()))
            .context("could not write to the relay")
    }

    /// Read one frame if the relay sent one, and keep the keepalive running.
    ///
    /// `Ok(None)` means nothing arrived within the slice, which is the ordinary
    /// case on an idle link.
    pub fn poll(&mut self) -> std::result::Result<Option<Inbound>, Disconnect> {
        self.tick_keepalive()?;

        match self.socket.read() {
            Ok(Message::Text(text)) => match serde_json::from_str::<Inbound>(&text) {
                Ok(Inbound::Pong) => {
                    self.awaiting_pong_since = None;
                    Ok(Some(Inbound::Pong))
                }
                Ok(frame) => Ok(Some(frame)),
                // A malformed frame is the relay's problem, not a reason to
                // tear down a working link.
                Err(err) => {
                    tracing::warn!(error = %err, "ignoring an unparseable relay frame");
                    Ok(None)
                }
            },
            // Binary is not part of the relay's vocabulary; ignore rather than
            // disconnect, for the same reason as above.
            Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {
                Ok(None)
            }
            Ok(Message::Close(frame)) => Err(match frame {
                Some(frame) => classify_close(close_code(frame.code), frame.reason.as_ref()),
                None => Disconnect::Retryable("the relay closed the link".to_owned()),
            }),
            Err(tungstenite::Error::Io(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(Disconnect::Retryable(format!("relay link failed: {err}"))),
        }
    }

    /// Send a keepalive when due, and fail the link when one goes unanswered.
    fn tick_keepalive(&mut self) -> std::result::Result<(), Disconnect> {
        if let Some(since) = self.awaiting_pong_since {
            if since.elapsed() >= KEEPALIVE_TIMEOUT {
                return Err(Disconnect::Retryable(format!(
                    "the relay did not answer a keepalive within {} seconds",
                    KEEPALIVE_TIMEOUT.as_secs()
                )));
            }
        } else if self.last_ping.elapsed() >= KEEPALIVE_INTERVAL {
            self.send(&Outbound::Ping)
                .map_err(|err| Disconnect::Retryable(format!("could not send a keepalive: {err}")))?;
            self.last_ping = Instant::now();
            self.awaiting_pong_since = Some(Instant::now());
        }
        Ok(())
    }

    pub fn close(&mut self) {
        if let Err(err) = self.socket.close(None) {
            tracing::debug!(error = %err, "the relay link did not close cleanly");
        }
    }

    pub fn socket_mut(&mut self) -> &mut WebSocket<S> {
        &mut self.socket
    }
}

/// The numeric form of a close code, including the private-use range the relay
/// signals with.
fn close_code(code: CloseCode) -> u16 {
    u16::from(code)
}

/// The read deadline a relay socket needs so `poll` can return to its timers.
pub fn read_slice() -> Duration {
    READ_SLICE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_revoked_device_must_not_retry() {
        let outcome = classify_close(CLOSE_REVOKED, "revoked");
        assert!(
            outcome.is_terminal(),
            "retrying after revocation costs the relay an authentication scan per attempt \
             and can never succeed"
        );
    }

    #[test]
    fn a_superseded_socket_is_an_ordinary_reconnect() {
        assert!(!classify_close(CLOSE_SUPERSEDED, "superseded").is_terminal());
    }

    #[test]
    fn an_unrecognised_close_code_is_retryable() {
        // Failing closed here would mean a relay bug permanently disconnects
        // every agent, which is worse than a retry loop.
        assert!(!classify_close(1006, "abnormal").is_terminal());
        assert!(!classify_close(1001, "going away").is_terminal());
    }

    #[test]
    fn the_wrong_endpoint_is_a_configuration_error() {
        assert!(classify_close(CLOSE_WRONG_ENDPOINT, "wrong kind").is_terminal());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let first = backoff.next_delay();
        let second = backoff.next_delay();
        assert!(first < Duration::from_secs(2), "first retry must be prompt");
        assert!(second > first, "delays must grow: {first:?} then {second:?}");

        for _ in 0..40 {
            let delay = backoff.next_delay();
            assert!(
                delay <= Duration::from_secs(90),
                "delay {delay:?} exceeded the cap plus jitter"
            );
        }
    }

    #[test]
    fn a_healthy_link_resets_the_backoff() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..8 {
            let _ = backoff.next_delay();
        }
        assert!(backoff.attempts() > 0);
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert!(backoff.next_delay() < Duration::from_secs(2));
    }

    #[test]
    fn outbound_frames_match_the_relay_vocabulary() {
        let to = Uuid::from_u128(1);
        let relay = serde_json::to_string(&Outbound::Relay {
            to,
            payload: "AQID".to_owned(),
        })
        .expect("encode");
        assert!(relay.contains(r#""t":"relay""#), "{relay}");
        assert!(relay.contains(r#""payload":"AQID""#), "{relay}");

        let ping = serde_json::to_string(&Outbound::Ping).expect("encode");
        assert_eq!(ping, r#"{"t":"ping"}"#);
    }

    #[test]
    fn inbound_frames_decode_and_unknown_types_survive() {
        let relayed: Inbound =
            serde_json::from_str(r#"{"t":"relay","from":"00000000-0000-0000-0000-000000000001","payload":"AQID"}"#)
                .expect("decode relay");
        assert_eq!(
            relayed,
            Inbound::Relay {
                from: Uuid::from_u128(1),
                payload: "AQID".to_owned()
            }
        );

        assert_eq!(
            serde_json::from_str::<Inbound>(r#"{"t":"pong"}"#).expect("decode pong"),
            Inbound::Pong
        );

        let failure: Inbound =
            serde_json::from_str(r#"{"t":"error","code":"not_found","message":"Peer is not connected"}"#)
                .expect("decode error");
        assert!(matches!(failure, Inbound::Error { .. }));

        // A newer relay must not be able to kill an older agent's link.
        assert_eq!(
            serde_json::from_str::<Inbound>(r#"{"t":"something.new","x":1}"#).expect("decode"),
            Inbound::Unknown
        );
    }

    #[test]
    fn the_endpoint_upgrades_the_scheme_and_carries_the_token() {
        use tungstenite::client::IntoClientRequest;

        let token = DeviceToken::new("acct.secret".to_owned());
        for (base, expected) in [
            ("https://relay.example", "wss://relay.example/v1/agent"),
            ("https://relay.example/", "wss://relay.example/v1/agent"),
            ("http://127.0.0.1:8099", "ws://127.0.0.1:8099/v1/agent"),
            ("wss://relay.example", "wss://relay.example/v1/agent"),
        ] {
            let request = agent_request(base, &token)
                .expect("build request")
                .into_client_request()
                .expect("materialise request");
            assert_eq!(request.uri().to_string(), expected, "for {base}");

            // The relay authenticates the upgrade itself and offers no
            // query-string or first-frame fallback, so a missing header is a
            // 401 rather than anything the agent could recover from.
            let authorization = request
                .headers()
                .get("Authorization")
                .expect("the upgrade must carry a bearer token")
                .to_str()
                .expect("header is ascii");
            assert_eq!(authorization, "Bearer acct.secret");
        }
    }

    #[test]
    fn a_relay_url_without_a_scheme_is_refused() {
        let token = DeviceToken::new("acct.secret".to_owned());
        assert!(agent_request("relay.example", &token).is_err());
    }
}
