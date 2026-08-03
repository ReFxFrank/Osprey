//! Keeps the relay attachment up for as long as the agent is running.
//!
//! Owns exactly one concern: *being connected*. It does not interpret payloads
//! — the relay is untrusted and the frames are opaque ciphertext — and it never
//! gives up for a reason that a retry could fix, nor retries one that it
//! cannot.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tungstenite::stream::MaybeTlsStream;

use crate::relay::link::{self, Backoff, Disconnect, Inbound, RelayLink};
use crate::relay::DeviceToken;

/// First retry delay. Short, because the overwhelmingly common cause is a brief
/// network blip.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Ceiling on the retry delay.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// How long a link must survive before it counts as healthy.
///
/// Without this, a connection that is accepted and immediately dropped would
/// reset the backoff every time and turn a failing relay into a hot loop.
const HEALTHY_AFTER: Duration = Duration::from_secs(30);

/// How finely a backoff sleep is chopped so shutdown stays responsive.
const SHUTDOWN_SLICE: Duration = Duration::from_millis(250);

/// What the supervisor needs to attach.
#[derive(Debug, Clone)]
pub struct RelayTarget {
    pub base_url: String,
    pub token: DeviceToken,
}

/// Run the connect/serve/reconnect cycle until `running` goes false.
pub fn spawn(target: RelayTarget, running: Arc<AtomicBool>) -> Option<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("osprey-relay".to_owned())
        .spawn(move || supervise(&target, &running))
        .map_err(|err| tracing::error!(error = %err, "could not start the relay supervisor"))
        .ok()
}

fn supervise(target: &RelayTarget, running: &AtomicBool) {
    let mut backoff = Backoff::new(BACKOFF_BASE, BACKOFF_CAP);

    while running.load(Ordering::Relaxed) {
        match attach(target) {
            Ok(mut live) => {
                tracing::info!(relay = %target.base_url, "attached to the relay");
                let started = Instant::now();
                let outcome = pump(&mut live, running);
                live.close();

                // Only a link that lasted counts as proof the relay is well;
                // otherwise a flapping endpoint would keep resetting the delay.
                if started.elapsed() >= HEALTHY_AFTER {
                    backoff.reset();
                }
                match outcome {
                    Some(Disconnect::Terminal(reason)) => {
                        tracing::error!(
                            reason = %reason,
                            "the relay link ended permanently; not retrying"
                        );
                        return;
                    }
                    Some(Disconnect::Retryable(reason)) => {
                        tracing::warn!(reason = %reason, "the relay link dropped");
                    }
                    // Shutdown, not a failure.
                    None => return,
                }
            }
            Err(err) => {
                tracing::warn!(
                    relay = %target.base_url,
                    error = %err,
                    attempt = backoff.attempts() + 1,
                    "could not attach to the relay"
                );
            }
        }

        if !sleep_unless_stopping(backoff.next_delay(), running) {
            return;
        }
    }
}

/// Open the socket and bound its reads so the pump can return to its timers.
fn attach(target: &RelayTarget) -> anyhow::Result<RelayLink<MaybeTlsStream<std::net::TcpStream>>> {
    let request = link::agent_request(&target.base_url, &target.token)?;
    let (socket, _response) = tungstenite::connect(request)?;
    let mut live = RelayLink::new(socket);

    // A blocking read with no deadline would park this thread forever on a
    // half-open socket — which is exactly the state a network drop leaves
    // behind, and exactly what the keepalive exists to detect.
    match live.socket_mut().get_mut() {
        MaybeTlsStream::Plain(stream) => stream.set_read_timeout(Some(link::read_slice()))?,
        MaybeTlsStream::NativeTls(stream) => {
            stream.get_ref().set_read_timeout(Some(link::read_slice()))?
        }
        // The enum is non-exhaustive; an unknown transport still works, it just
        // cannot have its deadline set here.
        _ => tracing::warn!("relay transport does not support a read deadline"),
    }
    Ok(live)
}

/// Read frames until the link ends. `None` means the agent is shutting down.
fn pump<S: std::io::Read + std::io::Write>(
    live: &mut RelayLink<S>,
    running: &AtomicBool,
) -> Option<Disconnect> {
    while running.load(Ordering::Relaxed) {
        match live.poll() {
            Ok(Some(Inbound::Relay { from, payload })) => {
                // Sessions over the relay are the next increment; until then a
                // frame is acknowledged in the log rather than silently
                // dropped, so a phone that reaches the agent this way leaves a
                // trace instead of appearing to be ignored.
                tracing::info!(
                    peer = %from,
                    bytes = payload.len(),
                    "received a relayed frame; relay-borne sessions are not served yet"
                );
            }
            Ok(Some(Inbound::Error { code, message })) => {
                tracing::warn!(code = %code, message = %message, "the relay refused a frame");
            }
            Ok(Some(Inbound::Pong) | Some(Inbound::Unknown) | None) => {}
            Err(disconnect) => return Some(disconnect),
        }
    }
    None
}

/// Sleep in slices, returning false if the agent is stopping.
fn sleep_unless_stopping(total: Duration, running: &AtomicBool) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if !running.load(Ordering::Relaxed) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(SHUTDOWN_SLICE));
    }
    running.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopping_agent_does_not_wait_out_the_backoff() {
        let running = AtomicBool::new(false);
        let started = Instant::now();
        assert!(!sleep_unless_stopping(Duration::from_secs(30), &running));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown waited {:?} on a backoff it should have abandoned",
            started.elapsed()
        );
    }

    #[test]
    fn a_running_agent_waits_the_whole_delay() {
        let running = AtomicBool::new(true);
        let started = Instant::now();
        assert!(sleep_unless_stopping(Duration::from_millis(400), &running));
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "returned after only {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_unreachable_relay_is_retried_rather_than_fatal() {
        // Port 1 on loopback refuses immediately, which is the connect-failure
        // path: the supervisor must keep trying rather than exit.
        let target = RelayTarget {
            base_url: "http://127.0.0.1:1".to_owned(),
            token: DeviceToken::new("acct.secret"),
        };
        assert!(attach(&target).is_err());

        let running = Arc::new(AtomicBool::new(true));
        let handle = spawn(target, Arc::clone(&running)).expect("spawn");
        std::thread::sleep(Duration::from_millis(300));
        // Still alive and retrying rather than having given up.
        assert!(!handle.is_finished(), "the supervisor abandoned a retryable failure");
        running.store(false, Ordering::Relaxed);
        handle.join().expect("join");
    }
}
