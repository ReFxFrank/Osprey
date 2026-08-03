//! `osprey-svc run` — serve steady-state sessions to already-pinned controllers.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use osprey_core::channel;
use osprey_core::identity::{DeviceIdentity, PinnedPeer};

use crate::discovery::Advertisement;
use crate::host::Host;
use crate::lan::{LanListener, DEFAULT_LAN_PORT};
use crate::metrics::MetricsEngine;
use crate::registry::{spawn_revocation_watcher, SessionRegistry, REVOCATION_POLL_INTERVAL};
use crate::relay::supervisor;
use crate::revoke::RevocationHandler;
use crate::session::{self, SessionConfig, SESSION_IDLE_TIMEOUT, SESSION_WRITE_TIMEOUT};
use crate::state::HostState;

/// How long the accept loop blocks before re-checking the shutdown flag.
const ACCEPT_SLICE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub port: u16,
    /// Publish `_osprey._tcp` on the LAN while listening (amendment A6).
    ///
    /// Defaults to **off** here and to **on** in the CLI, on purpose. Every
    /// in-process caller of this function is a test that runs both peers over
    /// loopback, and none of them should open a multicast socket or put a
    /// record on whatever network the machine running CI happens to be on.
    pub advertise_mdns: bool,

    /// Refuse to start when nothing is paired.
    ///
    /// True from the console, where an operator who typed `run` before pairing
    /// wants to be told so. False for the service, which is installed *before*
    /// anyone pairs and must sit and listen until they do — an agent with no
    /// pins is useless rather than unsafe, because `channel::accept` refuses
    /// every peer that is not pinned.
    pub require_paired_controller: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_LAN_PORT,
            advertise_mdns: false,
            require_paired_controller: true,
        }
    }
}

/// Accept sessions until `running` goes false.
///
/// Blocks. `running` is the only way out; the caller sets it from a signal
/// handler (P0) or from the service control handler (P1).
pub fn execute(
    host: &Host,
    options: &RunOptions,
    running: Arc<AtomicBool>,
    out: &mut dyn Write,
) -> Result<()> {
    if host.state.peers().is_empty() {
        if options.require_paired_controller {
            bail!("no controller is paired; run `osprey-svc pair` at this machine first");
        }
        tracing::warn!(
            "no controller is paired yet; listening anyway and refusing every connection until one is"
        );
    }
    let listener = LanListener::bind(options.port)?;
    // Held for the whole accept loop; dropping it deregisters the record, which
    // is why the binding is named rather than discarded.
    let _advertisement = Advertisement::publish(
        options.advertise_mdns,
        host.state.device_id(),
        listener.addresses(),
    );
    // Started before the accept loop so the ring is already filling when the
    // first controller connects and asks for history.
    let metrics = MetricsEngine::start();

    // An agent that has never enrolled is LAN-only by design (amendment A6),
    // so no relay is not a failure — it is the pairing mode the P0 gate used.
    let relay_status = Arc::new(supervisor::RelayStatus::default());
    let relay_supervisor = match relay_target(host) {
        Some(target) => supervisor::spawn(target, Arc::clone(&running), Arc::clone(&relay_status)),
        None => {
            tracing::info!("no relay enrolment; serving the local network only");
            None
        }
    };
    let registry = SessionRegistry::new();
    let watcher = spawn_revocation_watcher(
        host.layout.state.clone(),
        Arc::clone(&registry),
        Arc::clone(&running),
    );

    writeln!(out, "Osprey agent listening for paired controllers on:")?;
    for addr in listener.addresses() {
        writeln!(out, "  {addr}")?;
    }
    writeln!(out, "{} controller(s) pinned.", host.state.peers().len())?;
    out.flush().context("could not write the startup banner")?;

    let config = SessionConfig {
        device_id: host.state.device_id(),
        software_version: env!("CARGO_PKG_VERSION").to_owned(),
        display_name: crate::session::machine_display_name(),
    };
    let revocation = RevocationHandler::new(
        &host.layout.state,
        &host.audit,
        &registry,
        host.state.device_id(),
        host.pairing_context(),
    );

    // Scoped threads so each session can borrow the identity and the registry
    // without an `Arc` per connection, and so the scope's join is the single
    // place shutdown waits for sessions to finish.
    let result = std::thread::scope(|scope| -> Result<()> {
        while running.load(Ordering::Relaxed) {
            let Some((stream, peer_addr)) = listener.accept_timeout(ACCEPT_SLICE)? else {
                continue;
            };
            // Re-read from disk rather than trusting the snapshot taken at
            // startup: a `pair` run in another console has pinned a peer this
            // process has never seen, and an `unpair` has removed one.
            let pins = match HostState::read_peers(&host.layout.state) {
                Ok(peers) => peers.into_iter().map(|p| p.pinned).collect::<Vec<_>>(),
                Err(err) => {
                    tracing::error!(error = %err, "refusing a connection: pin store unreadable");
                    continue;
                }
            };
            let identity = &host.identity;
            let state_path = &host.layout.state;
            let revocation = &revocation;
            let registry = Arc::clone(&registry);
            let config = config.clone();
            let metrics = &metrics;
            scope.spawn(move || {
                let session = Session {
                    identity,
                    pins: &pins,
                    registry: &registry,
                    state_path,
                    config: &config,
                    revocation,
                    metrics,
                };
                if let Err(err) = serve_one(&session, stream, peer_addr) {
                    tracing::warn!(%peer_addr, error = %err, "session ended with an error");
                }
            });
        }
        // Inside the scope, not after it: the scope's implicit join waits for
        // every session thread, and a session thread is blocked in `recv` until
        // its socket is shut down. Revoking after the scope would make shutdown
        // take up to SESSION_IDLE_TIMEOUT (measured: a 300-second Ctrl-C).
        let closed = registry.revoke_all();
        if closed > 0 {
            tracing::info!(closed, "closing live sessions for shutdown");
        }
        Ok(())
    });

    running.store(false, Ordering::Relaxed);
    if let Err(err) = watcher.join() {
        tracing::error!(?err, "the revocation watcher thread did not exit cleanly");
    }
    if let Some(handle) = relay_supervisor {
        if handle.join().is_err() {
            tracing::error!("the relay supervisor thread panicked");
        }
    }
    result
}

/// Where this agent should attach, if it has enrolled at all.
///
/// A missing token with a recorded enrolment is a real inconsistency — the
/// keystore and `state.json` have diverged — so it is reported rather than
/// quietly treated as "LAN only".
fn relay_target(host: &Host) -> Option<supervisor::RelayTarget> {
    let enrolment = host.state.relay()?;
    match host.relay_token() {
        Ok(Some(token)) => Some(supervisor::RelayTarget {
            base_url: enrolment.base_url.clone(),
            token,
        }),
        Ok(None) => {
            tracing::error!(
                relay = %enrolment.base_url,
                "this agent is enrolled with a relay but its sealed token is missing; \
                 re-run `osprey-svc pair` to enrol again"
            );
            None
        }
        Err(err) => {
            tracing::error!(error = %err, "could not read the sealed relay token");
            None
        }
    }
}

/// What one session thread borrows from `execute` for its whole life.
struct Session<'a> {
    identity: &'a DeviceIdentity,
    /// The pin list as it stood when the socket was accepted.
    pins: &'a [PinnedPeer],
    registry: &'a Arc<SessionRegistry>,
    state_path: &'a Path,
    config: &'a SessionConfig,
    revocation: &'a RevocationHandler<'a>,
    /// Shared by every session: the counters are whole-machine values, so one
    /// sampler serves all of them.
    metrics: &'a MetricsEngine,
}

fn serve_one(session: &Session<'_>, mut stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    stream
        .set_read_timeout(Some(SESSION_IDLE_TIMEOUT))
        .context("could not set a session read timeout")?;
    // Without this a peer that stops reading parks the session thread inside
    // `write_all` forever: the loop never returns to `wait_readable`, so the
    // idle deadline cannot fire either, and the thread is unreclaimable until
    // the process exits. Pushed metrics ticks make that reachable without the
    // peer having to send anything at all.
    stream
        .set_write_timeout(Some(SESSION_WRITE_TIMEOUT))
        .context("could not set a session write timeout")?;

    // `accept` refuses any peer whose static is not pinned. That check is the
    // unpair enforcement point: nothing about it involves the relay, so a
    // revoked controller is refused even on a LAN the relay cannot see.
    let (peer, mut noise) = channel::accept(&mut stream, session.identity, session.pins)
        .with_context(|| format!("refused a session from {peer_addr}"))?;
    let fingerprint = peer.fingerprint();

    // Registered before the pin is re-checked, not after. `pins` was read before
    // the handshake, and a handshake takes milliseconds — long enough for an
    // `unpair` in another process to have completed against a list this thread
    // is still holding. Registering first means the revocation watcher can
    // already see this socket, so the re-read below and the watcher between them
    // leave no interval in which a revoked peer is both admitted and invisible.
    // The residual is bounded by REVOCATION_POLL_INTERVAL and nothing longer.
    let shutdown_handle = stream
        .try_clone()
        .context("could not duplicate the session socket for revocation")?;
    let _live = session.registry.register(fingerprint, shutdown_handle);

    let current = HostState::read_peers(session.state_path)
        .with_context(|| format!("could not re-check the pin store for {peer_addr}"))?;
    if !current.iter().any(|p| p.pinned == *peer) {
        anyhow::bail!(
            "{peer_addr} was unpaired during its handshake; refusing (watcher poll interval \
             is {} ms, which this check makes irrelevant here)",
            REVOCATION_POLL_INTERVAL.as_millis()
        );
    }
    tracing::info!(%peer_addr, fingerprint = %fingerprint.short(), "session established");

    let report = session::serve(
        &mut noise,
        &mut stream,
        session.config,
        peer,
        session.revocation,
        session.metrics,
    )?;
    tracing::info!(
        %peer_addr,
        fingerprint = %fingerprint.short(),
        peer_device_id = %report.peer_device_id,
        pings_answered = report.pings_answered,
        end = ?report.end,
        "session closed"
    );
    Ok(())
}
