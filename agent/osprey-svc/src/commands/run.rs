//! `osprey-svc run` — serve steady-state sessions to already-pinned controllers.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use osprey_core::channel;
use osprey_core::identity::DeviceIdentity;

use crate::host::Host;
use crate::lan::{LanListener, DEFAULT_LAN_PORT};
use crate::registry::{spawn_revocation_watcher, SessionRegistry};
use crate::session::{self, SessionConfig};
use crate::state::HostState;

/// How long the accept loop blocks before re-checking the shutdown flag.
const ACCEPT_SLICE: Duration = Duration::from_millis(250);

/// A session with nothing to say for this long is hung up on. Long enough that
/// a phone in a pocket is not disconnected between glances; short enough that a
/// dead TCP connection does not hold a thread forever.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub port: u16,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_LAN_PORT,
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
        bail!("no controller is paired; run `osprey-svc pair` at this machine first");
    }
    let listener = LanListener::bind(options.port)?;
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
    };

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
            let registry = Arc::clone(&registry);
            let config = config.clone();
            scope.spawn(move || {
                if let Err(err) = serve_one(identity, &pins, &registry, stream, peer_addr, &config)
                {
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
    result
}

fn serve_one(
    identity: &DeviceIdentity,
    pins: &[osprey_core::identity::PinnedPeer],
    registry: &Arc<SessionRegistry>,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    config: &SessionConfig,
) -> Result<()> {
    stream
        .set_read_timeout(Some(SESSION_IDLE_TIMEOUT))
        .context("could not set a session read timeout")?;

    // `accept` refuses any peer whose static is not pinned. That check is the
    // unpair enforcement point: nothing about it involves the relay, so a
    // revoked controller is refused even on a LAN the relay cannot see.
    let (peer, mut session) = channel::accept(&mut stream, identity, pins)
        .with_context(|| format!("refused a session from {peer_addr}"))?;
    let fingerprint = peer.fingerprint();
    tracing::info!(%peer_addr, fingerprint = %fingerprint.short(), "session established");

    // Registered before the first application byte, so an unpair that lands
    // one instruction later still finds a socket to shut down.
    let shutdown_handle = stream
        .try_clone()
        .context("could not duplicate the session socket for revocation")?;
    let _live = registry.register(peer.identity_pub, shutdown_handle);

    let report = session::serve(&mut session, &mut stream, config)?;
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
