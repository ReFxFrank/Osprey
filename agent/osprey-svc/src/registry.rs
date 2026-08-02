//! Live sessions, and the mechanism that kills them on unpair.
//!
//! Brief §6.1 requires revocation to be *immediate* and to drop any live
//! session. Removing a pin only stops the *next* handshake, so this registry
//! holds a `TcpStream` handle for every session in flight and shuts the socket
//! down under the session thread, which turns the peer's next read into an
//! error rather than waiting for it to notice.
//!
//! In P0 `unpair` is a separate process from `run`, so the two cannot share this
//! registry directly — the pin store on disk is what they share. That is what
//! [`spawn_revocation_watcher`] closes: `run` re-reads the pin file on a short
//! interval and hangs up on any session whose peer is no longer pinned. When P1
//! folds both into one service the watcher stays honest but the in-process call
//! to [`SessionRegistry::revoke_identity`] becomes the fast path.

use std::collections::HashMap;
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use osprey_core::identity::PinnedPeer;

use crate::state::HostState;

/// How often `run` re-reads the pin store. Short enough that "immediate" is
/// honest at human scale, long enough that it is not a busy loop.
pub const REVOCATION_POLL_INTERVAL: Duration = Duration::from_millis(200);

struct LiveSession {
    identity_pub: [u8; 32],
    socket: TcpStream,
}

/// Every session currently being served, keyed by an internal id.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<u64, LiveSession>>,
    next_id: AtomicU64,
}

/// Deregisters its session when dropped, so a thread that exits for any reason —
/// including a panic elsewhere in the process — cannot leave a stale socket
/// behind that a later revocation would try to shut down.
pub struct SessionHandle {
    registry: Arc<SessionRegistry>,
    id: u64,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a live session. `socket` must be a `try_clone` of the session's
    /// stream; it is used only to shut the connection down.
    pub fn register(self: &Arc<Self>, identity_pub: [u8; 32], socket: TcpStream) -> SessionHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(
            id,
            LiveSession {
                identity_pub,
                socket,
            },
        );
        SessionHandle {
            registry: Arc::clone(self),
            id,
        }
    }

    pub fn live_count(&self) -> usize {
        self.lock().len()
    }

    /// Hang up on every session with this peer identity. Returns how many were
    /// closed.
    pub fn revoke_identity(&self, identity_pub: &[u8; 32]) -> usize {
        self.shutdown_matching(|session| &session.identity_pub == identity_pub)
    }

    /// Hang up on every session whose peer is not in `allowed`.
    pub fn retain_pinned(&self, allowed: &[PinnedPeer]) -> usize {
        self.shutdown_matching(|session| {
            !allowed
                .iter()
                .any(|peer| peer.identity_pub == session.identity_pub)
        })
    }

    /// Hang up on everything. Used on shutdown and by `unpair all`.
    pub fn revoke_all(&self) -> usize {
        self.shutdown_matching(|_| true)
    }

    fn shutdown_matching(&self, predicate: impl Fn(&LiveSession) -> bool) -> usize {
        let mut closed = 0;
        // Entries stay in the map; the owning `SessionHandle` removes them when
        // its thread unwinds. Removing them here would make a second revocation
        // of a peer that has not yet noticed report zero sessions closed.
        for session in self.lock().values() {
            if !predicate(session) {
                continue;
            }
            match session.socket.shutdown(Shutdown::Both) {
                Ok(()) => closed += 1,
                // A peer that already hung up is the outcome we wanted, so it is
                // counted; anything else is reported rather than swallowed.
                Err(err) if err.kind() == std::io::ErrorKind::NotConnected => closed += 1,
                Err(err) => tracing::warn!(error = %err, "could not close a revoked session"),
            }
        }
        closed
    }

    fn remove(&self, id: u64) {
        self.lock().remove(&id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LiveSession>> {
        // A poisoned lock means some other thread panicked while holding it. The
        // map is a plain collection with no torn invariant, and refusing to
        // revoke sessions because of an unrelated panic would fail *open*.
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Watch the pin store and drop sessions whose peer has been unpaired.
///
/// Returns immediately; the caller keeps the handle to join on shutdown.
pub fn spawn_revocation_watcher(
    state_path: PathBuf,
    registry: Arc<SessionRegistry>,
    running: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match HostState::read_peers(&state_path) {
                Ok(peers) => {
                    let pins: Vec<PinnedPeer> = peers.into_iter().map(|p| p.pinned).collect();
                    let closed = registry.retain_pinned(&pins);
                    if closed > 0 {
                        tracing::warn!(closed, "dropped sessions for unpaired peers");
                    }
                }
                // An unreadable pin store must not be treated as "nobody is
                // pinned" (which would tear down every good session) nor as
                // "everybody is still pinned" silently.
                Err(err) => tracing::error!(error = %err, "could not re-read the pin store"),
            }
            std::thread::sleep(REVOCATION_POLL_INTERVAL);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osprey_core::identity::DeviceIdentity;
    use std::io::Read;
    use std::net::TcpListener;

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (client, server)
    }

    #[test]
    fn revoking_an_identity_unblocks_a_blocked_read() {
        let registry = SessionRegistry::new();
        let (mut client, server) = connected_pair();
        let handle = registry.register([3u8; 32], server.try_clone().expect("clone"));

        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            client.read(&mut buf)
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(registry.revoke_identity(&[3u8; 32]), 1);

        let result = reader.join().expect("reader thread");
        // The peer sees a clean end-of-stream, not a hang.
        assert_eq!(result.expect("read result"), 0);
        drop(handle);
        assert_eq!(registry.live_count(), 0);
    }

    #[test]
    fn a_different_identity_is_left_alone() {
        let registry = SessionRegistry::new();
        let (_client, server) = connected_pair();
        let _handle = registry.register([1u8; 32], server);
        assert_eq!(registry.revoke_identity(&[2u8; 32]), 0);
        assert_eq!(registry.live_count(), 1);
    }

    #[test]
    fn retain_pinned_closes_only_unpinned_peers() {
        let registry = SessionRegistry::new();
        let (_c1, s1) = connected_pair();
        let (_c2, s2) = connected_pair();
        let kept = PinnedPeer::pin(DeviceIdentity::generate().public()).expect("pin");
        let dropped = PinnedPeer::pin(DeviceIdentity::generate().public()).expect("pin");
        let _h1 = registry.register(kept.identity_pub, s1);
        let _h2 = registry.register(dropped.identity_pub, s2);
        assert_eq!(registry.retain_pinned(&[kept]), 1);
    }
}
