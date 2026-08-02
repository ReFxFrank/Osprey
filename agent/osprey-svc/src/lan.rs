//! The direct-LAN listener.
//!
//! ## Why the agent listens at all
//!
//! Brief §6.2 line 243 says "Agent makes **outbound connections only.** No
//! listening WAN port." Taken literally that forbids this module. It cannot be
//! meant literally: brief §3.1 makes direct-LAN the first rung of the connection
//! ladder, and the Gate P0 criterion requires the phone to complete a Noise
//! handshake with the agent "over the local network" — the phone is the IK
//! initiator (execution plan §2 #13), so something has to accept its TCP
//! connection. The constraint's own second sentence names the real scope: *WAN*.
//! Execution plan §2 #4 resolves it — the agent MAY listen on private and
//! link-local interfaces for the direct-LAN path, and outbound-only continues to
//! govern every relay and WAN-traversal path.
//!
//! That resolution is enforced here rather than documented and hoped for:
//!
//! * [`LanListener::bind`] binds one socket per *private* local address. It
//!   never binds `0.0.0.0` or `[::]`, because a wildcard bind on a
//!   multi-homed or directly-connected host is exactly the WAN-reachable port
//!   the brief forbids, and it is not visible in any configuration file that it
//!   has become one.
//! * [`LanListener::accept_timeout`] drops any peer whose address is not itself
//!   private. A private bind can still be reached from a public source across a
//!   router doing destination NAT, so the source check is a second, independent
//!   gate rather than a restatement of the first.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// Default LAN port. Registered to nothing; chosen high and fixed so a Windows
/// Firewall rule for the *Private* profile can name one port.
pub const DEFAULT_LAN_PORT: u16 = 47010;

/// How long a poll cycle sleeps when no listener has a pending connection.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Is `ip` unreachable from the public internet?
///
/// Loopback counts: it is the narrowest possible scope, and the in-process gate
/// test needs it. Carrier-grade NAT (100.64.0.0/10) deliberately does **not**
/// count — it is shared address space where a neighbouring subscriber is not a
/// peer the operator has physical access to.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    let seg = ip.segments();
    // fc00::/7 unique-local and fe80::/10 link-local. `Ipv6Addr::is_unique_local`
    // and `is_unicast_link_local` are still unstable, so the masks are open-coded.
    let unique_local = (seg[0] & 0xfe00) == 0xfc00;
    let link_local = (seg[0] & 0xffc0) == 0xfe80;
    if unique_local || link_local {
        return true;
    }
    // An IPv4-mapped address (::ffff:a.b.c.d) arrives here on a dual-stack
    // socket, so the v4 rules have to be applied to it or a public IPv4 peer
    // would be admitted through the v6 branch.
    match ip.to_ipv4_mapped() {
        Some(v4) => is_private_v4(v4),
        None => false,
    }
}

/// Every private address this host currently has, loopback last.
///
/// Loopback is ordered last so the QR's `lan_hints` lead with an address a phone
/// on the same network can actually reach.
pub fn private_addresses() -> Result<Vec<IpAddr>> {
    let interfaces = if_addrs::get_if_addrs().context("could not enumerate network interfaces")?;
    let mut addrs: Vec<IpAddr> = interfaces
        .into_iter()
        .map(|iface| iface.ip())
        .filter(|ip| is_private(*ip))
        .collect();
    addrs.sort_by_key(|ip| (ip.is_loopback(), ip.to_string()));
    addrs.dedup();
    Ok(addrs)
}

/// A set of private-only listening sockets, polled as one.
pub struct LanListener {
    listeners: Vec<TcpListener>,
    addrs: Vec<SocketAddr>,
}

impl LanListener {
    /// Bind every private local address on `port`.
    ///
    /// `port == 0` asks the OS for an ephemeral port on the first address and
    /// then reuses that number on the rest, so the QR advertises one port rather
    /// than one per interface.
    pub fn bind(port: u16) -> Result<Self> {
        let candidates = private_addresses()?;
        if candidates.is_empty() {
            return Err(anyhow!(
                "no private or link-local address is available to listen on; \
                 the agent will not bind a publicly routable address"
            ));
        }

        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        let mut chosen_port = port;
        for ip in candidates {
            let bind_to = SocketAddr::new(ip, chosen_port);
            match TcpListener::bind(bind_to) {
                Ok(listener) => {
                    let actual = listener
                        .local_addr()
                        .with_context(|| format!("could not read local address of {bind_to}"))?;
                    listener.set_nonblocking(true).with_context(|| {
                        format!("could not put the listener on {actual} into non-blocking mode")
                    })?;
                    if chosen_port == 0 {
                        chosen_port = actual.port();
                    }
                    listeners.push(listener);
                    addrs.push(actual);
                }
                // One unusable interface (an address that vanished between
                // enumeration and bind, a port already taken on that address)
                // must not take down the whole listener set, but it is never
                // silent.
                Err(err) => tracing::warn!(address = %bind_to, error = %err, "skipping interface"),
            }
        }

        if listeners.is_empty() {
            return Err(anyhow!("could not bind any private address on port {port}"));
        }
        Ok(Self { listeners, addrs })
    }

    /// The addresses actually bound — this is what goes into the QR's `lan_hints`.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Wait up to `timeout` for a connection from a private peer.
    ///
    /// Connections from non-private addresses are closed here and never returned
    /// to the caller, so no code path further in can accidentally serve one.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<(TcpStream, SocketAddr)>> {
        let deadline = Instant::now() + timeout;
        loop {
            for listener in &self.listeners {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        if !is_private(peer.ip()) {
                            tracing::warn!(
                                %peer,
                                "refused a connection from a non-private address"
                            );
                            if let Err(err) = stream.shutdown(std::net::Shutdown::Both) {
                                tracing::warn!(%peer, error = %err, "could not close refused peer");
                            }
                            continue;
                        }
                        // Windows accepted sockets inherit the listener's
                        // non-blocking mode; Linux ones do not. Set it either
                        // way so the caller gets identical blocking semantics on
                        // both platforms.
                        stream.set_nonblocking(false).with_context(|| {
                            format!("could not put the socket from {peer} into blocking mode")
                        })?;
                        stream
                            .set_nodelay(true)
                            .with_context(|| format!("could not disable Nagle for {peer}"))?;
                        return Ok(Some((stream, peer)));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("accept failed on {:?}", listener.local_addr())
                        })
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1918_link_local_and_loopback_are_private() {
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.20",
            "169.254.7.7",
            "127.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            let parsed: IpAddr = ip.parse().expect("parse");
            assert!(is_private(parsed), "{ip} should be private");
        }
    }

    #[test]
    fn public_and_cgnat_addresses_are_not_private() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.64.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let parsed: IpAddr = ip.parse().expect("parse");
            assert!(!is_private(parsed), "{ip} should not be private");
        }
    }

    #[test]
    fn bind_never_produces_a_wildcard_address() {
        let listener = LanListener::bind(0).expect("bind");
        assert!(!listener.addresses().is_empty());
        for addr in listener.addresses() {
            assert!(!addr.ip().is_unspecified(), "{addr} is a wildcard bind");
            assert!(is_private(addr.ip()), "{addr} is not private");
        }
    }

    #[test]
    fn accept_timeout_returns_none_when_idle() {
        let listener = LanListener::bind(0).expect("bind");
        let idle = listener
            .accept_timeout(Duration::from_millis(60))
            .expect("accept");
        assert!(idle.is_none());
    }

    #[test]
    fn a_loopback_peer_is_accepted() {
        let listener = LanListener::bind(0).expect("bind");
        let addr = listener
            .addresses()
            .iter()
            .find(|a| a.ip().is_loopback())
            .copied()
            .expect("a loopback listener");
        let _client = TcpStream::connect(addr).expect("connect");
        let accepted = listener
            .accept_timeout(Duration::from_secs(2))
            .expect("accept")
            .expect("a connection");
        assert!(is_private(accepted.1.ip()));
    }
}
