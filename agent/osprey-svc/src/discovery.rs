//! mDNS advertisement of the direct-LAN listener (`_osprey._tcp`).
//!
//! ## Why this exists
//!
//! The QR carries `lan_hints` — the addresses the agent was listening on at the
//! moment the code was rendered (amendment A6). Those are correct exactly once.
//! A DHCP lease renewal, a move between wifi and ethernet, or a docking station
//! invalidates them, and the phone would then be permanently unable to find a
//! host it is validly paired with. mDNS is the durable answer: the phone browses
//! for `_osprey._tcp.local.`, matches the `device_id` TXT record against a peer
//! it has already pinned, and uses whatever address the host currently has.
//!
//! ## What it is not
//!
//! It is not authentication, and nothing here is trusted. Anyone on the LAN can
//! publish a record claiming any `device_id`. All an advertisement can do is
//! propose an address; the Noise IK handshake against the pinned static is what
//! decides whether the thing at that address is the agent. So the TXT record
//! deliberately carries no key material, no account id and no display name —
//! only what a paired phone needs to pick the right row.
//!
//! ## Scope
//!
//! Amendment A7 confines the agent's listener to private and link-local
//! addresses. This module inherits that: it advertises only the private,
//! non-loopback addresses the listener actually bound, and it tells the mDNS
//! daemon to use those interfaces and no others, so a multi-homed host does not
//! start answering multicast queries on a public interface.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use uuid::Uuid;

use crate::lan::is_private;

/// DNS-SD service type. The trailing `.local.` is the mDNS domain and is part of
/// the type string `mdns-sd` expects.
pub const SERVICE_TYPE: &str = "_osprey._tcp.local.";

/// TXT key carrying the agent's device id — the only field a paired phone needs
/// in order to tell this host from any other Osprey host on the LAN.
pub const TXT_DEVICE_ID: &str = "device_id";

/// TXT key carrying the advertisement's schema version, so a future field change
/// is visible to an old client instead of being misread.
pub const TXT_VERSION: &str = "v";

/// Schema version of the TXT record set.
pub const ADVERT_VERSION: &str = "1";

/// How long to wait for the mDNS daemon to confirm the goodbye packets on
/// shutdown. Bounded because a hung daemon must not delay agent shutdown.
const DEREGISTER_TIMEOUT: Duration = Duration::from_secs(2);

/// The addresses of `bound` that may be advertised.
///
/// Loopback is excluded: it is private, so the listener binds it, but publishing
/// `127.0.0.1` to the LAN advertises an address that resolves to the *phone*.
pub fn advertisable(bound: &[SocketAddr]) -> Vec<SocketAddr> {
    bound
        .iter()
        .copied()
        .filter(|addr| is_private(addr.ip()) && !addr.ip().is_loopback())
        .collect()
}

/// Short, stable, collision-resistant label derived from the device id.
fn label(device_id: Uuid) -> String {
    let simple = device_id.simple().to_string();
    format!("osprey-{}", &simple[..12.min(simple.len())])
}

/// Build the service registration.
///
/// Pure: no socket is opened and no packet is sent, so the contents can be
/// asserted in a test without multicasting anything.
pub fn service_info(device_id: Uuid, addrs: &[SocketAddr]) -> Result<ServiceInfo> {
    let first = addrs
        .first()
        .ok_or_else(|| anyhow!("no advertisable address"))?;
    let port = first.port();
    // One DNS-SD record has one port. `LanListener` reuses a single port across
    // every interface it binds, so a mismatch means an assumption broke
    // elsewhere and should not be papered over by silently picking one.
    if let Some(odd) = addrs.iter().find(|addr| addr.port() != port) {
        return Err(anyhow!(
            "listener bound {odd} but mDNS can advertise only one port ({port})"
        ));
    }
    let ips: Vec<IpAddr> = addrs.iter().map(|addr| addr.ip()).collect();

    let instance = label(device_id);
    let mut properties = HashMap::new();
    properties.insert(TXT_VERSION.to_owned(), ADVERT_VERSION.to_owned());
    properties.insert(TXT_DEVICE_ID.to_owned(), device_id.to_string());

    ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &format!("{instance}.local."),
        &ips[..],
        port,
        properties,
    )
    .context("could not build the mDNS service registration")
}

/// A live `_osprey._tcp` advertisement.
///
/// Deregistration is in `Drop` rather than an explicit `stop()` so that every
/// exit path — clean shutdown, `?` on an unrelated error, a panic unwinding
/// through the caller — takes the record off the LAN. A stale record advertising
/// a port nothing is listening on costs a paired phone a connection timeout on
/// every attempt.
pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    /// Publish `addrs` under the agent's device id.
    ///
    /// `Ok(None)` means there was nothing to advertise — the host has no private
    /// non-loopback address, which is the case on a machine with only loopback
    /// and on CI. That is a normal outcome, not a failure.
    pub fn start(device_id: Uuid, bound: &[SocketAddr]) -> Result<Option<Self>> {
        let addrs = advertisable(bound);
        if addrs.is_empty() {
            tracing::info!(
                "no private non-loopback address to advertise; \
                 LAN discovery is unavailable and the QR's lan_hints are the only path"
            );
            return Ok(None);
        }
        let info = service_info(device_id, &addrs)?;
        let fullname = info.get_fullname().to_owned();

        let daemon = ServiceDaemon::new().context("could not start the mDNS daemon")?;
        // Deny by default, then admit exactly the interfaces the listener bound.
        // The reverse order would leave a window in which the daemon answers on
        // every interface the host has, including a public one (amendment A7).
        daemon
            .disable_interface(IfKind::All)
            .context("could not restrict the mDNS daemon to private interfaces")?;
        for addr in &addrs {
            daemon
                .enable_interface(IfKind::Addr(addr.ip()))
                .with_context(|| format!("could not enable mDNS on {}", addr.ip()))?;
        }
        daemon
            .register(info)
            .context("could not publish the mDNS service registration")?;
        tracing::info!(service = %fullname, addresses = addrs.len(), "advertising on the LAN");
        Ok(Some(Self { daemon, fullname }))
    }

    /// [`Self::start`], gated on `enabled`, reporting a failure rather than
    /// propagating it.
    ///
    /// Discovery is an optimisation over the QR's `lan_hints`: a host that
    /// cannot open a multicast socket must still pair and still serve sessions.
    /// The failure is logged with its cause on every path, so this is a
    /// deliberate degradation and not a swallowed error.
    ///
    /// When `enabled` is false nothing is constructed and no socket is opened,
    /// which is what keeps tests and CI off the multicast group.
    pub fn publish(enabled: bool, device_id: Uuid, bound: &[SocketAddr]) -> Option<Self> {
        if !enabled {
            return None;
        }
        match Self::start(device_id, bound) {
            Ok(advertisement) => advertisement,
            Err(err) => {
                tracing::warn!(error = %err,
                    "LAN discovery is unavailable; clients must use an address they \
                     already know");
                None
            }
        }
    }

    /// The full DNS-SD name this advertisement is published under.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        match self.daemon.unregister(&self.fullname) {
            // Waiting for the confirmation is what makes the goodbye packets
            // actually leave: `shutdown` below would otherwise race them.
            Ok(receiver) => {
                if let Err(err) = receiver.recv_timeout(DEREGISTER_TIMEOUT) {
                    tracing::warn!(error = %err, service = %self.fullname,
                        "mDNS deregistration was not confirmed; the record will expire on TTL");
                }
            }
            Err(err) => tracing::warn!(error = %err, service = %self.fullname,
                "could not deregister the mDNS advertisement"),
        }
        if let Err(err) = self.daemon.shutdown() {
            tracing::warn!(error = %err, "could not shut down the mDNS daemon");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_id() -> Uuid {
        Uuid::parse_str("3f2504e0-4f89-41d3-9a0c-0305e82c3301").expect("fixed uuid")
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    #[test]
    fn the_registration_has_the_expected_type_port_and_txt_records() {
        let info = service_info(device_id(), &[addr("192.168.1.20:47010")]).expect("build");
        assert_eq!(info.get_type(), SERVICE_TYPE);
        assert_eq!(info.get_port(), 47010);
        assert_eq!(
            info.get_property_val_str(TXT_DEVICE_ID),
            Some(device_id().to_string().as_str()),
            "a paired phone matches on this field alone"
        );
        assert_eq!(info.get_property_val_str(TXT_VERSION), Some(ADVERT_VERSION));
        assert_eq!(
            info.get_fullname(),
            format!("osprey-3f2504e04f89.{SERVICE_TYPE}")
        );
        assert!(info
            .get_addresses()
            .contains(&addr("192.168.1.20:47010").ip()));
    }

    #[test]
    fn the_txt_record_carries_nothing_beyond_the_two_documented_keys() {
        let info = service_info(device_id(), &[addr("10.0.0.5:47010")]).expect("build");
        let properties = info.get_properties();
        assert_eq!(
            properties.len(),
            2,
            "an advertisement is unauthenticated, so it must leak nothing extra"
        );
    }

    #[test]
    fn only_private_non_loopback_addresses_are_advertised() {
        let bound = [
            addr("127.0.0.1:47010"),
            addr("[::1]:47010"),
            addr("192.168.1.20:47010"),
            addr("[fe80::1]:47010"),
            addr("8.8.8.8:47010"),
        ];
        let chosen = advertisable(&bound);
        assert_eq!(
            chosen,
            vec![addr("192.168.1.20:47010"), addr("[fe80::1]:47010")]
        );
    }

    #[test]
    fn a_loopback_only_host_advertises_nothing_rather_than_advertising_itself() {
        assert!(advertisable(&[addr("127.0.0.1:47010")]).is_empty());
        assert!(
            Advertisement::start(device_id(), &[addr("127.0.0.1:47010")])
                .expect("start must not fail")
                .is_none()
        );
    }

    #[test]
    fn publish_opens_nothing_when_the_flag_is_off() {
        assert!(
            Advertisement::publish(false, device_id(), &[addr("192.168.1.20:47010")]).is_none()
        );
    }

    #[test]
    fn mixed_ports_are_an_error_rather_than_a_silently_dropped_address() {
        let bound = [addr("192.168.1.20:47010"), addr("10.0.0.5:47011")];
        assert!(service_info(device_id(), &bound).is_err());
    }

    #[test]
    fn no_address_is_an_error_rather_than_an_empty_registration() {
        assert!(service_info(device_id(), &[]).is_err());
    }
}
