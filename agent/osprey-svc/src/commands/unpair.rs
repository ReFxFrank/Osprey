//! `osprey-svc unpair` — revoke a controller, locally and authoritatively.
//!
//! The order of operations in [`execute`] is the security property, not an
//! implementation detail:
//!
//! 1. the pin is removed from the local store and the store is fsynced;
//! 2. every live session with that peer is hung up on;
//! 3. the unpair is written to the audit log;
//! 4. *only then* is the relay told, best-effort.
//!
//! The relay is never consulted and never gets a veto (execution plan §3, task
//! D3). A LAN session does not involve the relay at all, so a relay-side
//! revocation could not stop one; and a compromised relay that could refuse or
//! stall a revocation would be able to keep a device paired against the
//! operator's explicit instruction. Steps 1 and 2 therefore complete before any
//! network call is attempted, and a failure in step 4 cannot undo them.

use std::io::Write;

use anyhow::{Context, Result};
use osprey_core::audit::UnpairInitiator;
use osprey_core::pairing;

use crate::host::Host;
use crate::registry::{SessionRegistry, REVOCATION_POLL_INTERVAL};
use crate::relay::RelayClient;
use crate::state::{PairedPeer, PeerSelector};

#[derive(Debug)]
pub struct UnpairOutcome {
    pub removed: Vec<PairedPeer>,
    /// Sessions closed synchronously through `registry`. Zero when `unpair`
    /// runs as its own process — the running agent's watcher closes them
    /// instead, within [`REVOCATION_POLL_INTERVAL`].
    pub sessions_closed: usize,
    /// Relay calls that failed. Never fatal: the revocation has already taken
    /// effect by the time any of them is made.
    pub relay_errors: Vec<String>,
}

/// Revoke every peer matching `selector`.
///
/// `registry` is the live-session table when the caller is the process that is
/// also serving sessions (the P1 service, and the P0 gate test). The P0 console
/// `unpair` is a separate process and passes `None`.
pub fn execute(
    host: &mut Host,
    selector: &PeerSelector,
    registry: Option<&SessionRegistry>,
    out: &mut dyn Write,
) -> Result<UnpairOutcome> {
    let removed = host.state.remove_peers(selector)?;
    if removed.is_empty() {
        writeln!(out, "No pinned controller matched {selector}.")?;
        out.flush().context("could not write the unpair result")?;
        return Ok(UnpairOutcome {
            removed,
            sessions_closed: 0,
            relay_errors: Vec::new(),
        });
    }

    let sessions_closed = removed
        .iter()
        .map(|peer| match registry {
            Some(registry) => registry.revoke_identity(&peer.fingerprint()),
            None => 0,
        })
        .sum();

    let context = host.pairing_context();
    let mut audit_failures = Vec::new();
    for peer in &removed {
        // The pin is already gone, so an audit failure cannot be allowed to
        // abort the loop and leave later peers un-audited. Every failure is
        // collected and the command exits non-zero, which is the honest
        // outcome: revocation happened, the record of it did not.
        if let Err(err) =
            pairing::record_unpair(&host.audit, &context, &peer.pinned, UnpairInitiator::Host)
        {
            audit_failures.push(format!("{}: {err}", peer.fingerprint().short()));
        }
    }

    let notified = notify_relay(host, &removed);
    let relay_errors = notified.clone().unwrap_or_default();
    report(
        &removed,
        sessions_closed,
        registry.is_some(),
        notified.as_deref(),
        out,
    )?;

    if !audit_failures.is_empty() {
        anyhow::bail!(
            "unpaired, but the audit log could not be written for: {}",
            audit_failures.join(", ")
        );
    }
    Ok(UnpairOutcome {
        removed,
        sessions_closed,
        relay_errors,
    })
}

/// Tell the relay, after the fact. Errors are returned, never propagated.
///
/// `None` means there was no relay to notify — a LAN-only agent, which is a
/// complete configuration, not a degraded one.
fn notify_relay(host: &Host, removed: &[PairedPeer]) -> Option<Vec<String>> {
    let mut errors = Vec::new();
    let relay = host.state.relay()?;
    let token = match host.relay_token() {
        Ok(Some(token)) => token,
        Ok(None) => return None,
        Err(err) => {
            errors.push(format!("could not read the relay token: {err}"));
            return Some(errors);
        }
    };
    let client = match RelayClient::new(&relay.base_url) {
        Ok(client) => client,
        Err(err) => {
            errors.push(format!("relay url unusable: {err}"));
            return Some(errors);
        }
    };
    for peer in removed {
        let Some(device_id) = peer.relay_device_id else {
            // A LAN-only pairing has no relay row to revoke. Nothing failed.
            continue;
        };
        if let Err(err) = client.revoke_device(&token, device_id) {
            errors.push(format!("{device_id}: {err}"));
        }
    }
    Some(errors)
}

fn report(
    removed: &[PairedPeer],
    sessions_closed: usize,
    had_registry: bool,
    relay_errors: Option<&[String]>,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(out, "Unpaired {} controller(s):", removed.len())?;
    for peer in removed {
        writeln!(out, "  {}", peer.fingerprint().short())?;
    }
    if had_registry {
        writeln!(out, "Closed {sessions_closed} live session(s).")?;
    } else {
        writeln!(
            out,
            "A running `osprey-svc run` will drop any live session with these \
             controllers within {} ms.",
            REVOCATION_POLL_INTERVAL.as_millis()
        )?;
    }
    match relay_errors {
        None => writeln!(out, "No relay is configured; nothing to notify.")?,
        Some([]) => writeln!(out, "Relay notified.")?,
        Some(errors) => {
            writeln!(
                out,
                "The relay was not notified, which does not affect the revocation:"
            )?;
            for error in errors {
                writeln!(out, "  {error}")?;
            }
        }
    }
    out.flush().context("could not write the unpair result")?;
    Ok(())
}
