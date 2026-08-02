//! `osprey-svc pair` — enrol one controller, once, in front of the machine.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use osprey_core::identity::PinnedPeer;
use osprey_core::pairing::{self, PairingOffer, PairingSecret, QrPayload, DEFAULT_PAIRING_TTL};

use crate::host::Host;
use crate::lan::{LanListener, DEFAULT_LAN_PORT};
use crate::qrterm;
use crate::relay::{DeviceToken, RelayClient};
use crate::session::now_ms;
use crate::state::{PairedPeer, RelayEnrolment};

/// A phone that has scanned the QR connects immediately. A minute is generous
/// for a slow handshake and short enough that a stalled TCP connection cannot
/// occupy the pairing window.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct PairOptions {
    /// Relay base url. Falls back to the one stored at enrolment.
    pub relay_url: Option<String>,
    /// Deploy-time enrolment secret, required only on first contact with a
    /// relay (execution plan §2 #11).
    pub enrollment_secret: Option<String>,
    /// Pair without a relay at all. The QR then carries no relay url, and the
    /// phone must reach the host over the LAN.
    pub lan_only: bool,
    pub port: u16,
    pub ttl: Duration,
}

impl Default for PairOptions {
    fn default() -> Self {
        Self {
            relay_url: None,
            enrollment_secret: None,
            lan_only: false,
            port: DEFAULT_LAN_PORT,
            ttl: DEFAULT_PAIRING_TTL,
        }
    }
}

/// Ensure the agent has relay credentials, enrolling if this is first contact.
fn ensure_enrolled(host: &mut Host, options: &PairOptions) -> Result<Option<DeviceToken>> {
    if options.lan_only {
        return Ok(None);
    }
    let base_url = match (options.relay_url.as_deref(), host.state.relay()) {
        (Some(url), _) => url.to_owned(),
        (None, Some(relay)) => relay.base_url.clone(),
        (None, None) => bail!(
            "no relay configured: pass --relay-url with --enrollment-secret, or \
             pass --lan-only to pair without a relay"
        ),
    };
    let client = RelayClient::new(&base_url)?;

    // Re-use the existing enrolment only when it is for the same relay: a
    // different relay is a different tenant namespace, and presenting the old
    // account's token to it would simply fail authentication.
    let already = host
        .state
        .relay()
        .filter(|relay| relay.base_url == client.base_url());
    if already.is_some() {
        if let Some(token) = host.relay_token()? {
            return Ok(Some(token));
        }
    }

    let secret = options
        .enrollment_secret
        .clone()
        .or_else(|| std::env::var("OSPREY_ENROLLMENT_SECRET").ok())
        .context(
            "this agent is not enrolled with that relay; supply --enrollment-secret \
             or set OSPREY_ENROLLMENT_SECRET",
        )?;
    let enrolment = client.enrol(&secret, host.display_name(), host.identity.public())?;
    let token = DeviceToken::new(enrolment.device_token);
    host.store_relay_token(&token)?;
    host.state.set_relay(RelayEnrolment {
        base_url: client.base_url().to_owned(),
        account_id: enrolment.account_id,
        device_id: enrolment.device_id,
    })?;
    Ok(Some(token))
}

/// Render the QR, then accept exactly one pairing.
///
/// Returns the peer that was pinned. The audit entry — success or failure — is
/// written inside `osprey_core::pairing`, on every path, before this returns.
pub fn execute(host: &mut Host, options: &PairOptions, out: &mut dyn Write) -> Result<PairedPeer> {
    let token = ensure_enrolled(host, options)?;
    let listener = LanListener::bind(options.port)?;

    let mut offer = PairingOffer::new(PairingSecret::generate(), options.ttl);
    let (relay_url, account_id) = match (host.state.relay(), &token) {
        (Some(relay), Some(token)) => {
            let client = RelayClient::new(&relay.base_url)?;
            let issued = client.issue_pairing_token(token, &offer.routing_id())?;
            tracing::info!(token_id = %issued.token_id, expires_at = %issued.expires_at,
                "registered the pairing rendezvous with the relay");
            (relay.base_url.clone(), relay.account_id.to_string())
        }
        // TODO(frank): an empty `relay_url` is this build's encoding of "LAN
        // only, do not contact a relay". Decide whether the iOS client treats
        // an empty relay url that way or whether the QR should carry an
        // explicit `mode` field instead; the agent side works either way, but
        // both ends must agree before the phone can scan a LAN-only QR.
        _ => (String::new(), String::new()),
    };

    let payload = QrPayload::new(
        relay_url,
        account_id,
        host.state.device_id().to_string(),
        host.identity.public().clone(),
        listener.addresses().to_vec(),
        offer.secret().clone(),
    );
    print_offer(&payload, &listener, out)?;

    let peer = accept_one(host, &listener, &mut offer, options.ttl)?;
    let paired = PairedPeer {
        relay_device_id: lookup_relay_device(host, token.as_ref(), &peer),
        pinned: peer,
        paired_at_ms: now_ms(),
    };
    host.state.add_peer(paired.clone())?;
    print_pinned(&paired, out)?;
    Ok(paired)
}

/// Accept pairing attempts until one succeeds or the offer's window closes.
///
/// A failed attempt does **not** end the window: the offer is only consumed on
/// success, so an operator whose phone fumbled the first scan does not have to
/// restart the command. The 120-second TTL is what bounds the retries.
fn accept_one(
    host: &Host,
    listener: &LanListener,
    offer: &mut PairingOffer,
    ttl: Duration,
) -> Result<PinnedPeer> {
    let context = host.pairing_context();
    let deadline = Instant::now() + ttl;
    loop {
        let now = Instant::now();
        if now >= deadline || offer.is_expired() {
            bail!(
                "pairing window closed after {} seconds with no controller paired",
                ttl.as_secs()
            );
        }
        let Some((mut stream, peer_addr)) = listener.accept_timeout(deadline - now)? else {
            continue;
        };
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .context("could not set a handshake read timeout")?;
        tracing::info!(%peer_addr, "pairing attempt");
        match pairing::respond(&mut stream, &host.identity, offer, &context, &host.audit) {
            Ok(outcome) => return Ok(outcome.peer),
            // Already audited as a pairing failure by `respond`, with a typed
            // reason. Logged here so the operator watching the console sees it
            // too, and the window stays open for the real phone.
            Err(err) => tracing::warn!(%peer_addr, error = %err, "pairing attempt refused"),
        }
    }
}

/// Best-effort lookup of the new controller's relay device id.
///
/// Only used to address a later `DELETE /v1/devices/:id`. A failure is logged
/// and discarded because the pairing itself is already complete and locally
/// authoritative — refusing to record a successful pin because the relay was
/// unreachable would let the relay's availability decide what the agent trusts.
fn lookup_relay_device(
    host: &Host,
    token: Option<&DeviceToken>,
    peer: &PinnedPeer,
) -> Option<uuid::Uuid> {
    let (relay, token) = (host.state.relay()?, token?);
    let client = match RelayClient::new(&relay.base_url) {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(error = %err, "could not build a relay client for device lookup");
            return None;
        }
    };
    // Matching is by the peer's pinned identity key, so a relay that has not yet
    // written the row simply yields `None` and unpairing falls back to the
    // fingerprint the operator was shown.
    match client.find_device_by_identity(token, &peer.identity_pub) {
        Ok(found) => found,
        Err(err) => {
            tracing::warn!(error = %err, "could not resolve the peer's relay device id");
            None
        }
    }
}

fn print_offer(payload: &QrPayload, listener: &LanListener, out: &mut dyn Write) -> Result<()> {
    let text = payload.encode()?;
    writeln!(out, "\nScan this with the Osprey app on your phone:\n")?;
    writeln!(out, "{}", qrterm::render(&text)?)?;
    writeln!(out, "Listening on:")?;
    for addr in listener.addresses() {
        writeln!(out, "  {addr}")?;
    }
    writeln!(
        out,
        "\nHost identity fingerprint: {}",
        payload.agent_identity.fingerprint().short()
    )?;
    // The payload contains the pairing secret, so this is not debug output that
    // can be left on by default; the caller decides, and the operator sees it
    // only because they asked.
    writeln!(
        out,
        "\nPayload (contains the pairing secret — do not share):\n{text}\n"
    )?;
    out.flush().context("could not write the pairing offer")?;
    Ok(())
}

fn print_pinned(peer: &PairedPeer, out: &mut dyn Write) -> Result<()> {
    let fingerprint = peer.fingerprint();
    writeln!(out, "\nPaired.")?;
    writeln!(out, "  controller fingerprint : {}", fingerprint.short())?;
    writeln!(out, "  full                   : {fingerprint}")?;
    writeln!(
        out,
        "  noise static           : {}",
        hex::encode(peer.pinned.noise_static_pub)
    )?;
    if let Some(id) = peer.relay_device_id {
        writeln!(out, "  relay device id        : {id}")?;
    }
    // Displaying the pin is the whole point of execution plan §2 #14: an
    // operator who sees a fingerprint they do not recognise has just caught a
    // pairing they did not intend, and can unpair before the peer uses it.
    writeln!(
        out,
        "\nCheck this fingerprint against the one your phone is showing. If they \n\
         differ, run `osprey-svc unpair {}` now.",
        fingerprint.short()
    )?;
    out.flush().context("could not write the pairing result")?;
    Ok(())
}
