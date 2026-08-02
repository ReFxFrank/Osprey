//! Steady-state sessions between already-paired devices.
//!
//! Plain `Noise_IK` on the pinned statics — no PSK, because after pairing the
//! pin *is* the authentication. The responder's pin check here is also the
//! enforcement point for unpairing: drop the peer from `allowed` and its next
//! handshake is refused, with no dependency on the relay having delivered a
//! revocation.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, PinnedPeer};
use crate::noise::{Handshake, HandshakeConfig, NoiseSession, Pattern, Role};

/// Controller side: open a session to a pinned host.
pub fn connect<S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    peer: &PinnedPeer,
) -> Result<NoiseSession> {
    let local_static = identity.noise_static_secret();
    let handshake = Handshake::new(HandshakeConfig {
        pattern: Pattern::Session,
        role: Role::Initiator,
        local_static: &local_static,
        remote_static: Some(&peer.noise_static_pub),
        psk: None,
    })?;
    let (session, _) = handshake.run_initiator(stream, &[])?;
    // IK authenticates the responder cryptographically, but the check is stated
    // rather than assumed so a future pattern change cannot quietly drop it.
    if !peer.matches_handshake_static(session.remote_static()) {
        return Err(Error::UnpinnedPeer);
    }
    Ok(session)
}

/// Host side: accept a session only from a currently pinned controller.
pub fn accept<'a, S: Read + Write>(
    stream: &mut S,
    identity: &DeviceIdentity,
    allowed: &'a [PinnedPeer],
) -> Result<(&'a PinnedPeer, NoiseSession)> {
    let local_static = identity.noise_static_secret();
    let handshake = Handshake::new(HandshakeConfig {
        pattern: Pattern::Session,
        role: Role::Responder,
        local_static: &local_static,
        remote_static: None,
        psk: None,
    })?;
    let (session, _) = handshake.run_responder(stream, &[])?;
    let peer = allowed
        .iter()
        .find(|p| p.matches_handshake_static(session.remote_static()))
        .ok_or(Error::UnpinnedPeer)?;
    Ok((peer, session))
}
