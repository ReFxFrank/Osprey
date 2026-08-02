//! The QR payload: everything the phone needs, carried out of band.
//!
//! The QR is the trust bootstrap. It is displayed on the host's screen and
//! photographed by a phone standing in front of it, which is what makes
//! "physical access is required to enrol a controller" a cryptographic property
//! rather than a UX convention.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::PublicIdentity;
use crate::pairing::secret::PairingSecret;

/// Bumped if the field set changes, so an old phone build fails loudly instead
/// of silently misreading a field.
pub const QR_PAYLOAD_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPayload {
    pub v: u32,
    pub relay_url: String,
    pub account_id: String,
    pub device_id: String,
    /// The agent's Ed25519 identity key **and** its cross-signed X25519 Noise
    /// static.
    ///
    /// The plan's field list names only the identity key, but IK requires the
    /// initiator to hold the responder's *DH* static before the first message,
    /// and the phone has no other authenticated channel to learn it — so the
    /// static and its cross-certificate must travel in the QR too. The phone
    /// pins `identity_pub ‖ noise_static_pub` exactly as plan §2 #1 specifies.
    pub agent_identity: PublicIdentity,
    /// Private addresses the agent is listening on, valid by construction
    /// because the phone is physically at the host (plan §2 #3). The relay is
    /// not involved in the LAN path at all.
    pub lan_hints: Vec<SocketAddr>,
    pub pairing_secret: PairingSecret,
}

impl QrPayload {
    pub fn new(
        relay_url: impl Into<String>,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        agent_identity: PublicIdentity,
        lan_hints: Vec<SocketAddr>,
        pairing_secret: PairingSecret,
    ) -> Self {
        Self {
            v: QR_PAYLOAD_VERSION,
            relay_url: relay_url.into(),
            account_id: account_id.into(),
            device_id: device_id.into(),
            agent_identity,
            lan_hints,
            pairing_secret,
        }
    }

    /// Compact JSON, ready to be rendered into a QR by the caller.
    pub fn encode(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Error::PairingEncode)
    }

    /// Parse a scanned payload. Version and cross-signature are checked here so
    /// no caller can skip them.
    pub fn decode(text: &str) -> Result<Self> {
        let payload: Self = serde_json::from_str(text).map_err(Error::PairingDecode)?;
        if payload.v != QR_PAYLOAD_VERSION {
            return Err(Error::UnsupportedPayloadVersion {
                found: payload.v,
                expected: QR_PAYLOAD_VERSION,
            });
        }
        payload.agent_identity.verify_self_consistent()?;
        Ok(payload)
    }

    /// The rendezvous handle to hand the relay. Never send `pairing_secret`.
    pub fn routing_id(&self) -> crate::pairing::RoutingId {
        self.pairing_secret.routing_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn sample() -> QrPayload {
        let identity = DeviceIdentity::generate();
        QrPayload::new(
            "https://relay.example",
            "acct-1",
            "dev-1",
            identity.public().clone(),
            vec!["192.168.1.20:47010".parse().expect("addr")],
            PairingSecret::generate(),
        )
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let payload = sample();
        let text = payload.encode().expect("encode");
        let back = QrPayload::decode(&text).expect("decode");
        assert_eq!(back.relay_url, payload.relay_url);
        assert_eq!(back.account_id, payload.account_id);
        assert_eq!(back.device_id, payload.device_id);
        assert_eq!(back.agent_identity, payload.agent_identity);
        assert_eq!(back.lan_hints, payload.lan_hints);
        assert_eq!(
            back.pairing_secret.as_bytes(),
            payload.pairing_secret.as_bytes()
        );
        assert_eq!(back.routing_id(), payload.routing_id());
    }

    #[test]
    fn decode_rejects_a_wrong_version() {
        let mut payload = sample();
        payload.v = QR_PAYLOAD_VERSION + 1;
        let text = payload.encode().expect("encode");
        assert!(matches!(
            QrPayload::decode(&text),
            Err(Error::UnsupportedPayloadVersion {
                found: 2,
                expected: 1
            })
        ));
    }

    #[test]
    fn decode_rejects_a_forged_cross_signature() {
        let mut payload = sample();
        payload.agent_identity.noise_static_pub[0] ^= 0x01;
        let text = payload.encode().expect("encode");
        assert!(matches!(
            QrPayload::decode(&text),
            Err(Error::CrossSignature(_))
        ));
    }
}
