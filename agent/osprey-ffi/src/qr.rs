//! The scanned QR payload — the trust bootstrap.
//!
//! The pairing secret deliberately does not cross the FFI boundary as part of
//! the parsed payload. It is the one value that must never reach the relay, and
//! the fewer copies of it exist, the smaller the surface that has to be got
//! right: Swift gets everything it needs to talk to the relay and to show a
//! confirmation screen, and asks [`ScannedQr::start_pairing`] to turn the secret
//! into a handshake without ever holding it.

use std::sync::Arc;

use osprey_core::pairing::{PairingSecret, QrPayload};

use crate::error::{key32, Result};
use crate::handshake::NoiseHandshake;
use crate::identity::{IdentityFingerprint, PeerIdentity};

/// A scanned, version-checked, cross-signature-verified QR payload.
#[derive(uniffi::Object)]
pub struct ScannedQr {
    payload: QrPayload,
}

#[uniffi::export]
impl ScannedQr {
    pub fn relay_url(&self) -> String {
        self.payload.relay_url.clone()
    }

    pub fn account_id(&self) -> String {
        self.payload.account_id.clone()
    }

    pub fn device_id(&self) -> String {
        self.payload.device_id.clone()
    }

    /// Addresses the agent is listening on, as `host:port` strings. Valid by
    /// construction: the phone was standing in front of the host's screen.
    pub fn lan_hints(&self) -> Vec<String> {
        self.payload
            .lan_hints
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The agent's pinned identity and its cross-signed Noise static. The
    /// cross-certificate was verified during parsing.
    pub fn agent_identity(&self) -> PeerIdentity {
        PeerIdentity::from(&self.payload.agent_identity)
    }

    /// What the operator compares on the confirmation screen.
    pub fn agent_fingerprint(&self) -> IdentityFingerprint {
        self.payload.agent_identity.fingerprint().into()
    }

    /// `SHA-256(pairing_secret)` — the rendezvous handle for the relay. Safe to
    /// send; the secret itself never is.
    pub fn routing_id(&self) -> Vec<u8> {
        self.payload.routing_id().0.to_vec()
    }

    /// Begin pairing as the initiator, with this QR's secret as the Noise PSK.
    pub fn start_pairing(
        &self,
        local_noise_static_private: Vec<u8>,
    ) -> Result<Arc<NoiseHandshake>> {
        NoiseHandshake::pairing_initiator(
            local_noise_static_private,
            self.payload.agent_identity.noise_static_pub.to_vec(),
            self.payload.pairing_secret.as_bytes().to_vec(),
        )
    }
}

/// Parse the text a QR scanner produced.
///
/// Rejects an unknown payload version and a bad agent cross-certificate before
/// returning, so a caller cannot skip either check.
#[uniffi::export]
pub fn parse_qr_payload(text: String) -> Result<Arc<ScannedQr>> {
    let payload = QrPayload::decode(&text)?;
    Ok(Arc::new(ScannedQr { payload }))
}

/// `SHA-256(pairing_secret)`, the only value derived from the secret that the
/// relay is ever given.
#[uniffi::export]
pub fn routing_id_from_secret(pairing_secret: Vec<u8>) -> Result<Vec<u8>> {
    let secret = PairingSecret::from_bytes(key32("pairing secret", &pairing_secret)?);
    Ok(secret.routing_id().0.to_vec())
}
