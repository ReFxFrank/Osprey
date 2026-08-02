//! The pairing secret and the routing id derived from it.
//!
//! These two values are what defeat a compromised relay (P0 execution plan §2
//! #2). The secret only ever exists in the QR code on the host's screen and in
//! the phone that photographed it; the relay is given `SHA-256(secret)` and
//! nothing else, so preimage resistance is what stops it recovering the secret
//! and redeeming the pairing as itself.

use std::time::{Duration, SystemTime};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32 bytes — the size Noise requires for a PSK, and comfortably past the
/// ≥128-bit floor the plan sets.
pub const PAIRING_SECRET_LEN: usize = 32;

/// Default validity window for a pairing offer, matching brief §6.1.
pub const DEFAULT_PAIRING_TTL: Duration = Duration::from_secs(120);

/// High-entropy secret carried in the QR. Never sent to the relay.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret(#[serde(with = "crate::hex32")] [u8; PAIRING_SECRET_LEN]);

impl PairingSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; PAIRING_SECRET_LEN];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; PAIRING_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PAIRING_SECRET_LEN] {
        &self.0
    }

    /// `SHA-256(pairing_secret)` — the rendezvous handle the relay stores.
    ///
    /// Deliberately a bare hash with no domain separator: the iOS client derives
    /// the same value independently, and a spec both implementations can state
    /// in one line is worth more here than the marginal benefit of a prefix on a
    /// value that is used for exactly one purpose.
    pub fn routing_id(&self) -> RoutingId {
        let mut h = Sha256::new();
        h.update(self.0);
        RoutingId(h.finalize().into())
    }
}

// The secret must never reach a log line, a panic message, or a bug report.
impl std::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingSecret(redacted)")
    }
}

/// Public rendezvous handle. Safe to hand to an untrusted relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingId(#[serde(with = "crate::hex32")] pub [u8; 32]);

impl std::fmt::Display for RoutingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// A pairing the host has opened and is waiting on.
///
/// Single-use and time-boxed *locally*, because the agent's own state is
/// authoritative — the relay is untrusted and cannot be relied on to enforce
/// either property.
#[derive(Debug)]
pub struct PairingOffer {
    secret: PairingSecret,
    created_at: SystemTime,
    ttl: Duration,
    consumed: bool,
}

impl PairingOffer {
    pub fn new(secret: PairingSecret, ttl: Duration) -> Self {
        Self {
            secret,
            created_at: SystemTime::now(),
            ttl,
            consumed: false,
        }
    }

    /// Open a fresh offer with the default 120-second window.
    pub fn generate() -> Self {
        Self::new(PairingSecret::generate(), DEFAULT_PAIRING_TTL)
    }

    pub fn secret(&self) -> &PairingSecret {
        &self.secret
    }

    pub fn routing_id(&self) -> RoutingId {
        self.secret.routing_id()
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// A clock that has gone backwards is treated as expiry rather than as
    /// unlimited validity.
    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(self.created_at) {
            Ok(elapsed) => elapsed > self.ttl,
            Err(_) => true,
        }
    }

    pub(crate) fn consume(&mut self) {
        self.consumed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_id_is_sha256_of_the_secret() {
        let secret = PairingSecret::from_bytes([0u8; 32]);
        let expected: [u8; 32] = Sha256::digest([0u8; 32]).into();
        assert_eq!(secret.routing_id().0, expected);
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let secret = PairingSecret::from_bytes([0xABu8; 32]);
        assert_eq!(format!("{secret:?}"), "PairingSecret(redacted)");
    }

    #[test]
    fn zero_ttl_offer_is_expired() {
        let offer = PairingOffer::new(PairingSecret::generate(), Duration::ZERO);
        std::thread::sleep(Duration::from_millis(2));
        assert!(offer.is_expired());
    }
}
