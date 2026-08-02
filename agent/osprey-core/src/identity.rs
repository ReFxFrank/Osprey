//! Device identity: an Ed25519 root of trust plus a cross-signed X25519 Noise static.
//!
//! Two keys, not one, because Noise needs a Diffie-Hellman key and Ed25519 is a
//! signature algorithm — an Ed25519 key cannot be handed to a Noise handshake as
//! a static (P0 execution plan §2 #1). The Ed25519 key is therefore the durable,
//! *pinned* root of trust, and the X25519 key is the disposable DH key it
//! vouches for. That split is also the recovery path: if the software X25519
//! key is ever extracted, it is rotated and re-signed without re-pairing the
//! device's identity.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CrossSignatureFailure, Error, Result};
use crate::keystore::Keystore;

/// Domain separator for the identity→static cross-certificate.
///
/// Without this the 32-byte signed message would be indistinguishable from any
/// other 32-byte payload this identity key signs (revocations, challenges), so a
/// signature captured from one context could be replayed as a cross-certificate
/// for an attacker-chosen static key.
const CROSS_SIG_CONTEXT: &[u8] = b"osprey/cross-cert/noise-static/v1";

/// Schema version of the sealed key blob. Bumped only on a layout change; a
/// mismatch is a hard error rather than a best-effort parse.
const STORED_IDENTITY_VERSION: u32 = 1;

/// Keystore entry label under which the device's own identity is sealed.
pub const IDENTITY_LABEL: &str = "device-identity";

fn cross_sig_message(identity_pub: &[u8; 32], noise_static_pub: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CROSS_SIG_CONTEXT.len() + 64);
    msg.extend_from_slice(CROSS_SIG_CONTEXT);
    msg.extend_from_slice(identity_pub);
    msg.extend_from_slice(noise_static_pub);
    msg
}

/// SHA-256 of an Ed25519 identity public key. This is what a human is shown at
/// pairing and what the audit log records, so it names the *durable* key rather
/// than the rotatable Noise static.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint(#[serde(with = "crate::hex32")] pub [u8; 32]);

impl Fingerprint {
    pub fn of_identity(identity_pub: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(CROSS_SIG_CONTEXT);
        h.update(identity_pub);
        Self(h.finalize().into())
    }

    /// First 8 bytes, grouped for reading aloud during pairing confirmation.
    pub fn short(&self) -> String {
        self.0[..8]
            .chunks(2)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The public half of a device identity: what crosses the wire, what goes in the
/// QR code, and what a peer pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    #[serde(with = "crate::hex32")]
    pub identity_pub: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub noise_static_pub: [u8; 32],
    /// Ed25519 signature by `identity_pub` over the domain-separated pair.
    #[serde(with = "crate::hex64")]
    pub noise_static_sig: [u8; 64],
}

impl PublicIdentity {
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_identity(&self.identity_pub)
    }

    /// Verify the cross-certificate standalone (identity key taken from `self`).
    ///
    /// Only meaningful on first sight, before pinning. After pairing, callers
    /// must use [`PinnedPeer::accept_static`] so the identity key comes from the
    /// pin rather than from the message being validated.
    pub fn verify_self_consistent(&self) -> Result<()> {
        verify_cross_signature(
            &self.identity_pub,
            &self.noise_static_pub,
            &self.noise_static_sig,
        )
    }
}

/// Verify that `noise_static_pub` was cross-signed by `identity_pub`.
pub fn verify_cross_signature(
    identity_pub: &[u8; 32],
    noise_static_pub: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(identity_pub)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::BadIdentityKey))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::Malformed))?;
    vk.verify(&cross_sig_message(identity_pub, noise_static_pub), &sig)
        .map_err(|_| Error::CrossSignature(CrossSignatureFailure::NotSignedByIdentity))
}

/// A peer whose identity key has been pinned at pairing.
///
/// The pinned Ed25519 key is permanent; the peer's Noise static may be rotated
/// and is re-accepted through [`Self::accept_static`], which is the *only*
/// sanctioned way to learn a peer static after pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedPeer {
    #[serde(with = "crate::hex32")]
    pub identity_pub: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub noise_static_pub: [u8; 32],
}

impl PinnedPeer {
    /// Pin a peer seen for the first time, after checking its cross-certificate.
    pub fn pin(public: &PublicIdentity) -> Result<Self> {
        public.verify_self_consistent()?;
        Ok(Self {
            identity_pub: public.identity_pub,
            noise_static_pub: public.noise_static_pub,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_identity(&self.identity_pub)
    }

    /// Accept a (possibly rotated) Noise static for this pinned peer.
    ///
    /// The identity key is taken from the pin, never from `public`, so a rotation
    /// offered by an attacker fails signature verification instead of silently
    /// re-rooting trust.
    pub fn accept_static(&mut self, public: &PublicIdentity) -> Result<()> {
        if public.identity_pub != self.identity_pub {
            return Err(Error::UnpinnedPeer);
        }
        verify_cross_signature(
            &self.identity_pub,
            &public.noise_static_pub,
            &public.noise_static_sig,
        )?;
        self.noise_static_pub = public.noise_static_pub;
        Ok(())
    }

    /// Constant-time-independent equality against the static a handshake actually
    /// used. Public keys are not secret, so a data-dependent compare is fine.
    pub fn matches_handshake_static(&self, remote_static: &[u8]) -> bool {
        remote_static == self.noise_static_pub
    }
}

/// On-disk form of the private key material. Both fields are secret.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredIdentity {
    #[zeroize(skip)]
    version: u32,
    identity_secret: [u8; 32],
    noise_static_secret: [u8; 32],
}

/// This device's full identity, private halves included.
pub struct DeviceIdentity {
    identity: SigningKey,
    noise_static: StaticSecret,
    public: PublicIdentity,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("fingerprint", &self.public.fingerprint())
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Generate a fresh identity and its first cross-signed Noise static.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let identity = SigningKey::generate(&mut rng);
        let noise_static = StaticSecret::random_from_rng(&mut rng);
        Self::assemble(identity, noise_static)
    }

    fn assemble(identity: SigningKey, noise_static: StaticSecret) -> Self {
        let identity_pub = identity.verifying_key().to_bytes();
        let noise_static_pub = X25519Public::from(&noise_static).to_bytes();
        let sig = identity.sign(&cross_sig_message(&identity_pub, &noise_static_pub));
        let public = PublicIdentity {
            identity_pub,
            noise_static_pub,
            noise_static_sig: sig.to_bytes(),
        };
        Self {
            identity,
            noise_static,
            public,
        }
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }

    /// Raw 32-byte X25519 private key, the form `snow` requires.
    pub fn noise_static_secret(&self) -> [u8; 32] {
        self.noise_static.to_bytes()
    }

    /// Sign an application payload (for example a `pair.revoke`) under the
    /// durable identity key. Callers must supply their own domain separator;
    /// [`CROSS_SIG_CONTEXT`] is reserved for cross-certificates.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.identity.sign(message).to_bytes()
    }

    /// Replace the Noise static with a fresh one, re-signed by the same identity.
    ///
    /// Peers keep their pin on the identity key and re-accept the new static via
    /// [`PinnedPeer::accept_static`], so rotation does not require re-pairing.
    pub fn rotate_noise_static(&mut self) {
        let mut rng = rand_core::OsRng;
        let identity = self.identity.clone();
        *self = Self::assemble(identity, StaticSecret::random_from_rng(&mut rng));
    }

    /// Seal the private key material into the keystore under [`IDENTITY_LABEL`].
    pub fn save<K: Keystore + ?Sized>(&self, keystore: &K) -> Result<()> {
        let stored = StoredIdentity {
            version: STORED_IDENTITY_VERSION,
            identity_secret: self.identity.to_bytes(),
            noise_static_secret: self.noise_static.to_bytes(),
        };
        let mut json = serde_json::to_vec(&stored).map_err(Error::PairingEncode)?;
        let result = keystore
            .store(IDENTITY_LABEL, &json)
            .map_err(|source| Error::Keystore {
                label: IDENTITY_LABEL.to_string(),
                source,
            });
        json.zeroize();
        result
    }

    /// Load a previously sealed identity, or `None` if the device is unenrolled.
    pub fn load<K: Keystore + ?Sized>(keystore: &K) -> Result<Option<Self>> {
        let Some(bytes) = keystore
            .load(IDENTITY_LABEL)
            .map_err(|source| Error::Keystore {
                label: IDENTITY_LABEL.to_string(),
                source,
            })?
        else {
            return Ok(None);
        };
        let stored: StoredIdentity =
            serde_json::from_slice(&bytes).map_err(|e| Error::Keystore {
                label: IDENTITY_LABEL.to_string(),
                source: crate::error::KeystoreError::Decode(e),
            })?;
        if stored.version != STORED_IDENTITY_VERSION {
            return Err(Error::Keystore {
                label: IDENTITY_LABEL.to_string(),
                source: crate::error::KeystoreError::SchemaVersion {
                    found: stored.version,
                    expected: STORED_IDENTITY_VERSION,
                },
            });
        }
        Ok(Some(Self::assemble(
            SigningKey::from_bytes(&stored.identity_secret),
            StaticSecret::from(stored.noise_static_secret),
        )))
    }

    /// Load the sealed identity, generating and sealing one on first run.
    pub fn load_or_create<K: Keystore + ?Sized>(keystore: &K) -> Result<Self> {
        if let Some(existing) = Self::load(keystore)? {
            return Ok(existing);
        }
        let fresh = Self::generate();
        fresh.save(keystore)?;
        Ok(fresh)
    }
}
