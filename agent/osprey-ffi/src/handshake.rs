//! The phone's half of both Noise handshakes.
//!
//! The phone is always the initiator and the agent always the responder: IK
//! requires the initiator to know the responder's static up front, and only the
//! QR (or, afterwards, the pin) supplies it. There is therefore no responder
//! constructor here, and adding one would mean the phone had learned an agent
//! static from somewhere other than physical access.
//!
//! The phone's X25519 Noise static is a *software* key. The Secure Enclave holds
//! only the P-256 identity key and never exports it, so the private scalar Noise
//! needs cannot live there — the Enclave's job is to cross-sign the X25519
//! public key, not to be it (brief amendment A4).

use std::sync::{Arc, Mutex};

use osprey_core::noise::{Handshake, HandshakeConfig, Pattern, Role};
use osprey_core::pairing::PairingSecret;
use zeroize::Zeroize;

use crate::error::{key32, lock, OspreyError, Result};
use crate::framing::{push_bounded, take_frame};
use crate::session::NoiseTransport;

struct Inner {
    /// `None` once [`NoiseHandshake::into_transport`] has consumed it.
    state: Option<Handshake>,
    inbound: Vec<u8>,
    writes: u32,
    reads: u32,
}

/// A Noise handshake in progress. Byte-in, byte-out: Swift owns the socket.
#[derive(uniffi::Object)]
pub struct NoiseHandshake {
    inner: Mutex<Inner>,
}

impl NoiseHandshake {
    fn wrap(state: Handshake) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                state: Some(state),
                inbound: Vec::new(),
                writes: 0,
                reads: 0,
            }),
        })
    }
}

#[uniffi::export]
impl NoiseHandshake {
    /// Build the first-contact handshake: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
    /// with the QR's 32-byte `pairing_secret` as the PSK.
    ///
    /// The PSK is what a hostile relay cannot supply, so it — not the relay's
    /// routing — is what binds this handshake to the host whose screen was
    /// photographed.
    ///
    /// `local_static` is zeroized before this returns; the copy `snow` keeps is
    /// inside the returned object.
    #[uniffi::constructor]
    pub fn pairing_initiator(
        local_static: Vec<u8>,
        remote_static: Vec<u8>,
        psk: Vec<u8>,
    ) -> Result<Arc<Self>> {
        let secret = PairingSecret::from_bytes(key32("pairing secret", &psk)?);
        build(Pattern::Pairing, local_static, remote_static, Some(&secret))
    }

    /// Build a post-pairing handshake: plain `Noise_IK_25519_ChaChaPoly_BLAKE2s`
    /// on the pinned statics. The pin is the authentication, so the pairing
    /// secret is deliberately *not* carried forward.
    #[uniffi::constructor]
    pub fn session_initiator(local_static: Vec<u8>, remote_static: Vec<u8>) -> Result<Arc<Self>> {
        build(Pattern::Session, local_static, remote_static, None)
    }

    /// Produce the next handshake message carrying `payload`, already framed and
    /// ready to write to the socket.
    pub fn write_message(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let mut inner = lock(&self.inner)?;
        let message = inner.state_mut()?.write_message(&payload)?;
        inner.writes += 1;
        crate::framing::frame_encode(message)
    }

    /// Hand over bytes just read from the socket.
    pub fn push_bytes(&self, data: Vec<u8>) -> Result<()> {
        let mut inner = lock(&self.inner)?;
        push_bounded(&mut inner.inbound, &data)
    }

    /// Consume one buffered handshake message, returning its decrypted payload,
    /// or `None` when a complete frame has not arrived yet.
    ///
    /// A tampered byte anywhere in the message surfaces as
    /// [`OspreyError::HandshakeRejected`] with `stage = "read"`. It is never
    /// tolerated and never panics.
    pub fn read_message(&self) -> Result<Option<Vec<u8>>> {
        let mut inner = lock(&self.inner)?;
        let Some(frame) = take_frame(&mut inner.inbound)? else {
            return Ok(None);
        };
        let payload = inner.state_mut()?.read_message(&frame)?;
        inner.reads += 1;
        Ok(Some(payload))
    }

    /// Whether both handshake messages have been exchanged.
    ///
    /// Counted here rather than asked of `snow`, because `osprey-core`'s
    /// `Handshake` does not expose the flag. Both patterns this bridge can build
    /// are two-message IK variants driven from the initiator side, so one write
    /// plus one read *is* the finished condition. It is a convenience for the
    /// UI, not a safety check: [`Self::into_transport`] is authoritative, and
    /// `snow` refuses to promote a handshake that has not completed.
    pub fn is_handshake_finished(&self) -> Result<bool> {
        let inner = lock(&self.inner)?;
        Ok(inner.writes >= 1 && inner.reads >= 1)
    }

    /// Promote the completed handshake into a transport session.
    ///
    /// Any bytes already buffered past the handshake — the agent may pipeline
    /// its first transport message into the same TCP segment — move across with
    /// it, so nothing is lost at the boundary.
    pub fn into_transport(&self) -> Result<Arc<NoiseTransport>> {
        let mut inner = lock(&self.inner)?;
        let state = inner.state.take().ok_or_else(|| OspreyError::SessionState {
            detail: "handshake has already been promoted to a transport session".to_string(),
        })?;
        let leftover = std::mem::take(&mut inner.inbound);
        let session = state.into_session()?;
        Ok(Arc::new(NoiseTransport::from_session(session, leftover)))
    }
}

impl Inner {
    fn state_mut(&mut self) -> Result<&mut Handshake> {
        self.state.as_mut().ok_or_else(|| OspreyError::SessionState {
            detail: "handshake has already been promoted to a transport session".to_string(),
        })
    }
}

fn build(
    pattern: Pattern,
    local_static: Vec<u8>,
    remote_static: Vec<u8>,
    psk: Option<&PairingSecret>,
) -> Result<Arc<NoiseHandshake>> {
    let mut private = local_static;
    let mut local = key32("noise static private key", &private)?;
    private.zeroize();
    let remote = key32("agent noise static public key", &remote_static)?;
    let state = Handshake::new(HandshakeConfig {
        pattern,
        role: Role::Initiator,
        local_static: &local,
        remote_static: Some(&remote),
        psk,
    });
    local.zeroize();
    Ok(NoiseHandshake::wrap(state?))
}
