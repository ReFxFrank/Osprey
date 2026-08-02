//! The established Noise transport, driven by byte pushes instead of a socket.
//!
//! ## Why inbound messages are limited to one chunk
//!
//! `osprey_core::noise::NoiseSession` reads and reassembles a logical message
//! through `std::io::Read`, i.e. it *blocks* until the message's last chunk
//! arrives. A phone driving a non-blocking socket cannot supply that: it has
//! whatever bytes the last `recv(2)` returned, and it needs an answer now.
//!
//! Feeding `recv` a short buffer is not a recoverable "try again". The chunks it
//! already decrypted have advanced the AEAD nonce and their plaintext is dropped
//! on the floor when it returns `TruncatedFrame`, so a retry would decrypt the
//! remainder against a state that has silently lost the head of the message.
//! There is no way to detect a chunk boundary from outside the ciphertext either
//! — the continuation flag is *inside* the AEAD, which is exactly what makes
//! truncation attacks fail, so the property that protects the wire is the same
//! property that forbids peeking.
//!
//! So this bridge hands `recv` exactly one complete frame at a time, and lowers
//! the session's reassembly cap to one chunk so the bound is enforced by the
//! core rather than restated here. A multi-chunk inbound message is refused with
//! [`OspreyError::MessageTooLarge`] and kills the session; it is never partially
//! accepted. Outbound is unaffected — the agent reads from a blocking stream, so
//! [`NoiseTransport::encrypt`] chunks payloads of any size normally.
//!
//! TODO(frank): decide which side moves. Either `osprey-core` grows an
//! incremental per-frame decrypt on `NoiseSession` (e.g. `decrypt_frame(&[u8])
//! -> Option<Vec<u8>>` holding reassembly state across calls), which lets the
//! phone accept messages up to the full 4 MiB cap; or the protocol fixes
//! agent→phone messages at or below `max_chunk_payload_len()` (65518 bytes) and
//! P4's file transfer sizes its chunks accordingly. This bridge cannot pick:
//! the first is a change to a crate it does not own, the second is a protocol
//! constraint that belongs in `proto/messages.toml`.

use std::io::Cursor;
use std::sync::Mutex;

use osprey_core::noise::{NoiseSession, MAX_CHUNK_PAYLOAD_LEN};

use crate::error::{lock, OspreyError, Result};
use crate::framing::{complete_frame_len, push_bounded};

struct Inner {
    session: NoiseSession,
    inbound: Vec<u8>,
    /// Set once the channel has failed authentication or framing. A Noise
    /// session cannot be resynchronised after either, so every later call is
    /// refused rather than allowed to operate on a desynchronised cipher state.
    failed: Option<String>,
}

/// A live, authenticated channel to the agent.
#[derive(uniffi::Object)]
pub struct NoiseTransport {
    inner: Mutex<Inner>,
}

impl NoiseTransport {
    /// Wrap a completed Noise session. Rust-side only — the FFI surface reaches
    /// a transport through [`crate::NoiseHandshake::into_transport`], which is
    /// the only path that can produce a session in the first place.
    pub fn from_session(mut session: NoiseSession, inbound: Vec<u8>) -> Self {
        session.set_max_message_len(MAX_CHUNK_PAYLOAD_LEN);
        Self {
            inner: Mutex::new(Inner {
                session,
                inbound,
                failed: None,
            }),
        }
    }
}

#[uniffi::export]
impl NoiseTransport {
    /// The peer's X25519 static as authenticated by the handshake. Compare this
    /// against the pin before trusting anything that arrives on the channel.
    pub fn remote_static(&self) -> Result<Vec<u8>> {
        let inner = lock(&self.inner)?;
        Ok(inner.session.remote_static().to_vec())
    }

    /// Encrypt `payload` into wire bytes, ready to write to the socket. Payloads
    /// larger than one chunk are split across several frames, all returned in
    /// one buffer and all of which must be written, in order.
    pub fn encrypt(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let mut inner = lock(&self.inner)?;
        inner.check_live()?;
        let mut wire = Vec::new();
        if let Err(err) = inner.session.send(&payload, &mut wire) {
            return Err(inner.fail(err.into()));
        }
        Ok(wire)
    }

    /// Hand over bytes just read from the socket. Bounded: a peer that never
    /// completes a frame is refused rather than allowed to grow the buffer.
    pub fn push_bytes(&self, data: Vec<u8>) -> Result<()> {
        let mut inner = lock(&self.inner)?;
        inner.check_live()?;
        push_bounded(&mut inner.inbound, &data)
    }

    /// Decrypt the next complete message, or `None` if more bytes are needed.
    ///
    /// Call in a loop until it returns `None`: one socket read can carry several
    /// messages.
    pub fn next_message(&self) -> Result<Option<Vec<u8>>> {
        let mut inner = lock(&self.inner)?;
        inner.check_live()?;
        let Some(total) = complete_frame_len(&inner.inbound) else {
            return Ok(None);
        };
        let Inner {
            session, inbound, ..
        } = &mut *inner;
        let outcome = decrypt_one(session, &inbound[..total]);
        match outcome {
            Ok(message) => {
                inbound.drain(..total);
                Ok(Some(message))
            }
            Err(err) => Err(inner.fail(err)),
        }
    }
}

/// Decrypt exactly one framed chunk out of `wire`.
fn decrypt_one(session: &mut NoiseSession, wire: &[u8]) -> Result<Vec<u8>> {
    match session.recv(&mut Cursor::new(wire)) {
        Ok(Some(message)) => Ok(message),
        // `recv` was given one whole frame and nothing else, so a clean EOF
        // before any chunk is impossible — `complete_frame_len` already proved
        // the frame was there.
        Ok(None) => Err(OspreyError::Framing {
            detail: "core reported end-of-stream on a complete frame".to_string(),
        }),
        // The frame decrypted but carried a continuation flag, so `recv` went
        // looking for the next chunk and hit the end of the one-frame buffer.
        // That is not a truncated *stream*; it is a message longer than this
        // bridge can reassemble — see the module comment.
        Err(osprey_core::Error::TruncatedFrame { got: 0, want: 2 }) => {
            Err(OspreyError::MessageTooLarge {
                limit: MAX_CHUNK_PAYLOAD_LEN as u64,
            })
        }
        Err(err) => Err(err.into()),
    }
}

impl Inner {
    fn check_live(&self) -> Result<()> {
        match &self.failed {
            Some(detail) => Err(OspreyError::SessionState {
                detail: format!("session is closed after an earlier failure: {detail}"),
            }),
            None => Ok(()),
        }
    }

    /// Record a fatal channel error and hand it back unchanged.
    fn fail(&mut self, err: OspreyError) -> OspreyError {
        self.failed.get_or_insert_with(|| err.to_string());
        err
    }
}
