//! The authenticated, encrypted channel.
//!
//! Two Noise patterns, deliberately separated:
//!
//! * [`Pattern::Pairing`] — `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, with the
//!   32-byte QR `pairing_secret` as the PSK. This is the *only* moment the
//!   phone's key crosses an untrusted relay, so the PSK (which the relay never
//!   sees) is what stops a hostile relay redeeming the pairing as itself or
//!   substituting its own key.
//! * [`Pattern::Session`] — plain `Noise_IK_25519_ChaChaPoly_BLAKE2s` on the
//!   pinned statics. After pairing, the pin *is* the authentication, so carrying
//!   the pairing secret forward would only widen its blast radius.
//!
//! IK requires the initiator to already know the responder's static key. Only
//! the QR provides that, so the phone is always the initiator and the agent
//! always the responder (P0 execution plan §2 #13).

mod framing;
mod handshake;
mod session;

pub use framing::{
    read_frame, write_frame, FrameRead, CHUNK_HEADER_LEN, DEFAULT_MAX_MESSAGE_LEN,
    MAX_CHUNK_PAYLOAD_LEN, NOISE_MAX_MESSAGE_LEN, NOISE_MAX_PLAINTEXT_LEN, NOISE_TAG_LEN,
};
pub use handshake::{Handshake, HandshakeConfig, Pattern, Role};
pub use session::NoiseSession;
