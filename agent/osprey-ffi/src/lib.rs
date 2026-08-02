//! `osprey-ffi` — the Rust↔Swift bridge.
//!
//! The iOS client runs the same `snow` implementation as the Windows agent, so
//! there is one Noise implementation in the product rather than two that have to
//! be kept in agreement. This crate is the seam.
//!
//! Three properties shape the whole surface:
//!
//! * **Small and synchronous.** UniFFI's Swift 6 support is only partial — its
//!   async bindings are not `Sendable` — so nothing here is async and nothing
//!   here touches a socket. Every object is byte-in, byte-out and Swift drives
//!   all networking. That is also the right layering: `URLSession`, Network
//!   framework and the WebRTC data channels are Swift's business, and the crypto
//!   core has no opinion about which of them delivered a byte.
//!
//! * **Errors are typed values, never panics.** A panic unwinding across an FFI
//!   boundary is undefined behaviour. Every fallible entry point returns
//!   [`OspreyError`], and `unwrap`/`expect`/`panic!` are denied crate-wide
//!   outside tests.
//!
//! * **Private keys stay where they belong.** The Secure Enclave P-256 identity
//!   key never leaves Swift, so nothing here ever asks for it — the phone signs
//!   [`cross_certificate_bytes`] itself and hands back only the signature. The
//!   X25519 Noise static *is* software (the Enclave cannot hold one), so its
//!   private half is passed in, copied into `snow`, and zeroized on the way
//!   through.

#![forbid(unsafe_op_in_unsafe_fn)]
// Test code is allowed to assert; shipping code a remote peer can reach is not.
// Same rule as `osprey-core`, for the same reason.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod error;
mod framing;
mod handshake;
mod identity;
mod qr;
mod session;

uniffi::setup_scaffolding!();

pub use error::{CrossSignatureReason, OspreyError};
pub use framing::{
    frame_decode, frame_encode, max_chunk_payload_len, noise_max_message_len, FrameScan,
};
pub use handshake::NoiseHandshake;
pub use identity::{
    cross_certificate_bytes, decode_identity_message, encode_identity_message,
    identity_fingerprint, pair_accept_tag, pair_confirm_tag, verify_identity_bundle,
    IdentityFingerprint, PeerIdentity,
};
pub use qr::{parse_qr_payload, routing_id_from_secret, ScannedQr};
pub use session::NoiseTransport;
