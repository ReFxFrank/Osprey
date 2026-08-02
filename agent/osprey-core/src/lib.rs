//! Osprey's trust spine: device identity, sealed key storage, the Noise
//! channel, QR pairing, and the audit log.
//!
//! Everything here runs on a path a remote peer can reach, so the crate has no
//! `unwrap`, no `expect`, and no `panic!` outside test code — a malformed
//! network message must surface as [`error::Error`], never as a downed service.

#![forbid(unsafe_op_in_unsafe_fn)]
// Test code is allowed to assert; shipping code is not.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod audit;
pub mod channel;
pub mod error;
pub mod identity;
pub mod keystore;
pub mod noise;
pub mod pairing;

#[path = "hexser.rs"]
mod hexser;
pub(crate) use hexser::{hex32, hexbytes};

pub use error::{Error, Result};
