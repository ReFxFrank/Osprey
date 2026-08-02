//! Osprey wire protocol types.
//!
//! Everything under [`generated`] is produced by `proto/generate.ts` from
//! `proto/messages.toml`, which is the single source of truth for the wire.
//! Run `pnpm generate` in `proto/` after changing the registry; never hand-edit
//! a file under `src/generated/` and never add a parallel enum here.
//!
//! Decoding is two steps by design — parse the [`Envelope`], then
//! [`Envelope::decode_body`] — so a body that fails validation reports which
//! message type it claimed to be instead of a bare "invalid JSON".

// This crate sits directly on the network: every byte it parses arrives from a
// peer. A panic here is a remote denial of service, so the two panic-by-default
// combinators are denied outright rather than left to review.
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub(crate) mod b64;
pub mod error;
pub mod generated;

pub use error::{ProtoError, UnknownMessageType};
pub use generated::*;
