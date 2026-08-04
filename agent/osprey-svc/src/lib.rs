//! The P0 Osprey agent console.
//!
//! Brief §6.1 starts pairing from the agent's tray menu, but the tray lives in
//! `osprey-helper` and the Windows service wrapper are both P1 deliverables, so
//! P0's entry point is a console binary (P0 execution plan §2 #5). Every
//! decision that matters — key handling, the Noise handshakes, what gets pinned,
//! what gets audited — lives in `osprey-core`; this crate is the parts that
//! cannot: process lifecycle, the LAN socket, the terminal QR, the relay HTTP
//! calls, and the local pin store. That split is deliberate so the P1 tray
//! becomes another caller of these functions rather than a rewrite of them.
//!
//! Exposed as a library as well as a binary because the P0 gate's end-to-end
//! pairing test has to drive both peers in one process.

#![forbid(unsafe_op_in_unsafe_fn)]
// Every module here is reachable from a socket a remote peer connects to.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod cli;
pub mod commands;
pub mod discovery;
pub mod helper;
pub mod host;
pub mod lan;
pub mod metrics;
pub mod pacing;
pub mod paths;
pub mod qrterm;
pub mod registry;
pub mod relay;
pub mod revoke;
pub mod service;
pub mod session;
pub mod state;
