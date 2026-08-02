//! The three P0 subcommands.
//!
//! Each is a plain function over a [`crate::host::Host`] that writes its
//! operator-facing output to a caller-supplied sink, so the P1 tray helper can
//! call the same code without a console and the P0 gate test can call it without
//! a terminal.

pub mod pair;
pub mod run;
pub mod unpair;
