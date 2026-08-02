//! Placeholder for the user-session helper.
//!
//! Everything this crate will contain — the tray icon, screen capture, and
//! `SendInput` — is a P1 deliverable and cannot live in `osprey-svc`, which runs
//! in Session 0 with no desktop. The crate exists at P0 only so the workspace
//! layout matches brief §11 and so the P1 phase adds code rather than plumbing.
//!
//! It is deliberately empty. A stub tray or a fake capture surface here would be
//! exactly the plausible-looking fiction that makes a phase gate meaningless.

#![forbid(unsafe_op_in_unsafe_fn)]
