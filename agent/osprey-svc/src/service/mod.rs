//! Windows service registration and lifecycle.
//!
//! The agent is one binary in two modes. `osprey-svc run` is the developer's
//! console mode; the Service Control Manager starts the same executable with
//! the hidden `service` subcommand, and everything below the entry point is the
//! same code path. That is deliberate — a service that only works when the SCM
//! starts it is a service nobody can debug.
//!
//! Session 0 rules apply to everything here: this process has no desktop and
//! may never acquire one. `ServiceType::INTERACTIVE_PROCESS` exists in the
//! dependency's flags and is exactly the mistake brief §9.1 warns about.

use std::path::PathBuf;

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod windows_impl;
#[cfg(windows)]
pub use windows_impl::{dispatch, harden_data_dir, install, uninstall};

#[cfg(not(windows))]
mod unsupported;
#[cfg(not(windows))]
pub use unsupported::{dispatch, harden_data_dir, install, uninstall};

/// Registry key and SCM name.
pub const SERVICE_NAME: &str = "Osprey";

/// What an operator sees in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "Osprey Agent";

pub const SERVICE_DESCRIPTION: &str =
    "Remote access agent. Serves paired controllers over the local network and, \
     when configured, through the Osprey relay.";

/// What `install` was asked to register.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Port baked into the registered command line.
    pub port: u16,
    pub advertise_mdns: bool,
    /// Create the inbound firewall rule for `port` on the Private profile.
    pub firewall_rule: bool,
    /// Start the service once it is registered.
    pub start: bool,
}

#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub remove_firewall_rule: bool,
}

/// How the service should run once the SCM hands control over.
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    pub port: u16,
    pub advertise_mdns: bool,
    /// Overrides the platform data directory. Only ever set by tests and by
    /// `--data-dir`; the shipping service uses the default.
    pub data_dir: Option<PathBuf>,
}

/// Whether the process was actually started by the Service Control Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatched {
    /// The dispatcher connected, ran the service to completion and returned.
    AsService,
    /// This process is not running under the SCM. The caller should fall back
    /// to console mode instead of failing — this is what an operator gets when
    /// they run the hidden subcommand by hand.
    NotUnderScm,
}
