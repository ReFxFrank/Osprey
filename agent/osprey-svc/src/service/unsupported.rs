//! Service registration on platforms that have no Service Control Manager.
//!
//! Windows is the only agent platform (brief §2). These exist so the crate
//! builds and its tests run on the Linux CI host, and every one of them fails
//! with a message that says why rather than pretending to have done something.

use std::path::Path;

use anyhow::{bail, Result};

use crate::service::{Dispatched, InstallOptions, ServiceOptions, UninstallOptions};

pub fn install(_options: &InstallOptions) -> Result<()> {
    bail!("`install` registers a Windows service and only works on Windows")
}

pub fn uninstall(_options: &UninstallOptions) -> Result<()> {
    bail!("`uninstall` removes a Windows service and only works on Windows")
}

pub fn dispatch(_options: &ServiceOptions) -> Result<Dispatched> {
    // Not an error: there is no Service Control Manager to be started by, which
    // is precisely what `NotUnderScm` means. The caller then runs in console
    // mode, so `osprey-svc service` behaves like `run` off Windows instead of
    // dying.
    Ok(Dispatched::NotUnderScm)
}

pub fn harden_data_dir(_dir: &Path) -> Result<()> {
    bail!("the data directory ACL is a Windows access-control boundary and can only be set there")
}
