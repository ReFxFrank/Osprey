//! The inbound rule that makes the direct-LAN path work without a prompt.
//!
//! Amendment A7 scopes the agent's listener to private and link-local
//! addresses, so the rule is created on the **Private** profile only — never
//! Public, and never "all profiles". Without the rule the first `run` pops a
//! Windows firewall dialog, which is the second prompt the installer exists to
//! remove; with it scoped wider, the agent would be reachable on networks the
//! design says it must not be.
//!
//! Driven through the firewall's COM API rather than `netsh` for the same
//! reason the ACL avoids `icacls`: `netsh advfirewall firewall add rule` does
//! not deduplicate by name, reports through localised text, and gives a caller
//! no typed failure to propagate.

use std::path::Path;

use anyhow::{Context, Result};
use windows::core::BSTR;
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_PROFILE2_PRIVATE, NET_FW_RULE_DIR_IN,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};

/// Name the rule is created and removed under. Stable, because uninstall finds
/// it by exactly this string.
pub const RULE_NAME: &str = "Osprey LAN listener";

/// Initialises COM for the current thread and uninitialises it on drop.
struct ComApartment;

impl ComApartment {
    fn enter() -> Result<Self> {
        // SAFETY: paired with the CoUninitialize in `Drop`.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
            .ok()
            .context("could not initialise COM for the firewall API")?;
        Ok(ComApartment)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: paired with the CoInitializeEx in `enter`.
        unsafe { CoUninitialize() };
    }
}

/// Allow inbound TCP to this executable on `port`, Private profile only.
///
/// Replaces any existing rule of the same name rather than adding a second, so
/// reinstalling does not accumulate duplicates.
pub fn allow_inbound(port: u16) -> Result<()> {
    let executable =
        std::env::current_exe().context("could not locate the agent executable for the rule")?;
    create_rule(&executable, port)
}

/// Remove the rule this installer created. Absence is success.
pub fn remove_inbound() -> Result<()> {
    let _com = ComApartment::enter()?;
    let rules = open_rules()?;
    let name = BSTR::from(RULE_NAME);

    // SAFETY: `rules` is a live interface pointer and `name` outlives the call.
    if unsafe { rules.Item(&name) }.is_err() {
        return Ok(());
    }
    // SAFETY: as above; the rule was just observed to exist.
    unsafe { rules.Remove(&name) }.context("could not remove the firewall rule")
}

fn create_rule(executable: &Path, port: u16) -> Result<()> {
    let _com = ComApartment::enter()?;
    let rules = open_rules()?;
    let name = BSTR::from(RULE_NAME);

    // `Item` is the existence probe so that a genuine `Remove` failure stays an
    // error instead of being discarded to make the call idempotent.
    // SAFETY: `rules` is live; `name` outlives both calls.
    if unsafe { rules.Item(&name) }.is_ok() {
        unsafe { rules.Remove(&name) }.context("could not replace the existing firewall rule")?;
    }

    // SAFETY: the CLSID and the interface match.
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .context("could not create a firewall rule object")?;

    // SAFETY: `rule` is live and every BSTR outlives the call it is passed to.
    unsafe {
        rule.SetName(&name)?;
        rule.SetDescription(&BSTR::from(
            "Inbound connections from paired Osprey controllers on the local network.",
        ))?;
        rule.SetApplicationName(&BSTR::from(executable.to_string_lossy().as_ref()))?;
        // These two take the raw i32 rather than the newtype.
        rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
        rule.SetLocalPorts(&BSTR::from(port.to_string()))?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        rule.SetProfiles(NET_FW_PROFILE2_PRIVATE.0)?;
        rule.SetEnabled(VARIANT_TRUE)?;
        rules.Add(&rule)?;
    }
    Ok(())
}

fn open_rules() -> Result<windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules> {
    // SAFETY: the CLSID and the interface match; NetFwPolicy2 is in-proc.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .context("could not open the Windows Firewall policy")?;
    // SAFETY: `policy` is a live interface pointer.
    unsafe { policy.Rules() }.context("could not open the firewall rule collection")
}
