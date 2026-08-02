//! The runtime context every subcommand shares.
//!
//! `pair`, `run` and `unpair` all need the same four things — the sealed
//! identity, the pin store, the audit log, and somewhere to put the relay token
//! — and they must all resolve them the same way, or an unpair could remove a
//! pin the running agent is not consulting. Assembling them in one place is what
//! makes that impossible.

use anyhow::{Context, Result};
use osprey_core::audit::AuditLog;
use osprey_core::identity::DeviceIdentity;
use osprey_core::keystore::Keystore;
use osprey_core::pairing::PairingContext;

use crate::paths::DataLayout;
use crate::relay::DeviceToken;
use crate::state::{HostState, RELAY_TOKEN_LABEL};

/// The keystore this build uses. Selected at compile time rather than at run
/// time: the dev backend does not encrypt, and a runtime switch is a switch
/// someone can flip on a shipping host.
#[cfg(windows)]
pub type PlatformKeystore = osprey_core::keystore::DpapiKeystore;
#[cfg(not(windows))]
pub type PlatformKeystore = osprey_core::keystore::DevFileKeystore;

pub struct Host {
    pub layout: DataLayout,
    pub keystore: PlatformKeystore,
    pub identity: DeviceIdentity,
    pub state: HostState,
    pub audit: AuditLog,
}

impl Host {
    /// Open the agent's state, generating an identity on first run.
    pub fn open(layout: DataLayout, display_name: &str) -> Result<Self> {
        layout.create()?;
        let keystore = PlatformKeystore::open(&layout.keys)
            .with_context(|| format!("could not open the keystore at {}", layout.keys.display()))?;
        let identity = DeviceIdentity::load_or_create(&keystore)
            .context("could not load or create the device identity")?;
        let state = HostState::load_or_create(&layout.state, display_name)?;
        let audit = AuditLog::open(&layout.audit).with_context(|| {
            format!("could not open the audit log at {}", layout.audit.display())
        })?;
        Ok(Self {
            layout,
            keystore,
            identity,
            state,
            audit,
        })
    }

    /// Open the agent's state at the platform data directory.
    pub fn open_default(display_name: &str) -> Result<Self> {
        Self::open(DataLayout::create_default()?, display_name)
    }

    /// Identifiers stamped onto every audit entry.
    ///
    /// A LAN-only agent has no relay account, and the audit log says so in as
    /// many words rather than inventing an account id — the entry is a security
    /// record, and a plausible-looking uuid that corresponds to nothing would
    /// make it worse than useless.
    pub fn pairing_context(&self) -> PairingContext {
        let account = match self.state.relay() {
            Some(relay) => relay.account_id.to_string(),
            None => "lan-only".to_owned(),
        };
        PairingContext::new(account, self.state.device_id().to_string())
    }

    /// The sealed relay bearer token, if this agent has enrolled.
    pub fn relay_token(&self) -> Result<Option<DeviceToken>> {
        let sealed = self
            .keystore
            .load(RELAY_TOKEN_LABEL)
            .context("could not read the sealed relay token")?;
        let Some(bytes) = sealed else {
            return Ok(None);
        };
        let text = String::from_utf8(bytes)
            .context("the sealed relay token is not valid UTF-8; re-enroll the agent")?;
        Ok(Some(DeviceToken::new(text)))
    }

    pub fn store_relay_token(&self, token: &DeviceToken) -> Result<()> {
        self.keystore
            .store(RELAY_TOKEN_LABEL, token.as_str().as_bytes())
            .context("could not seal the relay token")
    }

    /// Name shown to the operator beside a fingerprint, and sent to the relay.
    pub fn display_name(&self) -> &str {
        self.state.display_name()
    }
}

/// The machine's own name, used as the agent's display name on first run.
pub fn default_display_name() -> String {
    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Some(value) = std::env::var_os(key) {
            let value = value.to_string_lossy().trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    "osprey-host".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_twice_keeps_the_same_identity_and_device_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = DataLayout::under(dir.path());
        let first = Host::open(layout.clone(), "host-a").expect("open");
        let fingerprint = first.identity.fingerprint();
        let device_id = first.state.device_id();
        drop(first);

        let second = Host::open(layout, "ignored").expect("reopen");
        assert_eq!(second.identity.fingerprint(), fingerprint);
        assert_eq!(second.state.device_id(), device_id);
        assert_eq!(second.display_name(), "host-a");
    }

    #[test]
    fn the_relay_token_round_trips_through_the_keystore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = Host::open(DataLayout::under(dir.path()), "host").expect("open");
        assert!(host.relay_token().expect("read").is_none());
        host.store_relay_token(&DeviceToken::new("acct.secret"))
            .expect("store");
        let loaded = host.relay_token().expect("read").expect("a token");
        assert_eq!(loaded.as_str(), "acct.secret");
    }

    #[test]
    fn a_lan_only_agent_audits_without_inventing_an_account_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = Host::open(DataLayout::under(dir.path()), "host").expect("open");
        assert_eq!(host.pairing_context().account_id, "lan-only");
    }
}
