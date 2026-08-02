//! The agent's local, authoritative record of who it is and who it trusts.
//!
//! The pinned-peer list here is the **enforcement point** for unpairing
//! (execution plan §3, task D3). A LAN session never touches the relay, so a
//! relay-side revocation cannot stop one; conversely a hostile relay must not be
//! able to reinstate a pin it does not hold. Both properties follow from the
//! same rule: this file decides, and the relay is told afterwards as a courtesy.
//!
//! Secrets do not live here. The relay device token is sealed in the keystore
//! alongside the private keys, so `state.json` contains only material that is
//! already public or is a pin — which is exactly the material an operator should
//! be able to read to audit what the agent trusts.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use osprey_core::identity::{Fingerprint, PinnedPeer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped on any layout change; a mismatch is a hard error, never a lossy parse.
pub const STATE_VERSION: u32 = 1;

/// Keystore label under which the relay device token is sealed.
pub const RELAY_TOKEN_LABEL: &str = "relay-device-token";

/// A controller this agent has pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPeer {
    pub pinned: PinnedPeer,
    /// The peer's relay device id, present only when the pairing was brokered
    /// through a relay. `None` for a LAN-only pairing, which is a complete and
    /// supported pairing — the relay is not part of the trust decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_device_id: Option<Uuid>,
    /// Wall-clock pin time in milliseconds since the Unix epoch, for display and
    /// for correlating with the audit log.
    pub paired_at_ms: i64,
}

impl PairedPeer {
    pub fn fingerprint(&self) -> Fingerprint {
        self.pinned.fingerprint()
    }
}

/// What the agent needs to talk to a relay it has enrolled with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEnrolment {
    pub base_url: String,
    pub account_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    /// Stable identifier for this agent, generated once. Independent of the
    /// relay's device id so a LAN-only agent still has one.
    device_id: Uuid,
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<RelayEnrolment>,
    #[serde(default)]
    peers: Vec<PairedPeer>,
}

/// How the operator named a peer on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSelector {
    /// Every pinned peer.
    All,
    /// A relay device id.
    DeviceId(Uuid),
    /// A lowercase hex prefix of the peer's identity fingerprint, at least
    /// [`MIN_FINGERPRINT_PREFIX`] characters. This is what `pair` prints, and it
    /// is the only identifier a LAN-only pairing has.
    FingerprintPrefix(String),
}

/// Short enough to type, long enough that a typo does not silently select a
/// different peer.
pub const MIN_FINGERPRINT_PREFIX: usize = 8;

impl PeerSelector {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }
        if let Ok(id) = Uuid::parse_str(trimmed) {
            return Ok(Self::DeviceId(id));
        }
        // `pair` prints the fingerprint grouped as `aabb-ccdd-...`; accept it
        // back in the form it was displayed.
        let normalised: String = trimmed
            .chars()
            .filter(|c| *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if normalised.len() >= MIN_FINGERPRINT_PREFIX
            && normalised.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Ok(Self::FingerprintPrefix(normalised));
        }
        Err(anyhow!(
            "{raw:?} is not `all`, a device uuid, or a fingerprint prefix of at \
             least {MIN_FINGERPRINT_PREFIX} hex characters"
        ))
    }

    pub fn matches(&self, peer: &PairedPeer) -> bool {
        match self {
            Self::All => true,
            Self::DeviceId(id) => peer.relay_device_id == Some(*id),
            Self::FingerprintPrefix(prefix) => peer.fingerprint().to_string().starts_with(prefix),
        }
    }
}

impl std::fmt::Display for PeerSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => f.write_str("all pinned controllers"),
            Self::DeviceId(id) => write!(f, "relay device {id}"),
            Self::FingerprintPrefix(prefix) => write!(f, "fingerprint prefix {prefix}"),
        }
    }
}

/// The on-disk state, loaded into memory.
#[derive(Debug)]
pub struct HostState {
    path: PathBuf,
    file: StateFile,
}

impl HostState {
    /// Load the state file, creating one with a fresh device id on first run.
    pub fn load_or_create(path: impl AsRef<Path>, display_name: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        match fs::read(&path) {
            Ok(bytes) => {
                let file: StateFile = serde_json::from_slice(&bytes)
                    .with_context(|| format!("{} is not valid Osprey state", path.display()))?;
                if file.version != STATE_VERSION {
                    return Err(anyhow!(
                        "{} is schema version {}, this build writes version {STATE_VERSION}",
                        path.display(),
                        file.version
                    ));
                }
                Ok(Self { path, file })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let state = Self {
                    path,
                    file: StateFile {
                        version: STATE_VERSION,
                        device_id: Uuid::new_v4(),
                        display_name: display_name.to_owned(),
                        relay: None,
                        peers: Vec::new(),
                    },
                };
                state.save()?;
                Ok(state)
            }
            Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
        }
    }

    /// Read only the pinned peers, without taking ownership of the state.
    ///
    /// Used by the revocation watcher, which must see an unpair performed by a
    /// *different* process (the P0 `unpair` subcommand) without holding the file
    /// open between polls.
    pub fn read_peers(path: impl AsRef<Path>) -> Result<Vec<PairedPeer>> {
        let path = path.as_ref();
        match fs::read(path) {
            Ok(bytes) => {
                let file: StateFile = serde_json::from_slice(&bytes)
                    .with_context(|| format!("{} is not valid Osprey state", path.display()))?;
                Ok(file.peers)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn device_id(&self) -> Uuid {
        self.file.device_id
    }

    pub fn display_name(&self) -> &str {
        &self.file.display_name
    }

    pub fn relay(&self) -> Option<&RelayEnrolment> {
        self.file.relay.as_ref()
    }

    pub fn peers(&self) -> &[PairedPeer] {
        &self.file.peers
    }

    /// The pin list in the form [`osprey_core::channel::accept`] expects.
    pub fn pins(&self) -> Vec<PinnedPeer> {
        self.file.peers.iter().map(|p| p.pinned.clone()).collect()
    }

    pub fn set_relay(&mut self, relay: RelayEnrolment) -> Result<()> {
        self.file.relay = Some(relay);
        self.save()
    }

    /// Pin a peer. Re-pairing an already-pinned identity replaces the record
    /// rather than adding a second one, so the peer's *current* Noise static is
    /// the only one that will ever be accepted.
    pub fn add_peer(&mut self, peer: PairedPeer) -> Result<()> {
        self.file
            .peers
            .retain(|existing| existing.pinned.identity_pub != peer.pinned.identity_pub);
        self.file.peers.push(peer);
        self.save()
    }

    /// Remove every peer matching `selector`, returning what was removed.
    pub fn remove_peers(&mut self, selector: &PeerSelector) -> Result<Vec<PairedPeer>> {
        let (removed, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.file.peers)
            .into_iter()
            .partition(|peer| selector.matches(peer));
        self.file.peers = kept;
        // Persist before returning even when nothing matched: the caller uses a
        // successful return as "the pin is gone", and a write that never
        // happened would make that a lie the first time the set does change.
        self.save()?;
        Ok(removed)
    }

    /// Write the state atomically: a torn write here would strand the device's
    /// pin list, which is the thing that decides who may connect.
    fn save(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent directory", self.path.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(&self.file).context("could not encode agent state")?;

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options
            .open(&tmp)
            .with_context(|| format!("could not open {}", tmp.display()))?;
        handle
            .write_all(&body)
            .with_context(|| format!("could not write {}", tmp.display()))?;
        handle
            .sync_all()
            .with_context(|| format!("could not flush {}", tmp.display()))?;
        drop(handle);
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("could not replace {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osprey_core::identity::DeviceIdentity;

    fn peer(seed: u8) -> PairedPeer {
        let identity = DeviceIdentity::generate();
        let mut pinned = PinnedPeer::pin(identity.public()).expect("pin");
        pinned.identity_pub[0] = seed;
        PairedPeer {
            pinned,
            relay_device_id: None,
            paired_at_ms: 0,
        }
    }

    #[test]
    fn selector_parses_all_uuids_and_fingerprint_prefixes() {
        assert_eq!(PeerSelector::parse("ALL").expect("all"), PeerSelector::All);
        let id = Uuid::new_v4();
        assert_eq!(
            PeerSelector::parse(&id.to_string()).expect("uuid"),
            PeerSelector::DeviceId(id)
        );
        assert_eq!(
            PeerSelector::parse("AABB-CCDD").expect("fingerprint"),
            PeerSelector::FingerprintPrefix("aabbccdd".into())
        );
        assert!(PeerSelector::parse("aabb").is_err());
        assert!(PeerSelector::parse("not-hex-at-all").is_err());
    }

    #[test]
    fn state_survives_a_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let mut state = HostState::load_or_create(&path, "host").expect("create");
        let device_id = state.device_id();
        state.add_peer(peer(1)).expect("add");

        let reloaded = HostState::load_or_create(&path, "ignored").expect("reload");
        assert_eq!(reloaded.device_id(), device_id);
        assert_eq!(reloaded.peers().len(), 1);
        assert_eq!(HostState::read_peers(&path).expect("read").len(), 1);
    }

    #[test]
    fn removing_by_fingerprint_leaves_other_peers_pinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let mut state = HostState::load_or_create(&path, "host").expect("create");
        let keep = peer(1);
        let drop = peer(2);
        state.add_peer(keep.clone()).expect("add");
        state.add_peer(drop.clone()).expect("add");

        let selector = PeerSelector::parse(&drop.fingerprint().to_string()).expect("selector");
        let removed = state.remove_peers(&selector).expect("remove");
        assert_eq!(removed, vec![drop]);
        assert_eq!(state.peers(), &[keep]);
        assert_eq!(HostState::read_peers(&path).expect("read").len(), 1);
    }

    #[test]
    fn repairing_the_same_identity_replaces_the_pin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let mut state = HostState::load_or_create(&path, "host").expect("create");
        let first = peer(7);
        let mut second = first.clone();
        second.pinned.noise_static_pub = [9u8; 32];
        state.add_peer(first).expect("add");
        state.add_peer(second.clone()).expect("re-add");
        assert_eq!(state.peers(), &[second]);
    }
}
