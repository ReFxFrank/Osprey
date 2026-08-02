//! The agent's half of the relay HTTP API.
//!
//! Nothing here is on the trust path. The relay is assumed fully compromised
//! (brief §6.2), so its job is rendezvous and nothing else: it learns
//! `SHA-256(pairing_secret)` and never the secret, it is told about a revocation
//! after that revocation has already taken effect locally, and no answer it
//! gives can cause the agent to pin, unpin, or trust anything. A LAN pairing
//! works with this module never being called at all.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use osprey_core::identity::PublicIdentity;
use osprey_core::pairing::RoutingId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The relay is only ever asked to do small, quick things; a hung relay must
/// never hold up a pairing the operator is standing in front of.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bearer credential for the relay, in the relay's `<accountId>.<secret>` form.
///
/// Sealed in the keystore rather than written to `state.json`, and redacted in
/// `Debug` so it cannot reach a log line or a panic message.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceToken(String);

impl DeviceToken {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    fn header(&self) -> String {
        format!("Bearer {}", self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for DeviceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceToken(redacted)")
    }
}

/// The key material the relay stores for a device. It never verifies these — it
/// cannot, since it holds no trust anchor — it only carries them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerMaterial {
    display_name: String,
    identity_public_key: String,
    identity_algorithm: String,
    noise_static_public_key: String,
    noise_static_signature: String,
}

impl PeerMaterial {
    fn from_identity(display_name: &str, identity: &PublicIdentity) -> Self {
        Self {
            display_name: display_name.to_owned(),
            identity_public_key: BASE64.encode(&identity.identity_pub),
            identity_algorithm: identity.identity_algorithm.to_string(),
            noise_static_public_key: BASE64.encode(identity.noise_static_pub),
            noise_static_signature: BASE64.encode(&identity.noise_static_sig),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrolRequest<'a> {
    enrollment_secret: &'a str,
    #[serde(flatten)]
    material: PeerMaterial,
}

/// What `POST /v1/agents/enroll` gives back.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrolment {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub device_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueTokenRequest {
    routing_id: String,
}

/// What `POST /v1/pairing/tokens` gives back.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingTokenIssued {
    pub token_id: Uuid,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct DeviceListing {
    devices: Vec<DeviceSummary>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSummary {
    id: Uuid,
    identity_public_key: String,
}

pub struct RelayClient {
    base_url: String,
    agent: ureq::Agent,
}

impl RelayClient {
    /// Build a client for `base_url`.
    ///
    /// The scheme is checked because `relay_url` is copied straight out of the
    /// agent's configuration into the QR the phone scans; a typo that produced
    /// something other than an HTTP URL should fail at the host, where a human
    /// is looking, not on the phone.
    pub fn new(base_url: &str) -> Result<Self> {
        let trimmed = base_url.trim_end_matches('/');
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            bail!("relay url {base_url:?} must start with http:// or https://");
        }
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            // Report the relay's own error body instead of a bare status code.
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .build(),
            )
            .build();
        Ok(Self {
            base_url: trimmed.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create this agent's account and device row. First contact only.
    pub fn enrol(
        &self,
        enrollment_secret: &str,
        display_name: &str,
        identity: &PublicIdentity,
    ) -> Result<Enrolment> {
        let request = EnrolRequest {
            enrollment_secret,
            material: PeerMaterial::from_identity(display_name, identity),
        };
        let mut response = self
            .agent
            .post(self.url("/v1/agents/enroll"))
            .send_json(&request)
            .context("could not reach the relay to enroll")?;
        check_status(&mut response, "enroll")?;
        response
            .body_mut()
            .read_json()
            .context("relay returned an unreadable enrollment response")
    }

    /// Register a pending pairing under `routing_id`.
    ///
    /// Only the hash goes over this call. The pairing secret it hashes exists in
    /// the QR on the host's screen and in the phone that photographed it, and
    /// nowhere else — that is what stops a hostile relay redeeming the pairing
    /// as itself (execution plan §2 #2).
    pub fn issue_pairing_token(
        &self,
        token: &DeviceToken,
        routing_id: &RoutingId,
    ) -> Result<PairingTokenIssued> {
        let mut response = self
            .agent
            .post(self.url("/v1/pairing/tokens"))
            .header("authorization", token.header())
            .send_json(IssueTokenRequest {
                routing_id: routing_id.to_string(),
            })
            .context("could not reach the relay to register the pairing")?;
        check_status(&mut response, "pairing token issue")?;
        response
            .body_mut()
            .read_json()
            .context("relay returned an unreadable pairing-token response")
    }

    /// Find the relay's device id for a peer, by its pinned identity key.
    ///
    /// The agent needs this because the relay hands the *client* its device id
    /// at redemption and never tells the host. Matching on the identity key
    /// rather than the Noise static is deliberate: the static is rotatable, the
    /// identity key is the pin. A relay that lies here can at worst cause the
    /// agent to revoke the wrong relay row — it cannot affect the local pin,
    /// which is already gone by the time this is called.
    pub fn find_device_by_identity(
        &self,
        token: &DeviceToken,
        identity_pub: &[u8],
    ) -> Result<Option<Uuid>> {
        let mut response = self
            .agent
            .get(self.url("/v1/devices"))
            .header("authorization", token.header())
            .call()
            .context("could not reach the relay to list devices")?;
        check_status(&mut response, "device list")?;
        let listing: DeviceListing = response
            .body_mut()
            .read_json()
            .context("relay returned an unreadable device list")?;
        let wanted = BASE64.encode(identity_pub);
        Ok(listing
            .devices
            .into_iter()
            .find(|device| device.identity_public_key == wanted)
            .map(|device| device.id))
    }

    /// Tell the relay a controller has been unpaired.
    ///
    /// Called *after* the local pin is already gone. A failure here is reported
    /// but never reverses the unpair: the relay is not the enforcement point and
    /// letting it veto a revocation would hand a compromised relay the ability
    /// to keep a device paired.
    pub fn revoke_device(&self, token: &DeviceToken, device_id: Uuid) -> Result<()> {
        let mut response = self
            .agent
            .delete(self.url(&format!("/v1/devices/{device_id}")))
            .header("authorization", token.header())
            .call()
            .context("could not reach the relay to revoke the device")?;
        // 404 is success in substance: the relay does not have (or will not
        // admit to having) a device to revoke, and the local pin is already
        // gone, so there is nothing left to reconcile.
        if response.status() == 404 {
            tracing::info!(%device_id, "relay reported no such device; local unpair stands");
            return Ok(());
        }
        check_status(&mut response, "device revoke")?;
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

fn check_status(response: &mut ureq::http::Response<ureq::Body>, what: &str) -> Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail = response
        .body_mut()
        .read_to_string()
        .unwrap_or_else(|err| format!("<unreadable body: {err}>"));
    Err(anyhow!(
        "relay rejected the {what} request with HTTP {status}: {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osprey_core::identity::DeviceIdentity;

    #[test]
    fn rejects_a_non_http_relay_url() {
        assert!(RelayClient::new("ws://relay.example").is_err());
        assert!(RelayClient::new("relay.example").is_err());
    }

    #[test]
    fn trailing_slashes_do_not_produce_double_slashed_paths() {
        let client = RelayClient::new("https://relay.example/").expect("client");
        assert_eq!(
            client.url("/v1/devices"),
            "https://relay.example/v1/devices"
        );
    }

    #[test]
    fn device_token_is_redacted_in_debug() {
        let token = DeviceToken::new("acct.secret");
        assert_eq!(format!("{token:?}"), "DeviceToken(redacted)");
    }

    #[test]
    fn peer_material_is_base64_of_the_raw_keys() {
        let identity = DeviceIdentity::generate();
        let material = PeerMaterial::from_identity("host", identity.public());
        let decoded = BASE64
            .decode(&material.identity_public_key)
            .expect("decode");
        assert_eq!(decoded, identity.public().identity_pub);
        assert_eq!(material.identity_algorithm, "ed25519");
    }
}
