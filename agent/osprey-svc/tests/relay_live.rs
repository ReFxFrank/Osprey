//! Opt-in checks against a *running* relay.
//!
//! Ignored by default: unlike everything else in this crate's suite these need a
//! live relay and a live Postgres, so they cannot be part of the default
//! `cargo test`. They exist because the alternative — asserting that the agent's
//! relay client matches the relay's route contract by reading both — is exactly
//! the kind of unverified claim a phase gate is supposed to catch.
//!
//! ```text
//! OSPREY_TEST_RELAY_URL=http://127.0.0.1:8099 \
//! OSPREY_TEST_ENROLLMENT_SECRET=<the relay's OSPREY_ENROLLMENT_SECRET> \
//!   cargo test -p osprey-svc --test relay_live -- --ignored --nocapture
//! ```

use osprey_core::identity::DeviceIdentity;
use osprey_core::pairing::PairingSecret;
use osprey_svc::relay::{DeviceToken, RelayClient};

fn env_pair() -> Option<(String, String)> {
    let url = std::env::var("OSPREY_TEST_RELAY_URL").ok()?;
    let secret = std::env::var("OSPREY_TEST_ENROLLMENT_SECRET").ok()?;
    Some((url, secret))
}

#[test]
#[ignore = "needs a running relay; see the module docs"]
fn enrol_issue_lookup_and_revoke_against_a_live_relay() {
    let Some((url, enrollment_secret)) = env_pair() else {
        panic!("set OSPREY_TEST_RELAY_URL and OSPREY_TEST_ENROLLMENT_SECRET");
    };
    let client = RelayClient::new(&url).expect("relay client");
    let identity = DeviceIdentity::generate();

    let enrolment = client
        .enrol(&enrollment_secret, "relay-live-test", identity.public())
        .expect("enroll");
    let token = DeviceToken::new(enrolment.device_token.clone());

    let secret = PairingSecret::generate();
    let issued = client
        .issue_pairing_token(&token, &secret.routing_id())
        .expect("issue a pairing token");
    println!("token {} expires {}", issued.token_id, issued.expires_at);

    let found = client
        .find_device_by_identity(&token, &identity.public().identity_pub)
        .expect("device list");
    assert_eq!(
        found,
        Some(enrolment.device_id),
        "the agent must find its own device row by its identity key"
    );

    client
        .revoke_device(&token, enrolment.device_id)
        .expect("revoke");

    // Revoking this device invalidated the credential it was authenticating
    // with, so the relay must stop answering for it. That is the property the
    // agent depends on when it revokes a *controller*.
    let after = client.find_device_by_identity(&token, &identity.public().identity_pub);
    assert!(
        after.is_err(),
        "a revoked device's token must stop working, got {after:?}"
    );
}
