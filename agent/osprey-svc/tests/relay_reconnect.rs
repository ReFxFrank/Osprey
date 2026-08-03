//! Gate P1: "reconnects to the relay after a network drop without intervention."
//!
//! Opt-in, because it needs a relay it is allowed to kill and restart:
//!
//! ```text
//! OSPREY_TEST_RELAY_URL=http://127.0.0.1:8099 \
//! OSPREY_TEST_ENROLLMENT_SECRET=<the relay's OSPREY_ENROLLMENT_SECRET> \
//! OSPREY_TEST_RELAY_RESTART="<command that restarts it>" \
//!   cargo test -p osprey-svc --test relay_reconnect -- --ignored --nocapture
//! ```
//!
//! The drop is produced by the operator's own restart command rather than by
//! anything this test does to the socket, because what the criterion is about
//! is an agent surviving something it did not cause.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use osprey_core::identity::DeviceIdentity;
use osprey_svc::relay::supervisor::{self, RelayStatus, RelayTarget};
use osprey_svc::relay::{DeviceToken, RelayClient};

fn env_pair() -> Option<(String, String)> {
    let url = std::env::var("OSPREY_TEST_RELAY_URL").ok()?;
    let secret = std::env::var("OSPREY_TEST_ENROLLMENT_SECRET").ok()?;
    Some((url, secret))
}

/// Wait for `predicate`, returning whether it became true in time.
fn within(limit: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
#[ignore = "needs a relay this test may restart; see the module docs"]
fn the_agent_reattaches_after_the_relay_goes_away() {
    let Some((url, enrollment_secret)) = env_pair() else {
        panic!("set OSPREY_TEST_RELAY_URL and OSPREY_TEST_ENROLLMENT_SECRET");
    };

    let client = RelayClient::new(&url).expect("relay client");
    let identity = DeviceIdentity::generate();
    let enrolment = client
        .enrol(&enrollment_secret, "reconnect-test", identity.public())
        .expect("enrol");

    let running = Arc::new(AtomicBool::new(true));
    let status = Arc::new(RelayStatus::default());
    let handle = supervisor::spawn(
        RelayTarget {
            base_url: url.clone(),
            token: DeviceToken::new(enrolment.device_token.clone()),
        },
        Arc::clone(&running),
        Arc::clone(&status),
    )
    .expect("spawn the supervisor");

    assert!(
        within(Duration::from_secs(15), || status.is_attached()),
        "the agent never attached to {url}"
    );
    let first = status.attachments();
    assert_eq!(first, 1, "expected exactly one attachment so far");
    println!("attached to {url} (attachments={first})");

    // The drop. Whoever runs this decides how the relay dies; the agent must
    // not care.
    let restart = std::env::var("OSPREY_TEST_RELAY_RESTART")
        .expect("set OSPREY_TEST_RELAY_RESTART to a command that restarts the relay");
    println!("dropping the relay with: {restart}");
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &restart])
        .output()
        .expect("run the restart command");
    println!(
        "restart command exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    assert!(
        within(Duration::from_secs(20), || !status.is_attached()),
        "the agent never noticed the relay had gone; its keepalive is not working"
    );
    println!("the agent detected the drop");

    // No intervention between here and the assertion: the supervisor's own
    // backoff is the only thing driving recovery.
    assert!(
        within(Duration::from_secs(90), || status.attachments() > first),
        "the agent did not reattach on its own within 90 seconds"
    );
    assert!(status.is_attached(), "reattached but did not stay attached");
    println!(
        "reattached without intervention (attachments={})",
        status.attachments()
    );

    running.store(false, Ordering::Relaxed);
    handle.join().expect("join the supervisor");
}
