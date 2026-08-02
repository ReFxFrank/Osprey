//! End-to-end LAN discovery: register, browse, resolve, deregister.
//!
//! `#[ignore]` by design. This test puts real multicast traffic on whatever
//! network the machine running it is attached to, which is exactly what the
//! `--no-mdns` gate exists to prevent in CI. Run it deliberately, on a host that
//! has a private non-loopback address:
//!
//! ```text
//! cargo test -p osprey-svc --test mdns_discovery -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};
use osprey_svc::discovery::{
    advertisable, Advertisement, ADVERT_VERSION, SERVICE_TYPE, TXT_DEVICE_ID, TXT_VERSION,
};
use osprey_svc::lan::LanListener;
use uuid::Uuid;

/// Long enough for a query/response exchange on a quiet LAN; short enough that a
/// host with no answer fails the test rather than hanging the suite.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

fn resolve(
    browser: &mdns_sd::Receiver<ServiceEvent>,
    fullname: &str,
) -> Option<mdns_sd::ResolvedService> {
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(found)) =
            browser.recv_timeout(Duration::from_millis(250))
        {
            if found.get_fullname() == fullname {
                return Some(*found);
            }
        }
    }
    None
}

#[test]
#[ignore = "puts real multicast traffic on the host's LAN; run explicitly"]
fn a_paired_phone_can_discover_the_listener_and_stops_seeing_it_after_shutdown() {
    let listener = LanListener::bind(0).expect("bind");
    if advertisable(listener.addresses()).is_empty() {
        panic!(
            "this host has no private non-loopback address, so there is nothing \
             to advertise; run this test on a machine attached to a LAN"
        );
    }

    let device_id = Uuid::new_v4();
    let advertisement = Advertisement::start(device_id, listener.addresses())
        .expect("start must not fail")
        .expect("a host with a private address must advertise");
    let fullname = advertisement.fullname().to_owned();

    let daemon = ServiceDaemon::new().expect("browser daemon");
    let browser = daemon.browse(SERVICE_TYPE).expect("browse");

    let found = resolve(&browser, &fullname).expect("the advertisement must be discoverable");
    assert_eq!(
        found.get_property_val_str(TXT_DEVICE_ID),
        Some(device_id.to_string().as_str()),
        "a paired phone matches the host on this field alone"
    );
    assert_eq!(
        found.get_property_val_str(TXT_VERSION),
        Some(ADVERT_VERSION)
    );
    assert_eq!(found.get_port(), listener.addresses()[0].port());

    // Dropping the advertisement must take the record off the LAN. A stale
    // record costs a paired phone a connection timeout on every attempt.
    drop(advertisement);
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    let mut removed = false;
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceRemoved(_, name)) =
            browser.recv_timeout(Duration::from_millis(250))
        {
            if name == fullname {
                removed = true;
                break;
            }
        }
    }
    daemon.shutdown().expect("browser shutdown");
    assert!(removed, "dropping the advertisement must deregister it");
}
