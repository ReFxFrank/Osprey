//! Gate P0: cross-signature enforcement, rotation, and key survival.

use osprey_core::error::{CrossSignatureFailure, Error};
use osprey_core::identity::{verify_cross_signature, DeviceIdentity, PinnedPeer};
use osprey_proto::IdentityAlgorithm;

use osprey_core::keystore::Keystore;

// The keystore tests run against whichever backend actually ships on the
// platform under test: DPAPI on Windows (the shipping path), the dev file
// backend elsewhere (compiled out on Windows so it cannot be selected there).
// Behavioural coverage of the trait must include the Windows backend, or
// gate criterion 2's "keys survive restart" is only ever proven against a
// backend the product never uses.
#[cfg(windows)]
fn open_keystore(dir: &std::path::Path) -> impl Keystore {
    osprey_core::keystore::DpapiKeystore::open(dir).expect("open keystore")
}

#[cfg(not(windows))]
fn open_keystore(dir: &std::path::Path) -> impl Keystore {
    osprey_core::keystore::DevFileKeystore::open(dir).expect("open keystore")
}

#[test]
fn a_valid_cross_signature_verifies() {
    let identity = DeviceIdentity::generate();
    let public = identity.public();
    verify_cross_signature(
        &public.identity_algorithm,
        &public.identity_pub,
        &public.noise_static_pub,
        &public.noise_static_sig,
    )
    .expect("own cross-signature must verify");
    public
        .verify_self_consistent()
        .expect("bundle must be self-consistent");
}

#[test]
fn a_static_signed_by_a_different_identity_is_rejected() {
    let real = DeviceIdentity::generate();
    let impostor = DeviceIdentity::generate();

    // The impostor's static, vouched for by the impostor, presented under the
    // real device's identity key: the substitution a hostile relay would try.
    let err = verify_cross_signature(
        &IdentityAlgorithm::Ed25519,
        &real.public().identity_pub,
        &impostor.public().noise_static_pub,
        &impostor.public().noise_static_sig,
    )
    .expect_err("foreign signature must not verify");
    assert!(matches!(
        err,
        Error::CrossSignature(CrossSignatureFailure::NotSignedByIdentity)
    ));
}

#[test]
fn a_swapped_static_inside_a_bundle_is_rejected() {
    let real = DeviceIdentity::generate();
    let impostor = DeviceIdentity::generate();
    let mut forged = real.public().clone();
    forged.noise_static_pub = impostor.public().noise_static_pub;
    assert!(matches!(
        PinnedPeer::pin(&forged),
        Err(Error::CrossSignature(
            CrossSignatureFailure::NotSignedByIdentity
        ))
    ));
}

#[test]
fn a_malformed_identity_key_is_a_typed_error_not_a_panic() {
    let identity = DeviceIdentity::generate();
    // All-zero is not a valid Ed25519 encoding of a usable public key.
    let mut bogus = [0u8; 32];
    bogus[31] = 0x80;
    let err = verify_cross_signature(
        &IdentityAlgorithm::Ed25519,
        &bogus,
        &identity.public().noise_static_pub,
        &identity.public().noise_static_sig,
    )
    .expect_err("must reject");
    assert!(matches!(err, Error::CrossSignature(_)));
}

#[test]
fn rotation_keeps_the_pin_and_replaces_the_static() {
    let mut agent = DeviceIdentity::generate();
    let mut peer = PinnedPeer::pin(agent.public()).expect("pin");
    let original_static = peer.noise_static_pub;
    let original_fingerprint = peer.fingerprint();

    agent.rotate_noise_static();
    assert_ne!(agent.public().noise_static_pub, original_static);

    peer.accept_static(agent.public())
        .expect("rotated static signed by the pinned identity is accepted");
    assert_eq!(peer.noise_static_pub, agent.public().noise_static_pub);
    assert_eq!(
        peer.fingerprint(),
        original_fingerprint,
        "rotation must not change the durable identity fingerprint"
    );
}

#[test]
fn a_pin_carries_its_cross_signature_and_re_verifies() {
    let agent = DeviceIdentity::generate();
    let peer = PinnedPeer::pin(agent.public()).expect("pin");
    assert_eq!(peer.noise_static_sig, agent.public().noise_static_sig);
    peer.verify().expect("a freshly made pin must re-verify");

    // What an edit to the on-disk pin store looks like: an attacker-chosen
    // session key under the operator's identity key. The signature the pin
    // carries is what makes this detectable at load time rather than at no time.
    let attacker = DeviceIdentity::generate();
    let mut substituted = peer.clone();
    substituted.noise_static_pub = attacker.public().noise_static_pub;
    assert!(matches!(
        substituted.verify(),
        Err(Error::CrossSignature(_))
    ));
}

#[test]
fn rotation_offered_by_a_different_identity_is_refused() {
    let agent = DeviceIdentity::generate();
    let attacker = DeviceIdentity::generate();
    let mut peer = PinnedPeer::pin(agent.public()).expect("pin");
    assert!(matches!(
        peer.accept_static(attacker.public()),
        Err(Error::UnpinnedPeer)
    ));
    assert_eq!(peer.noise_static_pub, agent.public().noise_static_pub);
}

#[test]
fn keystore_survives_a_save_load_cycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = open_keystore(dir.path());

    let original = DeviceIdentity::load_or_create(&keystore).expect("create");
    let original_public = original.public().clone();
    drop(original);

    // A fresh keystore handle stands in for an agent restart.
    let reopened = open_keystore(dir.path());
    let loaded = DeviceIdentity::load(&reopened)
        .expect("load")
        .expect("identity must survive restart");

    assert_eq!(loaded.public(), &original_public);
    assert_eq!(
        loaded.public().noise_static_sig,
        original_public.noise_static_sig,
        "cross-signature must be reproducible from the stored key material"
    );
    loaded
        .public()
        .verify_self_consistent()
        .expect("reloaded bundle must still verify");
}

#[test]
fn keystore_delete_removes_the_identity_and_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = open_keystore(dir.path());
    DeviceIdentity::load_or_create(&keystore).expect("create");
    keystore.delete("device-identity").expect("delete");
    keystore.delete("device-identity").expect("delete again");
    assert!(DeviceIdentity::load(&keystore).expect("load").is_none());
}

#[test]
fn keystore_rejects_a_traversing_label() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = open_keystore(dir.path());
    assert!(keystore.store("../escape", b"x").is_err());
    assert!(keystore.load("../escape").is_err());
}
