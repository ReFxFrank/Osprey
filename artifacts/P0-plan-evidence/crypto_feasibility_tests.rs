/// Proves: snow builds a Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s responder/initiator
/// with a caller-supplied raw X25519 static key and a PSK, and completes a handshake.
#[test]
fn ik_psk2_handshake_roundtrip() {
    use x25519_dalek::{StaticSecret, PublicKey};
    let params = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    // Agent (responder) static; phone (initiator) static — raw 32-byte X25519 keys we supply.
    let a_priv = StaticSecret::from([7u8; 32]);
    let a_pub = PublicKey::from(&a_priv);
    let i_priv = StaticSecret::from([9u8; 32]);

    let psk = [42u8; 32]; // the QR secret the relay never sees

    let mut initiator = snow::Builder::new(params)
        .local_private_key(&i_priv.to_bytes()).unwrap()
        .remote_public_key(a_pub.as_bytes()).unwrap()   // phone knows agent key from the QR
        .psk(2, &psk).unwrap()
        .build_initiator().unwrap();

    let params2 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let mut responder = snow::Builder::new(params2)
        .local_private_key(&a_priv.to_bytes()).unwrap()
        .psk(2, &psk).unwrap()
        .build_responder().unwrap();

    let mut buf = [0u8; 1024];
    let mut out = [0u8; 1024];

    // -> e, es, s, ss
    let n = initiator.write_message(&[], &mut buf).unwrap();
    let _ = responder.read_message(&buf[..n], &mut out).unwrap();
    // <- e, ee, se, psk
    let n = responder.write_message(&[], &mut buf).unwrap();
    let _ = initiator.read_message(&buf[..n], &mut out).unwrap();

    let mut it = initiator.into_transport_mode().unwrap();
    let mut rt = responder.into_transport_mode().unwrap();

    let n = it.write_message(b"ping", &mut buf).unwrap();
    let m = rt.read_message(&buf[..n], &mut out).unwrap();
    assert_eq!(&out[..m], b"ping");
}

/// Proves: ed25519-dalek can sign the X25519 Noise static (cross-cert binding
/// the DH key to the Ed25519 identity), and the signature verifies.
#[test]
fn ed25519_cross_signs_x25519_static() {
    use ed25519_dalek::{SigningKey, Signer, Verifier};
    use x25519_dalek::{StaticSecret, PublicKey};
    let mut csprng = rand_core::OsRng;
    let id = SigningKey::generate(&mut csprng);
    let noise_static = StaticSecret::from([3u8; 32]);
    let noise_pub = PublicKey::from(&noise_static);
    let sig = id.sign(noise_pub.as_bytes());
    assert!(id.verifying_key().verify(noise_pub.as_bytes(), &sig).is_ok());
}
