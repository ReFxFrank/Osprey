import Foundation

/// The exact byte strings this product signs.
///
/// Every constant and every layout here must byte-match its counterpart in
/// `agent/osprey-core/src/identity.rs` and `.../pairing/revoke.rs`. The agent is
/// the verifier for both, and a divergence surfaces only as "signature does not
/// verify" — never as a parse error — so these are kept in one file with the
/// Rust symbol named beside each one.
public enum SignedBytes {
    /// Domain separator for the identity → Noise-static cross-certificate.
    ///
    /// Rust: `osprey_core::identity::CROSS_SIG_CONTEXT`. Note this is *not* the
    /// string quoted in `proto/messages.toml`'s prose description of
    /// `noise_static_signature`, and the layout differs too: the shipping agent
    /// covers the identity key rather than the device id. The implementation is
    /// authoritative because it is what verifies the signature.
    static let crossCertificateContext = Data("osprey/cross-cert/noise-static/v1".utf8)

    /// Domain separator for a signed unpair.
    /// Rust: `osprey_core::pairing::REVOKE_CONTEXT`.
    static let revocationContext = Data("osprey/pair.revoke/v1".utf8)

    /// Rust: `osprey_core::pairing::REVOKE_NONCE_LEN`.
    public static let revocationNonceLength = 32

    /// `CROSS_SIG_CONTEXT ‖ identity_pub ‖ noise_static_pub`.
    ///
    /// No length prefix is needed: the verifier fixes the algorithm — and
    /// therefore the identity key's length — before it hashes anything.
    /// Rust: `osprey_core::identity::cross_sig_message`.
    ///
    /// This is the *offline* mirror, used only by `IdentityVerifier` so a peer's
    /// bundle can be checked with CryptoKit without a round trip through the
    /// FFI. Nothing signs from it: `DeviceIdentity` takes its message from
    /// `CrossCertificate.message(…)`, so the signer and the agent's verifier have
    /// one definition between them. `SignedBytesTests` asserts the two agree for
    /// both identity key lengths, because they agree today and would drift
    /// silently.
    public static func crossCertificate(
        identityPublicKey: Data,
        noiseStaticPublicKey: Data
    ) -> Data {
        var message = Data()
        message.reserveCapacity(
            crossCertificateContext.count + identityPublicKey.count + noiseStaticPublicKey.count)
        message.append(crossCertificateContext)
        message.append(identityPublicKey)
        message.append(noiseStaticPublicKey)
        return message
    }

    /// `REVOKE_CONTEXT ‖ issuer[16] ‖ revoked[16] ‖ issued_at_be[8] ‖ nonce[32]`.
    /// Rust: `osprey_core::pairing::revocation_signing_bytes`.
    public static func revocation(
        issuerDeviceID: UUID,
        revokedDeviceID: UUID,
        issuedAtMilliseconds: Int64,
        nonce: Data
    ) -> Data {
        var message = Data()
        message.reserveCapacity(revocationContext.count + 16 + 16 + 8 + nonce.count)
        message.append(revocationContext)
        message.append(issuerDeviceID.rawBytes)
        message.append(revokedDeviceID.rawBytes)
        message.append(withUnsafeBytes(of: issuedAtMilliseconds.bigEndian) { Data($0) })
        message.append(nonce)
        return message
    }
}

extension UUID {
    /// The 16 bytes of the UUID in RFC 4122 network order, which is the layout
    /// `uuid::Uuid::as_bytes` produces on the agent.
    public var rawBytes: Data {
        withUnsafeBytes(of: uuid) { Data($0) }
    }
}
