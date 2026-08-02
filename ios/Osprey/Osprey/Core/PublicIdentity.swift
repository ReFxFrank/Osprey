import Foundation

/// The public half of a device identity: a hardware-backed identity key plus the
/// X25519 Noise static that key cross-signs.
///
/// Wire-compatible with `osprey_core::identity::PublicIdentity`. The field names
/// and the hex encoding come from that type's `serde` attributes, not from the
/// generated protocol registry — this struct travels inside the QR payload and
/// inside the encrypted pairing handshake, neither of which is an envelope.
public struct PublicIdentity: Hashable, Sendable, Codable {
    /// Which signature scheme `identityPublicKey` and `noiseStaticSignature` use.
    /// Carried explicitly so a verifier never infers it from a key length.
    public var identityAlgorithm: IdentityAlgorithm
    /// 32 bytes for Ed25519; 65 bytes of X9.63 uncompressed point for P-256.
    public var identityPublicKey: Data
    /// X25519 Noise static, always 32 bytes.
    public var noiseStaticPublicKey: Data
    /// 64 raw bytes for Ed25519; variable-length ASN.1 DER for P-256.
    public var noiseStaticSignature: Data

    public init(
        identityAlgorithm: IdentityAlgorithm,
        identityPublicKey: Data,
        noiseStaticPublicKey: Data,
        noiseStaticSignature: Data
    ) {
        self.identityAlgorithm = identityAlgorithm
        self.identityPublicKey = identityPublicKey
        self.noiseStaticPublicKey = noiseStaticPublicKey
        self.noiseStaticSignature = noiseStaticSignature
    }

    private enum CodingKeys: String, CodingKey {
        case identityAlgorithm = "identity_algorithm"
        case identityPublicKey = "identity_pub"
        case noiseStaticPublicKey = "noise_static_pub"
        case noiseStaticSignature = "noise_static_sig"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        identityAlgorithm = try container.decode(
            IdentityAlgorithm.self, forKey: .identityAlgorithm)
        identityPublicKey = try container.decodeHex(forKey: .identityPublicKey)
        noiseStaticPublicKey = try container.decodeHex(
            forKey: .noiseStaticPublicKey, expecting: NoiseKeySizes.staticKeyLength)
        noiseStaticSignature = try container.decodeHex(forKey: .noiseStaticSignature)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(identityAlgorithm, forKey: .identityAlgorithm)
        try container.encodeHex(identityPublicKey, forKey: .identityPublicKey)
        try container.encodeHex(noiseStaticPublicKey, forKey: .noiseStaticPublicKey)
        try container.encodeHex(noiseStaticSignature, forKey: .noiseStaticSignature)
    }
}

/// Key sizes fixed by the Noise suite both ends run
/// (`Noise_IK[psk2]_25519_ChaChaPoly_BLAKE2s`).
public enum NoiseKeySizes {
    public static let staticKeyLength = 32
    public static let pairingSecretLength = 32
}

/// The payload exchanged inside the pairing handshake's encrypted messages.
///
/// Mirrors the private `IdentityMessage` in `osprey_core::pairing::flow`; the
/// single-field wrapper is part of the wire format, not decoration.
struct IdentityMessage: Codable, Sendable {
    var identity: PublicIdentity
}
