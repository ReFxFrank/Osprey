import CryptoKit
import Foundation

/// Verification of a peer's cross-certificate.
///
/// The Windows agent's root of trust is Ed25519 in DPAPI; this phone's is P-256
/// in the Secure Enclave. Both arms exist because a peer's algorithm is whatever
/// its hardware offers, and the algorithm is always read from the bundle's own
/// tag rather than inferred from a key length — inference is how a verifier ends
/// up choosing the algorithm an attacker prefers.
public enum IdentityVerifier {
    /// Ed25519 public keys are exactly this long.
    static let ed25519KeyLength = 32
    /// Ed25519 signatures are exactly this long.
    static let ed25519SignatureLength = 64
    /// An X9.63 uncompressed P-256 point: the `0x04` tag plus two coordinates.
    static let p256KeyLength = 65
    /// SEC1 tag byte for an uncompressed point.
    static let sec1UncompressedTag: UInt8 = 0x04
    /// A DER ECDSA signature over P-256 tops out at 72 bytes. The cap stops a
    /// peer making the verifier walk a large buffer before rejecting it.
    static let maxSignatureLength = 128

    /// Check that `identity.noiseStaticPublicKey` was cross-signed by
    /// `identity.identityPublicKey`.
    public static func verifyCrossSignature(_ identity: PublicIdentity) throws {
        let message = SignedBytes.crossCertificate(
            identityPublicKey: identity.identityPublicKey,
            noiseStaticPublicKey: identity.noiseStaticPublicKey)
        try verify(
            algorithm: identity.identityAlgorithm,
            identityPublicKey: identity.identityPublicKey,
            message: message,
            signature: identity.noiseStaticSignature)
    }

    public static func verify(
        algorithm: IdentityAlgorithm,
        identityPublicKey: Data,
        message: Data,
        signature: Data
    ) throws {
        guard signature.count <= maxSignatureLength else {
            throw CrossSignatureFailure.malformed
        }
        switch algorithm {
        case .ed25519:
            try verifyEd25519(
                identityPublicKey: identityPublicKey, message: message, signature: signature)
        case .p256:
            try verifyP256(
                identityPublicKey: identityPublicKey, message: message, signature: signature)
        case .unknown(let raw):
            // Accepting a signature under an algorithm this build cannot check
            // would pin a peer on evidence it never examined.
            throw CrossSignatureFailure.unsupportedAlgorithm(raw)
        }
    }

    private static func verifyEd25519(
        identityPublicKey: Data,
        message: Data,
        signature: Data
    ) throws {
        guard identityPublicKey.count == ed25519KeyLength else {
            throw CrossSignatureFailure.badIdentityKey
        }
        guard signature.count == ed25519SignatureLength else {
            throw CrossSignatureFailure.malformed
        }
        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: identityPublicKey)
        } catch {
            throw CrossSignatureFailure.badIdentityKey
        }
        guard key.isValidSignature(signature, for: message) else {
            throw CrossSignatureFailure.notSignedByIdentity
        }
    }

    /// Only the uncompressed encoding is admitted, even though SEC1 also defines
    /// a 33-byte compressed form. The raw key bytes are what gets pinned,
    /// fingerprinted and byte-compared, so allowing two encodings of one key
    /// would produce two different pins for one device.
    private static func verifyP256(
        identityPublicKey: Data,
        message: Data,
        signature: Data
    ) throws {
        guard identityPublicKey.count == p256KeyLength,
            identityPublicKey.first == sec1UncompressedTag
        else {
            throw CrossSignatureFailure.badIdentityKey
        }
        let key: P256.Signing.PublicKey
        do {
            key = try P256.Signing.PublicKey(x963Representation: identityPublicKey)
        } catch {
            throw CrossSignatureFailure.badIdentityKey
        }
        let parsed: P256.Signing.ECDSASignature
        do {
            parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw CrossSignatureFailure.malformed
        }
        guard key.isValidSignature(parsed, for: message) else {
            throw CrossSignatureFailure.notSignedByIdentity
        }
    }
}

public enum CrossSignatureFailure: Error, Hashable, Sendable {
    case badIdentityKey
    case malformed
    case notSignedByIdentity
    case unsupportedAlgorithm(String)
}

extension CrossSignatureFailure: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .badIdentityKey:
            return "The identity key is not the right shape for the algorithm it claims."
        case .malformed:
            return "The cross-signature is not a signature this app can parse."
        case .notSignedByIdentity:
            return "The host's connection key was not signed by the identity key in the code. "
                + "Pairing was refused."
        case .unsupportedAlgorithm(let raw):
            return "The host uses an identity algorithm this build cannot check (`\(raw)`)."
        }
    }
}
