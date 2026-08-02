import CryptoKit
import Foundation

/// A hash of an identity public key *and* the algorithm it belongs to.
///
/// This is what a human is shown after pairing, so it names the *durable*
/// identity key rather than the rotatable Noise static. The algorithm is inside
/// the hash because two devices could otherwise be told apart only by a field
/// outside the value the operator is asked to compare.
///
/// Must byte-match `osprey_core::identity::Fingerprint`, because the operator
/// compares what the host console prints against what this app displays.
public struct Fingerprint: Hashable, Sendable {
    /// Rust: `osprey_core::identity::FINGERPRINT_CONTEXT`.
    private static let context = Data("osprey/fingerprint/identity/v1".utf8)

    public let bytes: Data

    public static func of(
        algorithm: IdentityAlgorithm,
        identityPublicKey: Data
    ) -> Fingerprint {
        var hasher = SHA256()
        hasher.update(data: context)
        hasher.update(data: Data(algorithm.wireValue.utf8))
        // Algorithm names are ASCII and never contain NUL, so this separator
        // makes the concatenation unambiguous without a length prefix.
        hasher.update(data: Data([0]))
        hasher.update(data: identityPublicKey)
        return Fingerprint(bytes: Data(hasher.finalize()))
    }

    public static func of(_ identity: PublicIdentity) -> Fingerprint {
        of(
            algorithm: identity.identityAlgorithm,
            identityPublicKey: identity.identityPublicKey)
    }

    public var full: String { Hex.encode(bytes) }

    /// First 8 bytes, grouped for reading aloud during pairing confirmation.
    /// This is the form `osprey-svc` prints.
    public var short: String {
        Hex.encode(bytes.prefix(8))
            .chunked(into: 4)
            .joined(separator: "-")
    }

    /// The full hash in four-character groups, for side-by-side comparison with
    /// the host console.
    public var grouped: String {
        full.chunked(into: 4).joined(separator: " ")
    }
}

extension String {
    func chunked(into size: Int) -> [String] {
        guard size > 0 else { return [self] }
        var chunks: [String] = []
        var index = startIndex
        while index < endIndex {
            let end = self.index(index, offsetBy: size, limitedBy: endIndex) ?? endIndex
            chunks.append(String(self[index..<end]))
            index = end
        }
        return chunks
    }
}
