import XCTest

@testable import Osprey

/// Golden vectors produced by running the shipping Rust code.
///
/// These are not restatements of the Swift implementation: each expected string
/// below was printed by `osprey_core::identity::cross_certificate_bytes`,
/// `osprey_core::pairing::revocation_signing_bytes` and `serde_json` against the
/// same inputs. They are the only mechanical check that the two sides agree,
/// because a mismatch on either byte string shows up on the wire as nothing more
/// informative than "signature does not verify".
final class RustInteropVectorTests: XCTestCase {
    func testCrossCertificateMatchesTheRustVector() throws {
        let expected = try Hex.decode(
            "6f73707265792f63726f73732d636572742f6e6f6973652d7374617469632f7631"
                + String(repeating: "a1", count: 65)
                + String(repeating: "b2", count: 32))
        let actual = SignedBytes.crossCertificate(
            identityPublicKey: Data(repeating: 0xA1, count: 65),
            noiseStaticPublicKey: Data(repeating: 0xB2, count: 32))
        XCTAssertEqual(actual, expected)
    }

    func testRevocationMatchesTheRustVector() throws {
        let expected = try Hex.decode(
            "6f73707265792f706169722e7265766f6b652f7631"
                + "00112233445566778899aabbccddeeff"
                + "ffeeddccbbaa99887766554433221100"
                + "0000000000000001"
                + String(repeating: "5a", count: 32))
        let issuer = try XCTUnwrap(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff"))
        let revoked = try XCTUnwrap(UUID(uuidString: "ffeeddcc-bbaa-9988-7766-554433221100"))
        let actual = SignedBytes.revocation(
            issuerDeviceID: issuer,
            revokedDeviceID: revoked,
            issuedAtMilliseconds: 1,
            nonce: Data(repeating: 0x5A, count: 32))
        XCTAssertEqual(actual, expected)
    }

    /// The exact bytes `serde_json` produced for the pairing handshake payload.
    static let rustIdentityMessage = """
        {"identity":{"identity_algorithm":"p256",\
        "identity_pub":"\(String(repeating: "04", count: 65))",\
        "noise_static_pub":"\(String(repeating: "ee", count: 32))",\
        "noise_static_sig":"\(String(repeating: "22", count: 70))"}}
        """

    static let expectedIdentity = PublicIdentity(
        identityAlgorithm: .p256,
        identityPublicKey: Data(repeating: 0x04, count: 65),
        noiseStaticPublicKey: Data(repeating: 0xEE, count: 32),
        noiseStaticSignature: Data(repeating: 0x22, count: 70))

    func testRustIdentityMessageDecodes() throws {
        let decoded = try JSONDecoder().decode(
            IdentityMessage.self, from: Data(Self.rustIdentityMessage.utf8))
        XCTAssertEqual(decoded.identity, Self.expectedIdentity)
    }

    /// Field names and hex encoding have to match, not just parse. Comparing the
    /// two payloads as parsed JSON objects checks that without depending on key
    /// order, which neither `serde_json` nor `JSONEncoder` promises.
    func testSwiftEncodesTheSameObjectRustDoes() throws {
        let swiftEncoded = try JSONEncoder().encode(
            IdentityMessage(identity: Self.expectedIdentity))
        let fromSwift = try JSONSerialization.jsonObject(with: swiftEncoded)
        let fromRust = try JSONSerialization.jsonObject(
            with: Data(Self.rustIdentityMessage.utf8))
        XCTAssertEqual(
            NSDictionary(dictionary: try XCTUnwrap(fromSwift as? [String: Any])),
            NSDictionary(dictionary: try XCTUnwrap(fromRust as? [String: Any])))
    }
}
