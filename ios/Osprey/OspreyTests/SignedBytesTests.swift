import XCTest

@testable import Osprey

/// These layouts are what the agent verifies. A divergence here surfaces only as
/// "signature does not verify", so the bytes are asserted literally rather than
/// by reconstructing them the same way the implementation does.
final class SignedBytesTests: XCTestCase {
    func testCrossCertificateLayout() {
        let identityPub = Data(repeating: 0xA1, count: 65)
        let noiseStatic = Data(repeating: 0xB2, count: 32)
        let message = SignedBytes.crossCertificate(
            identityPublicKey: identityPub, noiseStaticPublicKey: noiseStatic)

        let context = Data("osprey/cross-cert/noise-static/v1".utf8)
        XCTAssertEqual(message.count, context.count + 65 + 32)
        XCTAssertEqual(message.prefix(context.count), context)
        XCTAssertEqual(
            message.dropFirst(context.count).prefix(65), identityPub)
        XCTAssertEqual(Data(message.suffix(32)), noiseStatic)
    }

    func testCrossCertificateContextIsExactlyTheAgentsConstant() {
        let message = SignedBytes.crossCertificate(
            identityPublicKey: Data(), noiseStaticPublicKey: Data())
        XCTAssertEqual(String(decoding: message, as: UTF8.self), "osprey/cross-cert/noise-static/v1")
    }

    func testRevocationLayout() throws {
        let issuer = try XCTUnwrap(UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff"))
        let revoked = try XCTUnwrap(UUID(uuidString: "ffeeddcc-bbaa-9988-7766-554433221100"))
        let nonce = Data(repeating: 0x5A, count: 32)
        let message = SignedBytes.revocation(
            issuerDeviceID: issuer,
            revokedDeviceID: revoked,
            issuedAtMilliseconds: 1,
            nonce: nonce)

        let context = Data("osprey/pair.revoke/v1".utf8)
        XCTAssertEqual(message.count, context.count + 16 + 16 + 8 + 32)
        XCTAssertEqual(message.prefix(context.count), context)

        let body = Data(message.dropFirst(context.count))
        XCTAssertEqual(
            Data(body.prefix(16)),
            Data([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            ]))
        XCTAssertEqual(
            Data(body.dropFirst(16).prefix(16)),
            Data([
                0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            ]))
        XCTAssertEqual(
            Data(body.dropFirst(32).prefix(8)),
            Data([0, 0, 0, 0, 0, 0, 0, 1]),
            "issued_at must be big-endian")
        XCTAssertEqual(Data(body.suffix(32)), nonce)
    }

    /// `SignedBytes.crossCertificate` is the offline mirror of the core's
    /// `cross_certificate_bytes`, kept only so `IdentityVerifier` can check a
    /// peer's bundle with CryptoKit. They agree today, which is exactly why a
    /// drift would be invisible: nothing on either side would fail to parse, and
    /// the first symptom would be a phone that cannot pair.
    ///
    /// Both identity key lengths are covered, because the layout has no length
    /// prefix and a bug that only bit one algorithm would be missed by the other.
    func testTheOfflineMirrorMatchesTheCore() throws {
        let noiseStatic = Data(repeating: 0xB2, count: 32)
        for identityPublicKey in [
            Data(repeating: 0xA1, count: 32),  // Ed25519, the agent's algorithm
            Data([0x04]) + Data(repeating: 0xA1, count: 64),  // P-256, this phone's
        ] {
            XCTAssertEqual(
                SignedBytes.crossCertificate(
                    identityPublicKey: identityPublicKey, noiseStaticPublicKey: noiseStatic),
                try CrossCertificate.message(
                    identityPublicKey: identityPublicKey, noiseStaticPublicKey: noiseStatic),
                "identity key of \(identityPublicKey.count) bytes")
        }
    }

    func testUUIDBytesAreNetworkOrder() throws {
        let uuid = try XCTUnwrap(UUID(uuidString: "01020304-0506-0708-090a-0b0c0d0e0f10"))
        XCTAssertEqual(
            uuid.rawBytes,
            Data([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ]))
    }
}
