import XCTest

@testable import Osprey

/// Fingerprints are what a human compares between the host console and this
/// screen, so the two implementations must agree exactly. The expected values
/// were printed by `osprey_core::identity::Fingerprint::of_identity`.
///
/// This file needs CryptoKit and therefore an Apple SDK; it does not build on
/// Linux, unlike the rest of this target.
final class FingerprintTests: XCTestCase {
    func testP256FingerprintMatchesTheRustVector() {
        let fingerprint = Fingerprint.of(
            algorithm: .p256, identityPublicKey: Data(repeating: 0xA1, count: 65))
        XCTAssertEqual(
            fingerprint.full,
            "fdec3411d174756e4ad734f861562bfae7543498a759a82f38b7efc6aac30565")
    }

    func testEd25519FingerprintMatchesTheRustVector() {
        let fingerprint = Fingerprint.of(
            algorithm: .ed25519, identityPublicKey: Data(repeating: 0xA1, count: 32))
        XCTAssertEqual(
            fingerprint.full,
            "1e07597e33e12abb91625471e8c5c821ba10ad910b505915bc6e618fbdbd0dff")
    }

    /// The short form is what `osprey-svc pair` prints and what the operator is
    /// asked to compare, so its grouping matters as much as its value.
    func testShortFormMatchesTheHostConsole() {
        let fingerprint = Fingerprint.of(
            algorithm: .ed25519, identityPublicKey: Data(repeating: 0xA1, count: 32))
        XCTAssertEqual(fingerprint.short, "1e07-597e-33e1-2abb")
    }

    func testGroupedFormIsFourCharacterGroups() {
        let fingerprint = Fingerprint.of(
            algorithm: .ed25519, identityPublicKey: Data(repeating: 0xA1, count: 32))
        XCTAssertEqual(fingerprint.grouped.split(separator: " ").count, 16)
        XCTAssertEqual(
            fingerprint.grouped.replacingOccurrences(of: " ", with: ""), fingerprint.full)
    }
}
