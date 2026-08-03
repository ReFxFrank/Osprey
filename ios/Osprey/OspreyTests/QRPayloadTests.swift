import XCTest

@testable import Osprey

final class QRPayloadTests: XCTestCase {
    static let identityPub = String(repeating: "a1", count: 32)
    static let noiseStaticPub = String(repeating: "b2", count: 32)
    static let noiseStaticSig = String(repeating: "c3", count: 64)
    static let pairingSecret = String(repeating: "d4", count: 32)

    static func json(
        version: Int = 1,
        hints: String = #"["192.168.1.20:47010","[fd00::1]:47010"]"#
    ) -> String {
        """
        {"v":\(version),
         "relay_url":"https://relay.example",
         "account_id":"7ec2a7d0-0000-4000-8000-000000000001",
         "device_id":"7ec2a7d0-0000-4000-8000-000000000002",
         "agent_identity":{"identity_algorithm":"ed25519",
                           "identity_pub":"\(identityPub)",
                           "noise_static_pub":"\(noiseStaticPub)",
                           "noise_static_sig":"\(noiseStaticSig)"},
         "lan_hints":\(hints),
         "pairing_secret":"\(pairingSecret)"}
        """
    }

    func testDecodesTheAgentsPayload() throws {
        let payload = try QRPayload.decode(Self.json())
        XCTAssertEqual(payload.version, 1)
        XCTAssertEqual(payload.relayURL, "https://relay.example")
        XCTAssertEqual(payload.agentDeviceID, "7ec2a7d0-0000-4000-8000-000000000002")
        XCTAssertEqual(payload.agentIdentity.identityAlgorithm, .ed25519)
        XCTAssertEqual(payload.agentIdentity.identityPublicKey.count, 32)
        XCTAssertEqual(payload.agentIdentity.noiseStaticPublicKey.count, 32)
        XCTAssertEqual(payload.agentIdentity.noiseStaticSignature.count, 64)
        XCTAssertEqual(payload.pairingSecret.count, 32)
        XCTAssertEqual(payload.lanHints.count, 2)
        XCTAssertEqual(payload.lanHints[0], LanEndpoint(host: "192.168.1.20", port: 47010, isIPv6: false))
        XCTAssertEqual(payload.lanHints[1], LanEndpoint(host: "fd00::1", port: 47010, isIPv6: true))
    }

    func testAFutureVersionIsRefused() {
        XCTAssertThrowsError(try QRPayload.decode(Self.json(version: 2)))
    }

    func testAShortNoiseStaticIsRefused() {
        let bad = Self.json().replacingOccurrences(
            of: Self.noiseStaticPub, with: String(repeating: "b2", count: 31))
        XCTAssertThrowsError(try QRPayload.decode(bad))
    }

    func testAShortPairingSecretIsRefused() {
        let bad = Self.json().replacingOccurrences(
            of: Self.pairingSecret, with: String(repeating: "d4", count: 16))
        XCTAssertThrowsError(try QRPayload.decode(bad))
    }

    func testDialOrderPrefersIPv4AndDropsUnreachableHints() throws {
        let payload = try QRPayload.decode(
            Self.json(
                hints: #"["[fd00::1]:47010","10.0.0.4:47010","127.0.0.1:47010","[fe80::1]:47010"]"#))
        XCTAssertEqual(
            payload.dialOrder,
            [
                LanEndpoint(host: "10.0.0.4", port: 47010, isIPv6: false),
                LanEndpoint(host: "fd00::1", port: 47010, isIPv6: true)
            ])
    }

    func testEndpointParsing() {
        XCTAssertEqual(
            LanEndpoint(text: "10.0.0.4:47010"),
            LanEndpoint(host: "10.0.0.4", port: 47010, isIPv6: false))
        XCTAssertEqual(
            LanEndpoint(text: "[fd00::1]:47010"),
            LanEndpoint(host: "fd00::1", port: 47010, isIPv6: true))
        XCTAssertNil(LanEndpoint(text: "10.0.0.4"))
        XCTAssertNil(LanEndpoint(text: "[fd00::1]47010"))
        XCTAssertNil(LanEndpoint(text: ":47010"))
        XCTAssertNil(LanEndpoint(text: "10.0.0.4:99999"))
    }

    func testEndpointsSurviveAStorageRoundTrip() throws {
        let hints = [
            LanEndpoint(host: "10.0.0.4", port: 47010, isIPv6: false),
            LanEndpoint(host: "fd00::1", port: 47010, isIPv6: true)
        ]
        let encoded = try JSONEncoder().encode(hints)
        XCTAssertEqual(try JSONDecoder().decode([LanEndpoint].self, from: encoded), hints)
    }
}
