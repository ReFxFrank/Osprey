import XCTest

@testable import Osprey

/// The Swift half of the protocol round-trip the gate requires. The Rust half
/// lives in `osprey-proto`; both are generated from `proto/messages.toml`, so
/// what is under test is that the generated Swift encodes and decodes its own
/// registry without loss.
final class ProtocolRoundTripTests: XCTestCase {
    func testEveryDefinedBodyRoundTrips() throws {
        let deviceID = UUID()
        let bodies: [MessageBody] = [
            .error(ErrorBody(code: .rateLimited, message: "slow down", retryable: true)),
            .hello(
                HelloBody(
                    protocolVersion: 1, minProtocolVersion: 1, capabilities: [.metrics, .files],
                    deviceId: deviceID, softwareVersion: "osprey-ios/test")),
            .helloOk(
                HelloOkBody(
                    protocolVersion: 1, capabilities: [], deviceId: deviceID,
                    softwareVersion: "osprey-svc/0.1.0", sessionId: UUID(),
                    displayName: "WORKSTATION")),
            .helloOk(
                HelloOkBody(
                    protocolVersion: 1, capabilities: [], deviceId: deviceID,
                    softwareVersion: "osprey-svc/0.1.0", sessionId: UUID(),
                    displayName: nil)),
            .ping(PingBody(seq: 42)),
            .pong(PongBody(seq: 42, echoTs: 1_700_000_000_000)),
            .bye(ByeBody(reason: .unpaired, detail: "pin removed")),
            .pairRevoke(
                PairRevokeBody(
                    issuerDeviceId: deviceID, revokedDeviceId: deviceID,
                    issuedAt: 1_700_000_000_000,
                    nonce: Data(repeating: 0x5A, count: 32),
                    signature: Data(repeating: 0x7B, count: 70))),
            .metricsSubscribe(MetricsSubscribeBody(backfillSeconds: 86_400, stream: true)),
            .metricsTick(
                MetricsTickBody(
                    sub: deviceID, ts: 1_700_000_000_000, cpuPercent: 12.5,
                    memUsedBytes: 17_179_869_184, memTotalBytes: 34_359_738_368,
                    diskLabels: ["C:", "D:"],
                    diskUsedBytes: [500_000_000_000, 0],
                    diskTotalBytes: [1_000_000_000_000, 2_000_000_000_000],
                    netRxBytesPerSec: 1_048_576, netTxBytesPerSec: 65_536)),
            .metricsHistory(
                MetricsHistoryBody(
                    sub: deviceID, startTs: 1_699_913_600_000, intervalMs: 30_000,
                    cpuPercent: [0.0, 55.5, 100.0],
                    memUsedBytes: [1, 2, 3], memTotalBytes: 34_359_738_368,
                    netRxBytesPerSec: [0, 10, 20], netTxBytesPerSec: [5, 15, 25])),
            // Absent is a different claim from zero — throughput the agent
            // could not determine, and a capacity it has not sampled yet. Both
            // must survive the round trip as absent.
            .metricsTick(
                MetricsTickBody(
                    sub: deviceID, ts: 1_700_000_000_000, cpuPercent: 0.0,
                    memUsedBytes: 1, memTotalBytes: 2,
                    diskLabels: [], diskUsedBytes: [], diskTotalBytes: [],
                    netRxBytesPerSec: nil, netTxBytesPerSec: nil)),
            .metricsHistory(
                MetricsHistoryBody(
                    sub: deviceID, startTs: 0, intervalMs: 30_000,
                    cpuPercent: [], memUsedBytes: [], memTotalBytes: nil,
                    netRxBytesPerSec: [], netTxBytesPerSec: []))
        ]

        for body in bodies {
            let id = UUID()
            let encoded = try encode(id: id, body: body)
            let decoded = try OspreyProtocol.decode(encoded)
            XCTAssertEqual(decoded.id, id)
            XCTAssertEqual(decoded.t, body.messageType)
            XCTAssertEqual(decoded.body, body)
        }
    }

    func testUnknownEnumValuesArePreserved() throws {
        let raw = try OspreyProtocol.encode(
            ts: 0,
            body: ByeBody(reason: .unknown("moon_phase"), detail: nil))
        let decoded = try OspreyProtocol.decode(raw)
        guard case .bye(let bye) = decoded.body else {
            return XCTFail("expected a bye, got \(decoded.t)")
        }
        XCTAssertEqual(bye.reason, .unknown("moon_phase"))
    }

    func testBytesTravelAsBase64() throws {
        let raw = try OspreyProtocol.encode(
            ts: 0,
            body: PairRevokeBody(
                issuerDeviceId: UUID(), revokedDeviceId: UUID(), issuedAt: 0,
                nonce: Data(repeating: 0x00, count: 32),
                signature: Data([0x01, 0x02, 0x03])))
        let text = try XCTUnwrap(String(bytes: raw, encoding: .utf8))
        XCTAssertTrue(
            text.contains("\"signature\":\"AQID\""),
            "the generated bodies must encode `bytes` as padded standard base64")
    }

    func testAFutureEnvelopeVersionIsRefused() throws {
        let payload = #"{"v":2,"id":"7ec2a7d0-0000-4000-8000-000000000001","t":"ping","ts":0,"body":{"seq":1}}"#
        XCTAssertThrowsError(try OspreyProtocol.decode(Data(payload.utf8))) { error in
            XCTAssertEqual(
                error as? OspreyProtocolError, .unsupportedVersion(found: 2, min: 1, max: 1))
        }
    }

    private func encode(id: UUID, body: MessageBody) throws -> Data {
        switch body {
        case .error(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .hello(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .helloOk(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .ping(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .pong(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .bye(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .pairRequest(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .pairConfirm(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        case .pairRevoke(let value): return try OspreyProtocol.encode(id: id, ts: 0, body: value)
        }
    }
}
