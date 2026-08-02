import XCTest

@testable import Osprey

/// The protocol conversation, driven against a scripted responder.
final class SessionClientTests: XCTestCase {
    static let staticKey = Data(repeating: 0x11, count: 32)

    /// Build an established session whose peer answers with `responder`.
    static func makeClient(
        responder: @escaping RespondingStream.Responder
    ) async throws -> SessionClient {
        let stream = RespondingStream(
            handshakeReply: try frame(Data()), responder: responder)
        let channel = NoiseChannel(engine: PassthroughNoiseEngine(remoteStatic: staticKey))
        let framed = FramedStream(stream: stream)
        let first = try await channel.begin(
            pattern: .session,
            localStaticPrivateKey: staticKey,
            remoteStaticPublicKey: staticKey,
            payload: Data())
        try await framed.writeFrame(first)
        let secondFrame = try await framed.readFrame()
        let second = try XCTUnwrap(secondFrame)
        _ = try await channel.complete(second)
        return SessionClient(session: NoiseSession(channel: channel, stream: stream))
    }

    func testHelloIsAnsweredWithHelloOk() async throws {
        let sessionID = UUID()
        let hostDeviceID = UUID()
        let client = try await Self.makeClient { request in
            let header = try OspreyProtocol.decodeHeader(request)
            XCTAssertEqual(header.t, .hello)
            return try OspreyProtocol.encode(
                id: header.id,
                ts: header.ts,
                body: HelloOkBody(
                    protocolVersion: 1,
                    capabilities: [],
                    deviceId: hostDeviceID,
                    softwareVersion: "osprey-svc/0.1.0",
                    sessionId: sessionID))
        }

        let helloOk = try await client.openSession(
            deviceID: UUID(), softwareVersion: "osprey-ios/test")
        XCTAssertEqual(helloOk.sessionId, sessionID)
        XCTAssertEqual(helloOk.deviceId, hostDeviceID)
        XCTAssertEqual(helloOk.softwareVersion, "osprey-svc/0.1.0")
    }

    func testPingIsAnsweredWithAMatchingPong() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            guard case .ping(let ping) = decoded.body else {
                XCTFail("expected a ping, got \(decoded.t)")
                return nil
            }
            return try OspreyProtocol.encode(
                id: decoded.id,
                ts: decoded.ts,
                body: PongBody(seq: ping.seq, echoTs: decoded.ts))
        }

        let result = try await client.ping(sequence: 7)
        XCTAssertEqual(result.sequence, 7)
        XCTAssertGreaterThanOrEqual(result.roundTripMilliseconds, 0)
    }

    func testAPongForTheWrongSequenceIsRefused() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return try OspreyProtocol.encode(
                id: decoded.id, ts: decoded.ts, body: PongBody(seq: 99, echoTs: decoded.ts))
        }

        do {
            _ = try await client.ping(sequence: 1)
            XCTFail("a mismatched pong sequence must be refused")
        } catch let error as SessionError {
            XCTAssertEqual(error, .pongSequenceMismatch(sent: 1, received: 99))
        }
    }

    func testAReplyToAnotherRequestIsRefused() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return try OspreyProtocol.encode(
                id: UUID(), ts: decoded.ts, body: PongBody(seq: 1, echoTs: decoded.ts))
        }

        do {
            _ = try await client.ping(sequence: 1)
            XCTFail("an uncorrelated reply must be refused")
        } catch let error as SessionError {
            guard case .correlationMismatch = error else {
                return XCTFail("expected a correlation mismatch, got \(error)")
            }
        }
    }

    func testAnErrorBodyIsSurfaced() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return try OspreyProtocol.encode(
                id: decoded.id,
                ts: decoded.ts,
                body: ErrorBody(
                    code: .unsupported, message: "not implemented in this build",
                    retryable: false))
        }

        do {
            _ = try await client.ping(sequence: 1)
            XCTFail("an error body must not be reported as success")
        } catch let error as SessionError {
            XCTAssertEqual(
                error,
                .hostRefused(
                    code: .unsupported, message: "not implemented in this build",
                    retryable: false))
        }
    }
}
