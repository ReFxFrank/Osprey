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
            handshakeReply: try frameEncode(message: Data()), responder: responder)
        let channel = NoiseChannel(engine: PassthroughNoiseEngine(remoteStatic: staticKey))
        let first = try await channel.begin(
            pattern: .session,
            localStaticPrivateKey: staticKey,
            remoteStaticPublicKey: staticKey,
            payload: Data())
        try await stream.write(first)
        let handshakePayload = try await readHandshakePayload(channel: channel, stream: stream)
        _ = try XCTUnwrap(handshakePayload, "the scripted host must answer the handshake")
        _ = try await channel.promote()
        return SessionClient(mux: SessionMux(session: NoiseSession(channel: channel, stream: stream)))
    }

    func testHelloIsAnsweredWithHelloOk() async throws {
        let sessionID = UUID()
        let hostDeviceID = UUID()
        let client = try await Self.makeClient { request in
            let header = try OspreyProtocol.decodeHeader(request)
            XCTAssertEqual(header.t, .hello)
            return [
                try OspreyProtocol.encode(
                    id: header.id,
                    ts: header.ts,
                    body: HelloOkBody(
                        protocolVersion: 1,
                        capabilities: [],
                        deviceId: hostDeviceID,
                        softwareVersion: "osprey-svc/0.1.0",
                        sessionId: sessionID,
                        displayName: nil))
            ]
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
                return []
            }
            return [
                try OspreyProtocol.encode(
                    id: decoded.id,
                    ts: decoded.ts,
                    body: PongBody(seq: ping.seq, echoTs: decoded.ts))
            ]
        }

        let result = try await client.ping(sequence: 7)
        XCTAssertEqual(result.sequence, 7)
        XCTAssertGreaterThanOrEqual(result.roundTripMilliseconds, 0)
    }

    func testAPongForTheWrongSequenceIsRefused() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return [
                try OspreyProtocol.encode(
                    id: decoded.id, ts: decoded.ts, body: PongBody(seq: 99, echoTs: decoded.ts))
            ]
        }

        do {
            _ = try await client.ping(sequence: 1)
            XCTFail("a mismatched pong sequence must be refused")
        } catch let error as SessionError {
            XCTAssertEqual(error, .pongSequenceMismatch(sent: 1, received: 99))
        }
    }

    /// The property the multiplexing reader exists for.
    ///
    /// Before it, the client read the next message and assumed it was the
    /// answer, so a message carrying someone else's id — or an unsolicited push
    /// like `metrics.tick` — was mistaken for the reply and failed the session.
    /// Now it is skipped and the real answer, arriving second, still resolves
    /// the request.
    func testAnUncorrelatedReplyIsSkippedRatherThanMistakenForTheAnswer() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return [
                // Someone else's correlation id, delivered first.
                try OspreyProtocol.encode(
                    id: UUID(), ts: decoded.ts, body: PongBody(seq: 999, echoTs: decoded.ts)),
                try OspreyProtocol.encode(
                    id: decoded.id, ts: decoded.ts, body: PongBody(seq: 1, echoTs: decoded.ts))
            ]
        }

        let result = try await client.ping(sequence: 1)
        XCTAssertEqual(
            result.sequence, 1,
            "the request must be answered by its own reply, not by the one before it")
    }

    func testAnErrorBodyIsSurfaced() async throws {
        let client = try await Self.makeClient { request in
            let decoded = try OspreyProtocol.decode(request)
            return [
                try OspreyProtocol.encode(
                    id: decoded.id,
                    ts: decoded.ts,
                    body: ErrorBody(
                        code: .unsupported, message: "not implemented in this build",
                        retryable: false))
            ]
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
