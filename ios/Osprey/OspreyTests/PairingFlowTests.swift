import XCTest

@testable import Osprey

/// Drives the controller's half of pairing against a scripted host.
///
/// The cryptography is stubbed out, so what is under test is exactly the part
/// Swift owns: message order, the identity comparison, and the two ways the
/// exchange must fail closed.
final class PairingFlowTests: XCTestCase {
    static let agentNoiseStatic = Data(repeating: 0xB2, count: 32)
    static let phoneNoiseStatic = Data(repeating: 0xC3, count: 32)

    static func identity(
        noiseStatic: Data = PairingFlowTests.agentNoiseStatic,
        algorithm: IdentityAlgorithm = .ed25519
    ) -> PublicIdentity {
        PublicIdentity(
            identityAlgorithm: algorithm,
            identityPublicKey: Data(repeating: 0xA1, count: 32),
            noiseStaticPublicKey: noiseStatic,
            noiseStaticSignature: Data(repeating: 0xD4, count: 64))
    }

    static func phoneIdentity() -> PublicIdentity {
        PublicIdentity(
            identityAlgorithm: .p256,
            identityPublicKey: Data([0x04]) + Data(repeating: 0x11, count: 64),
            noiseStaticPublicKey: Data(repeating: 0xEE, count: 32),
            noiseStaticSignature: Data(repeating: 0x22, count: 70))
    }

    /// The bytes a well-behaved agent puts on the wire.
    static func hostScript(
        offering identity: PublicIdentity,
        accept: Data = PairingFlow.acceptTag
    ) throws -> Data {
        var script = Data()
        script.append(try frame(try JSONEncoder().encode(IdentityMessage(identity: identity))))
        script.append(try finalChunk(accept))
        return script
    }

    func testHappyPath() async throws {
        let expected = Self.identity()
        let stream = ScriptedStream(inbound: try Self.hostScript(offering: expected))
        let engine = PassthroughNoiseEngine(remoteStatic: Self.agentNoiseStatic)

        let session = try await PairingFlow.run(
            stream: stream,
            engine: engine,
            localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
            localPublicIdentity: Self.phoneIdentity(),
            expectedAgentIdentity: expected,
            pairingSecret: Data(repeating: 0xD4, count: 32))

        XCTAssertEqual(engine.patternsRequested, ["pairing"])
        XCTAssertEqual(engine.pairingSecretSeen, Data(repeating: 0xD4, count: 32))

        // Frame 1 is the phone's identity; frame 2 is the confirmation the agent
        // needs before it will pin anything.
        let written = ScriptedStream(inbound: stream.outbound)
        let framed = FramedStream(stream: written)
        let helloFrame = try await framed.readFrame()
        let hello = try XCTUnwrap(helloFrame)
        let offered = try JSONDecoder().decode(IdentityMessage.self, from: hello)
        XCTAssertEqual(offered.identity, Self.phoneIdentity())

        let confirmFrame = try await framed.readFrame()
        XCTAssertEqual(confirmFrame, Data([0x00]) + PairingFlow.confirmTag)
        let trailing = try await framed.readFrame()
        XCTAssertNil(trailing, "nothing else may be sent")

        await session.close()
        XCTAssertTrue(stream.isClosed)
    }

    func testADifferentHostIdentityIsRefused() async throws {
        let expected = Self.identity()
        let impostor = PublicIdentity(
            identityAlgorithm: .ed25519,
            identityPublicKey: Data(repeating: 0x99, count: 32),
            noiseStaticPublicKey: Self.agentNoiseStatic,
            noiseStaticSignature: Data(repeating: 0xD4, count: 64))
        let stream = ScriptedStream(inbound: try Self.hostScript(offering: impostor))

        await assertThrows(PairingError.hostIdentityMismatch) {
            _ = try await PairingFlow.run(
                stream: stream,
                engine: PassthroughNoiseEngine(remoteStatic: Self.agentNoiseStatic),
                localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
                localPublicIdentity: Self.phoneIdentity(),
                expectedAgentIdentity: expected,
                pairingSecret: Data(repeating: 0xD4, count: 32))
        }
    }

    /// A bundle that vouches for one key while the handshake used another.
    func testAVouchedForKeyThatIsNotTheHandshakeKeyIsRefused() async throws {
        let expected = Self.identity()
        let stream = ScriptedStream(inbound: try Self.hostScript(offering: expected))

        await assertThrows(PairingError.hostStaticMismatch) {
            _ = try await PairingFlow.run(
                stream: stream,
                engine: PassthroughNoiseEngine(remoteStatic: Data(repeating: 0x77, count: 32)),
                localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
                localPublicIdentity: Self.phoneIdentity(),
                expectedAgentIdentity: expected,
                pairingSecret: Data(repeating: 0xD4, count: 32))
        }
    }

    func testAWrongAcceptanceTagIsRefused() async throws {
        let expected = Self.identity()
        let stream = ScriptedStream(
            inbound: try Self.hostScript(offering: expected, accept: Data("nope".utf8)))

        await assertThrows(PairingError.unexpectedHostAcceptance) {
            _ = try await PairingFlow.run(
                stream: stream,
                engine: PassthroughNoiseEngine(remoteStatic: Self.agentNoiseStatic),
                localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
                localPublicIdentity: Self.phoneIdentity(),
                expectedAgentIdentity: expected,
                pairingSecret: Data(repeating: 0xD4, count: 32))
        }
    }

    func testAHostThatHangsUpIsRefused() async throws {
        let stream = ScriptedStream(inbound: Data())

        await assertThrows(PairingError.hostClosedDuringHandshake) {
            _ = try await PairingFlow.run(
                stream: stream,
                engine: PassthroughNoiseEngine(remoteStatic: Self.agentNoiseStatic),
                localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
                localPublicIdentity: Self.phoneIdentity(),
                expectedAgentIdentity: Self.identity(),
                pairingSecret: Data(repeating: 0xD4, count: 32))
        }
    }

    func testAShortPairingSecretIsRefusedBeforeAnythingIsSent() async throws {
        let stream = ScriptedStream(inbound: Data())

        await assertThrows(
            NoiseChannelError.badKeyLength(label: "pairing secret", expected: 32, found: 16)
        ) {
            _ = try await PairingFlow.run(
                stream: stream,
                engine: PassthroughNoiseEngine(remoteStatic: Self.agentNoiseStatic),
                localNoiseStaticPrivateKey: Self.phoneNoiseStatic,
                localPublicIdentity: Self.phoneIdentity(),
                expectedAgentIdentity: Self.identity(),
                pairingSecret: Data(repeating: 0xD4, count: 16))
        }
        XCTAssertTrue(stream.outbound.isEmpty)
    }

    private func assertThrows<E: Error & Equatable>(
        _ expected: E,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as E {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("expected \(expected), got \(error)", file: file, line: line)
        }
    }
}
