import XCTest

@testable import Osprey

/// What the Swift layer actually puts on the wire, checked against lengths
/// measured by running the shipping Rust.
///
/// The suite this replaces exercised a Swift reimplementation of the framing
/// against itself, so it passed while the app double-prefixed every message and
/// carried two continuation flags. These assertions instead pin the Swift output
/// to numbers observed from `osprey-ffi` driving a real `osprey-core` responder:
///
/// ```
/// # measured 2026-08-02 against osprey-ffi 0.1.0
/// pairing msg1 payload=0   wire=98      session msg1 payload=0   wire=98
/// pairing msg1 payload=1   wire=99      session msg1 payload=1   wire=99
/// pairing msg1 payload=300 wire=398     session msg1 payload=300 wire=398
/// transport plaintext=0     wire=19        transport plaintext=22    wire=41
/// transport plaintext=65518 wire=65537     transport plaintext=65519 wire=65557
/// max_chunk_payload_len=65518   noise_max_message_len=65535
/// ```
///
/// `TODO(frank):` the responder half of the handshake cannot be replayed from a
/// recording — the initiator's ephemeral is fresh on every run and `osprey-ffi`
/// exposes no responder constructor and no RNG injection, so recorded second-
/// message bytes decrypt under nothing. Decide whether `osprey-ffi` should export
/// a responder constructor for tests, which would let Swift drive both halves of
/// a real handshake and assert a plaintext round trip, or whether the agent-side
/// `tests/pairing_interop.rs` is where that coverage stays. Until then the real
/// engine is exercised through message one only, and the transport leg is held to
/// the measured constants above.
final class NoiseWireFormatTests: XCTestCase {
    /// Frame prefix (2) + ephemeral (32) + encrypted static (32 + 16) + payload
    /// tag (16). Identical for `IK` and `IKpsk2`.
    static let handshakeMessageOverhead = 98
    /// Frame prefix (2) + continuation flag (1) + ChaCha20-Poly1305 tag (16).
    static let transportFrameOverhead = 19

    static let localStatic = Data(repeating: 0x11, count: 32)
    /// X25519 treats every 32-byte string as a public u-coordinate, so this
    /// needs no structure — only the right length, which `NoiseChannel` enforces.
    static let agentStatic = Data(repeating: 0x22, count: 32)

    /// The regression this file exists for: one frame out, not two.
    func testTheRealEngineFramesTheFirstMessageExactlyOnce() async throws {
        for payloadLength in [0, 1, 300] {
            let channel = NoiseChannel(engine: FFINoiseEngine())
            let wire = try await channel.begin(
                pattern: .pairing(pairingSecret: Data(repeating: 0x5A, count: 32)),
                localStaticPrivateKey: Self.localStatic,
                remoteStaticPublicKey: Self.agentStatic,
                payload: Data(repeating: 0xA5, count: payloadLength))

            XCTAssertEqual(
                wire.count, Self.handshakeMessageOverhead + payloadLength,
                "a second length prefix or chunk header would show up here")

            let scan = try frameDecode(buffer: wire)
            let body = try XCTUnwrap(scan.frame, "begin must emit one complete frame")
            XCTAssertEqual(
                Int(scan.consumed), wire.count, "no bytes may be left outside the frame")
            XCTAssertEqual(body.count, wire.count - 2)
        }
    }

    func testBothPatternsProduceTheSameFirstMessageLength() async throws {
        let channel = NoiseChannel(engine: FFINoiseEngine())
        let wire = try await channel.begin(
            pattern: .session,
            localStaticPrivateKey: Self.localStatic,
            remoteStaticPublicKey: Self.agentStatic,
            payload: Data())
        XCTAssertEqual(wire.count, Self.handshakeMessageOverhead)
    }

    /// The chunking constants the transport overhead is derived from, read back
    /// from the core rather than restated.
    func testTheCoreConstantsAreTheOnesTheseNumbersCameFrom() {
        XCTAssertEqual(Int(noiseMaxMessageLen()), 65535)
        XCTAssertEqual(Int(maxChunkPayloadLen()), 65518)
        // The largest payload that still fits in a single frame.
        XCTAssertEqual(
            Int(maxChunkPayloadLen()) + Self.transportFrameOverhead,
            Int(noiseMaxMessageLen()) + 2)
    }

    /// The Swift layer must add nothing to what the transport returned.
    ///
    /// `PassthroughTransport` frames with the core's own `frameEncode`, so if
    /// `seal` ever reintroduces chunking or a second prefix the equality breaks.
    func testSealWritesTheTransportOutputVerbatim() async throws {
        let channel = try await Self.establishedPassthroughChannel(pipelining: Data())

        for payload in [Data(), Data([0x01]), Data(repeating: 0x7E, count: 4096)] {
            let sealed = try await channel.seal(payload)
            XCTAssertEqual(sealed, try frameEncode(message: payload))
        }
    }

    /// Bytes the agent pipelined into the handshake's last segment survive
    /// promotion, because `into_transport` moves the core's leftover across.
    func testAPipelinedTransportMessageSurvivesPromotion() async throws {
        let pipelined = Data("pipelined".utf8)
        let channel = try await Self.establishedPassthroughChannel(
            pipelining: try frameEncode(message: pipelined))

        let first = try await channel.nextMessage()
        XCTAssertEqual(first, pipelined)
        let second = try await channel.nextMessage()
        XCTAssertNil(second)
    }

    /// A channel in transport mode, with `trailing` bytes delivered in the same
    /// push as the handshake reply.
    private static func establishedPassthroughChannel(
        pipelining trailing: Data
    ) async throws -> NoiseChannel {
        let channel = NoiseChannel(engine: PassthroughNoiseEngine(remoteStatic: localStatic))
        _ = try await channel.begin(
            pattern: .session,
            localStaticPrivateKey: localStatic,
            remoteStaticPublicKey: agentStatic,
            payload: Data())

        var segment = try frameEncode(message: Data())
        segment.append(trailing)
        try await channel.push(segment)

        let payload = try await channel.handshakePayload()
        _ = try XCTUnwrap(payload, "the handshake reply must be one complete frame")
        _ = try await channel.promote()
        return channel
    }
}
