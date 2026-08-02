import Foundation

/// An established Noise channel over a byte stream.
///
/// A byte pump, not a framer: `send` writes whatever `NoiseChannel.seal`
/// produced, and `receive` feeds socket bytes back in until the Rust core says a
/// whole message has arrived. Chunking, the continuation flag, the length
/// prefix and the reassembly ceiling are all the core's, so there is exactly one
/// implementation of the wire format and it is the one the agent runs.
public struct NoiseSession: Sendable {
    /// How many bytes to ask the socket for at a time.
    ///
    /// A hint only — any value is correct, because the core buffers whatever
    /// arrives. 16 KiB carries most management-plane messages in one read
    /// without reserving a 64 KiB buffer per receive.
    static let readChunkLength = 16 * 1024

    let channel: NoiseChannel
    let stream: any ByteStream
    private let sendGate: SendGate

    public init(channel: NoiseChannel, stream: any ByteStream) {
        self.channel = channel
        self.stream = stream
        self.sendGate = SendGate()
    }

    /// Encrypt and write one message.
    ///
    /// Sealing and writing are one indivisible step. Noise numbers every
    /// ciphertext, so the order bytes reach the socket must match the order they
    /// were sealed in — and `seal` and `write` are separate suspension points,
    /// so two concurrent callers could otherwise seal as (A, B) and write as
    /// (B, A). The peer would reject the out-of-order nonce and the session
    /// would be dead with no useful diagnostic. `SendGate` makes the pair
    /// atomic; the actor around the cipher state alone is not enough.
    public func send(_ payload: Data) async throws {
        try await sendGate.serialized { [channel, stream] in
            try await stream.write(channel.seal(payload))
        }
    }

    /// Read, decrypt and reassemble one logical message.
    ///
    /// `nil` means the peer closed. A peer that closes part-way through a frame
    /// is reported the same way, because the reassembly buffer lives in the Rust
    /// core and does not report its depth — nothing is accepted either way, as
    /// an incomplete frame is discarded before it is ever authenticated, so the
    /// difference is diagnostic rather than a trust boundary.
    public func receive() async throws -> Data? {
        while true {
            // Drained first: `intoTransport` carries bytes the agent pipelined
            // into the handshake's last TCP segment across to the transport, and
            // one socket read can carry several messages.
            if let message = try await channel.nextMessage() { return message }
            guard let bytes = try await stream.read(upTo: Self.readChunkLength) else {
                return nil
            }
            try await channel.push(bytes)
        }
    }

    /// Receive one message, treating a close as a failure.
    public func receiveRequired() async throws -> Data {
        guard let message = try await receive() else {
            throw NoiseSessionError.peerClosedMidExchange
        }
        return message
    }

    public func close() async {
        await stream.close()
    }
}

/// Drive one handshake message in from the socket.
///
/// `nil` means the peer closed before a complete message arrived. Shared by
/// pairing and session setup, which differ only in what they do with the payload.
func readHandshakePayload(
    channel: NoiseChannel,
    stream: any ByteStream
) async throws -> Data? {
    while true {
        if let payload = try await channel.handshakePayload() { return payload }
        guard let bytes = try await stream.read(upTo: NoiseSession.readChunkLength) else {
            return nil
        }
        try await channel.push(bytes)
    }
}

public enum NoiseSessionError: Error, Hashable, Sendable {
    case peerClosedMidExchange
}

extension NoiseSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .peerClosedMidExchange:
            return "The host closed the connection before it answered."
        }
    }
}
