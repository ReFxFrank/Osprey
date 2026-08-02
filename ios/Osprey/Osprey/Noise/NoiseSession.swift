import Foundation

/// An established Noise channel over a framed byte stream.
///
/// Message-level, not byte-level: `send` chunks and frames one logical payload,
/// `receive` reassembles one.
public struct NoiseSession: Sendable {
    /// Management-plane messages are small. Capping reassembly means a peer
    /// cannot make the phone buffer megabytes before a single field has been
    /// validated. Matches `osprey-svc`'s `MAX_SESSION_MESSAGE_LEN`.
    public static let maxMessageLength = 64 * 1024

    let channel: NoiseChannel
    let framed: FramedStream
    let maxMessageLength: Int

    public init(
        channel: NoiseChannel,
        stream: any ByteStream,
        maxMessageLength: Int = NoiseSession.maxMessageLength
    ) {
        self.channel = channel
        self.framed = FramedStream(stream: stream)
        self.maxMessageLength = maxMessageLength
    }

    public func send(_ payload: Data) async throws {
        for chunk in try await channel.seal(payload) {
            try await framed.writeFrame(chunk)
        }
    }

    /// Read, decrypt and reassemble one logical message.
    ///
    /// `nil` means the peer closed cleanly on a message boundary.
    ///
    /// Two independent bounds apply, because the byte cap alone is not a
    /// progress bound: an authenticated peer can emit continuation chunks whose
    /// bodies are empty, adding zero bytes per chunk and stalling the reader
    /// forever. So an empty non-final chunk is refused outright, and the total
    /// chunk count is capped as well.
    public func receive() async throws -> Data? {
        let chunkCeiling = NoiseFraming.maxChunks(forMessageLength: maxMessageLength)
        var assembled = Data()
        var chunks = 0
        while true {
            guard let frame = try await framed.readFrame() else {
                if chunks == 0 { return nil }
                throw NoiseFramingError.truncatedFrame(got: 0, want: 2)
            }
            chunks += 1
            guard chunks <= chunkCeiling else {
                throw NoiseFramingError.tooManyChunks(max: chunkCeiling)
            }
            let chunk = try await channel.open(chunk: frame)
            if !chunk.isFinal && chunk.body.isEmpty {
                throw NoiseFramingError.emptyContinuationChunk
            }
            guard assembled.count + chunk.body.count <= maxMessageLength else {
                throw NoiseFramingError.messageTooLarge(max: maxMessageLength)
            }
            assembled.append(chunk.body)
            if chunk.isFinal { return assembled }
        }
    }

    /// Receive one message, treating a clean close as a failure.
    public func receiveRequired() async throws -> Data {
        guard let message = try await receive() else {
            throw NoiseFramingError.truncatedFrame(got: 0, want: 2)
        }
        return message
    }

    public func close() async {
        await framed.stream.close()
    }
}
