import Foundation

/// Length-prefix framing and chunking for Noise transport messages.
///
/// `snow` does no framing at all, so the two ends have to agree on it out of
/// band. This is the Swift half of `osprey-core/src/noise/framing.rs`: a 2-byte
/// big-endian length prefix, and a one-byte continuation flag carried *inside*
/// the encrypted plaintext so an attacker cannot splice, truncate or reorder a
/// multi-chunk message without failing the AEAD.
public enum NoiseFraming {
    /// A Noise message is length-prefixed with two bytes, so it cannot exceed this.
    public static let maxMessageLength = 65535
    /// ChaCha20-Poly1305 tag appended to every encrypted Noise message.
    public static let tagLength = 16
    /// Largest plaintext `snow` will encrypt into one message.
    public static let maxPlaintextLength = maxMessageLength - tagLength
    /// The continuation flag prepended to every chunk's plaintext.
    public static let chunkHeaderLength = 1
    /// Largest slice of caller payload that fits in one chunk.
    public static let maxChunkPayloadLength = maxPlaintextLength - chunkHeaderLength

    static let flagFinal: UInt8 = 0x00
    static let flagMore: UInt8 = 0x01

    /// Split a payload into chunk plaintexts, each prefixed with its
    /// continuation flag. An empty payload still yields one final, empty-bodied
    /// chunk so zero-length application messages survive the round trip.
    public static func split(_ payload: Data) -> [Data] {
        guard !payload.isEmpty else { return [Data([flagFinal])] }
        var chunks: [Data] = []
        var offset = payload.startIndex
        while offset < payload.endIndex {
            let end =
                payload.index(offset, offsetBy: maxChunkPayloadLength, limitedBy: payload.endIndex)
                ?? payload.endIndex
            var chunk = Data([end == payload.endIndex ? flagFinal : flagMore])
            chunk.append(payload[offset..<end])
            chunks.append(chunk)
            offset = end
        }
        return chunks
    }

    /// Strip and interpret a chunk's continuation flag.
    public static func splitChunkHeader(_ chunk: Data) throws -> (isFinal: Bool, body: Data) {
        guard let flag = chunk.first else { throw NoiseFramingError.emptyChunk }
        let body = Data(chunk.dropFirst())
        switch flag {
        case flagFinal: return (true, body)
        case flagMore: return (false, body)
        default: throw NoiseFramingError.badContinuationFlag(flag)
        }
    }

    /// The 2-byte big-endian prefix for a message of `count` bytes.
    public static func lengthPrefix(_ count: Int) throws -> Data {
        guard let length = UInt16(exactly: count) else {
            throw NoiseFramingError.frameTooLarge(length: count, max: maxMessageLength)
        }
        return Data([UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)])
    }

    /// Read a 2-byte big-endian prefix.
    public static func frameLength(_ prefix: Data) throws -> Int {
        guard prefix.count == 2 else {
            throw NoiseFramingError.truncatedFrame(got: prefix.count, want: 2)
        }
        let high = Int(prefix[prefix.startIndex])
        let low = Int(prefix[prefix.index(after: prefix.startIndex)])
        return (high << 8) | low
    }

    /// How many chunks an honest sender could need for a message of the
    /// permitted size. The `+ 2` absorbs a partial final chunk and the single
    /// chunk a zero-length message still produces.
    public static func maxChunks(forMessageLength max: Int) -> Int {
        max / maxChunkPayloadLength + 2
    }
}

public enum NoiseFramingError: Error, Hashable, Sendable {
    case emptyChunk
    case badContinuationFlag(UInt8)
    case emptyContinuationChunk
    case frameTooLarge(length: Int, max: Int)
    case truncatedFrame(got: Int, want: Int)
    case tooManyChunks(max: Int)
    case messageTooLarge(max: Int)
}

extension NoiseFramingError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .emptyChunk:
            return "the peer sent a chunk with no continuation flag"
        case .badContinuationFlag(let flag):
            return "the peer sent an unknown continuation flag (0x\(String(flag, radix: 16)))"
        case .emptyContinuationChunk:
            return "the peer sent an empty continuation chunk"
        case .frameTooLarge(let length, let max):
            return "frame of \(length) bytes exceeds the \(max)-byte Noise ceiling"
        case .truncatedFrame(let got, let want):
            return "the connection ended mid-frame (\(got) of \(want) bytes)"
        case .tooManyChunks(let max):
            return "the peer exceeded the \(max)-chunk ceiling for one message"
        case .messageTooLarge(let max):
            return "the peer exceeded the \(max)-byte ceiling for one message"
        }
    }
}
