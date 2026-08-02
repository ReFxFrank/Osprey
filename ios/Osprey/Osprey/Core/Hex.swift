import Foundation

/// Hex codec for key material.
///
/// The agent serialises every key, signature and secret as lower-case hex
/// (`osprey-core/src/hexser.rs`) rather than base64, because those values end up
/// in a QR code, an audit line and a support email, where a human has to compare
/// two of them by eye. The generated protocol bodies use base64 for their
/// `bytes` fields; the pairing payloads on this path do not, and mixing the two
/// up produces a decode failure rather than a silent misread.
public enum Hex {
    private static let lowercaseDigits: [Character] = Array("0123456789abcdef")

    public static func encode(_ bytes: Data) -> String {
        var out = String()
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(lowercaseDigits[Int(byte >> 4)])
            out.append(lowercaseDigits[Int(byte & 0x0F)])
        }
        return out
    }

    public static func decode(_ text: String) throws -> Data {
        let ascii = Array(text.utf8)
        guard ascii.count.isMultiple(of: 2) else {
            throw HexError.oddLength(ascii.count)
        }
        var out = Data()
        out.reserveCapacity(ascii.count / 2)
        var index = 0
        while index < ascii.count {
            let high = try nibble(ascii[index])
            let low = try nibble(ascii[index + 1])
            out.append((high << 4) | low)
            index += 2
        }
        return out
    }

    /// Decode and require an exact byte count, so a caller never has to check
    /// the length of a key separately from parsing it.
    public static func decode(_ text: String, expecting length: Int) throws -> Data {
        let decoded = try decode(text)
        guard decoded.count == length else {
            throw HexError.unexpectedLength(expected: length, found: decoded.count)
        }
        return decoded
    }

    private static func nibble(_ ascii: UInt8) throws -> UInt8 {
        switch ascii {
        case 0x30...0x39: return ascii - 0x30
        case 0x61...0x66: return ascii - 0x61 + 10
        case 0x41...0x46: return ascii - 0x41 + 10
        default: throw HexError.invalidByte(ascii)
        }
    }
}

public enum HexError: Error, Hashable, Sendable {
    case oddLength(Int)
    case invalidByte(UInt8)
    case unexpectedLength(expected: Int, found: Int)
}

extension HexError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .oddLength(let count):
            return "hex string has an odd length (\(count))"
        case .invalidByte(let byte):
            return "hex string contains a non-hex byte (0x\(String(byte, radix: 16)))"
        case .unexpectedLength(let expected, let found):
            return "expected \(expected) bytes of hex, found \(found)"
        }
    }
}

extension KeyedDecodingContainer {
    /// Decode a hex-encoded byte string.
    func decodeHex(forKey key: Key) throws -> Data {
        let text = try decode(String.self, forKey: key)
        do {
            return try Hex.decode(text)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: self, debugDescription: "not a hex string: \(error)")
        }
    }

    /// Decode a hex-encoded byte string of a fixed length.
    func decodeHex(forKey key: Key, expecting length: Int) throws -> Data {
        let text = try decode(String.self, forKey: key)
        do {
            return try Hex.decode(text, expecting: length)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: self,
                debugDescription: "not \(length) bytes of hex: \(error)")
        }
    }
}

extension KeyedEncodingContainer {
    mutating func encodeHex(_ bytes: Data, forKey key: Key) throws {
        try encode(Hex.encode(bytes), forKey: key)
    }
}
