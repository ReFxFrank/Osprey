import Foundation

/// A bidirectional byte stream.
///
/// The Noise layer needs exactly this and nothing more, so the transport can be
/// a real TCP connection on the device and an in-memory pipe in a test without
/// either side knowing.
public protocol ByteStream: Sendable {
    func write(_ data: Data) async throws
    /// Read exactly `count` bytes.
    ///
    /// Returns `nil` only for a clean close on a message boundary — zero bytes
    /// available. A close *mid*-read throws, because accepting the prefix of a
    /// truncated message is how truncation attacks succeed.
    func read(exactly count: Int) async throws -> Data?
    func close() async
}

/// Run `operation`, closing `stream` if it has not finished within `seconds`.
///
/// A stalled peer is what this defends against: every read on this path blocks
/// until bytes arrive, and closing the stream is what turns an indefinite wait
/// into a thrown error the caller can report.
public func withStreamDeadline<T>(
    seconds: TimeInterval,
    stream: any ByteStream,
    operation: () async throws -> T
) async throws -> T {
    let watchdog = Task {
        do {
            try await Task.sleep(for: .seconds(seconds))
        } catch {
            // Cancelled because the operation finished first. Nothing to close.
            return
        }
        await stream.close()
    }
    defer { watchdog.cancel() }
    return try await operation()
}

/// 2-byte-big-endian framing over a byte stream.
public struct FramedStream: Sendable {
    public let stream: any ByteStream

    public init(stream: any ByteStream) {
        self.stream = stream
    }

    public func writeFrame(_ message: Data) async throws {
        var framed = try NoiseFraming.lengthPrefix(message.count)
        framed.append(message)
        try await stream.write(framed)
    }

    /// Returns `nil` on a clean close at a frame boundary.
    public func readFrame() async throws -> Data? {
        guard let prefix = try await stream.read(exactly: 2) else { return nil }
        let length = try NoiseFraming.frameLength(prefix)
        guard length > 0 else { return Data() }
        guard let body = try await stream.read(exactly: length) else {
            throw NoiseFramingError.truncatedFrame(got: 0, want: length)
        }
        return body
    }
}
