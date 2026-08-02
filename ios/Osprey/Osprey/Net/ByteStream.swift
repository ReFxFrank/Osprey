import Foundation

/// A bidirectional byte stream.
///
/// The Noise layer needs exactly this and nothing more, so the transport can be
/// a real TCP connection on the device and an in-memory pipe in a test without
/// either side knowing.
///
/// There is deliberately no `readFrame`. Framing belongs to the Rust core, which
/// buffers and reassembles for itself, so this protocol stops at "bytes".
public protocol ByteStream: Sendable {
    func write(_ data: Data) async throws
    /// Read whatever has arrived, up to `maxCount` bytes.
    ///
    /// `nil` means the peer closed. A non-nil result is never empty: a caller
    /// looping until it has a complete message cannot make progress — and cannot
    /// tell a stall from a close — if empty reads are allowed.
    func read(upTo maxCount: Int) async throws -> Data?
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
