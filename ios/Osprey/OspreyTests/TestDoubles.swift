import Foundation

@testable import Osprey

/// Test doubles.
///
/// Every lock is taken inside a synchronous helper: `NSLock.lock()` is
/// `noasync`, so an `async` method must not hold one across its own body.

/// A byte stream whose reads come from a script and whose writes are recorded.
///
/// Test-only. It exists so the pairing state machine can be driven without a
/// socket; it is never linked into the app target.
final class ScriptedStream: ByteStream, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound: Data
    private var written = Data()
    private var closed = false

    init(inbound: Data) {
        self.inbound = inbound
    }

    var outbound: Data {
        lock.lock()
        defer { lock.unlock() }
        return written
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    func write(_ data: Data) async throws {
        record(data)
    }

    func read(exactly count: Int) async throws -> Data? {
        try take(count)
    }

    func close() async {
        markClosed()
    }

    private func record(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        written.append(data)
    }

    private func take(_ count: Int) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard inbound.count >= count else {
            if inbound.isEmpty { return nil }
            throw StreamStandInError.truncated
        }
        let head = Data(inbound.prefix(count))
        inbound = Data(inbound.dropFirst(count))
        return head
    }

    private func markClosed() {
        lock.lock()
        defer { lock.unlock() }
        closed = true
    }
}

enum StreamStandInError: Error {
    case truncated
}

/// A stream that answers each logical message the client sends.
///
/// Assumes `PassthroughTransport`, so a "ciphertext" chunk is just
/// `[flag] ‖ payload`. Handshake frames are counted and ignored; every frame
/// after them is treated as one complete application message.
final class RespondingStream: ByteStream, @unchecked Sendable {
    typealias Responder = @Sendable (Data) throws -> Data?

    private let lock = NSLock()
    private let responder: Responder
    private var readable: Data
    private var pendingWrite = Data()
    private var handshakeFramesToIgnore: Int

    init(handshakeReply: Data, handshakeFramesToIgnore: Int = 1, responder: @escaping Responder) {
        self.readable = handshakeReply
        self.handshakeFramesToIgnore = handshakeFramesToIgnore
        self.responder = responder
    }

    func write(_ data: Data) async throws {
        try consume(data)
    }

    func read(exactly count: Int) async throws -> Data? {
        try take(count)
    }

    func close() async {}

    private func consume(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        pendingWrite.append(data)
        while let message = takeFrameLocked() {
            if handshakeFramesToIgnore > 0 {
                handshakeFramesToIgnore -= 1
                continue
            }
            let (_, envelope) = try NoiseFraming.splitChunkHeader(message)
            if let reply = try responder(envelope) {
                readable.append(try finalChunk(reply))
            }
        }
    }

    private func take(_ count: Int) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard readable.count >= count else {
            if readable.isEmpty { return nil }
            throw StreamStandInError.truncated
        }
        let head = Data(readable.prefix(count))
        readable = Data(readable.dropFirst(count))
        return head
    }

    private func takeFrameLocked() -> Data? {
        guard pendingWrite.count >= 2 else { return nil }
        let high = Int(pendingWrite[pendingWrite.startIndex])
        let low = Int(pendingWrite[pendingWrite.index(after: pendingWrite.startIndex)])
        let length = (high << 8) | low
        guard pendingWrite.count >= 2 + length else { return nil }
        let body = Data(pendingWrite.dropFirst(2).prefix(length))
        pendingWrite = Data(pendingWrite.dropFirst(2 + length))
        return body
    }
}

/// A `NoiseEngine` that does no cryptography.
///
/// Test-only, and never a runtime fallback: `FFINoiseEngine` is the only engine
/// the app target constructs. Handshake and transport messages pass through
/// unchanged, which is what lets a test script the responder's bytes literally.
final class PassthroughNoiseEngine: NoiseEngine, @unchecked Sendable {
    private let lock = NSLock()
    private let remoteStatic: Data
    private var secretSeen: Data?
    private var patterns: [String] = []

    init(remoteStatic: Data) {
        self.remoteStatic = remoteStatic
    }

    var pairingSecretSeen: Data? {
        lock.lock()
        defer { lock.unlock() }
        return secretSeen
    }

    var patternsRequested: [String] {
        lock.lock()
        defer { lock.unlock() }
        return patterns
    }

    func pairingInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data,
        pairingSecret: Data
    ) throws -> any NoiseHandshaking {
        lock.lock()
        secretSeen = pairingSecret
        patterns.append("pairing")
        lock.unlock()
        return PassthroughHandshake(remoteStatic: remoteStatic)
    }

    func sessionInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data
    ) throws -> any NoiseHandshaking {
        lock.lock()
        patterns.append("session")
        lock.unlock()
        return PassthroughHandshake(remoteStatic: remoteStatic)
    }
}

final class PassthroughHandshake: NoiseHandshaking {
    private let remoteStatic: Data

    init(remoteStatic: Data) {
        self.remoteStatic = remoteStatic
    }

    func writeMessage(_ payload: Data) throws -> Data { payload }
    func readMessage(_ message: Data) throws -> Data { message }
    func remoteStaticPublicKey() throws -> Data { remoteStatic }
    func intoTransport() throws -> any NoiseTransporting { PassthroughTransport() }
}

final class PassthroughTransport: NoiseTransporting {
    func encrypt(_ plaintext: Data) throws -> Data { plaintext }
    func decrypt(_ ciphertext: Data) throws -> Data { ciphertext }
}

/// A `PairingPayloadSource` that replays a scripted list of QR strings.
///
/// This is the seam the Simulator needs: it has no camera, so
/// `CameraPairingPayloadSource` cannot run there. It lives in the test target
/// precisely so it cannot become a runtime fallback in a shipped build.
final class ScriptedPairingPayloadSource: PairingPayloadSource, @unchecked Sendable {
    private let scripted: [String]
    private let lock = NSLock()
    private var continuation: AsyncStream<String>.Continuation?
    private var didStart = false

    init(scripted: [String]) {
        self.scripted = scripted
    }

    var started: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didStart
    }

    func payloads() -> AsyncStream<String> {
        AsyncStream { continuation in
            attach(continuation)
        }
    }

    func start() async throws {
        let sink = markStarted()
        for text in scripted {
            sink?.yield(text)
        }
    }

    func stop() async {
        detach()?.finish()
    }

    private func attach(_ continuation: AsyncStream<String>.Continuation) {
        lock.lock()
        defer { lock.unlock() }
        self.continuation = continuation
    }

    private func markStarted() -> AsyncStream<String>.Continuation? {
        lock.lock()
        defer { lock.unlock() }
        didStart = true
        return continuation
    }

    private func detach() -> AsyncStream<String>.Continuation? {
        lock.lock()
        defer { lock.unlock() }
        let sink = continuation
        continuation = nil
        return sink
    }
}

/// Build one wire frame: 2-byte big-endian length, then the message.
func frame(_ message: Data) throws -> Data {
    var out = try NoiseFraming.lengthPrefix(message.count)
    out.append(message)
    return out
}

/// Build one transport chunk as `PassthroughTransport` would carry it.
func finalChunk(_ payload: Data) throws -> Data {
    var chunk = Data([0x00])
    chunk.append(payload)
    return try frame(chunk)
}
