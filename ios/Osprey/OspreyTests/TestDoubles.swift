import Foundation

@testable import Osprey

/// Test doubles.
///
/// Every lock is taken inside a synchronous helper: `NSLock.lock()` is
/// `noasync`, so an `async` method must not hold one across its own body.
///
/// Every double that has to find a message boundary cuts frames with the Rust
/// core's own `frameDecode`, and builds them with `frameEncode`. A double that
/// reimplemented the length prefix would be able to agree with a Swift bug and
/// disagree with the agent, which is precisely how the double-framing defect
/// survived a green test suite.

/// Frame reassembly over the core's decoder.
struct FrameBuffer {
    private var bytes = Data()

    var pending: Data { bytes }

    mutating func push(_ data: Data) {
        bytes.append(data)
    }

    /// The next complete frame body, or `nil` while more bytes are needed.
    mutating func take() throws -> Data? {
        let scan = try frameDecode(buffer: bytes)
        guard let frame = scan.frame else { return nil }
        bytes = Data(bytes.dropFirst(Int(scan.consumed)))
        return frame
    }

    /// Hand the unparsed remainder to whoever takes over the stream.
    mutating func drain() -> Data {
        let rest = bytes
        bytes = Data()
        return rest
    }
}

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

    func read(upTo maxCount: Int) async throws -> Data? {
        take(maxCount)
    }

    func close() async {
        markClosed()
    }

    private func record(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        written.append(data)
    }

    private func take(_ maxCount: Int) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard !inbound.isEmpty else { return nil }
        let head = Data(inbound.prefix(maxCount))
        inbound = Data(inbound.dropFirst(head.count))
        return head
    }

    private func markClosed() {
        lock.lock()
        defer { lock.unlock() }
        closed = true
    }
}

/// A stream that answers each logical message the client sends.
///
/// Assumes `PassthroughTransport`, so a "ciphertext" frame carries the envelope
/// unchanged. Handshake frames are counted and ignored; every frame after them
/// is treated as one complete application message.
final class RespondingStream: ByteStream, @unchecked Sendable {
    /// Zero or more replies to one request. A list rather than one optional so a
    /// test can script a host that answers twice — which is how the
    /// uncorrelated-reply case is exercised.
    typealias Responder = @Sendable (Data) throws -> [Data]

    /// How long an idle read waits before giving up.
    ///
    /// A real `ByteStream` blocks until bytes arrive or the peer closes, and
    /// `SessionMux` reads continuously — so a double that returned `nil` for
    /// "nothing yet" would be telling the mux the host had hung up the instant
    /// it started. Bounded so a test that scripts no reply fails instead of
    /// hanging the suite.
    static let idleTimeout: Duration = .seconds(5)
    private static let pollInterval: Duration = .milliseconds(2)

    private let lock = NSLock()
    private let responder: Responder
    private var readable: Data
    private var pendingWrite = FrameBuffer()
    private var handshakeFramesToIgnore: Int
    private var closed = false

    init(handshakeReply: Data, handshakeFramesToIgnore: Int = 1, responder: @escaping Responder) {
        self.readable = handshakeReply
        self.handshakeFramesToIgnore = handshakeFramesToIgnore
        self.responder = responder
    }

    func write(_ data: Data) async throws {
        try consume(data)
    }

    func read(upTo maxCount: Int) async throws -> Data? {
        let deadline = ContinuousClock.now.advanced(by: Self.idleTimeout)
        while ContinuousClock.now < deadline {
            if Task.isCancelled { return nil }
            if let chunk = take(maxCount) { return chunk }
            if isClosed { return nil }
            try await Task.sleep(for: Self.pollInterval)
        }
        // Out of patience: report a close so the reader ends rather than
        // spinning, and the waiting exchange fails with a stated reason.
        return nil
    }

    func close() async {
        lock.lock()
        defer { lock.unlock() }
        closed = true
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func consume(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        pendingWrite.push(data)
        while let envelope = try pendingWrite.take() {
            if handshakeFramesToIgnore > 0 {
                handshakeFramesToIgnore -= 1
                continue
            }
            for reply in try responder(envelope) {
                readable.append(try frameEncode(message: reply))
            }
        }
    }

    private func take(_ maxCount: Int) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard !readable.isEmpty else { return nil }
        let head = Data(readable.prefix(maxCount))
        readable = Data(readable.dropFirst(head.count))
        return head
    }
}

/// A `NoiseEngine` that does no cryptography.
///
/// Test-only, and never a runtime fallback: `FFINoiseEngine` is the only engine
/// the app target constructs. Handshake and transport payloads pass through
/// unencrypted but *are* framed by the core, so a test scripts the responder's
/// bytes in the same shape the agent would send them.
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
    private var inbound = FrameBuffer()

    init(remoteStatic: Data) {
        self.remoteStatic = remoteStatic
    }

    func writeMessage(_ payload: Data) throws -> Data {
        try frameEncode(message: payload)
    }

    func pushBytes(_ data: Data) throws {
        inbound.push(data)
    }

    func readMessage() throws -> Data? {
        try inbound.take()
    }

    func intoTransport() throws -> any NoiseTransporting {
        PassthroughTransport(remoteStatic: remoteStatic, buffered: inbound.drain())
    }
}

final class PassthroughTransport: NoiseTransporting {
    private let remoteStatic: Data
    private var inbound = FrameBuffer()

    init(remoteStatic: Data, buffered: Data = Data()) {
        self.remoteStatic = remoteStatic
        inbound.push(buffered)
    }

    func encrypt(_ payload: Data) throws -> Data {
        try frameEncode(message: payload)
    }

    func pushBytes(_ data: Data) throws {
        inbound.push(data)
    }

    func nextMessage() throws -> Data? {
        try inbound.take()
    }

    func remoteStaticPublicKey() throws -> Data {
        remoteStatic
    }
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
