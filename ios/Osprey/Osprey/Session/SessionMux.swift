import Foundation

/// Owns the read side of a session and routes what arrives.
///
/// ## Why this exists
///
/// Until P1 the client was strictly lock-step: send a request, read the next
/// message, assume it is the answer. That works exactly as long as the host only
/// ever speaks when spoken to. `metrics.tick` breaks it — the host pushes those
/// uncorrelated, at 1 Hz, whenever it feels like it — and under the old shape a
/// tick arriving mid-exchange would be mistaken for the reply and fail the
/// correlation check, killing a perfectly healthy session.
///
/// So one task reads continuously and dispatches: correlated envelopes resume
/// whoever is waiting on that id, and pushes go to their stream. Nothing else in
/// the app may read from the session, or two readers would race for frames.
public actor SessionMux {
    private let session: NoiseSession
    private var pending: [UUID: CheckedContinuation<DecodedEnvelope, any Error>] = [:]
    /// Replies that arrived before their caller was waiting.
    ///
    /// `exchange` has to `await` the send, and the reader is free to run during
    /// that suspension — so on a fast link the answer can be dispatched before
    /// the continuation is registered. Dropping it there would hang the caller
    /// forever. Bounded, because a hostile host could otherwise grow this by
    /// sending replies nobody asked for.
    private var early: [UUID: DecodedEnvelope] = [:]
    private static let maxEarlyReplies = 16
    private var tickContinuation: AsyncStream<MetricsTickBody>.Continuation?
    private var reader: Task<Void, Never>?
    /// Set once the link is finished, so a later `exchange` fails immediately
    /// with the original cause instead of hanging forever.
    private var closure: (any Error)?

    public init(session: NoiseSession) {
        self.session = session
    }

    /// Begin reading. Idempotent.
    public func start() {
        guard reader == nil, closure == nil else { return }
        reader = Task { [weak self] in
            await self?.readLoop()
        }
    }

    /// Send `request` and wait for the envelope carrying `id`.
    public func exchange(id: UUID, request: Data) async throws -> DecodedEnvelope {
        if let closure { throw closure }
        start()
        try await session.send(request)
        if let answered = early.removeValue(forKey: id) { return answered }

        return try await withCheckedThrowingContinuation { continuation in
            // Both re-checked inside the continuation: the reader can fail *or*
            // answer between the send above and this registration, and a
            // continuation stored after either would never be resumed.
            if let closure {
                continuation.resume(throwing: closure)
                return
            }
            if let answered = early.removeValue(forKey: id) {
                continuation.resume(returning: answered)
                return
            }
            pending[id] = continuation
        }
    }

    /// Fire-and-forget, for messages with no reply such as `bye`.
    public func send(_ payload: Data) async throws {
        if let closure { throw closure }
        try await session.send(payload)
    }

    /// The stream of pushed metric samples.
    ///
    /// One stream per session; asking twice replaces the first, which then
    /// finishes. Ticks that arrive with nobody listening are dropped rather than
    /// buffered — a chart only ever draws the present.
    public func metricsTicks() -> AsyncStream<MetricsTickBody> {
        tickContinuation?.finish()
        let (stream, continuation) = AsyncStream<MetricsTickBody>.makeStream(
            bufferingPolicy: .bufferingNewest(8))
        tickContinuation = continuation
        start()
        return stream
    }

    /// Stop reading and fail everything still waiting.
    public func shutdown(_ error: (any Error)? = nil) {
        let cause = error ?? SessionMuxError.closed
        closure = cause
        reader?.cancel()
        reader = nil

        for (_, continuation) in pending {
            continuation.resume(throwing: cause)
        }
        pending.removeAll()
        early.removeAll()
        tickContinuation?.finish()
        tickContinuation = nil
    }

    private func readLoop() async {
        do {
            while !Task.isCancelled {
                guard let raw = try await session.receive() else {
                    // A clean close on a message boundary.
                    shutdown(SessionMuxError.hostClosed)
                    return
                }
                let decoded = try OspreyProtocol.decode(raw)
                dispatch(decoded)
            }
        } catch {
            shutdown(error)
        }
    }

    private func dispatch(_ envelope: DecodedEnvelope) {
        if case .metricsTick(let tick) = envelope.body {
            // A tick names its subscription in `sub`; deciding whether it is the
            // *current* subscription is the consumer's job, because only the
            // consumer knows which subscribe it last issued.
            tickContinuation?.yield(tick)
            return
        }
        if let continuation = pending.removeValue(forKey: envelope.id) {
            continuation.resume(returning: envelope)
            return
        }
        // Nobody is waiting *yet*. Park it briefly rather than dropping it: the
        // caller may still be inside its send. Beyond the bound these are
        // replies to requests nobody made, so the oldest is discarded.
        if early.count >= Self.maxEarlyReplies, let oldest = early.keys.first {
            early.removeValue(forKey: oldest)
            OspreyLog.session.debug("discarding an unclaimed reply; the host is answering unasked")
        }
        early[envelope.id] = envelope
    }
}

public enum SessionMuxError: Error, Hashable, Sendable {
    case closed
    case hostClosed
}

extension SessionMuxError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .closed:
            return "The session was closed."
        case .hostClosed:
            return "The host closed the session."
        }
    }
}
