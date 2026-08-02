import Foundation

/// The protocol conversation on an established Noise session.
///
/// Every message is a generated envelope from `proto/messages.toml`; nothing on
/// this path hand-rolls a wire type.
public struct SessionClient: Sendable {
    /// Message groups this build implements.
    ///
    /// Empty, and deliberately so: P0 implements none of them, and advertising a
    /// capability the app cannot use would be exactly the plausible-looking
    /// fiction the anti-slop rules forbid. Later phases add entries here.
    public static let capabilities: [Capability] = []

    let session: NoiseSession

    public init(session: NoiseSession) {
        self.session = session
    }

    /// Send `hello` and read the host's `hello.ok`.
    public func openSession(
        deviceID: UUID,
        softwareVersion: String
    ) async throws -> HelloOkBody {
        let id = UUID()
        let body = HelloBody(
            protocolVersion: OspreyProtocol.protocolVersion,
            minProtocolVersion: OspreyProtocol.minProtocolVersion,
            capabilities: Self.capabilities,
            deviceId: deviceID,
            softwareVersion: softwareVersion)
        let reply = try await exchange(id: id, body: body)
        guard case .helloOk(let helloOk) = reply.body else {
            throw SessionError.unexpectedReply(expected: .helloOk, found: reply.t)
        }
        return helloOk
    }

    /// Send `ping` and read the matching `pong`.
    public func ping(sequence: UInt64) async throws -> PingRoundTrip {
        let id = UUID()
        let sentAt = Self.nowMilliseconds()
        let reply = try await exchange(id: id, ts: sentAt, body: PingBody(seq: sequence))
        guard case .pong(let pong) = reply.body else {
            throw SessionError.unexpectedReply(expected: .pong, found: reply.t)
        }
        guard pong.seq == sequence else {
            throw SessionError.pongSequenceMismatch(sent: sequence, received: pong.seq)
        }
        return PingRoundTrip(
            sequence: sequence,
            roundTripMilliseconds: max(0, Self.nowMilliseconds() - pong.echoTs))
    }

    /// Ask the host to drop this phone's pin.
    ///
    /// The signature is made by the Secure Enclave key the host pinned at
    /// pairing, so the host verifies it against its own store rather than
    /// against anything in this message.
    public func revokePairing(
        issuerDeviceID: UUID,
        revokedDeviceID: UUID,
        nonce: Data,
        signature: Data,
        issuedAtMilliseconds: Int64
    ) async throws -> ByeBody {
        let id = UUID()
        let body = PairRevokeBody(
            issuerDeviceId: issuerDeviceID,
            revokedDeviceId: revokedDeviceID,
            issuedAt: issuedAtMilliseconds,
            nonce: nonce,
            signature: signature)
        let reply = try await exchange(id: id, body: body)
        guard case .bye(let bye) = reply.body else {
            throw SessionError.unexpectedReply(expected: .bye, found: reply.t)
        }
        return bye
    }

    /// Orderly teardown.
    ///
    /// The host must handle a dropped transport identically, so this is
    /// best-effort. The failure is *returned* rather than logged here, so the
    /// caller decides whether a failed goodbye is worth reporting instead of
    /// this layer deciding it is not.
    public func sayGoodbye() async -> (any Error)? {
        do {
            let envelope = try OspreyProtocol.encode(
                ts: Self.nowMilliseconds(),
                body: ByeBody(reason: .normal, detail: nil))
            try await session.send(envelope)
            return nil
        } catch {
            return error
        }
    }

    /// One request, one correlated response.
    private func exchange<Body: OspreyMessageBody>(
        id: UUID,
        ts: Int64? = nil,
        body: Body
    ) async throws -> DecodedEnvelope {
        let sentAt = ts ?? Self.nowMilliseconds()
        let request = try OspreyProtocol.encode(id: id, ts: sentAt, body: body)
        try await session.send(request)
        let raw = try await session.receiveRequired()
        let decoded = try OspreyProtocol.decode(raw)
        guard decoded.id == id else {
            throw SessionError.correlationMismatch(sent: id, received: decoded.id)
        }
        if case .error(let failure) = decoded.body {
            throw SessionError.hostRefused(
                code: failure.code, message: failure.message, retryable: failure.retryable)
        }
        return decoded
    }

    /// Milliseconds since the Unix epoch. Advisory only — the protocol never
    /// authenticates on it.
    public static func nowMilliseconds() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }
}

public struct PingRoundTrip: Hashable, Sendable {
    public let sequence: UInt64
    public let roundTripMilliseconds: Int64
}

public enum SessionError: Error, Hashable, Sendable {
    case unexpectedReply(expected: MessageType, found: MessageType)
    case correlationMismatch(sent: UUID, received: UUID)
    case pongSequenceMismatch(sent: UInt64, received: UInt64)
    case hostRefused(code: ErrorCode, message: String, retryable: Bool)
    case hostIsNotThePinnedOne
}

extension SessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unexpectedReply(let expected, let found):
            return "The host answered with `\(found.rawValue)` where `\(expected.rawValue)` "
                + "was expected."
        case .correlationMismatch:
            return "The host answered a request this app did not send."
        case .pongSequenceMismatch(let sent, let received):
            return "The host echoed ping \(received) for ping \(sent)."
        case .hostRefused(let code, let message, _):
            return "The host refused the request (\(code.wireValue)): \(message)"
        case .hostIsNotThePinnedOne:
            return "The machine that answered is not the one this phone is paired with."
        }
    }
}
