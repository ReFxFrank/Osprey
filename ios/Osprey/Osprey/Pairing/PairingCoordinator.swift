import Foundation

/// Turns a scanned QR into a pinned host.
///
/// The order of operations is the security property, not an implementation
/// detail: the QR's cross-certificate is checked *before* a byte goes on the
/// wire, so the identity the handshake is compared against was never influenced
/// by anything the network said.
public struct PairingCoordinator: Sendable {
    /// The agent gives a scanning phone a 60-second handshake window and a
    /// 120-second pairing window. Twenty seconds is generous for a LAN
    /// round trip and short enough that a wrong address is reported while the
    /// operator is still standing at the host.
    public static let connectTimeout: TimeInterval = 20
    /// The whole exchange is four small messages; anything slower is a stall.
    public static let exchangeTimeout: TimeInterval = 30

    let engine: any NoiseEngine
    let identity: DeviceIdentity

    public init(engine: any NoiseEngine, identity: DeviceIdentity) {
        self.engine = engine
        self.identity = identity
    }

    public func pair(with payload: QRPayload) async throws -> PairedHost {
        // The trust anchor. A forged or tampered QR dies here.
        try IdentityVerifier.verifyCrossSignature(payload.agentIdentity)

        let endpoints = payload.dialOrder
        guard !endpoints.isEmpty else { throw QRPayloadError.noReachableAddress }

        let stream = try await Self.dial(endpoints)
        let session = try await withStreamDeadline(
            seconds: Self.exchangeTimeout, stream: stream
        ) {
            try await PairingFlow.run(
                stream: stream,
                engine: engine,
                localNoiseStaticPrivateKey: identity.noiseStaticPrivateKey,
                localPublicIdentity: identity.publicIdentity,
                expectedAgentIdentity: payload.agentIdentity,
                pairingSecret: payload.pairingSecret)
        }

        // The agent hangs up after `pair` and serves sessions from a separate
        // `run` invocation, so nothing is sent on this session after the accept.
        await session.close()

        let host = PairedHost(
            agentDeviceID: payload.agentDeviceID,
            accountID: payload.accountID,
            relayURL: payload.relayURL,
            lanHints: payload.lanHints,
            pinnedIdentity: payload.agentIdentity,
            pairedAtMilliseconds: SessionClient.nowMilliseconds())
        OspreyLog.pairing.notice(
            "pinned host \(Fingerprint.of(payload.agentIdentity).short, privacy: .public)")
        return host
    }

    /// Try each hint in turn, reporting every failure rather than only the last.
    static func dial(_ endpoints: [LanEndpoint]) async throws -> TCPByteStream {
        var failures: [String] = []
        for endpoint in endpoints {
            do {
                return try await TCPByteStream.connect(
                    host: endpoint.host, port: endpoint.port, timeout: connectTimeout)
            } catch {
                let detail = (error as? LocalizedError)?.errorDescription
                    ?? String(describing: error)
                OspreyLog.network.notice(
                    "\(endpoint.description, privacy: .public) unreachable: \(detail, privacy: .public)"
                )
                failures.append("\(endpoint.description): \(detail)")
            }
        }
        throw PairingError.couldNotReachHost(failures.joined(separator: "; "))
    }
}
