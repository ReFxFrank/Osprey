import Foundation

/// The controller's half of the pairing exchange.
///
/// Mirrors `osprey_core::pairing::flow::initiate_inner` step for step. The phone
/// is always the Noise initiator (amendment A15) because IK requires the
/// initiator to know the responder's static in advance, and only the QR conveys
/// it.
///
/// ## Why there is a confirmation round after the handshake
///
/// In `IKpsk2` the PSK is mixed into the *second* message, so the responder
/// reaches transport mode without ever learning whether the initiator holds the
/// same PSK. The agent therefore pins nothing until it has decrypted one
/// transport-mode message from this side. That message is `confirmTag`, and a
/// wrong PSK fails there — closed, and audited on the host.
public enum PairingFlow {
    static let confirmTag = Data("osprey/pair/confirm/v1".utf8)
    static let acceptTag = Data("osprey/pair/accept/v1".utf8)

    // Six parameters, deliberately: this signature mirrors
    // osprey_core::pairing::flow::initiate_inner input-for-input, and that
    // 1:1 correspondence is what lets the two implementations be audited
    // against each other. Grouping them into structs would satisfy the lint
    // at the cost of the property this file exists to preserve.
    // swiftlint:disable function_parameter_count

    /// Run the exchange over an already-connected stream.
    ///
    /// `expectedAgentIdentity` must already have had its cross-signature
    /// verified — that check is the trust anchor and it happens before a single
    /// byte goes on the wire, so this function only has to prove that the peer
    /// on the socket *is* that identity.
    public static func run(
        stream: any ByteStream,
        engine: any NoiseEngine,
        localNoiseStaticPrivateKey: Data,
        localPublicIdentity: PublicIdentity,
        expectedAgentIdentity: PublicIdentity,
        pairingSecret: Data
    ) async throws -> NoiseSession {
        let channel = NoiseChannel(engine: engine)

        let hello = try JSONEncoder().encode(IdentityMessage(identity: localPublicIdentity))
        let first = try await channel.begin(
            pattern: .pairing(pairingSecret: pairingSecret),
            localStaticPrivateKey: localNoiseStaticPrivateKey,
            remoteStaticPublicKey: expectedAgentIdentity.noiseStaticPublicKey,
            payload: hello)
        // Written verbatim: the core already framed it.
        try await stream.write(first)

        guard let second = try await readHandshakePayload(channel: channel, stream: stream) else {
            throw PairingError.hostClosedDuringHandshake
        }
        let remoteStaticPublicKey = try await channel.promote()

        let offered: IdentityMessage
        do {
            offered = try JSONDecoder().decode(IdentityMessage.self, from: second)
        } catch {
            throw PairingError.malformedHostIdentity(String(describing: error))
        }

        // The QR is the only authenticated description of the host, so the
        // bundle that arrives inside the handshake has to match it byte for
        // byte. This comparison is what a hostile relay cannot defeat.
        guard offered.identity == expectedAgentIdentity else {
            throw PairingError.hostIdentityMismatch
        }
        // …and the key the handshake actually authenticated has to be the one
        // that bundle vouches for, or a peer could have one key vouched for and
        // use another.
        guard offered.identity.noiseStaticPublicKey == remoteStaticPublicKey else {
            throw PairingError.hostStaticMismatch
        }

        let session = NoiseSession(channel: channel, stream: stream)
        try await session.send(confirmTag)
        let accept = try await session.receiveRequired()
        guard accept == acceptTag else {
            throw PairingError.unexpectedHostAcceptance
        }
        return session
    }
    // swiftlint:enable function_parameter_count
}

public enum PairingError: Error, Hashable, Sendable {
    case hostClosedDuringHandshake
    case malformedHostIdentity(String)
    case hostIdentityMismatch
    case hostStaticMismatch
    case unexpectedHostAcceptance
    case couldNotReachHost(String)
    case alreadyPaired
}

extension PairingError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .hostClosedDuringHandshake:
            return "The host closed the connection during pairing. "
                + "Its pairing window may have expired — run `osprey-svc pair` again."
        case .malformedHostIdentity(let detail):
            return "The host sent an identity this app could not read: \(detail)"
        case .hostIdentityMismatch:
            return "The machine that answered is not the one in the scanned code. "
                + "Pairing was refused."
        case .hostStaticMismatch:
            return "The host's signed key does not match the key it handshook with. "
                + "Pairing was refused."
        case .unexpectedHostAcceptance:
            return "The host did not confirm the pairing. Pairing was refused."
        case .couldNotReachHost(let detail):
            return "Could not reach the host: \(detail)"
        case .alreadyPaired:
            return "This phone is already paired with a host. Unpair first."
        }
    }
}
