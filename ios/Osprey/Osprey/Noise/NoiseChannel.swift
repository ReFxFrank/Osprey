import Foundation

/// Serialises every call into the Rust Noise core.
///
/// The FFI objects hold mutable cipher state and are not `Sendable`, so they are
/// created and kept inside this actor and never handed out. Every method here is
/// synchronous internally — there is no `await` between reading the handshake
/// state and writing it back — which means the actor cannot be re-entered
/// half-way through a handshake step. I/O happens in `NoiseSession`, above.
public actor NoiseChannel {
    /// Which handshake to run.
    public enum Pattern: Sendable {
        /// First contact, authenticated by the 32-byte QR secret.
        case pairing(pairingSecret: Data)
        /// Every session afterwards, authenticated by the pinned statics.
        case session
    }

    private let engine: any NoiseEngine
    private var handshake: (any NoiseHandshaking)?
    private var transport: (any NoiseTransporting)?

    public init(engine: any NoiseEngine) {
        self.engine = engine
    }

    /// Build the handshake and produce the first message.
    public func begin(
        pattern: Pattern,
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data,
        payload: Data
    ) throws -> Data {
        guard handshake == nil, transport == nil else {
            throw NoiseChannelError.handshakeAlreadyStarted
        }
        try Self.requireStaticKeyLength(localStaticPrivateKey, label: "local Noise static")
        try Self.requireStaticKeyLength(remoteStaticPublicKey, label: "peer Noise static")

        let started: any NoiseHandshaking
        switch pattern {
        case .pairing(let pairingSecret):
            guard pairingSecret.count == NoiseKeySizes.pairingSecretLength else {
                throw NoiseChannelError.badKeyLength(
                    label: "pairing secret",
                    expected: NoiseKeySizes.pairingSecretLength,
                    found: pairingSecret.count)
            }
            started = try engine.pairingInitiator(
                localStaticPrivateKey: localStaticPrivateKey,
                remoteStaticPublicKey: remoteStaticPublicKey,
                pairingSecret: pairingSecret)
        case .session:
            started = try engine.sessionInitiator(
                localStaticPrivateKey: localStaticPrivateKey,
                remoteStaticPublicKey: remoteStaticPublicKey)
        }
        handshake = started
        return try started.writeMessage(payload)
    }

    /// Consume the responder's message and promote to transport mode.
    ///
    /// A tampered byte anywhere in `message` surfaces here as a thrown error.
    /// It is never silently tolerated and it never traps.
    public func complete(_ message: Data) throws -> HandshakeResult {
        guard let handshake else { throw NoiseChannelError.handshakeNotStarted }
        let payload = try handshake.readMessage(message)
        let remoteStatic = try handshake.remoteStaticPublicKey()
        try Self.requireStaticKeyLength(remoteStatic, label: "peer Noise static")
        transport = try handshake.intoTransport()
        self.handshake = nil
        return HandshakeResult(payload: payload, remoteStaticPublicKey: remoteStatic)
    }

    /// Encrypt one logical payload into its wire chunks.
    public func seal(_ payload: Data) throws -> [Data] {
        guard let transport else { throw NoiseChannelError.transportNotEstablished }
        return try NoiseFraming.split(payload).map(transport.encrypt)
    }

    /// Decrypt one wire chunk and strip its continuation flag.
    public func open(chunk ciphertext: Data) throws -> NoiseChunk {
        guard let transport else { throw NoiseChannelError.transportNotEstablished }
        let plaintext = try transport.decrypt(ciphertext)
        let (isFinal, body) = try NoiseFraming.splitChunkHeader(plaintext)
        return NoiseChunk(isFinal: isFinal, body: body)
    }

    private static func requireStaticKeyLength(_ key: Data, label: String) throws {
        guard key.count == NoiseKeySizes.staticKeyLength else {
            throw NoiseChannelError.badKeyLength(
                label: label, expected: NoiseKeySizes.staticKeyLength, found: key.count)
        }
    }
}

public struct HandshakeResult: Hashable, Sendable {
    /// The responder's decrypted second-message payload.
    public let payload: Data
    public let remoteStaticPublicKey: Data
}

public struct NoiseChunk: Hashable, Sendable {
    public let isFinal: Bool
    public let body: Data
}
