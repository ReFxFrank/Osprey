import Foundation

/// Serialises every call into the Rust Noise core.
///
/// The FFI objects hold mutable cipher state and are not `Sendable`, so they are
/// created and kept inside this actor and never handed out. Every method here is
/// synchronous internally — there is no `await` between reading the handshake
/// state and writing it back — which means the actor cannot be re-entered
/// half-way through a handshake step. I/O happens in `NoiseSession`, above.
///
/// Nothing here reads or writes a length prefix, a chunk header or a
/// continuation flag: what `begin` and `seal` return is wire-ready exactly as the
/// Rust core produced it, and what `push` takes is whatever the socket returned.
/// A Swift framing layer would put a second prefix on every message, which is
/// the bug this shape exists to make unrepresentable.
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

    /// Build the handshake and produce the first message's wire bytes.
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

    /// Hand socket bytes to whichever half of the channel is live.
    ///
    /// The reassembly buffer and its ceiling live in the Rust core, so a peer
    /// that dribbles bytes without ever completing a frame is refused there
    /// rather than allowed to grow a buffer here.
    public func push(_ data: Data) throws {
        if let transport {
            try transport.pushBytes(data)
            return
        }
        guard let handshake else { throw NoiseChannelError.handshakeNotStarted }
        try handshake.pushBytes(data)
    }

    /// The responder's decrypted handshake payload, once a whole message has
    /// arrived; `nil` while more socket bytes are needed.
    ///
    /// A tampered byte anywhere in that message surfaces here as a thrown error.
    /// It is never silently tolerated and it never traps.
    public func handshakePayload() throws -> Data? {
        guard let handshake else { throw NoiseChannelError.handshakeNotStarted }
        return try handshake.readMessage()
    }

    /// Promote to transport mode and hand back the peer static the handshake
    /// authenticated.
    ///
    /// Promotion comes first and the key is read afterwards, because the
    /// authenticated static is a property of a *completed* handshake: asking a
    /// half-finished one would be asking for a key nothing has proved yet.
    public func promote() throws -> Data {
        guard let handshake else { throw NoiseChannelError.handshakeNotStarted }
        let established = try handshake.intoTransport()
        self.handshake = nil
        transport = established
        let remoteStatic = try established.remoteStaticPublicKey()
        try Self.requireStaticKeyLength(remoteStatic, label: "peer Noise static")
        return remoteStatic
    }

    /// Encrypt one logical payload into its wire bytes.
    public func seal(_ payload: Data) throws -> Data {
        guard let transport else { throw NoiseChannelError.transportNotEstablished }
        return try transport.encrypt(payload)
    }

    /// The next decrypted message, or `nil` while more socket bytes are needed.
    public func nextMessage() throws -> Data? {
        guard let transport else { throw NoiseChannelError.transportNotEstablished }
        return try transport.nextMessage()
    }

    private static func requireStaticKeyLength(_ key: Data, label: String) throws {
        guard key.count == NoiseKeySizes.staticKeyLength else {
            throw NoiseChannelError.badKeyLength(
                label: label, expected: NoiseKeySizes.staticKeyLength, found: key.count)
        }
    }
}
