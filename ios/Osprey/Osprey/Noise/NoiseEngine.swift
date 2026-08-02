import Foundation

/// The Noise primitives this app needs from the Rust core.
///
/// Noise itself is never reimplemented in Swift: both ends run the same `snow`
/// build, which is the whole reason the product has one Noise implementation
/// rather than two (execution plan §4).
///
/// Framing and chunking are not reimplemented here either. `osprey-ffi` already
/// length-prefixes every handshake message and splits every transport payload
/// into flagged chunks, so a Swift framing layer would put a second prefix and a
/// second continuation flag on the wire and no handshake would ever complete.
/// The shape below therefore mirrors the Rust surface exactly — write bytes,
/// push bytes, poll for a message — rather than pretending the boundary is
/// message-at-a-time.
public protocol NoiseEngine: Sendable {
    /// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, initiator, PSK at position 2.
    /// The phone is always the initiator (amendment A15).
    func pairingInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data,
        pairingSecret: Data
    ) throws -> any NoiseHandshaking

    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s`, initiator. Used after pairing, when
    /// the pin is the authentication and carrying the pairing secret forward
    /// would only widen its blast radius.
    func sessionInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data
    ) throws -> any NoiseHandshaking
}

/// A handshake in progress. Both Osprey patterns are two messages, so an
/// initiator writes once and reads once.
///
/// Mirrors `osprey_ffi::NoiseHandshake`. The argument labels are dropped to keep
/// Swift call sites idiomatic; the semantics are the Rust ones and must stay
/// that way.
public protocol NoiseHandshaking: AnyObject {
    /// The next handshake message carrying `payload`, already framed and ready
    /// to write to the socket verbatim.
    func writeMessage(_ payload: Data) throws -> Data
    /// Hand over bytes just read from the socket.
    func pushBytes(_ data: Data) throws
    /// The peer's decrypted handshake payload, or `nil` while a complete message
    /// has not arrived yet. A tampered byte throws; it is never tolerated.
    func readMessage() throws -> Data?
    /// Promote the finished handshake, carrying any bytes the peer pipelined
    /// past it across to the transport so none are lost at the boundary.
    func intoTransport() throws -> any NoiseTransporting
}

/// An established transport. One call per *logical* payload: chunking happens
/// below this, inside the Rust core.
public protocol NoiseTransporting: AnyObject {
    /// Encrypt `payload` into wire bytes — chunked and framed, all of which must
    /// be written to the socket in order.
    func encrypt(_ payload: Data) throws -> Data
    /// Hand over bytes just read from the socket.
    func pushBytes(_ data: Data) throws
    /// The next complete message, or `nil` while more bytes are needed. One
    /// socket read can carry several, so callers poll until it returns `nil`.
    func nextMessage() throws -> Data?
    /// The peer static the handshake authenticated. This is the value the caller
    /// compares against its pin, and it lives on the transport because only a
    /// completed handshake has proved it.
    func remoteStaticPublicKey() throws -> Data
}

public enum NoiseChannelError: Error, Hashable, Sendable {
    case handshakeNotStarted
    case handshakeAlreadyStarted
    case transportNotEstablished
    case badKeyLength(label: String, expected: Int, found: Int)
}

extension NoiseChannelError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .handshakeNotStarted:
            return "the Noise handshake was not started"
        case .handshakeAlreadyStarted:
            return "the Noise handshake was already started"
        case .transportNotEstablished:
            return "the Noise transport is not established"
        case .badKeyLength(let label, let expected, let found):
            return "\(label) must be \(expected) bytes, got \(found)"
        }
    }
}
