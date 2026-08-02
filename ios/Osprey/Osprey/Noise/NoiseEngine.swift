import Foundation

/// The Noise primitives this app needs from the Rust core.
///
/// Noise itself is never reimplemented in Swift: both ends run the same `snow`
/// build, which is the whole reason the product has one Noise implementation
/// rather than two (execution plan §4). Everything above the raw
/// encrypt/decrypt pair — framing, chunking, message ordering — lives in Swift
/// because it is testable without a device.
///
/// The surface is deliberately synchronous and byte-in/byte-out: no callbacks,
/// no async, nothing that has to be re-entered. `NoiseChannel` is what makes it
/// safe to touch from Swift concurrency.
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
public protocol NoiseHandshaking: AnyObject {
    func writeMessage(_ payload: Data) throws -> Data
    func readMessage(_ message: Data) throws -> Data
    /// The peer static the handshake authenticated, valid once the handshake is
    /// complete. This is the value the caller compares against its pin.
    func remoteStaticPublicKey() throws -> Data
    func intoTransport() throws -> any NoiseTransporting
}

/// An established transport. One call per Noise message, not per logical
/// payload: chunking happens above this.
public protocol NoiseTransporting: AnyObject {
    func encrypt(_ plaintext: Data) throws -> Data
    func decrypt(_ ciphertext: Data) throws -> Data
}

public enum NoiseChannelError: Error, Hashable, Sendable {
    case handshakeNotStarted
    case handshakeAlreadyStarted
    case transportNotEstablished
    case badKeyLength(label: String, expected: Int, found: Int)
    case peerStaticDoesNotMatchPin
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
        case .peerStaticDoesNotMatchPin:
            return "the host presented a Noise key that is not the pinned one"
        }
    }
}
