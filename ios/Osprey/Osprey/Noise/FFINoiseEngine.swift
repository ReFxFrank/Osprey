import Foundation

// No `import` for the Rust core: UniFFI emits `osprey_ffi.swift`, which
// `scripts/build-xcframework.sh` adds directly to this Xcode target, so its
// types are already in this module. The generated file imports the C shim
// (`osprey_ffiFFI`) from the XCFramework's modulemap itself. Importing a
// hand-guessed module name here would fail to compile.

/// The only file in the app that touches the Rust core.
///
/// Noise is not reimplemented in Swift: both ends run the same `snow` build, so
/// the entire class of cross-implementation handshake bugs — transcript-hash
/// divergence, nonce encoding, PSK ordering — cannot occur (execution plan §4).
/// Everything the app does *around* Noise lives in Swift and is testable without
/// the framework.
///
/// ## The contract this file expects from `agent/osprey-ffi`
///
/// UniFFI, procedural macros, no UDL. Lower-camel-cases into Swift as written:
///
/// ```rust
/// #[derive(uniffi::Error, thiserror::Error, Debug)]
/// pub enum NoiseFfiError { #[error("{message}")] Noise { message: String }, … }
///
/// #[derive(uniffi::Object)]
/// pub struct NoiseHandshake { /* Mutex<Option<snow::HandshakeState>> */ }
///
/// #[uniffi::export]
/// impl NoiseHandshake {
///     #[uniffi::constructor]
///     pub fn pairing_initiator(local_static: Vec<u8>, remote_static: Vec<u8>,
///                              psk: Vec<u8>) -> Result<Arc<Self>, NoiseFfiError>;
///     #[uniffi::constructor]
///     pub fn session_initiator(local_static: Vec<u8>, remote_static: Vec<u8>)
///                              -> Result<Arc<Self>, NoiseFfiError>;
///     pub fn write_message(&self, payload: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError>;
///     pub fn read_message(&self, message: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError>;
///     pub fn remote_static_public_key(&self) -> Result<Vec<u8>, NoiseFfiError>;
///     pub fn into_transport(&self) -> Result<Arc<NoiseTransport>, NoiseFfiError>;
/// }
///
/// #[derive(uniffi::Object)]
/// pub struct NoiseTransport { /* Mutex<snow::TransportState> */ }
///
/// #[uniffi::export]
/// impl NoiseTransport {
///     pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError>;
///     pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, NoiseFfiError>;
/// }
/// ```
///
/// `Vec<u8>` crosses as `Data`. Every method is synchronous and infallible-free:
/// a malformed or tampered message returns an error, never a panic, because a
/// Rust panic across the FFI boundary aborts the app.
///
/// Framing, chunking and the 65535-byte message ceiling are deliberately *not*
/// on the Rust side of this boundary — they are in `NoiseFraming`, where they
/// can be tested on any machine.
public struct FFINoiseEngine: NoiseEngine {
    public init() {}

    public func pairingInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data,
        pairingSecret: Data
    ) throws -> any NoiseHandshaking {
        let handshake = try NoiseHandshake.pairingInitiator(
            localStatic: localStaticPrivateKey,
            remoteStatic: remoteStaticPublicKey,
            psk: pairingSecret)
        return FFIHandshake(inner: handshake)
    }

    public func sessionInitiator(
        localStaticPrivateKey: Data,
        remoteStaticPublicKey: Data
    ) throws -> any NoiseHandshaking {
        let handshake = try NoiseHandshake.sessionInitiator(
            localStatic: localStaticPrivateKey,
            remoteStatic: remoteStaticPublicKey)
        return FFIHandshake(inner: handshake)
    }
}

/// Adapts the generated UniFFI object to the app's protocol.
///
/// The adapter exists so the generated type's exact spelling is confined to this
/// file: if the Rust surface is renamed, one file changes rather than the
/// pairing and session flows.
final class FFIHandshake: NoiseHandshaking {
    private let inner: NoiseHandshake

    init(inner: NoiseHandshake) {
        self.inner = inner
    }

    func writeMessage(_ payload: Data) throws -> Data {
        try inner.writeMessage(payload: payload)
    }

    func readMessage(_ message: Data) throws -> Data {
        try inner.readMessage(message: message)
    }

    func remoteStaticPublicKey() throws -> Data {
        try inner.remoteStaticPublicKey()
    }

    func intoTransport() throws -> any NoiseTransporting {
        FFITransport(inner: try inner.intoTransport())
    }
}

final class FFITransport: NoiseTransporting {
    private let inner: NoiseTransport

    init(inner: NoiseTransport) {
        self.inner = inner
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        try inner.encrypt(plaintext: plaintext)
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        try inner.decrypt(ciphertext: ciphertext)
    }
}
