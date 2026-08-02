import Foundation

// No `import` for the Rust core: UniFFI emits `osprey_ffi.swift`, which
// `scripts/build-xcframework.sh` adds directly to this Xcode target, so its
// types are already in this module. The generated file imports the C shim
// (`osprey_ffiFFI`) from the XCFramework's modulemap itself. Importing a
// hand-guessed module name here would fail to compile.

/// The only file in the app that names a generated Rust symbol.
///
/// Noise is not reimplemented in Swift: both ends run the same `snow` build, so
/// the entire class of cross-implementation handshake bugs — transcript-hash
/// divergence, nonce encoding, PSK ordering — cannot occur (execution plan §4).
///
/// Neither is framing. `osprey-ffi` length-prefixes handshake messages and
/// chunks transport payloads itself, so everything crossing this boundary is
/// already wire-ready; this file adapts spellings and nothing else. The
/// generated surface is authoritative — regenerate it with
/// `cargo run -p osprey-ffi --features bindgen-cli --bin uniffi-bindgen -- \
/// generate --library <lib> --language swift` and read it, rather than trusting
/// a description of it.
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

/// The cross-certificate byte string, taken from the Rust core rather than
/// rebuilt.
///
/// `osprey-ffi` exports it precisely so Swift never defines it a second time
/// (`osprey-ffi/src/identity.rs`: "Swift asks `cross_certificate_bytes` for the
/// exact message to sign"). The agent is the verifier, so a Swift restatement
/// that drifted would surface only as "signature does not verify" — never as a
/// parse error — on a phone that had already been shipped.
public enum CrossCertificate {
    public static func message(
        identityPublicKey: Data,
        noiseStaticPublicKey: Data
    ) throws -> Data {
        try crossCertificateBytes(
            identityPub: identityPublicKey, noiseStaticPub: noiseStaticPublicKey)
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

    func pushBytes(_ data: Data) throws {
        try inner.pushBytes(data: data)
    }

    func readMessage() throws -> Data? {
        try inner.readMessage()
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

    func encrypt(_ payload: Data) throws -> Data {
        try inner.encrypt(payload: payload)
    }

    func pushBytes(_ data: Data) throws {
        try inner.pushBytes(data: data)
    }

    func nextMessage() throws -> Data? {
        try inner.nextMessage()
    }

    func remoteStaticPublicKey() throws -> Data {
        try inner.remoteStatic()
    }
}
