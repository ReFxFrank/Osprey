import CryptoKit
import Foundation
import Security

/// This phone's identity: a Secure Enclave P-256 signing key that is the pinned
/// root of trust, plus a software X25519 Noise static that the Enclave key
/// cross-signs.
///
/// Two keys, not one, because Noise needs a Diffie-Hellman key and the Enclave
/// key is not one: `snow` requires the raw 32-byte private scalar and the
/// Enclave never exports a private key at all — that is its entire point
/// (amendment A4). The Enclave key is therefore the durable, pinned root, and
/// the X25519 key is the disposable DH key it vouches for.
///
/// Only bytes are held here — the Enclave blob and the X25519 scalar — and the
/// `SecureEnclave.P256.Signing.PrivateKey` is reconstituted for each signature.
/// That keeps the value `Sendable` without relying on CryptoKit's conformances,
/// and an Enclave signature costs a few milliseconds.
public struct DeviceIdentity: Sendable {
    /// This device's id, chosen here and pinned by the agent.
    public let deviceID: UUID
    /// Raw 32-byte X25519 private key — the form `snow` requires.
    public let noiseStaticPrivateKey: Data
    public let publicIdentity: PublicIdentity

    private let secureEnclaveKeyBlob: Data

    fileprivate init(
        deviceID: UUID,
        noiseStaticPrivateKey: Data,
        publicIdentity: PublicIdentity,
        secureEnclaveKeyBlob: Data
    ) {
        self.deviceID = deviceID
        self.noiseStaticPrivateKey = noiseStaticPrivateKey
        self.publicIdentity = publicIdentity
        self.secureEnclaveKeyBlob = secureEnclaveKeyBlob
    }

    public var fingerprint: Fingerprint { Fingerprint.of(publicIdentity) }

    /// Sign under the Secure Enclave identity key.
    ///
    /// `signature(for:)` SHA-256-hashes the message itself and returns an ASN.1
    /// DER `SEQUENCE` of two `INTEGER`s, which is exactly what the agent's
    /// RustCrypto verifier expects (`Signature::from_der`). The fixed-width
    /// `r ‖ s` form must not be used.
    public func sign(_ message: Data) throws -> Data {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: secureEnclaveKeyBlob)
        return try key.signature(for: message).derRepresentation
    }
}

/// Creation, loading and destruction of the device identity.
public enum DeviceIdentityStore {
    public static let keychainService = "com.osprey.app.identity"

    static let secureEnclaveAccount = "identity-p256-secure-enclave"
    static let noiseStaticAccount = "noise-static-x25519"
    static let deviceIDAccount = "device-id"

    /// Load the stored identity, generating one on first run.
    ///
    /// Both key blobs and the device id are written before this returns, so the
    /// identity survives an app restart — Gate P0 criterion 2.
    public static func loadOrCreate(keychain: KeychainStore) throws -> DeviceIdentity {
        if let existing = try load(keychain: keychain) {
            return existing
        }
        return try create(keychain: keychain)
    }

    public static func load(keychain: KeychainStore) throws -> DeviceIdentity? {
        guard let blob = try keychain.load(account: secureEnclaveAccount),
            let noiseScalar = try keychain.load(account: noiseStaticAccount),
            let deviceIDData = try keychain.load(account: deviceIDAccount)
        else {
            return nil
        }
        guard let deviceIDText = String(data: deviceIDData, encoding: .utf8),
            let deviceID = UUID(uuidString: deviceIDText)
        else {
            throw IdentityError.corruptStoredIdentity("device id is not a UUID")
        }
        guard noiseScalar.count == NoiseKeySizes.staticKeyLength else {
            throw IdentityError.corruptStoredIdentity(
                "Noise static is \(noiseScalar.count) bytes, expected "
                    + "\(NoiseKeySizes.staticKeyLength)")
        }
        return try assemble(
            deviceID: deviceID, secureEnclaveKeyBlob: blob, noiseStaticPrivateKey: noiseScalar)
    }

    /// Forget this device's identity entirely.
    ///
    /// Only meaningful alongside dropping every pin: a host that pinned the old
    /// key will refuse the new one, which is the correct outcome but has to be
    /// the operator's deliberate choice.
    public static func destroy(keychain: KeychainStore) throws {
        try keychain.delete(account: secureEnclaveAccount)
        try keychain.delete(account: noiseStaticAccount)
        try keychain.delete(account: deviceIDAccount)
    }

    private static func create(keychain: KeychainStore) throws -> DeviceIdentity {
        guard SecureEnclave.isAvailable else {
            throw IdentityError.secureEnclaveUnavailable
        }
        let access = try accessControl()
        let enclaveKey: SecureEnclave.P256.Signing.PrivateKey
        do {
            enclaveKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            throw IdentityError.secureEnclaveKeyGeneration(String(describing: error))
        }
        let noiseStatic = Curve25519.KeyAgreement.PrivateKey()
        let deviceID = UUID()

        let identity = try assemble(
            deviceID: deviceID,
            secureEnclaveKeyBlob: enclaveKey.dataRepresentation,
            noiseStaticPrivateKey: noiseStatic.rawRepresentation)

        // The device id is written last: if the process dies mid-write, the next
        // launch sees an incomplete set and regenerates, rather than loading a
        // key pair that was never cross-signed.
        try keychain.save(enclaveKey.dataRepresentation, account: secureEnclaveAccount)
        try keychain.save(noiseStatic.rawRepresentation, account: noiseStaticAccount)
        try keychain.save(Data(deviceID.uuidString.utf8), account: deviceIDAccount)
        return identity
    }

    /// Rebuild the public bundle and its cross-certificate from stored material.
    ///
    /// The certificate is re-signed on every load rather than stored, because
    /// ECDSA is randomised — a stored signature and a fresh one differ, and only
    /// one of them can be the one a host pinned. The identity key and the Noise
    /// static are what the host pins; the signature is only ever checked at the
    /// moment it is presented.
    private static func assemble(
        deviceID: UUID,
        secureEnclaveKeyBlob: Data,
        noiseStaticPrivateKey: Data
    ) throws -> DeviceIdentity {
        let enclaveKey: SecureEnclave.P256.Signing.PrivateKey
        do {
            enclaveKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: secureEnclaveKeyBlob)
        } catch {
            throw IdentityError.corruptStoredIdentity(
                "Secure Enclave key could not be reconstituted: \(error)")
        }
        let noiseKey: Curve25519.KeyAgreement.PrivateKey
        do {
            noiseKey = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: noiseStaticPrivateKey)
        } catch {
            throw IdentityError.corruptStoredIdentity("Noise static is not a valid X25519 key")
        }

        let identityPublicKey = enclaveKey.publicKey.x963Representation
        let noiseStaticPublicKey = noiseKey.publicKey.rawRepresentation
        let message = SignedBytes.crossCertificate(
            identityPublicKey: identityPublicKey,
            noiseStaticPublicKey: noiseStaticPublicKey)
        let signature: Data
        do {
            signature = try enclaveKey.signature(for: message).derRepresentation
        } catch {
            throw IdentityError.secureEnclaveSigning(String(describing: error))
        }

        let publicIdentity = PublicIdentity(
            identityAlgorithm: .p256,
            identityPublicKey: identityPublicKey,
            noiseStaticPublicKey: noiseStaticPublicKey,
            noiseStaticSignature: signature)
        // Refuse to hand out a bundle this device cannot itself verify: a
        // cross-certificate that fails here would fail on the agent as an
        // unexplained pairing rejection.
        try IdentityVerifier.verifyCrossSignature(publicIdentity)

        return DeviceIdentity(
            deviceID: deviceID,
            noiseStaticPrivateKey: noiseStaticPrivateKey,
            publicIdentity: publicIdentity,
            secureEnclaveKeyBlob: secureEnclaveKeyBlob)
    }

    /// `WhenUnlockedThisDeviceOnly` rather than CryptoKit's default of
    /// `WhenPasscodeSetThisDeviceOnly`: the default makes the identity
    /// unusable — and therefore the pairing dead — the moment the operator
    /// removes their passcode, which is a surprising way to lose a paired host.
    /// `.privateKeyUsage` alone means no biometric prompt on every signature.
    private static func accessControl() throws -> SecAccessControl {
        var errorRef: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &errorRef)
        if let errorRef {
            let failure = errorRef.takeRetainedValue()
            throw IdentityError.accessControl(String(describing: failure))
        }
        guard let access else {
            throw IdentityError.accessControl("SecAccessControlCreateWithFlags returned nothing")
        }
        return access
    }
}

public enum IdentityError: Error, Hashable, Sendable {
    case secureEnclaveUnavailable
    case accessControl(String)
    case secureEnclaveKeyGeneration(String)
    case secureEnclaveSigning(String)
    case corruptStoredIdentity(String)
}

extension IdentityError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "This device has no Secure Enclave, so Osprey cannot create a hardware "
                + "identity. The iOS Simulator has none; a physical iPhone is required."
        case .accessControl(let detail):
            return "Could not build the Secure Enclave access policy: \(detail)"
        case .secureEnclaveKeyGeneration(let detail):
            return "Could not create a Secure Enclave key: \(detail)"
        case .secureEnclaveSigning(let detail):
            return "The Secure Enclave refused to sign: \(detail)"
        case .corruptStoredIdentity(let detail):
            return "The stored identity is unusable: \(detail)"
        }
    }
}
