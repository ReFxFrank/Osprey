import Foundation
import Security

/// Generic-password storage for the two key blobs and the pin.
///
/// A Secure Enclave signing key and a raw X25519 scalar have no native keychain
/// class of their own — `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation`
/// is an opaque blob the Enclave alone can reconstitute, and CryptoKit's
/// `Curve25519` types are pure Swift values. Apple's documented pattern for both
/// is a `kSecClassGenericPassword` item, which is what this is.
///
/// Accessibility is `WhenUnlockedThisDeviceOnly`: the pairing must survive a
/// restart (Gate P0 criterion 2) but must never migrate to another device via a
/// backup or an iCloud keychain, because the pin the host holds names *this*
/// phone.
public struct KeychainStore: Sendable {
    public let service: String

    public init(service: String) {
        self.service = service
    }

    public func save(_ data: Data, account: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        // Delete-then-add rather than SecItemUpdate: an update leaves the
        // original accessibility attribute in place, so an item written by an
        // earlier build would silently keep the old protection class.
        let removal = SecItemDelete(query as CFDictionary)
        guard removal == errSecSuccess || removal == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(operation: "delete", status: removal)
        }
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(operation: "add", status: status)
        }
    }

    public func load(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw KeychainError.unexpectedItemType(account: account)
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(operation: "copy", status: status)
        }
    }

    /// Remove an item. Absence is success — the caller wants it gone.
    public func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(operation: "delete", status: status)
        }
    }
}

public enum KeychainError: Error, Hashable, Sendable {
    case unexpectedStatus(operation: String, status: OSStatus)
    case unexpectedItemType(account: String)
}

extension KeychainError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let operation, let status):
            let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Keychain \(operation) failed: \(detail)"
        case .unexpectedItemType(let account):
            return "Keychain item `\(account)` did not hold data."
        }
    }
}
