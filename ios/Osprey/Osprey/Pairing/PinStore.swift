import Foundation

/// Persistence for the host pin.
///
/// The pin is what authenticates every session after pairing, so it lives in the
/// keychain beside the keys rather than in `UserDefaults`, which is a plain file
/// in the app container.
///
/// P0 stores at most one host. `TODO(frank):` brief §12 item 11 — one host or a
/// device list — is still open; the relay schema already supports N agents per
/// account. Decide before the pairing UI grows an "add another machine" path,
/// because the stored shape changes from one record to a keyed set.
public struct PinStore: Sendable {
    static let account = "paired-host"

    let keychain: KeychainStore

    public init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    public func load() throws -> PairedHost? {
        guard let data = try keychain.load(account: Self.account) else { return nil }
        do {
            return try JSONDecoder().decode(PairedHost.self, from: data)
        } catch {
            throw PinStoreError.corruptRecord(String(describing: error))
        }
    }

    public func save(_ host: PairedHost) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(host)
        } catch {
            throw PinStoreError.couldNotEncode(String(describing: error))
        }
        try keychain.save(data, account: Self.account)
    }

    public func clear() throws {
        try keychain.delete(account: Self.account)
    }
}

public enum PinStoreError: Error, Hashable, Sendable {
    case corruptRecord(String)
    case couldNotEncode(String)
}

extension PinStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .corruptRecord(let detail):
            return "The stored pairing could not be read: \(detail)"
        case .couldNotEncode(let detail):
            return "The pairing could not be stored: \(detail)"
        }
    }
}
