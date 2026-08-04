import Foundation

/// Persistence for the host pins.
///
/// The pin is what authenticates every session after pairing, so it lives in the
/// keychain beside the keys rather than in `UserDefaults`, which is a plain file
/// in the app container.
///
/// Amendment A23 settled the shape: the app opens to a device list, so this
/// stores a *set* of hosts keyed by agent device id. P0 shipped a single record
/// under a different account name, and [`loadAll`] migrates it — a phone that
/// paired at the P0 gate must not silently lose its pairing on upgrade, because
/// re-pairing requires physical access to the host by design.
public struct PinStore: Sendable {
    /// Where the keyed set lives.
    static let account = "paired-hosts"
    /// P0's single-record account, read once and then removed.
    static let legacyAccount = "paired-host"

    let keychain: KeychainStore

    public init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    /// Every pinned host, oldest pairing first.
    ///
    /// Migrates a P0 single-record pin on first call. The migration writes the
    /// new record *before* deleting the old one, so an interruption between the
    /// two leaves a duplicate rather than nothing — recoverable, where the other
    /// order is not.
    public func loadAll() throws -> [PairedHost] {
        if let data = try keychain.load(account: Self.account) {
            return try decodeSet(data)
        }
        guard let legacy = try keychain.load(account: Self.legacyAccount) else {
            return []
        }
        let host: PairedHost
        do {
            host = try JSONDecoder().decode(PairedHost.self, from: legacy)
        } catch {
            throw PinStoreError.corruptRecord(String(describing: error))
        }
        try writeSet([host])
        try keychain.delete(account: Self.legacyAccount)
        return [host]
    }

    /// Insert or replace by agent device id.
    ///
    /// Replacing rather than appending matters: re-pairing an already-pinned
    /// machine must leave one record holding its *current* Noise static, not two
    /// records where the stale one still looks usable.
    public func save(_ host: PairedHost) throws {
        var hosts = try loadAll()
        if let index = hosts.firstIndex(where: { $0.agentDeviceID == host.agentDeviceID }) {
            hosts[index] = host
        } else {
            hosts.append(host)
        }
        try writeSet(hosts)
    }

    /// Remove one host. Removing one that is not stored is success.
    public func remove(agentDeviceID: String) throws {
        let hosts = try loadAll().filter { $0.agentDeviceID != agentDeviceID }
        try writeSet(hosts)
    }

    /// Forget every pairing.
    public func clear() throws {
        try keychain.delete(account: Self.account)
        try keychain.delete(account: Self.legacyAccount)
    }

    private func decodeSet(_ data: Data) throws -> [PairedHost] {
        do {
            return try JSONDecoder().decode([PairedHost].self, from: data)
        } catch {
            throw PinStoreError.corruptRecord(String(describing: error))
        }
    }

    private func writeSet(_ hosts: [PairedHost]) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(hosts)
        } catch {
            throw PinStoreError.couldNotEncode(String(describing: error))
        }
        try keychain.save(data, account: Self.account)
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
