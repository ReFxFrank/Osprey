import Foundation

/// A `host:port` hint from the QR's `lan_hints`.
///
/// Rust serialises `std::net::SocketAddr` with its `Display` form, so IPv4
/// arrives as `10.0.0.4:47010` and IPv6 as `[fd00::1]:47010`.
public struct LanEndpoint: Hashable, Sendable, CustomStringConvertible {
    public let host: String
    public let port: UInt16
    public let isIPv6: Bool

    public init(host: String, port: UInt16, isIPv6: Bool) {
        self.host = host
        self.port = port
        self.isIPv6 = isIPv6
    }

    public init?(text: String) {
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            let host = String(text[text.index(after: text.startIndex)..<close])
            let rest = text[text.index(after: close)...]
            guard rest.hasPrefix(":"), let port = UInt16(rest.dropFirst()), !host.isEmpty else {
                return nil
            }
            self.init(host: host, port: port, isIPv6: true)
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            let host = String(text[text.startIndex..<colon])
            guard let port = UInt16(text[text.index(after: colon)...]), !host.isEmpty else {
                return nil
            }
            self.init(host: host, port: port, isIPv6: false)
        }
    }

    public var description: String {
        isIPv6 ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

/// Stored and transported as the same `host:port` text the agent emits, so a
/// persisted hint and a freshly scanned one are the same bytes.
extension LanEndpoint: Codable {
    public init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let parsed = LanEndpoint(text: text) else {
            throw QRPayloadError.malformedLanHint(text)
        }
        self = parsed
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension Array where Element == LanEndpoint {
    /// Hints in dial order.
    ///
    /// IPv4 first: the agent advertises link-local IPv6 addresses too, but
    /// Rust's `SocketAddrV6` `Display` drops the scope id, and a `fe80::`
    /// address without one cannot be dialled from the phone. Loopback is dropped
    /// outright — on the phone it resolves to the phone.
    public var dialOrder: [LanEndpoint] {
        let reachable = filter { !$0.isLoopback && !$0.isScopelessLinkLocalIPv6 }
        return reachable.filter { !$0.isIPv6 } + reachable.filter(\.isIPv6)
    }
}

/// The scanned pairing payload.
///
/// Wire-compatible with `osprey_core::pairing::QrPayload`. This is the trust
/// bootstrap: it is displayed on the host's screen and photographed by a phone
/// standing in front of it, which is what makes "physical access is required to
/// enrol a controller" a cryptographic property rather than a convention.
///
/// `pairingSecret` is the Noise PSK and never leaves the device. The relay only
/// ever learns `SHA-256(pairingSecret)`.
public struct QRPayload: Sendable, Decodable {
    /// Rust: `osprey_core::pairing::QR_PAYLOAD_VERSION`. A mismatch is a hard
    /// error so an old build fails loudly instead of misreading a field.
    public static let supportedVersion: UInt32 = 1

    public let version: UInt32
    /// TODO(frank): the agent encodes "LAN only, do not contact a relay" as an
    /// empty `relay_url` *and* an empty `account_id` (see the matching
    /// `TODO(frank)` in `osprey-svc/src/commands/pair.rs`). P0 never contacts the
    /// relay from the phone, so this build only records the values. Decide
    /// whether that empty-string encoding is the contract or whether the QR
    /// gains an explicit `mode` field before the phone starts using `relayURL`.
    public let relayURL: String
    public let accountID: String
    /// The agent's device id as a string. It is a UUID in practice, but it is
    /// kept verbatim here because the QR types it as a string and rejecting a
    /// scan on a formatting detail would be a worse failure than carrying it.
    public let agentDeviceID: String
    public let agentIdentity: PublicIdentity
    public let lanHints: [LanEndpoint]
    public let pairingSecret: Data

    private enum CodingKeys: String, CodingKey {
        case version = "v"
        case relayURL = "relay_url"
        case accountID = "account_id"
        case agentDeviceID = "device_id"
        case agentIdentity = "agent_identity"
        case lanHints = "lan_hints"
        case pairingSecret = "pairing_secret"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(UInt32.self, forKey: .version)
        guard version == Self.supportedVersion else {
            throw QRPayloadError.unsupportedVersion(
                found: version, expected: Self.supportedVersion)
        }
        relayURL = try container.decode(String.self, forKey: .relayURL)
        accountID = try container.decode(String.self, forKey: .accountID)
        agentDeviceID = try container.decode(String.self, forKey: .agentDeviceID)
        agentIdentity = try container.decode(PublicIdentity.self, forKey: .agentIdentity)
        pairingSecret = try container.decodeHex(
            forKey: .pairingSecret, expecting: NoiseKeySizes.pairingSecretLength)
        lanHints = try container.decode([LanEndpoint].self, forKey: .lanHints)
    }

    public static func decode(_ text: String) throws -> QRPayload {
        guard let data = text.data(using: .utf8) else {
            throw QRPayloadError.notUTF8
        }
        return try JSONDecoder().decode(QRPayload.self, from: data)
    }

    public var dialOrder: [LanEndpoint] { lanHints.dialOrder }
}

extension LanEndpoint {
    var isLoopback: Bool {
        host == "127.0.0.1" || host == "::1" || host.hasPrefix("127.")
    }

    /// `fe80::/10` without a zone identifier. Unusable as a destination.
    var isScopelessLinkLocalIPv6: Bool {
        guard isIPv6, !host.contains("%") else { return false }
        let lowered = host.lowercased()
        return lowered.hasPrefix("fe8") || lowered.hasPrefix("fe9")
            || lowered.hasPrefix("fea") || lowered.hasPrefix("feb")
    }
}

public enum QRPayloadError: Error, Hashable, Sendable {
    case notUTF8
    case unsupportedVersion(found: UInt32, expected: UInt32)
    case malformedLanHint(String)
    case noReachableAddress
}

extension QRPayloadError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notUTF8:
            return "The scanned code is not UTF-8 text."
        case .unsupportedVersion(let found, let expected):
            return "This code is version \(found); this app understands version \(expected). "
                + "Update the Osprey app or the agent so both are on the same version."
        case .malformedLanHint(let text):
            return "The code carries an address this app cannot parse: \(text)"
        case .noReachableAddress:
            return "The code carries no address this phone can reach. "
                + "Check that the phone and the host are on the same network."
        }
    }
}
