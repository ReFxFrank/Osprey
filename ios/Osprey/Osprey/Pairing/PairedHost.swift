import Foundation

/// A host this phone has pinned.
///
/// The pinned identity key is permanent; the host's Noise static is what the
/// identity key vouches for and is what steady-state sessions handshake against.
/// Everything else here is routing information and may go stale.
public struct PairedHost: Codable, Hashable, Sendable {
    /// The agent's device id, verbatim from the QR.
    public var agentDeviceID: String
    /// The relay tenant this agent belongs to. Empty when the QR was LAN-only.
    public var accountID: String
    /// Empty when the QR was LAN-only. See the `TODO(frank)` on `QRPayload`.
    public var relayURL: String
    /// Addresses the agent was listening on when the QR was rendered. Correct
    /// exactly once — a DHCP renewal or a move between wifi and ethernet
    /// invalidates them, which is why mDNS exists (amendment A6).
    public var lanHints: [LanEndpoint]
    public var pinnedIdentity: PublicIdentity
    public var pairedAtMilliseconds: Int64
    /// The machine's own name, learned from `hello.ok` (amendment A24).
    ///
    /// `nil` until this phone has completed one session, because the QR carries
    /// no name — so a freshly paired machine is listed by its fingerprint until
    /// it introduces itself. Display-only, and attacker-supplied like any other
    /// peer-provided text: never used as an identifier or compared against.
    public var displayName: String?

    public init(
        agentDeviceID: String,
        accountID: String,
        relayURL: String,
        lanHints: [LanEndpoint],
        pinnedIdentity: PublicIdentity,
        pairedAtMilliseconds: Int64,
        displayName: String? = nil
    ) {
        self.agentDeviceID = agentDeviceID
        self.accountID = accountID
        self.relayURL = relayURL
        self.lanHints = lanHints
        self.pinnedIdentity = pinnedIdentity
        self.pairedAtMilliseconds = pairedAtMilliseconds
        self.displayName = displayName
    }

    /// The pinned key's fingerprint — the durable identity of this machine, and
    /// the thing an operator compares against what the host printed.
    public var fingerprint: Fingerprint { Fingerprint.of(pinnedIdentity) }

    /// What to show in the device list: the machine's name once it has given
    /// one, and its pinned fingerprint until then.
    public var listLabel: String {
        if let displayName, !displayName.isEmpty { return displayName }
        return fingerprint.short
    }

    public var pairedAt: Date {
        Date(timeIntervalSince1970: Double(pairedAtMilliseconds) / 1000)
    }
}
