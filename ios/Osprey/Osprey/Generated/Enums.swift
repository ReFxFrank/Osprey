// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

import Foundation

/// Machine-readable failure class. Pair with `retryable` to decide whether to back off or give up.
///
/// Unrecognised wire values decode to `.unknown`, preserving the original string.
public enum ErrorCode: Codable, Hashable, Sendable {
    /// Envelope or body failed schema validation.
    case badRequest
    /// Well-formed message the peer does not implement — capability not negotiated.
    case unsupported
    /// Peer is not paired, or the pairing was revoked.
    case unauthorized
    /// Referenced resource does not exist. Never distinguishes 'absent' from 'not yours'.
    case notFound
    /// Request contradicts current state, e.g. redeeming an already-redeemed pairing.
    case conflict
    /// Caller exceeded a quota. Retryable after a delay.
    case rateLimited
    /// The peer gave up waiting on something downstream.
    case timeout
    /// No envelope version in common — see hello / hello.ok.
    case versionMismatch
    /// Unexpected host-side failure. Details stay in the host audit log, not on the wire.
    case `internal`
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    case unknown(String)

    /// Wire spelling of this value.
    public var wireValue: String {
        switch self {
        case .badRequest: return "bad_request"
        case .unsupported: return "unsupported"
        case .unauthorized: return "unauthorized"
        case .notFound: return "not_found"
        case .conflict: return "conflict"
        case .rateLimited: return "rate_limited"
        case .timeout: return "timeout"
        case .versionMismatch: return "version_mismatch"
        case .`internal`: return "internal"
        case .unknown(let raw): return raw
        }
    }

    public init(wireValue: String) {
        switch wireValue {
        case "bad_request": self = .badRequest
        case "unsupported": self = .unsupported
        case "unauthorized": self = .unauthorized
        case "not_found": self = .notFound
        case "conflict": self = .conflict
        case "rate_limited": self = .rateLimited
        case "timeout": self = .timeout
        case "version_mismatch": self = .versionMismatch
        case "internal": self = .`internal`
        default: self = .unknown(wireValue)
        }
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self.init(wireValue: raw)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireValue)
    }
}

/// Why a session is ending. Recorded in the host audit log (brief §6.4).
///
/// Unrecognised wire values decode to `.unknown`, preserving the original string.
public enum ByeReason: Codable, Hashable, Sendable {
    /// Orderly shutdown by either peer.
    case normal
    /// Pairing was revoked; the session is being dropped immediately (brief §6.1).
    case unpaired
    /// Host machine is powering off or the service is stopping.
    case hostShutdown
    /// No traffic within the keepalive window.
    case idleTimeout
    /// Peer sent something unparseable or out of sequence.
    case protocolError
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    case unknown(String)

    /// Wire spelling of this value.
    public var wireValue: String {
        switch self {
        case .normal: return "normal"
        case .unpaired: return "unpaired"
        case .hostShutdown: return "host_shutdown"
        case .idleTimeout: return "idle_timeout"
        case .protocolError: return "protocol_error"
        case .unknown(let raw): return raw
        }
    }

    public init(wireValue: String) {
        switch wireValue {
        case "normal": self = .normal
        case "unpaired": self = .unpaired
        case "host_shutdown": self = .hostShutdown
        case "idle_timeout": self = .idleTimeout
        case "protocol_error": self = .protocolError
        default: self = .unknown(wireValue)
        }
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self.init(wireValue: raw)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireValue)
    }
}

/// Signature algorithm of a peer's hardware-backed identity key. The agent is Ed25519 in DPAPI; iOS is P-256 in the Secure Enclave, because Ed25519 is not Secure-Enclave-backed (brief §6.1). Carrying the algorithm explicitly means a verifier never has to infer it from key length.
///
/// Unrecognised wire values decode to `.unknown`, preserving the original string.
public enum IdentityAlgorithm: Codable, Hashable, Sendable {
    /// Ed25519, 32-byte public key. Windows agent and the P10 desktop client.
    case ed25519
    /// NIST P-256 ECDSA, 65-byte SEC1 uncompressed public key. iOS Secure Enclave.
    case p256
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    case unknown(String)

    /// Wire spelling of this value.
    public var wireValue: String {
        switch self {
        case .ed25519: return "ed25519"
        case .p256: return "p256"
        case .unknown(let raw): return raw
        }
    }

    public init(wireValue: String) {
        switch wireValue {
        case "ed25519": self = .ed25519
        case "p256": self = .p256
        default: self = .unknown(wireValue)
        }
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self.init(wireValue: raw)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireValue)
    }
}

/// A message group a peer implements. Negotiated in `hello`/`hello.ok`; the
/// effective set for a session is the intersection of both peers' sets.
///
/// Unrecognised wire values decode to `.unknown`, preserving the original string.
public enum Capability: Codable, Hashable, Sendable {
    /// CPU/RAM/disk/network/GPU telemetry (M-01, M-02, M-03).
    case metrics
    /// Process enumeration and control (M-04, M-05).
    case process
    /// Windows service enumeration and control (M-06).
    case service
    /// Power state transitions and Wake-on-LAN (M-07, M-08).
    case power
    /// One-shot command execution (M-12). Opt-in per agent, off by default.
    case exec
    /// Interactive ConPTY terminal (M-11).
    case terminal
    /// File browsing and chunked transfer (M-09, M-10).
    case files
    /// Windows Event Log query and live tail (M-13).
    case events
    /// Installed application inventory and uninstall (M-14).
    case apps
    /// Scheduled task enumeration and control (M-15).
    case tasks
    /// Interface, connection and throughput reporting (M-16).
    case network
    /// Threshold rules, firing and acknowledgement (M-17).
    case alerts
    /// Screen capture, encode and monitor selection (S-*).
    case sessionPlane
    /// Remote input injection (S-*). Split across two data channels — see `unreliable`.
    case input
    /// Clipboard synchronisation (S-*).
    case clipboard
    /// Host audio capture and playback (S-*).
    case audio
    /// Host-side privacy controls: blank screen, block local input (S-*).
    case privacy
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    case unknown(String)

    /// Wire spelling of this value.
    public var wireValue: String {
        switch self {
        case .metrics: return "metrics"
        case .process: return "process"
        case .service: return "service"
        case .power: return "power"
        case .exec: return "exec"
        case .terminal: return "terminal"
        case .files: return "files"
        case .events: return "events"
        case .apps: return "apps"
        case .tasks: return "tasks"
        case .network: return "network"
        case .alerts: return "alerts"
        case .sessionPlane: return "session_plane"
        case .input: return "input"
        case .clipboard: return "clipboard"
        case .audio: return "audio"
        case .privacy: return "privacy"
        case .unknown(let raw): return raw
        }
    }

    public init(wireValue: String) {
        switch wireValue {
        case "metrics": self = .metrics
        case "process": self = .process
        case "service": self = .service
        case "power": self = .power
        case "exec": self = .exec
        case "terminal": self = .terminal
        case "files": self = .files
        case "events": self = .events
        case "apps": self = .apps
        case "tasks": self = .tasks
        case "network": self = .network
        case "alerts": self = .alerts
        case "session_plane": self = .sessionPlane
        case "input": self = .input
        case "clipboard": self = .clipboard
        case "audio": self = .audio
        case "privacy": self = .privacy
        default: self = .unknown(wireValue)
        }
    }

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self.init(wireValue: raw)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireValue)
    }
}

/// Which data channel a message must travel on (brief §5.3).
public enum Channel: Hashable, Sendable {
    /// Reliable and ordered. A dropped keystroke is unacceptable.
    case reliable
    /// Unordered with `maxRetransmits: 0`. A dropped mouse-move is invisible.
    case unreliable
}
