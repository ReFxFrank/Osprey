// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

import Foundation

/// A body schema that knows which registry type it belongs to.
public protocol OspreyMessageBody: Codable, Hashable, Sendable {
    static var messageType: MessageType { get }
}

/// Universal failure response. Brief §5.1 promises every request maps to exactly one response type or an `error`, but the §5.2 registry omitted the type — it is defined here (execution plan §2 #6). Carries the correlation id of the request it rejects.
/// Wire type: `error`.
public struct ErrorBody: OspreyMessageBody {
    public static let messageType: MessageType = .error

    /// Failure class.
    public var code: ErrorCode
    /// Human-readable detail. Safe to display; never contains host paths or secrets.
    public var message: String
    /// True if an identical retry could succeed later. False means the caller must change something.
    public var retryable: Bool

    public init(code: ErrorCode, message: String, retryable: Bool) {
        self.code = code
        self.message = message
        self.retryable = retryable
    }

    private enum CodingKeys: String, CodingKey {
        case code = "code"
        case message = "message"
        case retryable = "retryable"
    }
}

/// First message on an established Noise channel, sent by the initiator (the client — see execution plan §2 #13). Version and capability negotiation exist from day one because Gate P10 fails the design if a later phase needs a new protocol message; a capability set means later phases add capabilities, not messages.
/// Wire type: `hello`.
public struct HelloBody: OspreyMessageBody {
    public static let messageType: MessageType = .hello

    /// Highest envelope version the sender speaks.
    public var protocolVersion: UInt32
    /// Lowest envelope version the sender accepts.
    public var minProtocolVersion: UInt32
    /// Message groups the sender implements. Unknown entries must be ignored, not rejected.
    public var capabilities: [Capability]
    /// Sender's device id, as pinned at pairing.
    public var deviceId: UUID
    /// Sender build version, for diagnostics and the audit log. Never used to gate behaviour — capabilities do that.
    public var softwareVersion: String

    public init(protocolVersion: UInt32, minProtocolVersion: UInt32, capabilities: [Capability], deviceId: UUID, softwareVersion: String) {
        self.protocolVersion = protocolVersion
        self.minProtocolVersion = minProtocolVersion
        self.capabilities = capabilities
        self.deviceId = deviceId
        self.softwareVersion = softwareVersion
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case minProtocolVersion = "min_protocol_version"
        case capabilities = "capabilities"
        case deviceId = "device_id"
        case softwareVersion = "software_version"
    }
}

/// Responder's answer to `hello`. If no envelope version is common to both peers the responder sends `error` with `version_mismatch` instead of this.
/// Wire type: `hello.ok`.
public struct HelloOkBody: OspreyMessageBody {
    public static let messageType: MessageType = .helloOk

    /// Envelope version selected for this session. Both peers use exactly this from here on.
    public var protocolVersion: UInt32
    /// Responder's implemented groups. The effective set for the session is the intersection with the initiator's.
    public var capabilities: [Capability]
    /// Responder's device id, as pinned at pairing.
    public var deviceId: UUID
    /// Responder build version.
    public var softwareVersion: String
    /// Identifies this session in the host audit log, which records start/stop with duration and peer device id (brief §6.4).
    public var sessionId: UUID
    /// Human-readable machine name for the client's device list and dashboard title (amendment A23). Optional so a peer predating this field still speaks. Display-only text — never an identifier.
    public var displayName: String?

    public init(protocolVersion: UInt32, capabilities: [Capability], deviceId: UUID, softwareVersion: String, sessionId: UUID, displayName: String?) {
        self.protocolVersion = protocolVersion
        self.capabilities = capabilities
        self.deviceId = deviceId
        self.softwareVersion = softwareVersion
        self.sessionId = sessionId
        self.displayName = displayName
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case capabilities = "capabilities"
        case deviceId = "device_id"
        case softwareVersion = "software_version"
        case sessionId = "session_id"
        case displayName = "display_name"
    }
}

/// Liveness probe and round-trip measurement. Either peer may send it.
/// Wire type: `ping`.
public struct PingBody: OspreyMessageBody {
    public static let messageType: MessageType = .ping

    /// Monotonic per-session counter, so a late `pong` is attributable rather than merely stale.
    public var seq: UInt64

    public init(seq: UInt64) {
        self.seq = seq
    }

    private enum CodingKeys: String, CodingKey {
        case seq = "seq"
    }
}

/// Answer to `ping`, carrying the same envelope correlation id.
/// Wire type: `pong`.
public struct PongBody: OspreyMessageBody {
    public static let messageType: MessageType = .pong

    /// Echo of the ping's `seq`.
    public var seq: UInt64
    /// Echo of the ping envelope's `ts`, so the sender computes round-trip time without holding per-ping state.
    public var echoTs: Int64

    public init(seq: UInt64, echoTs: Int64) {
        self.seq = seq
        self.echoTs = echoTs
    }

    private enum CodingKeys: String, CodingKey {
        case seq = "seq"
        case echoTs = "echo_ts"
    }
}

/// Orderly session teardown. Best-effort: a peer must handle a dropped transport identically.
/// Wire type: `bye`.
public struct ByeBody: OspreyMessageBody {
    public static let messageType: MessageType = .bye

    /// Why the session is ending.
    public var reason: ByeReason
    /// Optional human-readable elaboration for the audit log.
    public var detail: String?

    public init(reason: ByeReason, detail: String?) {
        self.reason = reason
        self.detail = detail
    }

    private enum CodingKeys: String, CodingKey {
        case reason = "reason"
        case detail = "detail"
    }
}

/// Client → agent, first message inside the `Noise_IKpsk2` channel whose PSK is the `pairing_secret` from the physically scanned QR. Only the physical scanner holds that secret, so reaching this point already proves physical access; this body carries the material the agent pins.
/// Wire type: `pair.request`.
public struct PairRequestBody: OspreyMessageBody {
    public static let messageType: MessageType = .pairRequest

    /// Client device id, chosen by the client and pinned by the agent.
    public var deviceId: UUID
    /// Algorithm of `identity_public_key`.
    public var identityAlgorithm: IdentityAlgorithm
    /// Hardware-backed identity public key. The durable root of trust; the agent pins this permanently.
    public var identityPublicKey: Data
    /// X25519 Noise static public key, 32 bytes. Rotatable by re-signing; the identity key above is what makes a rotation trustworthy.
    public var noiseStaticPublicKey: Data
    /// Cross-signature binding the Noise static to the identity key: Sign_identity("osprey/cross-cert/noise-static/v1" || identity_public_key || noise_static_public_key[32]). The identity key is 32 bytes for ed25519 and 65 for p256 (X9.63 uncompressed); no length prefix is needed because `identity_algorithm` fixes that length before the verifier hashes anything. The receiver MUST reject the pairing if this does not verify. See brief amendment A22.
    public var noiseStaticSignature: Data
    /// Peer-supplied label shown beside the key fingerprint during host confirmation. Attacker-controlled text — display it, never trust it, never use it as an identifier.
    public var displayName: String

    public init(deviceId: UUID, identityAlgorithm: IdentityAlgorithm, identityPublicKey: Data, noiseStaticPublicKey: Data, noiseStaticSignature: Data, displayName: String) {
        self.deviceId = deviceId
        self.identityAlgorithm = identityAlgorithm
        self.identityPublicKey = identityPublicKey
        self.noiseStaticPublicKey = noiseStaticPublicKey
        self.noiseStaticSignature = noiseStaticSignature
        self.displayName = displayName
    }

    private enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case identityAlgorithm = "identity_algorithm"
        case identityPublicKey = "identity_public_key"
        case noiseStaticPublicKey = "noise_static_public_key"
        case noiseStaticSignature = "noise_static_signature"
        case displayName = "display_name"
    }
}

/// Agent → client, answering `pair.request`. The mirror image: the agent's own pinnable material. The client already holds the agent identity key from the QR, so it MUST compare `identity_public_key` against the scanned value and abort on mismatch — that comparison is what a hostile relay cannot defeat.
/// Wire type: `pair.confirm`.
public struct PairConfirmBody: OspreyMessageBody {
    public static let messageType: MessageType = .pairConfirm

    /// Agent device id.
    public var deviceId: UUID
    /// Relay account this agent belongs to. Every relay row is scoped to it (brief §6.7).
    public var accountId: UUID
    /// Algorithm of `identity_public_key`. Ed25519 for a Windows agent.
    public var identityAlgorithm: IdentityAlgorithm
    /// Agent's hardware-backed identity public key. Must byte-equal the key carried in the scanned QR.
    public var identityPublicKey: Data
    /// Agent's X25519 Noise static public key, 32 bytes. Pinned for all post-pairing sessions, which run plain Noise_IK with no PSK.
    public var noiseStaticPublicKey: Data
    /// Cross-signature over the Noise static, same construction as in pair.request. Reject the pairing if it does not verify under `identity_public_key`.
    public var noiseStaticSignature: Data
    /// Host machine name, shown in the client's device list.
    public var displayName: String
    /// Agent clock at pin time, milliseconds since the Unix epoch. Audit metadata only.
    public var pairedAt: Int64

    public init(deviceId: UUID, accountId: UUID, identityAlgorithm: IdentityAlgorithm, identityPublicKey: Data, noiseStaticPublicKey: Data, noiseStaticSignature: Data, displayName: String, pairedAt: Int64) {
        self.deviceId = deviceId
        self.accountId = accountId
        self.identityAlgorithm = identityAlgorithm
        self.identityPublicKey = identityPublicKey
        self.noiseStaticPublicKey = noiseStaticPublicKey
        self.noiseStaticSignature = noiseStaticSignature
        self.displayName = displayName
        self.pairedAt = pairedAt
    }

    private enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case accountId = "account_id"
        case identityAlgorithm = "identity_algorithm"
        case identityPublicKey = "identity_public_key"
        case noiseStaticPublicKey = "noise_static_public_key"
        case noiseStaticSignature = "noise_static_signature"
        case displayName = "display_name"
        case pairedAt = "paired_at"
    }
}

/// Signed unpair, sent over the authenticated Noise channel (execution plan §3, task D3). The agent's local pin store is authoritative — the relay is untrusted and is not even on the path for a LAN session — so this message is what lets the *client* drop a pairing the operator is not standing next to. The relay may carry it best-effort but can neither forge nor suppress it. Every revocation is audited.
/// Wire type: `pair.revoke`.
public struct PairRevokeBody: OspreyMessageBody {
    public static let messageType: MessageType = .pairRevoke

    /// Device that signed this revocation.
    public var issuerDeviceId: UUID
    /// Device whose pin is being removed. Either peer may revoke either side of the pairing.
    public var revokedDeviceId: UUID
    /// Signing time, milliseconds since the Unix epoch. Covered by the signature. Receivers reject revocations far outside their own clock window.
    public var issuedAt: Int64
    /// 32 random bytes. Covered by the signature; the receiver rejects a nonce it has already accepted, so a captured revocation cannot be replayed after re-pairing.
    public var nonce: Data
    /// Sign_identity("osprey/pair.revoke/v1" || issuer_device_id[16] || revoked_device_id[16] || issued_at as big-endian i64[8] || nonce[32]), by the issuer's pinned identity key.
    public var signature: Data

    public init(issuerDeviceId: UUID, revokedDeviceId: UUID, issuedAt: Int64, nonce: Data, signature: Data) {
        self.issuerDeviceId = issuerDeviceId
        self.revokedDeviceId = revokedDeviceId
        self.issuedAt = issuedAt
        self.nonce = nonce
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case issuerDeviceId = "issuer_device_id"
        case revokedDeviceId = "revoked_device_id"
        case issuedAt = "issued_at"
        case nonce = "nonce"
        case signature = "signature"
    }
}

/// Client → agent. Opens (or replaces) the session's metrics stream. At most one subscription is active per session; a new subscribe supersedes the previous one, and `stream = false` doubles as unsubscribe — which is what keeps the metrics registry at its three reserved names (Gate P10 forbids new message types). The correlated response is a `metrics.history` body carrying the requested backfill; if `stream` is true, uncorrelated `metrics.tick` pushes follow at ~1 Hz (brief M-01) carrying this request's envelope id as `sub`.
/// Wire type: `metrics.subscribe`.
public struct MetricsSubscribeBody: OspreyMessageBody {
    public static let messageType: MessageType = .metricsSubscribe

    /// How much ring-buffer history the correlated `metrics.history` response should carry. 0 means none — the response then has empty sample arrays. The agent may serve less than requested (it only holds 24 h) and may decimate; `interval_ms` in the response is authoritative.
    public var backfillSeconds: UInt32
    /// True: push `metrics.tick` at the live cadence until superseded or the session ends. False: one-shot history query, and cancels any active stream.
    public var stream: Bool

    public init(backfillSeconds: UInt32, stream: Bool) {
        self.backfillSeconds = backfillSeconds
        self.stream = stream
    }

    private enum CodingKeys: String, CodingKey {
        case backfillSeconds = "backfill_seconds"
        case stream = "stream"
    }
}

/// Agent → client, uncorrelated server-push (§5.1's stream model): carries the `sub` id of the subscribe that opened the stream rather than answering any envelope. One whole-machine sample. Disk arrays are parallel by index — the schema DSL has no nested structs, deliberately (it keeps both decoders trivial), so structured data rides as parallel arrays.
/// Wire type: `metrics.tick`.
public struct MetricsTickBody: OspreyMessageBody {
    public static let messageType: MessageType = .metricsTick

    /// Envelope id of the `metrics.subscribe` that opened this stream. A client ignores ticks for a `sub` it no longer tracks — they can be in flight when a new subscribe supersedes the old one.
    public var sub: UUID
    /// Sample time, milliseconds since the Unix epoch. Distinct from the envelope's send-time `ts`.
    public var ts: Int64
    /// Whole-machine CPU utilisation, 0–100, across all logical processors.
    public var cpuPercent: Double
    /// Physical memory in use.
    public var memUsedBytes: UInt64
    /// Physical memory installed.
    public var memTotalBytes: UInt64
    /// Fixed-volume labels (e.g. "C:"), parallel with the two disk arrays.
    public var diskLabels: [String]
    /// Used bytes per volume, parallel with `disk_labels`.
    public var diskUsedBytes: [UInt64]
    /// Capacity per volume, parallel with `disk_labels`.
    public var diskTotalBytes: [UInt64]
    /// Aggregate receive rate across physical interfaces since the previous sample. Per-interface detail is M-16 (`net.interfaces`), not this message.
    public var netRxBytesPerSec: UInt64
    /// Aggregate transmit rate across physical interfaces since the previous sample.
    public var netTxBytesPerSec: UInt64

    public init(sub: UUID, ts: Int64, cpuPercent: Double, memUsedBytes: UInt64, memTotalBytes: UInt64, diskLabels: [String], diskUsedBytes: [UInt64], diskTotalBytes: [UInt64], netRxBytesPerSec: UInt64, netTxBytesPerSec: UInt64) {
        self.sub = sub
        self.ts = ts
        self.cpuPercent = cpuPercent
        self.memUsedBytes = memUsedBytes
        self.memTotalBytes = memTotalBytes
        self.diskLabels = diskLabels
        self.diskUsedBytes = diskUsedBytes
        self.diskTotalBytes = diskTotalBytes
        self.netRxBytesPerSec = netRxBytesPerSec
        self.netTxBytesPerSec = netTxBytesPerSec
    }

    private enum CodingKeys: String, CodingKey {
        case sub = "sub"
        case ts = "ts"
        case cpuPercent = "cpu_percent"
        case memUsedBytes = "mem_used_bytes"
        case memTotalBytes = "mem_total_bytes"
        case diskLabels = "disk_labels"
        case diskUsedBytes = "disk_used_bytes"
        case diskTotalBytes = "disk_total_bytes"
        case netRxBytesPerSec = "net_rx_bytes_per_sec"
        case netTxBytesPerSec = "net_tx_bytes_per_sec"
    }
}

/// Agent → client, and only ever a *response* — it answers `metrics.subscribe` with the requested backfill (correlated by envelope id). Samples are fixed-cadence parallel arrays: `start_ts` plus `interval_ms` locate every sample without a per-sample timestamp array, which is what keeps a 24 h backfill inside the session's message-size cap. The agent decimates (and says so via `interval_ms`) rather than exceeding the cap. Disk usage has no history — it moves too slowly to chart and rides every `metrics.tick` instead.
/// Wire type: `metrics.history`.
public struct MetricsHistoryBody: OspreyMessageBody {
    public static let messageType: MessageType = .metricsHistory

    /// Envelope id of the `metrics.subscribe` this answers, mirroring `metrics.tick`.
    public var sub: UUID
    /// Timestamp of the first sample, milliseconds since the Unix epoch. Sample N is at start_ts + N * interval_ms.
    public var startTs: Int64
    /// Spacing between samples. The ring buffer's native cadence is 30 s; a larger value means the agent decimated to fit the message cap.
    public var intervalMs: UInt32
    /// Whole-machine CPU utilisation per sample, 0–100.
    public var cpuPercent: [Double]
    /// Physical memory in use per sample.
    public var memUsedBytes: [UInt64]
    /// Physical memory installed. Scalar — capacity does not vary sample to sample.
    public var memTotalBytes: UInt64
    /// Aggregate receive rate per sample.
    public var netRxBytesPerSec: [UInt64]
    /// Aggregate transmit rate per sample.
    public var netTxBytesPerSec: [UInt64]

    public init(sub: UUID, startTs: Int64, intervalMs: UInt32, cpuPercent: [Double], memUsedBytes: [UInt64], memTotalBytes: UInt64, netRxBytesPerSec: [UInt64], netTxBytesPerSec: [UInt64]) {
        self.sub = sub
        self.startTs = startTs
        self.intervalMs = intervalMs
        self.cpuPercent = cpuPercent
        self.memUsedBytes = memUsedBytes
        self.memTotalBytes = memTotalBytes
        self.netRxBytesPerSec = netRxBytesPerSec
        self.netTxBytesPerSec = netTxBytesPerSec
    }

    private enum CodingKeys: String, CodingKey {
        case sub = "sub"
        case startTs = "start_ts"
        case intervalMs = "interval_ms"
        case cpuPercent = "cpu_percent"
        case memUsedBytes = "mem_used_bytes"
        case memTotalBytes = "mem_total_bytes"
        case netRxBytesPerSec = "net_rx_bytes_per_sec"
        case netTxBytesPerSec = "net_tx_bytes_per_sec"
    }
}

