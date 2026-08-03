// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

//! Body schemas for the message types that are fully defined.
//!
//! Unknown JSON fields are ignored rather than rejected, so a peer on an older
//! build can read a message a newer peer extended.

use serde::{Deserialize, Serialize};

use super::enums::{ByeReason, Capability, ErrorCode, IdentityAlgorithm};

/// Universal failure response. Brief §5.1 promises every request maps to exactly one response type or an `error`, but the §5.2 registry omitted the type — it is defined here (execution plan §2 #6). Carries the correlation id of the request it rejects.
/// Wire type: `error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Failure class.
    pub code: ErrorCode,
    /// Human-readable detail. Safe to display; never contains host paths or secrets.
    pub message: String,
    /// True if an identical retry could succeed later. False means the caller must change something.
    pub retryable: bool,
}

/// First message on an established Noise channel, sent by the initiator (the client — see execution plan §2 #13). Version and capability negotiation exist from day one because Gate P10 fails the design if a later phase needs a new protocol message; a capability set means later phases add capabilities, not messages.
/// Wire type: `hello`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloBody {
    /// Highest envelope version the sender speaks.
    pub protocol_version: u32,
    /// Lowest envelope version the sender accepts.
    pub min_protocol_version: u32,
    /// Message groups the sender implements. Unknown entries must be ignored, not rejected.
    pub capabilities: Vec<Capability>,
    /// Sender's device id, as pinned at pairing.
    pub device_id: uuid::Uuid,
    /// Sender build version, for diagnostics and the audit log. Never used to gate behaviour — capabilities do that.
    pub software_version: String,
}

/// Responder's answer to `hello`. If no envelope version is common to both peers the responder sends `error` with `version_mismatch` instead of this.
/// Wire type: `hello.ok`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloOkBody {
    /// Envelope version selected for this session. Both peers use exactly this from here on.
    pub protocol_version: u32,
    /// Responder's implemented groups. The effective set for the session is the intersection with the initiator's.
    pub capabilities: Vec<Capability>,
    /// Responder's device id, as pinned at pairing.
    pub device_id: uuid::Uuid,
    /// Responder build version.
    pub software_version: String,
    /// Identifies this session in the host audit log, which records start/stop with duration and peer device id (brief §6.4).
    pub session_id: uuid::Uuid,
    /// Human-readable machine name for the client's device list and dashboard title (amendment A23). Optional so a peer predating this field still speaks. Display-only text — never an identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Liveness probe and round-trip measurement. Either peer may send it.
/// Wire type: `ping`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingBody {
    /// Monotonic per-session counter, so a late `pong` is attributable rather than merely stale.
    pub seq: u64,
}

/// Answer to `ping`, carrying the same envelope correlation id.
/// Wire type: `pong`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PongBody {
    /// Echo of the ping's `seq`.
    pub seq: u64,
    /// Echo of the ping envelope's `ts`, so the sender computes round-trip time without holding per-ping state.
    pub echo_ts: i64,
}

/// Orderly session teardown. Best-effort: a peer must handle a dropped transport identically.
/// Wire type: `bye`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByeBody {
    /// Why the session is ending.
    pub reason: ByeReason,
    /// Optional human-readable elaboration for the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Client → agent, first message inside the `Noise_IKpsk2` channel whose PSK is the `pairing_secret` from the physically scanned QR. Only the physical scanner holds that secret, so reaching this point already proves physical access; this body carries the material the agent pins.
/// Wire type: `pair.request`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairRequestBody {
    /// Client device id, chosen by the client and pinned by the agent.
    pub device_id: uuid::Uuid,
    /// Algorithm of `identity_public_key`.
    pub identity_algorithm: IdentityAlgorithm,
    /// Hardware-backed identity public key. The durable root of trust; the agent pins this permanently.
    #[serde(with = "crate::b64")]
    pub identity_public_key: Vec<u8>,
    /// X25519 Noise static public key, 32 bytes. Rotatable by re-signing; the identity key above is what makes a rotation trustworthy.
    #[serde(with = "crate::b64")]
    pub noise_static_public_key: Vec<u8>,
    /// Cross-signature binding the Noise static to the identity key: Sign_identity("osprey/cross-cert/noise-static/v1" || identity_public_key || noise_static_public_key[32]). The identity key is 32 bytes for ed25519 and 65 for p256 (X9.63 uncompressed); no length prefix is needed because `identity_algorithm` fixes that length before the verifier hashes anything. The receiver MUST reject the pairing if this does not verify. See brief amendment A22.
    #[serde(with = "crate::b64")]
    pub noise_static_signature: Vec<u8>,
    /// Peer-supplied label shown beside the key fingerprint during host confirmation. Attacker-controlled text — display it, never trust it, never use it as an identifier.
    pub display_name: String,
}

/// Agent → client, answering `pair.request`. The mirror image: the agent's own pinnable material. The client already holds the agent identity key from the QR, so it MUST compare `identity_public_key` against the scanned value and abort on mismatch — that comparison is what a hostile relay cannot defeat.
/// Wire type: `pair.confirm`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairConfirmBody {
    /// Agent device id.
    pub device_id: uuid::Uuid,
    /// Relay account this agent belongs to. Every relay row is scoped to it (brief §6.7).
    pub account_id: uuid::Uuid,
    /// Algorithm of `identity_public_key`. Ed25519 for a Windows agent.
    pub identity_algorithm: IdentityAlgorithm,
    /// Agent's hardware-backed identity public key. Must byte-equal the key carried in the scanned QR.
    #[serde(with = "crate::b64")]
    pub identity_public_key: Vec<u8>,
    /// Agent's X25519 Noise static public key, 32 bytes. Pinned for all post-pairing sessions, which run plain Noise_IK with no PSK.
    #[serde(with = "crate::b64")]
    pub noise_static_public_key: Vec<u8>,
    /// Cross-signature over the Noise static, same construction as in pair.request. Reject the pairing if it does not verify under `identity_public_key`.
    #[serde(with = "crate::b64")]
    pub noise_static_signature: Vec<u8>,
    /// Host machine name, shown in the client's device list.
    pub display_name: String,
    /// Agent clock at pin time, milliseconds since the Unix epoch. Audit metadata only.
    pub paired_at: i64,
}

/// Signed unpair, sent over the authenticated Noise channel (execution plan §3, task D3). The agent's local pin store is authoritative — the relay is untrusted and is not even on the path for a LAN session — so this message is what lets the *client* drop a pairing the operator is not standing next to. The relay may carry it best-effort but can neither forge nor suppress it. Every revocation is audited.
/// Wire type: `pair.revoke`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairRevokeBody {
    /// Device that signed this revocation.
    pub issuer_device_id: uuid::Uuid,
    /// Device whose pin is being removed. Either peer may revoke either side of the pairing.
    pub revoked_device_id: uuid::Uuid,
    /// Signing time, milliseconds since the Unix epoch. Covered by the signature. Receivers reject revocations far outside their own clock window.
    pub issued_at: i64,
    /// 32 random bytes. Covered by the signature; the receiver rejects a nonce it has already accepted, so a captured revocation cannot be replayed after re-pairing.
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    /// Sign_identity("osprey/pair.revoke/v1" || issuer_device_id[16] || revoked_device_id[16] || issued_at as big-endian i64[8] || nonce[32]), by the issuer's pinned identity key.
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

/// Client → agent. Opens (or replaces) the session's metrics stream. At most one subscription is active per session; a new subscribe supersedes the previous one, and `stream = false` doubles as unsubscribe — which is what keeps the metrics registry at its three reserved names (Gate P10 forbids new message types). The correlated response is a `metrics.history` body carrying the requested backfill; if `stream` is true, uncorrelated `metrics.tick` pushes follow at ~1 Hz (brief M-01) carrying this request's envelope id as `sub`.
/// Wire type: `metrics.subscribe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSubscribeBody {
    /// How much ring-buffer history the correlated `metrics.history` response should carry. 0 means none — the response then has empty sample arrays. The agent may serve less than requested (it only holds 24 h) and may decimate; `interval_ms` in the response is authoritative.
    pub backfill_seconds: u32,
    /// True: push `metrics.tick` at the live cadence until superseded or the session ends. False: one-shot history query, and cancels any active stream.
    pub stream: bool,
}

/// Agent → client, uncorrelated server-push (§5.1's stream model): carries the `sub` id of the subscribe that opened the stream rather than answering any envelope. One whole-machine sample. Disk arrays are parallel by index — the schema DSL has no nested structs, deliberately (it keeps both decoders trivial), so structured data rides as parallel arrays.
/// Wire type: `metrics.tick`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsTickBody {
    /// Envelope id of the `metrics.subscribe` that opened this stream. A client ignores ticks for a `sub` it no longer tracks — they can be in flight when a new subscribe supersedes the old one.
    pub sub: uuid::Uuid,
    /// Sample time, milliseconds since the Unix epoch. Distinct from the envelope's send-time `ts`.
    pub ts: i64,
    /// Whole-machine CPU utilisation, 0–100, across all logical processors.
    pub cpu_percent: f64,
    /// Physical memory in use.
    pub mem_used_bytes: u64,
    /// Physical memory installed.
    pub mem_total_bytes: u64,
    /// Fixed-volume labels (e.g. "C:"), parallel with the two disk arrays.
    pub disk_labels: Vec<String>,
    /// Used bytes per volume, parallel with `disk_labels`.
    pub disk_used_bytes: Vec<u64>,
    /// Capacity per volume, parallel with `disk_labels`.
    pub disk_total_bytes: Vec<u64>,
    /// Aggregate receive rate across physical interfaces since the previous sample. Per-interface detail is M-16 (`net.interfaces`), not this message.
    pub net_rx_bytes_per_sec: u64,
    /// Aggregate transmit rate across physical interfaces since the previous sample.
    pub net_tx_bytes_per_sec: u64,
}

/// Agent → client, and only ever a *response* — it answers `metrics.subscribe` with the requested backfill (correlated by envelope id). Samples are fixed-cadence parallel arrays: `start_ts` plus `interval_ms` locate every sample without a per-sample timestamp array, which is what keeps a 24 h backfill inside the session's message-size cap. The agent decimates (and says so via `interval_ms`) rather than exceeding the cap. Disk usage has no history — it moves too slowly to chart and rides every `metrics.tick` instead.
/// Wire type: `metrics.history`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsHistoryBody {
    /// Envelope id of the `metrics.subscribe` this answers, mirroring `metrics.tick`.
    pub sub: uuid::Uuid,
    /// Timestamp of the first sample, milliseconds since the Unix epoch. Sample N is at start_ts + N * interval_ms.
    pub start_ts: i64,
    /// Spacing between samples. The ring buffer's native cadence is 30 s; a larger value means the agent decimated to fit the message cap.
    pub interval_ms: u32,
    /// Whole-machine CPU utilisation per sample, 0–100.
    pub cpu_percent: Vec<f64>,
    /// Physical memory in use per sample.
    pub mem_used_bytes: Vec<u64>,
    /// Physical memory installed. Scalar — capacity does not vary sample to sample.
    pub mem_total_bytes: u64,
    /// Aggregate receive rate per sample.
    pub net_rx_bytes_per_sec: Vec<u64>,
    /// Aggregate transmit rate per sample.
    pub net_tx_bytes_per_sec: Vec<u64>,
}

