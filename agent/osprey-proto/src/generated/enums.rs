// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

//! Value enumerations shared across message bodies.

use serde::{Deserialize, Serialize};

/// Machine-readable failure class. Pair with `retryable` to decide whether to back off or give up.
///
/// Unrecognised wire values decode to `Unknown`, preserving the original string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ErrorCode {
    /// Envelope or body failed schema validation.
    BadRequest,
    /// Well-formed message the peer does not implement — capability not negotiated.
    Unsupported,
    /// Peer is not paired, or the pairing was revoked.
    Unauthorized,
    /// Referenced resource does not exist. Never distinguishes 'absent' from 'not yours'.
    NotFound,
    /// Request contradicts current state, e.g. redeeming an already-redeemed pairing.
    Conflict,
    /// Caller exceeded a quota. Retryable after a delay.
    RateLimited,
    /// The peer gave up waiting on something downstream.
    Timeout,
    /// No envelope version in common — see hello / hello.ok.
    VersionMismatch,
    /// Unexpected host-side failure. Details stay in the host audit log, not on the wire.
    Internal,
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    Unknown(String),
}

impl ErrorCode {
    /// Wire spelling of this value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unsupported => "unsupported",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::VersionMismatch => "version_mismatch",
            Self::Internal => "internal",
            Self::Unknown(raw) => raw.as_str(),
        }
    }
}

impl From<String> for ErrorCode {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            "bad_request" => Self::BadRequest,
            "unsupported" => Self::Unsupported,
            "unauthorized" => Self::Unauthorized,
            "not_found" => Self::NotFound,
            "conflict" => Self::Conflict,
            "rate_limited" => Self::RateLimited,
            "timeout" => Self::Timeout,
            "version_mismatch" => Self::VersionMismatch,
            "internal" => Self::Internal,
            _ => Self::Unknown(raw),
        }
    }
}

impl From<ErrorCode> for String {
    fn from(value: ErrorCode) -> Self {
        match value {
            ErrorCode::Unknown(raw) => raw,
            other => other.as_str().to_owned(),
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a session is ending. Recorded in the host audit log (brief §6.4).
///
/// Unrecognised wire values decode to `Unknown`, preserving the original string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ByeReason {
    /// Orderly shutdown by either peer.
    Normal,
    /// Pairing was revoked; the session is being dropped immediately (brief §6.1).
    Unpaired,
    /// Host machine is powering off or the service is stopping.
    HostShutdown,
    /// No traffic within the keepalive window.
    IdleTimeout,
    /// Peer sent something unparseable or out of sequence.
    ProtocolError,
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    Unknown(String),
}

impl ByeReason {
    /// Wire spelling of this value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Normal => "normal",
            Self::Unpaired => "unpaired",
            Self::HostShutdown => "host_shutdown",
            Self::IdleTimeout => "idle_timeout",
            Self::ProtocolError => "protocol_error",
            Self::Unknown(raw) => raw.as_str(),
        }
    }
}

impl From<String> for ByeReason {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            "normal" => Self::Normal,
            "unpaired" => Self::Unpaired,
            "host_shutdown" => Self::HostShutdown,
            "idle_timeout" => Self::IdleTimeout,
            "protocol_error" => Self::ProtocolError,
            _ => Self::Unknown(raw),
        }
    }
}

impl From<ByeReason> for String {
    fn from(value: ByeReason) -> Self {
        match value {
            ByeReason::Unknown(raw) => raw,
            other => other.as_str().to_owned(),
        }
    }
}

impl core::fmt::Display for ByeReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Signature algorithm of a peer's hardware-backed identity key. The agent is Ed25519 in DPAPI; iOS is P-256 in the Secure Enclave, because Ed25519 is not Secure-Enclave-backed (brief §6.1). Carrying the algorithm explicitly means a verifier never has to infer it from key length.
///
/// Unrecognised wire values decode to `Unknown`, preserving the original string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum IdentityAlgorithm {
    /// Ed25519, 32-byte public key. Windows agent and the P10 desktop client.
    Ed25519,
    /// NIST P-256 ECDSA, 65-byte SEC1 uncompressed public key. iOS Secure Enclave.
    P256,
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    Unknown(String),
}

impl IdentityAlgorithm {
    /// Wire spelling of this value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
            Self::Unknown(raw) => raw.as_str(),
        }
    }
}

impl From<String> for IdentityAlgorithm {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            "ed25519" => Self::Ed25519,
            "p256" => Self::P256,
            _ => Self::Unknown(raw),
        }
    }
}

impl From<IdentityAlgorithm> for String {
    fn from(value: IdentityAlgorithm) -> Self {
        match value {
            IdentityAlgorithm::Unknown(raw) => raw,
            other => other.as_str().to_owned(),
        }
    }
}

impl core::fmt::Display for IdentityAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A message group a peer implements. Negotiated in `hello`/`hello.ok`; the
/// effective set for a session is the intersection of both peers' sets.
///
/// Unrecognised wire values decode to `Unknown`, preserving the original string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Capability {
    /// CPU/RAM/disk/network/GPU telemetry (M-01, M-02, M-03).
    Metrics,
    /// Process enumeration and control (M-04, M-05).
    Process,
    /// Windows service enumeration and control (M-06).
    Service,
    /// Power state transitions and Wake-on-LAN (M-07, M-08).
    Power,
    /// One-shot command execution (M-12). Opt-in per agent, off by default.
    Exec,
    /// Interactive ConPTY terminal (M-11).
    Terminal,
    /// File browsing and chunked transfer (M-09, M-10).
    Files,
    /// Windows Event Log query and live tail (M-13).
    Events,
    /// Installed application inventory and uninstall (M-14).
    Apps,
    /// Scheduled task enumeration and control (M-15).
    Tasks,
    /// Interface, connection and throughput reporting (M-16).
    Network,
    /// Threshold rules, firing and acknowledgement (M-17).
    Alerts,
    /// Screen capture, encode and monitor selection (S-*).
    SessionPlane,
    /// Remote input injection (S-*). Split across two data channels — see `unreliable`.
    Input,
    /// Clipboard synchronisation (S-*).
    Clipboard,
    /// Host audio capture and playback (S-*).
    Audio,
    /// Host-side privacy controls: blank screen, block local input (S-*).
    Privacy,
    /// A value this build does not know, kept verbatim so it can be logged or relayed.
    Unknown(String),
}

impl Capability {
    /// Wire spelling of this value.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Metrics => "metrics",
            Self::Process => "process",
            Self::Service => "service",
            Self::Power => "power",
            Self::Exec => "exec",
            Self::Terminal => "terminal",
            Self::Files => "files",
            Self::Events => "events",
            Self::Apps => "apps",
            Self::Tasks => "tasks",
            Self::Network => "network",
            Self::Alerts => "alerts",
            Self::SessionPlane => "session_plane",
            Self::Input => "input",
            Self::Clipboard => "clipboard",
            Self::Audio => "audio",
            Self::Privacy => "privacy",
            Self::Unknown(raw) => raw.as_str(),
        }
    }
}

impl From<String> for Capability {
    fn from(raw: String) -> Self {
        match raw.as_str() {
            "metrics" => Self::Metrics,
            "process" => Self::Process,
            "service" => Self::Service,
            "power" => Self::Power,
            "exec" => Self::Exec,
            "terminal" => Self::Terminal,
            "files" => Self::Files,
            "events" => Self::Events,
            "apps" => Self::Apps,
            "tasks" => Self::Tasks,
            "network" => Self::Network,
            "alerts" => Self::Alerts,
            "session_plane" => Self::SessionPlane,
            "input" => Self::Input,
            "clipboard" => Self::Clipboard,
            "audio" => Self::Audio,
            "privacy" => Self::Privacy,
            _ => Self::Unknown(raw),
        }
    }
}

impl From<Capability> for String {
    fn from(value: Capability) -> Self {
        match value {
            Capability::Unknown(raw) => raw,
            other => other.as_str().to_owned(),
        }
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which data channel a message must travel on (brief §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Reliable and ordered. A dropped keystroke is unacceptable.
    Reliable,
    /// Unordered with `maxRetransmits: 0`. A dropped mouse-move is invisible.
    Unreliable,
}
