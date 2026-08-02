//! The error type that crosses the FFI boundary.
//!
//! A panic unwinding across an FFI boundary is undefined behaviour, so every
//! fallible path here returns one of these instead. The variants are a
//! *narrowing* of [`osprey_core::Error`], not a copy of it: the phone can never
//! reach the agent's keystore or audit log, so those arms collapse into
//! [`OspreyError::Unexpected`] rather than becoming Swift cases that can never
//! occur.
//!
//! The mapping is an exhaustive `match`, deliberately. If `osprey-core` grows a
//! variant, this file fails to compile — which is the only way a new failure
//! mode is guaranteed to be classified rather than silently folded into a
//! catch-all.

use osprey_core::error::{CrossSignatureFailure, Error as CoreError};

/// Why a peer's cross-certificate was refused. Mirrors
/// [`CrossSignatureFailure`] so Swift can branch on the reason without parsing
/// a message string.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CrossSignatureReason {
    /// Signature bytes are not well-formed for the declared algorithm.
    Malformed,
    /// Well-formed, but does not verify under the identity key.
    NotSignedByIdentity,
    /// The identity key bytes are not a valid public key for the algorithm.
    BadIdentityKey,
    /// This build cannot verify the algorithm the peer named. `raw` is the
    /// value the peer sent, kept so it reaches the audit trail intact.
    UnsupportedAlgorithm { raw: String },
}

impl From<&CrossSignatureFailure> for CrossSignatureReason {
    fn from(failure: &CrossSignatureFailure) -> Self {
        match failure {
            CrossSignatureFailure::Malformed => Self::Malformed,
            CrossSignatureFailure::NotSignedByIdentity => Self::NotSignedByIdentity,
            CrossSignatureFailure::BadIdentityKey => Self::BadIdentityKey,
            CrossSignatureFailure::UnsupportedAlgorithm(raw) => Self::UnsupportedAlgorithm {
                raw: raw.clone(),
            },
        }
    }
}

/// Deliberately *not* `#[uniffi(flat_error)]`: a flat error would reach Swift as
/// a bare case plus a message string, and the pairing UI has to branch on
/// [`CrossSignatureReason`] and on the handshake stage rather than scrape prose.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OspreyError {
    /// The caller assembled an impossible handshake — a pairing handshake with
    /// no PSK, or an initiator with no peer static.
    #[error("handshake configuration is invalid: {detail}")]
    HandshakeConfig { detail: String },

    /// A handshake message failed to decrypt or authenticate. On `stage =
    /// "read"` this is a tampered, forged, or wrong-PSK message and is a
    /// security event, not a transport hiccup.
    #[error("noise handshake failed at {stage} stage: {detail}")]
    HandshakeRejected { stage: String, detail: String },

    /// AEAD authentication failed on an established session. Always tampering,
    /// truncation, or replay.
    #[error("transport message failed authentication: {detail}")]
    TransportAuth { detail: String },

    /// The byte stream is not valid Osprey framing.
    #[error("framing error: {detail}")]
    Framing { detail: String },

    #[error("reassembled message would exceed the {limit}-byte limit")]
    MessageTooLarge { limit: u64 },

    #[error("peer's cross-certificate was rejected: {detail}")]
    CrossSignature {
        reason: CrossSignatureReason,
        detail: String,
    },

    /// The peer completed the handshake with a static key that is not the one
    /// pinned at pairing. The key is internally consistent; it is the wrong
    /// device.
    #[error("peer presented an unpinned noise static key")]
    UnpinnedPeer,

    #[error("QR payload is version {found}, this build speaks version {expected}")]
    UnsupportedQrVersion { found: u32, expected: u32 },

    #[error("could not decode payload: {detail}")]
    PayloadDecode { detail: String },

    #[error("could not encode payload: {detail}")]
    PayloadEncode { detail: String },

    #[error("{label} must be {expected} bytes, got {actual}")]
    BadKeyLength {
        label: String,
        expected: u64,
        actual: u64,
    },

    /// The object was used out of order — a handshake consumed twice, a session
    /// used after a fatal transport error, or a lock left poisoned by an earlier
    /// panic. Always a caller bug on the Swift side.
    #[error("object used out of order: {detail}")]
    SessionState { detail: String },

    /// The caller pushed more unparsed bytes than the reassembly bound allows.
    /// Refused rather than grown, because the buffer is fed straight from a
    /// socket a hostile peer controls.
    #[error("inbound buffer would exceed the {limit}-byte bound")]
    InboundOverflow { limit: u64 },

    /// A failure `osprey-core` can raise but this bridge cannot reach — the
    /// keystore and the audit log are agent-side only. Surfaced verbatim rather
    /// than swallowed, so an unexpected path is visible instead of silent.
    #[error("unexpected core failure: {detail}")]
    Unexpected { detail: String },
}

pub type Result<T> = std::result::Result<T, OspreyError>;

/// Flatten an error chain into one line. No `osprey-core` error's `Display`
/// carries key material or the pairing secret, so this is safe to show and log.
pub(crate) fn detail(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

impl From<CoreError> for OspreyError {
    fn from(err: CoreError) -> Self {
        let detail = detail(&err);
        match err {
            CoreError::Handshake { stage, .. } => Self::HandshakeRejected {
                stage: stage.to_string(),
                detail,
            },
            CoreError::TransportAuth(_) => Self::TransportAuth { detail },
            CoreError::HandshakeConfig(_) => Self::HandshakeConfig { detail },
            CoreError::FrameTooLarge { .. }
            | CoreError::BadContinuationFlag { .. }
            | CoreError::EmptyChunk
            | CoreError::EmptyContinuationChunk
            | CoreError::TooManyChunks { .. }
            | CoreError::TruncatedFrame { .. } => Self::Framing { detail },
            CoreError::MessageTooLarge { max } => Self::MessageTooLarge { limit: max as u64 },
            CoreError::CrossSignature(ref failure) => Self::CrossSignature {
                reason: CrossSignatureReason::from(failure),
                detail,
            },
            CoreError::UnpinnedPeer => Self::UnpinnedPeer,
            CoreError::MissingRemoteStatic => Self::HandshakeRejected {
                stage: "transport".to_string(),
                detail,
            },
            CoreError::BadKeyLength { label, len } => Self::BadKeyLength {
                label: label.to_string(),
                // `osprey-core` reports only the length it received; the
                // expectation is fixed at 32 for every key it names this way.
                expected: 32,
                actual: len as u64,
            },
            CoreError::PairingEncode(_) => Self::PayloadEncode { detail },
            CoreError::PairingDecode(_) => Self::PayloadDecode { detail },
            CoreError::UnsupportedPayloadVersion { found, expected } => {
                Self::UnsupportedQrVersion { found, expected }
            }
            CoreError::Io(_) => Self::Framing { detail },
            CoreError::Keystore { .. } | CoreError::Audit(_) => Self::Unexpected { detail },
        }
    }
}

/// Copy a caller-supplied key into the fixed-size array `snow` requires.
pub(crate) fn key32(label: &str, bytes: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| OspreyError::BadKeyLength {
        label: label.to_string(),
        expected: 32,
        actual: bytes.len() as u64,
    })
}

/// Take a lock without `unwrap`. A poisoned lock means an earlier call panicked
/// while holding it, so the guarded state is of unknown validity and the object
/// is refused rather than reused.
pub(crate) fn lock<T>(mutex: &std::sync::Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| OspreyError::SessionState {
        detail: "internal lock was poisoned by an earlier failure".to_string(),
    })
}
