//! Typed errors for the trust spine.
//!
//! Every variant here is reachable from remote input, so the whole crate is
//! written to return one of these rather than panic. CLAUDE.md rule 2 makes a
//! panic on a malformed network message an outright defect, and `snow` signals
//! both "you built the handshake wrong" and "this ciphertext is forged" through
//! the same `snow::Error` type — so the distinction is carried in *our* variant,
//! not in the source error.

use std::fmt;

/// Which side of the Noise handshake produced an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    /// Constructing the `snow` state machine (bad parameters, bad key length).
    Build,
    /// Producing an outbound handshake message.
    Write,
    /// Consuming an inbound handshake message. A tampered byte lands here.
    Read,
    /// Promoting a completed handshake into transport mode.
    Transport,
}

impl fmt::Display for HandshakeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Build => "build",
            Self::Write => "write",
            Self::Read => "read",
            Self::Transport => "transport",
        };
        f.write_str(s)
    }
}

/// Why a peer's cross-signed Noise static was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossSignatureFailure {
    /// The 64 signature bytes are not a well-formed Ed25519 signature.
    Malformed,
    /// Well-formed, but does not verify under the pinned identity key.
    NotSignedByIdentity,
    /// The pinned identity key bytes are not a valid Ed25519 public key.
    BadIdentityKey,
}

impl fmt::Display for CrossSignatureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Malformed => "malformed signature encoding",
            Self::NotSignedByIdentity => "signature does not verify under the pinned identity key",
            Self::BadIdentityKey => "pinned identity key is not a valid Ed25519 public key",
        };
        f.write_str(s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A handshake step failed. On [`HandshakeStage::Read`] this is the
    /// tampered/forged-message case and must be audited by the caller.
    #[error("noise handshake failed at {stage} stage")]
    Handshake {
        stage: HandshakeStage,
        #[source]
        source: snow::Error,
    },

    /// AEAD authentication failed on an established session. Always tampering,
    /// truncation, or replay — never a benign condition.
    #[error("transport message failed authentication")]
    TransportAuth(#[source] snow::Error),

    /// The caller assembled an impossible handshake (pairing without a PSK, an
    /// initiator without the peer's static). A local programming error, but
    /// returned rather than asserted because getting it wrong would silently
    /// weaken authentication.
    #[error("handshake configuration is invalid: {0}")]
    HandshakeConfig(&'static str),

    #[error("frame is {len} bytes, exceeds the {max}-byte Noise message limit")]
    FrameTooLarge { len: usize, max: usize },

    #[error("reassembled message would exceed the {max}-byte limit")]
    MessageTooLarge { max: usize },

    #[error("peer sent a chunk with an unknown continuation flag {flag:#04x}")]
    BadContinuationFlag { flag: u8 },

    #[error("peer sent an empty chunk, which carries no continuation flag")]
    EmptyChunk,

    #[error("connection closed mid-frame after {got} of {want} bytes")]
    TruncatedFrame { got: usize, want: usize },

    #[error("peer's noise static key was rejected: {0}")]
    CrossSignature(CrossSignatureFailure),

    /// The peer completed the handshake with a static key that is not the one
    /// pinned at pairing. Distinct from a signature failure: the key is
    /// internally consistent, it is just the wrong device.
    #[error("peer presented an unpinned noise static key")]
    UnpinnedPeer,

    /// A handshake finished without the remote static Noise requires. Never
    /// expected from IK/IKpsk2, but treated as a failure rather than assumed.
    #[error("handshake completed without a remote static key")]
    MissingRemoteStatic,

    #[error("key material for {label:?} has the wrong length: {len} bytes")]
    BadKeyLength { label: &'static str, len: usize },

    #[error("keystore operation failed for entry {label:?}")]
    Keystore {
        label: String,
        #[source]
        source: KeystoreError,
    },

    #[error("could not encode pairing payload")]
    PairingEncode(#[source] serde_json::Error),

    #[error("could not decode pairing payload")]
    PairingDecode(#[source] serde_json::Error),

    #[error("QR payload is version {found}, this build speaks version {expected}")]
    UnsupportedPayloadVersion { found: u32, expected: u32 },

    #[error("audit log write failed")]
    Audit(#[source] std::io::Error),

    #[error("i/o error on the noise transport")]
    Io(#[source] std::io::Error),
}

/// Failures specific to sealed key storage, kept separate so the backends can
/// report platform detail without every caller matching on OS-specific cases.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("filesystem error")]
    Io(#[from] std::io::Error),

    #[error("sealed blob is corrupt or was sealed on a different machine")]
    Unseal,

    #[error("stored key material is not valid JSON")]
    Decode(#[source] serde_json::Error),

    #[error("key material could not be serialised for storage")]
    Encode(#[source] serde_json::Error),

    #[error("stored key material has an unsupported schema version {found}, expected {expected}")]
    SchemaVersion { found: u32, expected: u32 },

    #[error("entry label {0:?} is not a safe filename")]
    UnsafeLabel(String),

    #[error("platform key protection call failed: {0}")]
    Platform(String),
}

pub type Result<T> = std::result::Result<T, Error>;
