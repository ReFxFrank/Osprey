//! Protocol-layer error types.

use crate::generated::registry::MessageType;

/// Everything that can go wrong turning bytes into a typed message.
///
/// Every variant is recoverable by the caller: the correct response to any of
/// them is an `error` message or a dropped connection, never a panic.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Peer offered an envelope version outside the range this build supports.
    #[error("envelope version {found} is outside the supported range {min}..={max}")]
    UnsupportedVersion { found: u32, min: u32, max: u32 },

    /// The type is reserved in the registry but its body schema is not yet
    /// defined, so there is nothing to decode into.
    #[error("no body schema is defined for message type `{0}`")]
    BodyDeferred(MessageType),

    /// The body did not match the schema selected by the envelope's `t`.
    #[error("malformed `{t}` body")]
    MalformedBody {
        t: MessageType,
        #[source]
        source: serde_json::Error,
    },

    /// A body could not be serialised. Reachable only through a body type
    /// whose `Serialize` fails, which the generated types never do; kept so the
    /// encode path has no reason to panic.
    #[error("could not encode `{t}` body")]
    Encode {
        t: MessageType,
        #[source]
        source: serde_json::Error,
    },
}

/// A `t` string that is not in the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown message type `{0}`")]
pub struct UnknownMessageType(pub String);
