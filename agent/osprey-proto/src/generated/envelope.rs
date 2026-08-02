// DO NOT EDIT — generated from proto/messages.toml by proto/generate.ts.
// Run `pnpm generate` in proto/ after changing the registry.

//! The wire envelope and the decoded body union.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::bodies::{ByeBody, ErrorBody, HelloBody, HelloOkBody, PairConfirmBody, PairRequestBody, PairRevokeBody, PingBody, PongBody};
use super::registry::MessageType;
use crate::error::ProtoError;

/// Highest envelope version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// Lowest envelope version this build accepts from a peer.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// Wire envelope common to every Osprey message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope version. Peers reject a version outside [min_protocol_version, protocol_version].
    pub v: u32,
    /// Correlation id. A response carries the id of the request it answers.
    pub id: uuid::Uuid,
    /// Message type; selects the body schema.
    pub t: MessageType,
    /// Sender clock, milliseconds since the Unix epoch. Advisory only — never used for authentication or expiry.
    pub ts: i64,
    /// Type-specific payload. Decoded in a second step so an unparseable body reports which type it belonged to.
    pub body: serde_json::Value,
}

/// A decoded envelope body, one variant per fully defined message type.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Body {
    /// `error`
    Error(ErrorBody),
    /// `hello`
    Hello(HelloBody),
    /// `hello.ok`
    HelloOk(HelloOkBody),
    /// `ping`
    Ping(PingBody),
    /// `pong`
    Pong(PongBody),
    /// `bye`
    Bye(ByeBody),
    /// `pair.request`
    PairRequest(PairRequestBody),
    /// `pair.confirm`
    PairConfirm(PairConfirmBody),
    /// `pair.revoke`
    PairRevoke(PairRevokeBody),
}

impl Body {
    /// The registry type this body belongs to.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Error(_) => MessageType::Error,
            Self::Hello(_) => MessageType::Hello,
            Self::HelloOk(_) => MessageType::HelloOk,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::Bye(_) => MessageType::Bye,
            Self::PairRequest(_) => MessageType::PairRequest,
            Self::PairConfirm(_) => MessageType::PairConfirm,
            Self::PairRevoke(_) => MessageType::PairRevoke,
        }
    }
}

impl Envelope {
    /// Wraps a decoded body in an envelope at the current protocol version.
    pub fn new(id: Uuid, ts: i64, body: &Body) -> Result<Self, ProtoError> {
        let t = body.message_type();
        let value = serde_json::to_value(body).map_err(|source| ProtoError::Encode { t, source })?;
        Ok(Self { v: PROTOCOL_VERSION, id, t, ts, body: value })
    }

    /// Rejects an envelope this build cannot interpret.
    pub fn check_version(&self) -> Result<(), ProtoError> {
        if self.v < MIN_PROTOCOL_VERSION || self.v > PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion {
                found: self.v,
                min: MIN_PROTOCOL_VERSION,
                max: PROTOCOL_VERSION,
            });
        }
        Ok(())
    }

    /// Decodes `body` against the schema selected by `t`.
    ///
    /// Separate from envelope parsing so a body that fails validation reports
    /// which message type it claimed to be.
    pub fn decode_body(&self) -> Result<Body, ProtoError> {
        match self.t {
            MessageType::Error => decode(self.t, &self.body).map(Body::Error),
            MessageType::Hello => decode(self.t, &self.body).map(Body::Hello),
            MessageType::HelloOk => decode(self.t, &self.body).map(Body::HelloOk),
            MessageType::Ping => decode(self.t, &self.body).map(Body::Ping),
            MessageType::Pong => decode(self.t, &self.body).map(Body::Pong),
            MessageType::Bye => decode(self.t, &self.body).map(Body::Bye),
            MessageType::PairRequest => decode(self.t, &self.body).map(Body::PairRequest),
            MessageType::PairConfirm => decode(self.t, &self.body).map(Body::PairConfirm),
            MessageType::PairRevoke => decode(self.t, &self.body).map(Body::PairRevoke),
            other => Err(ProtoError::BodyDeferred(other)),
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    t: MessageType,
    body: &serde_json::Value,
) -> Result<T, ProtoError> {
    T::deserialize(body).map_err(|source| ProtoError::MalformedBody { t, source })
}
