//! Base64 codec for `bytes` fields.
//!
//! RFC 4648 standard alphabet with padding, because that is what Foundation's
//! `JSONEncoder.DataEncodingStrategy.base64` produces on the iOS side. Any
//! other choice would make the two peers disagree about key material.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    STANDARD
        .decode(encoded.as_bytes())
        .map_err(serde::de::Error::custom)
}
