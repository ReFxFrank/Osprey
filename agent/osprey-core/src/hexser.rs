//! Hex serde adapters for fixed-size key material.
//!
//! Keys are serialised as hex rather than serde's default byte-array-of-numbers
//! because these values end up in a QR code, an audit line, and a support email
//! — all places where a human has to compare two of them by eye.

macro_rules! hex_array_module {
    ($name:ident, $len:expr) => {
        pub mod $name {
            use serde::de::{Error as _, Unexpected};
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                value: &[u8; $len],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&hex::encode(value))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<[u8; $len], D::Error> {
                let text = String::deserialize(deserializer)?;
                let bytes = hex::decode(&text)
                    .map_err(|_| D::Error::invalid_value(Unexpected::Str(&text), &"hex string"))?;
                <[u8; $len]>::try_from(bytes.as_slice()).map_err(|_| {
                    D::Error::invalid_length(bytes.len(), &concat!(stringify!($len), " bytes"))
                })
            }
        }
    };
}

hex_array_module!(hex32, 32);

/// Hex adapter for key material whose length depends on the algorithm — an
/// Ed25519 identity key is 32 bytes, a P-256 one is 65, and an ECDSA signature
/// is variable-length DER. Length is checked by the verifier that knows the
/// algorithm, never here.
pub mod hexbytes {
    use serde::de::{Error as _, Unexpected};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .map_err(|_| D::Error::invalid_value(Unexpected::Str(&text), &"hex string"))
    }
}
