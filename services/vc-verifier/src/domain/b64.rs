//! Bytes in stored and served JSON as base64url text.

use access_kernel::json::{b64url_decode, b64url_encode};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

/// A list of byte strings.
pub mod list {
    use super::{Deserialize, Deserializer, Error, Serializer, b64url_decode, b64url_encode};

    /// Serializes.
    ///
    /// # Errors
    /// The serializer's.
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|b| b64url_encode(b)))
    }

    /// Deserializes.
    ///
    /// # Errors
    /// An element that is not base64url.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|t| b64url_decode(t).map_err(|_| D::Error::custom("base64url")))
            .collect()
    }
}
