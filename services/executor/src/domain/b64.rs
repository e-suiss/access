//! Bytes in the history as base64url text.

use access_kernel::json::{b64url_decode, b64url_encode};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

/// Any bytes.
pub mod bytes {
    use super::{Deserialize, Deserializer, Error, Serializer, b64url_decode, b64url_encode};

    /// Serializes.
    ///
    /// # Errors
    /// The serializer's.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64url_encode(v))
    }

    /// Deserializes.
    ///
    /// # Errors
    /// Text that is not base64url.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = String::deserialize(d)?;
        b64url_decode(&t).map_err(|_| D::Error::custom("base64url"))
    }
}

/// Exactly `N` bytes.
pub mod fixed {
    use super::{Deserialize, Deserializer, Error, Serializer, b64url_decode, b64url_encode};

    /// Serializes.
    ///
    /// # Errors
    /// The serializer's.
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64url_encode(v))
    }

    /// Deserializes.
    ///
    /// # Errors
    /// Text that is not base64url of `N` bytes.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let t = String::deserialize(d)?;
        let b = b64url_decode(&t).map_err(|_| D::Error::custom("base64url"))?;
        <[u8; N]>::try_from(b).map_err(|_| D::Error::custom("length"))
    }
}

/// A list of byte strings.
pub mod list {
    use super::{Deserialize, Deserializer, Error, Serializer, b64url_decode, b64url_encode};
    use serde::ser::SerializeSeq as _;

    /// Serializes.
    ///
    /// # Errors
    /// The serializer's.
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&b64url_encode(b))?;
        }
        seq.end()
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
