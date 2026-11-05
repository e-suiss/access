//! Token Status Lists at the verifier (L2-STL-1 to L2-STL-3, §9.12.4, PI-9): a list token
//! verified under the domain's `status-list` key, its ZLIB `lst` inflated within a size
//! limit, and the projection's bit read. A list is an information channel: without a fresh list
//! the contract's horizon and Δ decide, fail-closed.

use alloc::vec::Vec;

use access_kernel::model::TrustedTime;
use access_kernel::status::{self, CWT_CONTENT_TYPE, ListToken, StatusError, StatusRef};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{CoseError, parse_sign1, verify_sign1};
use access_kernel::verify::key_scope::{DomainMetadata, KeyScopeError, KeyUsage, operational_key};

/// Largest inflated list, in bytes: 2^25 one-bit entries.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// Why a list token is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ListError {
    /// The payload is not a list token (L2-STL-2).
    #[error("status-malformed")]
    Malformed,
    /// The key is not the domain's `status-list` key at `iat`.
    #[error("status-key: {0}")]
    Key(KeyScopeError),
    /// The signature does not verify.
    #[error("status-signature")]
    Signature(CoseError),
    /// `lst` is not ZLIB data within [`MAX_LIST_BYTES`].
    #[error("status-compression")]
    Compression,
}

impl ListError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "status-malformed",
            Self::Key(_) => "status-key",
            Self::Signature(_) => "status-signature",
            Self::Compression => "status-compression",
        }
    }
}

/// Inflates a list's ZLIB `lst` (RFC 1950) within [`MAX_LIST_BYTES`] (OP-150 m.6 (d)).
///
/// # Errors
/// [`ListError::Compression`].
pub fn inflate(lst: &[u8]) -> Result<Vec<u8>, ListError> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(lst, MAX_LIST_BYTES)
        .map_err(|_| ListError::Compression)
}

/// A verified list with its bits inflated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusList {
    token: ListToken,
    bits: Vec<u8>,
}

impl StatusList {
    /// Verifies a list token (`COSE_Sign1`, `application/statuslist+cwt`) of the metadata's
    /// domain with its key excerpt, and inflates it (L2-STL-2).
    ///
    /// # Errors
    /// [`ListError`].
    pub fn verify(
        metadata: &DomainMetadata,
        sign1: &[u8],
        excerpt: &[u8],
    ) -> Result<Self, ListError> {
        let unverified = parse_sign1(sign1)
            .ok()
            .and_then(|s| s.payload)
            .ok_or(ListError::Malformed)?;
        let claimed = ListToken::from_bytes(&unverified).map_err(|_| ListError::Malformed)?;
        let iat = claimed.iat.checked_mul(1_000).ok_or(ListError::Malformed)?;
        let key = operational_key(
            &PureBackend,
            metadata,
            &metadata.domain,
            excerpt,
            KeyUsage::StatusList,
            iat,
        )
        .map_err(ListError::Key)?;
        let verified = verify_sign1(&PureBackend, sign1, &key.key_set(), CWT_CONTENT_TYPE)
            .map_err(ListError::Signature)?;
        let token = ListToken::from_bytes(&verified.payload).map_err(|_| ListError::Malformed)?;
        let bits = inflate(&token.lst)?;
        Ok(Self { token, bits })
    }

    /// The list token.
    #[must_use]
    pub const fn token(&self) -> &ListToken {
        &self.token
    }

    /// The `recorded_at` of the canonical position the list reflects, Unix milliseconds: the
    /// time a contract's Δ is measured from (T24).
    #[must_use]
    pub fn recorded_at(&self) -> Option<TrustedTime> {
        self.token.iat.checked_mul(1_000)
    }

    /// Whether the referenced entry is invalid (L2-STL-3).
    ///
    /// # Errors
    /// [`StatusError`].
    pub fn is_invalid(&self, reference: &StatusRef) -> Result<bool, StatusError> {
        status::lookup(&self.token, &self.bits, reference)
    }
}
