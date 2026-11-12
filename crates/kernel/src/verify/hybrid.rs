//! Hybrid signatures (CR-42, L0-SIG-18, L0-SIG-75a, SAI-44, OP-159 m.3 (e)): two separate
//! `COSE_Sign1` over the same payload, one classical and one ML-DSA, each with its own key
//! excerpt. The Domain Metadata `hybrid` field decides which are required; the artefact never
//! does. There is no composite signature and a component is never accepted on its own where
//! the policy asks for both.

use super::Backend;
use super::cose::{CoseError, Verified, verify_sign1};
use super::key_scope::{DomainMetadata, Hybrid, KeyScopeError, KeyUsage, resolve};
use super::ml_dsa::is_ml_dsa;
use crate::digest::Digest;
use crate::model::TrustedTime;

/// One signed component of an artefact: its `COSE_Sign1` and its key excerpt.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Component<'a> {
    /// The tagged `COSE_Sign1`.
    pub sign1: &'a [u8],
    /// The binding-signed key excerpt of its operational key.
    pub excerpt: &'a [u8],
}

impl<'a> Component<'a> {
    /// The component signed by `sign1` under the key `excerpt` declares.
    #[must_use]
    pub const fn new(sign1: &'a [u8], excerpt: &'a [u8]) -> Self {
        Self { sign1, excerpt }
    }
}

/// Why a hybrid artefact is refused. Each is a local DENY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HybridError {
    /// A component the policy requires is absent.
    #[error("required signature missing")]
    Missing,
    /// A component's key does not resolve.
    #[error("key: {0}")]
    Key(#[from] KeyScopeError),
    /// A component's signature does not verify.
    #[error("signature: {0}")]
    Signature(#[from] CoseError),
    /// The two components sign different payloads.
    #[error("components sign different payloads")]
    Payload,
}

impl HybridError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "hybrid-missing",
            Self::Key(_) => "hybrid-key",
            Self::Signature(_) => "hybrid-signature",
            Self::Payload => "hybrid-payload",
        }
    }
}

/// What the verifier knows about the artefact: its domain, the key usage and the `iat` it
/// claims.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Expected<'a> {
    /// The artefact's domain.
    pub domain: &'a Digest,
    /// What the keys must be allowed to sign.
    pub usage: KeyUsage,
    /// The signing time the payload claims.
    pub iat: TrustedTime,
    /// The artefact's content type.
    pub content_type: &'a str,
}

impl<'a> Expected<'a> {
    /// An artefact of `domain` signed for `usage` at `iat` with `content_type`.
    #[must_use]
    pub const fn new(
        domain: &'a Digest,
        usage: KeyUsage,
        iat: TrustedTime,
        content_type: &'a str,
    ) -> Self {
        Self {
            domain,
            usage,
            iat,
            content_type,
        }
    }
}

fn component(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    c: Component<'_>,
    expected: &Expected<'_>,
    pq: bool,
) -> Result<Verified, HybridError> {
    let key = resolve(
        backend,
        metadata,
        (expected.domain, c.excerpt, expected.usage, expected.iat),
        None,
        |alg| is_ml_dsa(alg) == pq,
    )?;
    Ok(verify_sign1(
        backend,
        c.sign1,
        &key.key_set(),
        expected.content_type,
    )?)
}

/// Verifies the components the metadata's hybrid policy requires (L0-SIG-75a): `classic` (or
/// no field) the classical one, `pq` the ML-DSA one, `both` the two, valid and over the same
/// payload. A component the policy does not require is ignored. Returns the classical
/// component's verification, or the ML-DSA one under `pq`.
///
/// # Errors
/// [`HybridError`], the first failure.
pub fn verify(
    backend: &impl Backend,
    metadata: &DomainMetadata,
    classic: Option<Component<'_>>,
    pq: Option<Component<'_>>,
    expected: &Expected<'_>,
) -> Result<Verified, HybridError> {
    match metadata.hybrid.unwrap_or(Hybrid::Classic) {
        Hybrid::Classic => component(
            backend,
            metadata,
            classic.ok_or(HybridError::Missing)?,
            expected,
            false,
        ),
        Hybrid::Pq => component(
            backend,
            metadata,
            pq.ok_or(HybridError::Missing)?,
            expected,
            true,
        ),
        Hybrid::Both => {
            let (Some(c), Some(p)) = (classic, pq) else {
                return Err(HybridError::Missing);
            };
            let classical = component(backend, metadata, c, expected, false)?;
            let post_quantum = component(backend, metadata, p, expected, true)?;
            if classical.payload != post_quantum.payload {
                return Err(HybridError::Payload);
            }
            Ok(classical)
        }
    }
}
