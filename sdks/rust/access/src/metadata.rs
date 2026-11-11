//! Domain Metadata verified against the domain root (CR-58, §9.10 step 1, OP-157 m.3 (s)): the
//! first-contact check a Decision PEP or an Offline Verifier makes before it trusts any key the
//! metadata declares. The signature must verify under one of the root's binding keys, which the
//! caller pinned from the domain's Genesis, and the metadata must name the domain the caller
//! asked for. A later refresh is verified against the metadata held, as `resource::keys` does.

use alloc::collections::BTreeSet;

use access_kernel::digest::Digest;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey};
use access_kernel::verify::key_scope::{
    DomainMetadata, KeyScopeError, thumbprint, verify_metadata,
};

/// Largest Domain Metadata document read (§14.6).
pub const MAX_METADATA: usize = 64 * 1024;

/// Why Domain Metadata is not trusted. Each one is a local DENY of whatever relies on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// Larger than [`MAX_METADATA`].
    #[error("metadata too large")]
    TooLarge,
    /// No root binding key or no allowed algorithm was given.
    #[error("no domain root")]
    NoRoot,
    /// The signature, the signer or the payload does not verify under the root keys.
    #[error("signature: {0}")]
    Signature(KeyScopeError),
    /// The metadata names another domain.
    #[error("other domain")]
    OtherDomain,
    /// A binding key the metadata declares is not named by its own thumbprint.
    #[error("binding key id is not its thumbprint")]
    Thumbprint,
}

/// The key set of the domain root's binding `keys`, each named by its RFC 7638 thumbprint, for
/// the algorithms the caller allows.
#[must_use]
pub fn root(keys: &[PublicKey], allowed: &BTreeSet<Algorithm>) -> KeySet {
    let mut set = KeySet::default();
    set.keys
        .extend(keys.iter().map(|k| (thumbprint(k), k.clone())));
    set.allowed.extend(allowed.iter().copied());
    set
}

/// Verifies binding-signed Domain Metadata `signed` for `domain` against the domain root's
/// binding keys `root` (CR-58, OP-157 m.3 (s)).
///
/// # Errors
/// [`MetadataError`]; nothing the metadata declares may then be used.
pub fn verify(
    signed: &[u8],
    domain: &Digest,
    root: &KeySet,
) -> Result<DomainMetadata, MetadataError> {
    if signed.len() > MAX_METADATA {
        return Err(MetadataError::TooLarge);
    }
    if root.keys.is_empty() || root.allowed.is_empty() {
        return Err(MetadataError::NoRoot);
    }
    let metadata = verify_metadata(&PureBackend, signed, root).map_err(MetadataError::Signature)?;
    if metadata.domain != *domain {
        return Err(MetadataError::OtherDomain);
    }
    if metadata
        .binding
        .iter()
        .any(|(kid, b)| *kid != b.kid || thumbprint(&b.key) != b.kid)
    {
        return Err(MetadataError::Thumbprint);
    }
    Ok(metadata)
}
