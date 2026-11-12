//! The Kernel's thin ML-DSA layer (CR-41 m.4, CR-42, OP-159 m.3 (c), (h)): the parameter sets,
//! `AKP` keys (RFC 9964) and the post-quantum anchors a verifier pins. The primitive sits behind
//! the [`super::Backend`] port; until it answers, every ML-DSA artefact is refused.

use alloc::vec::Vec;

use suiss_crypto::dcbor::Value;

use super::cose::{Algorithm, PublicKey};
use super::key_scope::{Witness, set_of_vec, thumbprint, witness, witness_value};
use crate::codec::{Canonical, Fields, ModelError, map, set_value, uint};
use crate::digest::Digest;
use crate::model::TrustedTime;

/// The ML-DSA parameter sets (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PqAlgorithm {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl PqAlgorithm {
    /// Every parameter set.
    pub const ALL: [Self; 3] = [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87];

    /// The COSE algorithm.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::MlDsa44 => Algorithm::MlDsa44,
            Self::MlDsa65 => Algorithm::MlDsa65,
            Self::MlDsa87 => Algorithm::MlDsa87,
        }
    }

    /// The JOSE `alg` name.
    #[must_use]
    pub const fn jose(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// The exact public key length in bytes.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// The exact signature length in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// The parameter set of a COSE algorithm, if it is one.
    #[must_use]
    pub const fn of(alg: Algorithm) -> Option<Self> {
        match alg {
            Algorithm::MlDsa44 => Some(Self::MlDsa44),
            Algorithm::MlDsa65 => Some(Self::MlDsa65),
            Algorithm::MlDsa87 => Some(Self::MlDsa87),
            _ => None,
        }
    }
}

/// An `AKP` public key (RFC 9964): its parameter set, which `alg` must name, and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AkpKey {
    /// The parameter set.
    pub alg: PqAlgorithm,
    /// The public key.
    pub public: Vec<u8>,
}

impl AkpKey {
    /// The key `public` of `alg`.
    #[must_use]
    pub const fn new(alg: PqAlgorithm, public: Vec<u8>) -> Self {
        Self { alg, public }
    }
}

/// A post-quantum anchor a verifier pins before the classical algorithm is retired
/// (`pq-anchor.cddl`, CR-45 RA-7, OP-159 m.3 (h)): the key that signs the domain's post-quantum
/// re-anchor checkpoints and the witnesses whose post-quantum cosigns count.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PqAnchor {
    /// The domain.
    pub domain: Digest,
    /// RFC 7638 thumbprint of `key`.
    pub kid: [u8; 32],
    /// The ML-DSA key that signs the post-quantum checkpoints.
    pub key: PublicKey,
    /// The witnesses and their post-quantum cosign keys.
    pub witnesses: Vec<Witness>,
    /// When the anchor was published.
    pub issued_at: TrustedTime,
}

impl PqAnchor {
    /// The anchor of `domain` with checkpoint key `key` (thumbprint `kid`) and `witnesses`.
    #[must_use]
    pub const fn new(
        domain: Digest,
        kid: [u8; 32],
        key: PublicKey,
        witnesses: Vec<Witness>,
        issued_at: TrustedTime,
    ) -> Self {
        Self {
            domain,
            kid,
            key,
            witnesses,
            issued_at,
        }
    }
}

impl Canonical for PqAnchor {
    fn to_value(&self) -> Value {
        map([
            ("domain", Some(self.domain.to_value())),
            ("kid", Some(Value::Bytes(self.kid.to_vec()))),
            ("key", Some(self.key.to_value())),
            (
                "witnesses",
                Some(set_value(self.witnesses.iter().map(witness_value))),
            ),
            ("issued_at", Some(Value::Unsigned(self.issued_at))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let kid = match f.req("kid")? {
            Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ModelError::Range)?,
            _ => return Err(ModelError::Shape),
        };
        let out = Self {
            domain: Digest::from_value(f.req("domain")?).ok_or(ModelError::Shape)?,
            kid,
            key: PublicKey::from_value(f.req("key")?)?,
            witnesses: set_of_vec(f.req("witnesses")?, true, witness)?,
            issued_at: uint(f.req("issued_at")?)?,
        };
        f.done()?;
        if out.kid != thumbprint(&out.key) {
            return Err(ModelError::Range);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
