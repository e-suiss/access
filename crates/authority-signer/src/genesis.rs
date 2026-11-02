//! The Genesis statement: the domain's binding key signs the `DomainID` and the Genesis record
//! digest it was opened with, so a verifier holding the binding key learns which log the key
//! speaks for (T20, CR-58, OP-143 m.1 E4).

use access_kernel::digest::Digest;
use suiss_crypto::cose::{CoseError, KeySet, verify_sign1};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::sig::Backend;

/// `COSE_Sign1` content type of a Genesis statement.
pub const CONTENT_TYPE: &str = "application/access-genesis+cbor";

/// What the binding key states about its domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Domain.
    pub domain: Digest,
    /// Digest of the Genesis record (L0-ENC-25).
    pub genesis: Digest,
    /// Signing time.
    pub issued_at: u64,
}

/// Why a Genesis statement is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GenesisError {
    /// The signature does not verify under a trusted binding key.
    #[error("signature: {0}")]
    Signature(#[from] CoseError),
    /// The payload is not a Genesis statement.
    #[error("malformed")]
    Malformed,
    /// The statement is about another domain.
    #[error("domain mismatch")]
    Domain,
}

impl GenesisError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Signature(_) => "genesis-signature",
            Self::Malformed => "genesis-malformed",
            Self::Domain => "genesis-domain",
        }
    }
}

impl Statement {
    /// The deterministic CBOR payload.
    ///
    /// # Errors
    /// [`GenesisError::Malformed`] when it cannot be encoded.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GenesisError> {
        let v = Value::Map(vec![
            (Value::text("domain"), self.domain.to_value()),
            (Value::text("genesis"), self.genesis.to_value()),
            (Value::text("issued_at"), Value::Unsigned(self.issued_at)),
        ]);
        dcbor::encode(&v, Limits::CEILING).map_err(|_| GenesisError::Malformed)
    }

    /// A statement from its payload; any other field is rejected.
    ///
    /// # Errors
    /// [`GenesisError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| GenesisError::Malformed)?;
        let Value::Map(entries) = &v else {
            return Err(GenesisError::Malformed);
        };
        if entries.len() != 3 {
            return Err(GenesisError::Malformed);
        }
        let digest = |k: &str| {
            v.get(k)
                .and_then(Digest::from_value)
                .ok_or(GenesisError::Malformed)
        };
        Ok(Self {
            domain: digest("domain")?,
            genesis: digest("genesis")?,
            issued_at: match v.get("issued_at") {
                Some(Value::Unsigned(n)) => *n,
                _ => return Err(GenesisError::Malformed),
            },
        })
    }
}

/// Verifies a Genesis statement under the binding keys a verifier trusts and checks that it
/// names `domain`.
///
/// # Errors
/// [`GenesisError`].
pub fn verify(
    backend: &impl Backend,
    bytes: &[u8],
    trusted: &KeySet,
    domain: &Digest,
) -> Result<Statement, GenesisError> {
    let verified = verify_sign1(backend, bytes, trusted, CONTENT_TYPE)?;
    let s = Statement::from_bytes(&verified.payload)?;
    if s.domain != *domain {
        return Err(GenesisError::Domain);
    }
    Ok(s)
}

#[cfg(test)]
mod tests;
