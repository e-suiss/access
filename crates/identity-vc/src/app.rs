//! The issuer's use case (OID4VCI 1.0 §8; E55, Ek B 4196): a credential request under a
//! redeemed pre-authorized grant for one type and one subject. The type must be the granted
//! one and in the closed set, the key proof must carry this `c_nonce`, the fact must be verified
//! for the subject now, and the credential gets a fresh status list entry. Anything missing
//! refuses the request; nothing is issued on a guess.

use access_kernel::json::Json;
use access_kernel::verify::PureBackend;
use suiss_crypto::signer::Signer;

use crate::domain::issue::{Credential, IssueError, issue, requested};
use crate::domain::proof::{self, Expect, Holder, ProofError};
use crate::domain::types::{PersonAttribute, TypeRefused};
use crate::ports::{Clock, Facts, Random, StatusList};

/// What the redeemed pre-authorized code allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The subject the offer was made for.
    pub subject: [u8; 16],
    /// The one type it offered.
    pub attribute: PersonAttribute,
    /// The key the credential binds to.
    pub holder: Holder,
}

/// Why a credential request is refused (OID4VCI 1.0 §8.3.1.2 error codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The type is not a person attribute, or not the one granted (`unsupported_credential_type`).
    #[error("unsupported_credential_type")]
    Type,
    /// The request is not in the profile (`invalid_credential_request`).
    #[error("invalid_credential_request")]
    Malformed,
    /// The key proof is refused (`invalid_proof`, `invalid_nonce`).
    #[error("{0}")]
    Proof(ProofError),
    /// The fact is not verified for the subject (`credential_request_denied`).
    #[error("credential_request_denied")]
    NotVerified,
    /// Time, randomness, the status list or the key is not available.
    #[error("issuer-unavailable")]
    Unavailable,
}

impl From<TypeRefused> for RequestError {
    fn from(_: TypeRefused) -> Self {
        Self::Type
    }
}

impl From<IssueError> for RequestError {
    fn from(e: IssueError) -> Self {
        match e {
            IssueError::Value => Self::NotVerified,
            IssueError::Sign => Self::Unavailable,
        }
    }
}

/// The realm issuer.
pub struct Issuer<'a, F, S, C, R> {
    /// The realm issuer identifier.
    pub issuer: &'a str,
    /// The person's verified facts.
    pub facts: F,
    /// The status list.
    pub status: S,
    /// Time.
    pub clock: C,
    /// Randomness.
    pub random: R,
    /// The realm issuer's signing key.
    pub signer: &'a dyn Signer,
}

impl<F: Facts, S: StatusList, C: Clock, R: Random> Issuer<'_, F, S, C, R> {
    /// Answers one credential request: `body` the request JSON, `nonce` the `c_nonce` the issuer
    /// gave this holder.
    ///
    /// # Errors
    /// [`RequestError`].
    pub fn credential(
        &self,
        grant: &Grant,
        body: &Json,
        nonce: &str,
    ) -> Result<String, RequestError> {
        let name = requested(body).ok_or(RequestError::Malformed)?;
        let attribute = PersonAttribute::parse(name)?;
        if attribute != grant.attribute {
            return Err(RequestError::Type);
        }
        let jwt = body
            .get("proofs")
            .and_then(|p| p.get("jwt"))
            .and_then(|j| match j {
                Json::Array(items) => match items.as_slice() {
                    [Json::Str(one)] => Some(one.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .ok_or(RequestError::Malformed)?;
        let now = self.clock.now().ok_or(RequestError::Unavailable)?;
        let holder = proof::verify(
            &PureBackend,
            jwt,
            &grant.holder,
            &Expect {
                issuer: self.issuer,
                nonce,
                now,
            },
        )
        .map_err(RequestError::Proof)?;
        let value = self
            .facts
            .value(&grant.subject, attribute)
            .ok_or(RequestError::NotVerified)?;
        let salt = self.random.bytes().ok_or(RequestError::Unavailable)?;
        let (idx, uri) = self.status.allocate().ok_or(RequestError::Unavailable)?;
        Ok(issue(
            self.signer,
            &Credential {
                issuer: self.issuer,
                attribute,
                value,
                holder,
                status: (idx, &uri),
                now_ms: now,
                salt,
            },
        )?)
    }
}
