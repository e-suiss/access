//! The DPoP check of a request at the authorization server or a resource server of the realm
//! (§10.4.3, IDP-11): the Kernel's stateless steps, then the server nonce (TN-29), then the
//! replay cache (TN-30). A proof that fails is never recorded.

use access_crypto::AwsLcBackend;
use access_crypto::dpop::{NonceError, NonceRing, replay_key};
use access_kernel::verify::dpop::{ProofRules, Step, verify_proof};

use crate::domain::dpop::{DpopProfile, Failure, Jkt};
use crate::ports::dpop::{Clock, ReplayCache};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// What the request presents. `Debug` shows neither the proofs nor the access token.
#[derive(Clone, Copy)]
pub struct DpopRequest<'a> {
    /// Every `DPoP` header value of the request.
    pub proofs: &'a [&'a str],
    /// The request method.
    pub method: &'a str,
    /// The request's target URI as the server sees it.
    pub uri: &'a str,
    /// The access token sent with the proof, at a resource server.
    pub access_token: Option<&'a str>,
    /// The key the token, code or refresh token is bound to.
    pub bound: Option<Jkt>,
}

impl core::fmt::Debug for DpopRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DpopRequest")
            .field("proofs", &self.proofs.len())
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("access_token", &self.access_token.map(|_| "[redacted]"))
            .field("bound", &self.bound)
            .finish()
    }
}

/// An accepted proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The proof key's thumbprint, for `cnf.jkt` and refresh binding.
    pub jkt: Jkt,
    /// The `DPoP-Nonce` to send with the response (TN-29).
    pub nonce: String,
}

/// Checks DPoP proofs for one role of one realm.
pub struct DpopChecker<'a, R, C> {
    profile: &'a DpopProfile,
    nonces: &'a NonceRing,
    replay: &'a R,
    clock: &'a C,
}

fn invalid(step: Step, code: &'static str) -> Failure {
    Failure::InvalidProof { step, code }
}

impl<'a, R: ReplayCache, C: Clock> DpopChecker<'a, R, C> {
    /// A checker over the realm's profile, its nonce keys for this role and its replay cache.
    #[must_use]
    pub const fn new(
        profile: &'a DpopProfile,
        nonces: &'a NonceRing,
        replay: &'a R,
        clock: &'a C,
    ) -> Self {
        Self {
            profile,
            nonces,
            replay,
            clock,
        }
    }

    fn now(&self) -> Result<u64, Failure> {
        self.clock.now().map_err(|_| Failure::Unavailable)
    }

    fn issue(&self, now: u64) -> Result<String, Failure> {
        self.nonces.issue(now).map_err(|_| Failure::Unavailable)
    }

    /// The nonce for a response that carried no proof check (TN-29: on every 200).
    ///
    /// # Errors
    /// [`Failure::Unavailable`].
    pub fn nonce(&self) -> Result<String, Failure> {
        let now = self.now()?;
        self.issue(now)
    }

    /// Runs the 12 steps (IDP-11) over the request's proof.
    ///
    /// # Errors
    /// [`Failure`].
    pub async fn check(&self, request: &DpopRequest<'_>) -> Result<Accepted, Failure> {
        // IDP-11 step 1
        let [proof] = request.proofs else {
            return Err(invalid(Step::Shape, "dpop-header-count"));
        };
        let now = self.now()?;
        let bound = request.bound.map(|j| j.0);
        let rules = ProofRules {
            method: request.method,
            uri: request.uri,
            allowed: self.profile.allowed(),
            now,
            lifetime_ms: self.profile.lifetime_ms(),
            skew_ms: self.profile.skew_ms(),
            access_token: request.access_token,
            bound_jkt: bound.as_ref(),
        };
        let proof =
            verify_proof(&AwsLcBackend, proof, &rules).map_err(|e| invalid(e.step(), e.code()))?;
        // IDP-11 step 10, TN-29
        match self.nonces.check(proof.nonce.as_deref(), now) {
            Ok(()) => {}
            Err(NonceError::Unavailable | NonceError::Policy) => return Err(Failure::Unavailable),
            Err(_) => {
                return Err(Failure::UseNonce {
                    nonce: self.issue(now)?,
                });
            }
        }
        // IDP-11 step 9, TN-30
        let key = replay_key(&proof.htm, &proof.htu, &proof.jti);
        let day = u32::try_from(proof.iat.checked_div(DAY_MS).unwrap_or(0))
            .map_err(|_| invalid(Step::Iat, "dpop-iat"))?;
        match self.replay.first_use(day, key).await {
            Ok(true) => {}
            Ok(false) => return Err(invalid(Step::Jti, "dpop-replay")),
            Err(_) => return Err(Failure::Unavailable),
        }
        Ok(Accepted {
            jkt: Jkt(proof.jkt),
            nonce: self.issue(now)?,
        })
    }
}

#[cfg(test)]
mod tests;
