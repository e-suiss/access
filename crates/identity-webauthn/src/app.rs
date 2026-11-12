//! Use cases over the domain and its ports (OP-63): start and finish registration and
//! authentication, and refresh FIDO metadata.

use serde_json::Value;

use crate::WebAuthnError;
use crate::domain::Rejection;
use crate::domain::assurance::Assurance;
use crate::domain::attestation::{AttestationObject, Evidence, revocation_points};
use crate::domain::authenticator_data::AuthenticatorData;
use crate::domain::ceremony::{
    AssertionResponse, AuthenticationState, RegistrationResponse, RegistrationState, Signal,
    verify_assertion, verify_registration,
};
use crate::domain::credential::CredentialRecord;
use crate::domain::decoy::decoy_descriptors;
use crate::domain::ids::{CredentialId, UserHandle};
use crate::domain::mds::{MdsBlob, MdsError, verify_blob};
use crate::domain::options::{CredentialDescriptor, UserEntity, creation_options, request_options};
use crate::domain::policy::{AttestationPolicy, RealmPolicy};
use crate::domain::prf::{PrfConfig, PrfSalt};
use crate::domain::rp::RelyingParty;
use crate::ports::{
    AttestationSources, Clock, CredentialRegistry, DecoySource, Inserted, MdsCache, MdsSource,
    Random, SignalSink,
};

/// A started registration: keep `state` server-side, send `options` to the browser.
#[derive(Debug)]
pub struct RegistrationStart {
    /// Single-use state.
    pub state: RegistrationState,
    /// `PublicKeyCredentialCreationOptionsJSON`.
    pub options: Value,
}

/// The outcome of a registration.
#[derive(Debug, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// Stored.
    Registered(Box<CredentialRecord>),
    /// Refused.
    Rejected(Rejection),
}

/// Who is signing in.
#[derive(Clone, Copy, Debug)]
pub enum Identified<'a> {
    /// "Sign in with a passkey": no identifier, empty `allowCredentials` (TN-96).
    Discoverable,
    /// Identifier-first: the normalized identifier and the account, if one exists.
    Identifier {
        /// The identifier as typed, after normalization.
        normalized: &'a str,
        /// The account's handle; `None` when there is no account.
        user: Option<UserHandle>,
    },
}

/// A started authentication: keep `state` server-side, send `options` to the browser.
#[derive(Debug)]
pub struct AuthenticationStart {
    /// Single-use state.
    pub state: AuthenticationState,
    /// `PublicKeyCredentialRequestOptionsJSON`.
    pub options: Value,
}

/// The outcome of an authentication.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthenticationOutcome {
    /// Verified.
    Authenticated {
        /// The account.
        user: UserHandle,
        /// The credential used.
        credential: CredentialId,
        /// What it can satisfy.
        assurance: Assurance,
        /// Signals raised.
        signals: Vec<Signal>,
        /// What the assertion showed.
        facts: AssertionFacts,
    },
    /// Refused.
    Rejected(Rejection),
}

/// What a verified assertion showed, for the WebAuthn details of its `authentication` Claim
/// (§10.1.2): flags, counter and the AAGUID hint. User presence is always proven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssertionFacts {
    /// The AAGUID recorded at registration; a hint only.
    pub aaguid: [u8; 16],
    /// The counter stored after the assertion.
    pub sign_count: u32,
    /// UV.
    pub user_verified: bool,
    /// BE.
    pub backup_eligible: bool,
    /// BS.
    pub backup_state: bool,
}

/// The WebAuthn relying party over its ports.
pub struct WebAuthn<R, C, N, D, S> {
    /// Credential registry.
    pub registry: R,
    /// Trusted time.
    pub clock: C,
    /// Randomness.
    pub random: N,
    /// Decoy key.
    pub decoys: D,
    /// Signal sink.
    pub signals: S,
}

fn descriptor(record: &CredentialRecord) -> CredentialDescriptor {
    CredentialDescriptor {
        id: record.id.clone(),
        transports: record.transports.clone(),
    }
}

impl<R, C, N, D, S> WebAuthn<R, C, N, D, S>
where
    R: CredentialRegistry + Sync,
    C: Clock + Sync,
    N: Random + Sync,
    D: DecoySource + Sync,
    S: SignalSink + Sync,
{
    fn challenge(&self) -> Result<[u8; 32], WebAuthnError> {
        let mut out = [0; 32];
        self.random.fill(&mut out)?;
        Ok(out)
    }

    /// A fresh 64-byte `user.id` for a new account (§12.3.6 invariant 10).
    ///
    /// # Errors
    /// [`WebAuthnError::Random`].
    pub fn new_user_handle(&self) -> Result<UserHandle, WebAuthnError> {
        let mut out = [0; UserHandle::LEN];
        self.random.fill(&mut out)?;
        Ok(UserHandle::from_bytes(out))
    }

    /// Starts a registration. `prf_purpose` requests a PRF salt for that use.
    ///
    /// # Errors
    /// [`WebAuthnError`].
    pub async fn start_registration(
        &self,
        rp: &RelyingParty,
        policy: &RealmPolicy,
        user: &UserEntity<'_>,
        conditional: bool,
        prf_purpose: Option<&str>,
    ) -> Result<RegistrationStart, WebAuthnError> {
        let now = self.clock.now()?;
        let challenge = self.challenge()?;
        let exclude: Vec<CredentialDescriptor> = self
            .registry
            .list(rp.realm, user.handle)
            .await?
            .iter()
            .map(descriptor)
            .collect();
        let prf_salt = match prf_purpose {
            Some(purpose) => Some(PrfSalt::derive(purpose, &self.challenge()?)),
            None => None,
        };
        let prf = prf_salt.map(|s| PrfConfig::new(true, s));
        let options = creation_options(
            rp,
            policy,
            user,
            &challenge,
            &exclude,
            conditional,
            prf.as_ref(),
        );
        Ok(RegistrationStart {
            state: RegistrationState {
                realm: rp.realm,
                user: *user.handle,
                challenge,
                conditional,
                expires_at: now.saturating_add(policy.ceremony_ttl),
                prf_salt,
            },
            options,
        })
    }

    /// Finishes a registration and stores the credential. Under `direct` the metadata and the
    /// CRLs of the statement's chain come from `sources` first (OP-159 m.3 (ll)).
    ///
    /// # Errors
    /// [`WebAuthnError`]; refusals are [`RegistrationOutcome::Rejected`].
    pub async fn finish_registration(
        &self,
        rp: &RelyingParty,
        policy: &RealmPolicy,
        state: &RegistrationState,
        response: &RegistrationResponse<'_>,
        sources: &(dyn AttestationSources + Sync),
    ) -> Result<RegistrationOutcome, WebAuthnError> {
        let evidence = attestation_evidence(policy, response, sources).await;
        let now = self.clock.now()?;
        let record = match verify_registration(rp, policy, state, response, &evidence, now) {
            Ok(r) => r,
            Err(e) => return Ok(RegistrationOutcome::Rejected(e)),
        };
        match self.registry.insert(&record).await? {
            Inserted::Stored => Ok(RegistrationOutcome::Registered(Box::new(record))),
            Inserted::Duplicate => Ok(RegistrationOutcome::Rejected(Rejection::CredentialExists)),
        }
    }

    /// Starts an authentication. An identifier without passkeys, or without an account, gets
    /// decoy descriptors (TN-97).
    ///
    /// # Errors
    /// [`WebAuthnError`].
    pub async fn start_authentication(
        &self,
        rp: &RelyingParty,
        policy: &RealmPolicy,
        who: Identified<'_>,
        require_user_verification: bool,
    ) -> Result<AuthenticationStart, WebAuthnError> {
        let now = self.clock.now()?;
        let challenge = self.challenge()?;
        let (user, allow) = match who {
            Identified::Discoverable => (None, Vec::new()),
            Identified::Identifier { normalized, user } => {
                let real = match user {
                    Some(u) => self.registry.list(rp.realm, &u).await?,
                    None => Vec::new(),
                };
                let allow = if real.is_empty() {
                    decoy_descriptors(rp.realm, normalized, |input| {
                        self.decoys.derive(rp.realm, input)
                    })?
                } else {
                    real.iter().map(descriptor).collect()
                };
                (user, allow)
            }
        };
        let options = request_options(rp, policy, &challenge, &allow);
        Ok(AuthenticationStart {
            state: AuthenticationState {
                realm: rp.realm,
                challenge,
                user,
                allowed: allow.into_iter().map(|d| d.id).collect(),
                require_user_verification,
                expires_at: now.saturating_add(policy.ceremony_ttl),
            },
            options,
        })
    }

    /// Finishes an authentication, records the use and raises signals.
    ///
    /// # Errors
    /// [`WebAuthnError`]; refusals are [`AuthenticationOutcome::Rejected`].
    pub async fn finish_authentication(
        &self,
        rp: &RelyingParty,
        policy: &RealmPolicy,
        state: &AuthenticationState,
        response: &AssertionResponse<'_>,
    ) -> Result<AuthenticationOutcome, WebAuthnError> {
        let now = self.clock.now()?;
        let Some(id) = CredentialId::new(response.raw_id) else {
            return Ok(AuthenticationOutcome::Rejected(
                Rejection::UnknownCredential,
            ));
        };
        let Some(stored) = self.registry.find(rp.realm, &id).await? else {
            return Ok(AuthenticationOutcome::Rejected(
                Rejection::UnknownCredential,
            ));
        };
        let verified = match verify_assertion(rp, policy, state, response, &stored, now) {
            Ok(v) => v,
            Err(Rejection::SignCount) => {
                let presented = AuthenticatorData::parse(response.authenticator_data)
                    .map_or(0, |a| a.sign_count);
                let signal = Signal::SignCountRegressed {
                    stored: stored.sign_count,
                    presented,
                };
                self.signals.emit(rp.realm, &id, signal).await?;
                return Ok(AuthenticationOutcome::Rejected(Rejection::SignCount));
            }
            Err(e) => return Ok(AuthenticationOutcome::Rejected(e)),
        };
        for signal in &verified.signals {
            self.signals.emit(rp.realm, &id, *signal).await?;
        }
        self.registry
            .record_use(
                rp.realm,
                &id,
                verified.sign_count,
                verified.backup_state,
                now,
            )
            .await?;
        Ok(AuthenticationOutcome::Authenticated {
            user: stored.user,
            credential: id,
            facts: AssertionFacts {
                aaguid: stored.aaguid.0,
                sign_count: verified.sign_count,
                user_verified: verified.assurance.user_verified,
                backup_eligible: stored.backup_eligible,
                backup_state: verified.backup_state,
            },
            assurance: verified.assurance,
            signals: verified.signals,
        })
    }
}

/// What a `direct` realm verifies `response` against: nothing under `none`, where attestation
/// is never a trust input (§10.2.4, OP-159 m.3 (ll)).
pub async fn attestation_evidence(
    policy: &RealmPolicy,
    response: &RegistrationResponse<'_>,
    sources: &(dyn AttestationSources + Sync),
) -> Evidence {
    if policy.attestation == AttestationPolicy::None {
        return Evidence::default();
    }
    let mut evidence = Evidence::metadata(sources.metadata().await);
    let points = AttestationObject::parse(response.attestation_object)
        .map(|o| revocation_points(&o))
        .unwrap_or_default();
    for url in points {
        let crl = sources.crl(&url).await;
        evidence.crls.insert(url, crl);
    }
    evidence
}

/// Fetches, verifies and caches a metadata blob (OP-146 m.4 (d)). A blob whose serial is below
/// the cached one is refused; the same serial keeps the cached blob.
///
/// # Errors
/// [`WebAuthnError`].
pub async fn refresh_metadata(
    source: &(impl MdsSource + Sync),
    cache: &(impl MdsCache + Sync),
    root: &[u8],
    clock: &(impl Clock + Sync),
) -> Result<MdsBlob, WebAuthnError> {
    let now = clock.now()?;
    let bytes = source.fetch().await?;
    let blob = verify_blob(&bytes, root, now)?;
    if let Some(current) = cache.current().await? {
        if blob.serial < current.serial {
            return Err(MdsError::Rollback.into());
        }
        if blob.serial == current.serial {
            return Ok(current);
        }
    }
    cache.replace(blob.clone()).await?;
    Ok(blob)
}

/// The cached blob if it is still fresh; `direct` realms fail closed without it.
///
/// # Errors
/// [`WebAuthnError`].
pub async fn fresh_metadata(
    cache: &(impl MdsCache + Sync),
    clock: &(impl Clock + Sync),
) -> Result<Option<MdsBlob>, WebAuthnError> {
    let now = clock.now()?;
    Ok(cache.current().await?.filter(|b| b.is_fresh(now)))
}
