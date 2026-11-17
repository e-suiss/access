//! The first second factor of an account, enrolled at sign-in (OP-159 m.48 (a)): only at the
//! `EnrollSecondFactor` step of a login, after the first factor, when the environment requires a
//! second factor and the account never held a TOTP credential or a passkey (a removed one counts).
//! An account that has or had one is never offered this, so a stolen password cannot enrol the
//! thief's own factor. A TOTP enrollment completes the sign-in only once its first code verifies;
//! a passkey enrollment registers the credential and the sign-in then completes with an assertion
//! of it. Turning MFA on ends every other session (TN-64).

use access_crypto::Secret;
use access_identity_account::app::events;
use access_identity_account::app::sealing::{open, subject_key};
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::signal::{Initiator, Signal};
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::ceremony::{RegistrationResponse, RegistrationState};
use access_identity_webauthn::domain::ids::UserHandle;
use access_identity_webauthn::domain::prf::PrfSalt;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::accounts::SealedSecret;
use serde_json::Value;

use super::{
    Auth, CODE_NOT_ACCEPTED, FlowRef, Loaded, Resume, STEP_NOT_ALLOWED, Step, TOTP, active, audit,
    gone, hex_decode, load, refuse, save,
};
use crate::SessionError;
use crate::domain::assurance::Factor;
use crate::domain::codes::{base32, otpauth_uri};
use crate::domain::flow::{Purpose, Registration, SealedBlob};
use crate::domain::requirement::{MfaPolicy, Requirement};
use crate::ports::{Clock, Random, SessionDb, SessionTx};
use access_identity_account::ports::AccountTx;

use super::Notifier;

/// The throttle key kind of the enrollment's first code (TN-59).
const ENROLL_KIND: &str = "totp-enroll";

/// The TOTP seed of an enrollment, shown while the step waits for its first code.
pub struct TotpSetup {
    /// The seed in base32, for manual entry.
    pub secret: Secret<String>,
    /// The `otpauth://` URI.
    pub uri: Secret<String>,
}

/// What the enrollment step offers.
pub struct SignInEnrollment {
    /// The TOTP seed.
    pub totp: TotpSetup,
    /// `PublicKeyCredentialCreationOptionsJSON`, when the environment offers passkeys.
    pub passkey: Option<Value>,
}

/// A confirmed TOTP enrollment at sign-in.
pub struct EnrolledAtSignIn {
    /// Where the flow went: signed in, or what is still missing.
    pub step: Step,
    /// Recovery codes, shown once (§10.2.2: mandatory companion).
    pub recovery_codes: Option<Vec<Secret<String>>>,
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    /// The subject of a login flow that may enroll its first second factor (OP-159 m.48 (a)): the
    /// first factor is done, the account is live, the environment requires a second factor, the
    /// account holds none and never held a TOTP credential or a passkey, and what is missing is
    /// exactly the enrollment.
    async fn may_enroll(
        &self,
        tx: &mut D::Tx,
        l: &Loaded,
    ) -> Result<Option<[u8; 16]>, SessionError> {
        if !matches!(l.state.purpose, Purpose::Login) || self.policy.mfa != MfaPolicy::Required {
            return Ok(None);
        }
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            return Ok(None);
        };
        let live = tx
            .subject(subject, false)
            .await?
            .is_some_and(|r| active(&r.status));
        if !live {
            return Ok(None);
        }
        let enrolled = self.enrolled(tx, subject).await?;
        if enrolled.second_factor() || tx.second_factor_ever(subject).await? {
            return Ok(None);
        }
        let needs = self.needs(&l.state, enrolled, false);
        Ok(needs
            .contains(&Requirement::EnrollSecondFactor)
            .then_some(subject))
    }

    /// The enrollment the flow offers (OP-159 m.48 (a)): its TOTP seed, made once and kept sealed
    /// in the flow until the first code, and a fresh passkey creation when the environment offers
    /// passkeys. `Err` is the refusal when the flow may not enroll.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sign_in_enrollment(
        &self,
        flow: &FlowRef<'_>,
        issuer: &str,
        label: &str,
    ) -> Result<Result<SignInEnrollment, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let Some(subject) = self.may_enroll(&mut tx, &l).await? else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        let seed = if let Some(blob) = &l.state.sealed {
            let row = tx
                .subject(subject, false)
                .await?
                .ok_or(SessionError::Corrupt)?;
            let dek = subject_key(&self.environment, &row)?;
            let hex = open(&self.environment, &dek, &subject, TOTP, &sealed_of(blob))?;
            hex_decode(hex.expose()).ok_or(SessionError::Corrupt)?
        } else {
            let (seed, sealed) = self.new_seed(&mut tx, subject).await?;
            l.state.sealed = Some(SealedBlob {
                kek_id: sealed.kek_id,
                wrapped_dek: sealed.wrapped_dek,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
            });
            seed.to_vec()
        };
        let passkey = if self.policy.passkey {
            let handle = self.user_handle(&mut tx, subject).await?;
            let start = self.creation(handle, label, label).await?;
            l.state.registration = Some(Registration {
                challenge: start.state.challenge,
                user: handle.to_vec(),
                conditional: start.state.conditional,
                expires_at_s: start.state.expires_at,
                prf_salt: start.state.prf_salt.map(|s| s.0),
            });
            Some(start.options)
        } else {
            None
        };
        save(&mut tx, &l, "open", Resume::Keep).await?;
        tx.commit().await?;
        let params = access_crypto::totp::TotpParams::DEFAULT;
        Ok(Ok(SignInEnrollment {
            totp: TotpSetup {
                secret: Secret::new(base32(&seed)),
                uri: Secret::new(otpauth_uri(
                    issuer,
                    label,
                    &seed,
                    params.algorithm.uri_name(),
                    params.digits,
                )),
            },
            passkey,
        }))
    }

    /// Confirms the flow's TOTP enrollment with its first code (OP-159 m.48 (a)): in one
    /// transaction the credential and its used step, recovery codes when there are none, every
    /// other session ended (TN-64), the enrollment audited, and the code recorded as the sign-in's
    /// second factor. At most 100 consecutive failures (TN-59).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn confirm_sign_in_totp(
        &self,
        flow: &FlowRef<'_>,
        code: &str,
        correlation: &str,
    ) -> Result<EnrolledAtSignIn, SessionError> {
        let refused = |step| EnrolledAtSignIn {
            step,
            recovery_codes: None,
        };
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(refused(gone(e))),
        };
        let Some(subject) = self.may_enroll(&mut tx, &l).await? else {
            return Ok(refused(refuse(STEP_NOT_ALLOWED)));
        };
        let Some(blob) = l.state.sealed.clone() else {
            return Ok(refused(refuse(STEP_NOT_ALLOWED)));
        };
        let key = self.factor_key(subject, ENROLL_KIND);
        let gate = match self.factor_gate(&mut tx, &key, now).await? {
            Ok(s) => s,
            Err(step) => {
                tx.commit().await?;
                return Ok(refused(step));
            }
        };
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let added = self
            .add_totp(&mut tx, subject, &row, &sealed_of(&blob), code, now)
            .await?;
        self.factor_counted(&mut tx, &key, &gate, added.is_some(), now)
            .await?;
        let target = self.external(subject)?;
        let Some((credential, recovery_codes)) = added else {
            audit(
                &mut tx,
                "login.totp.failed",
                super::signin::ANONYMOUS,
                &target,
                correlation,
            )
            .await?;
            tx.commit().await?;
            return Ok(refused(refuse(CODE_NOT_ACCEPTED)));
        };
        self.mfa_turned_on(&mut tx, subject, now, correlation)
            .await?;
        self.totp_announced(&mut tx, subject, now, correlation)
            .await?;
        l.state.sealed = None;
        l.state.registration = None;
        if l.state
            .record(subject, Factor::totp(credential, now))
            .is_err()
        {
            return Err(SessionError::Corrupt);
        }
        let step = self.advance(tx, l, now, correlation).await?;
        Ok(EnrolledAtSignIn {
            step,
            recovery_codes,
        })
    }

    /// Registers the flow's passkey enrollment (OP-159 m.48 (a)): the creation ceremony is used
    /// once; a registered passkey ends every other session (TN-64) and is audited, and the flow
    /// then asks for an assertion of it as the sign-in's second factor.
    ///
    /// # Errors
    /// [`SessionError`]; a refused credential is [`RegistrationOutcome::Rejected`].
    pub async fn enroll_sign_in_passkey(
        &self,
        flow: &FlowRef<'_>,
        response: &RegistrationResponse<'_>,
        correlation: &str,
    ) -> Result<Result<RegistrationOutcome, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let Some(subject) = self.may_enroll(&mut tx, &l).await? else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        let Some(reg) = l.state.registration.take() else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        save(&mut tx, &l, "open", Resume::Keep).await?;
        tx.commit().await?;
        let state = RegistrationState {
            environment: self.wa_environment(),
            user: UserHandle::from_slice(&reg.user).ok_or(SessionError::Corrupt)?,
            challenge: reg.challenge,
            conditional: reg.conditional,
            expires_at: reg.expires_at_s,
            prf_salt: reg.prf_salt.map(PrfSalt),
        };
        let outcome = self
            .register_passkey(subject, &state, response, correlation)
            .await?;
        if matches!(outcome, RegistrationOutcome::Registered(_)) {
            let mut tx = self.begin().await?;
            self.mfa_turned_on(&mut tx, subject, now, correlation)
                .await?;
            let mut l = match load(&mut tx, flow, now).await? {
                Ok(l) => l,
                Err(e) => {
                    tx.commit().await?;
                    return Ok(Err(gone(e)));
                }
            };
            l.state.sealed = None;
            save(&mut tx, &l, "open", Resume::Keep).await?;
            tx.commit().await?;
        }
        Ok(Ok(outcome))
    }

    /// What turning MFA on at sign-in does besides the credential (OP-159 m.48 (a), TN-64): every
    /// session of the subject ends and the enrollment is audited.
    async fn mfa_turned_on(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        now: u64,
        correlation: &str,
    ) -> Result<(), SessionError> {
        let epoch = tx
            .end_sessions(subject)
            .await?
            .ok_or(SessionError::Corrupt)?;
        // TN-41, MD-7
        let s = Signal::session_revoked(fresh_id()?, subject, Initiator::System, now);
        signal(tx, &s).await?;
        // OP-151 m.3 (i)
        events::sessions_ended(tx, &self.environment, subject, epoch).await?;
        let target = self.external(subject)?;
        audit(
            tx,
            "login.second_factor.enrolled",
            &target,
            &target,
            correlation,
        )
        .await?;
        Ok(())
    }
}

fn sealed_of(blob: &SealedBlob) -> SealedSecret {
    SealedSecret {
        kek_id: blob.kek_id.clone(),
        wrapped_dek: blob.wrapped_dek.clone(),
        nonce: blob.nonce,
        ciphertext: blob.ciphertext.clone(),
        pepper_version: None,
    }
}
