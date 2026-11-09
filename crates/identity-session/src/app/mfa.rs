//! Second factors and passkeys from a live session (§10.2.2, §10.2.4, TN-59, TN-64): TOTP
//! enrollment with its mandatory recovery-code companion, recovery code regeneration, and
//! passkey registration. Turning MFA on ends every other session in the same transaction
//! (TN-64).

use access_crypto::Secret;
use access_identity_account::app::events;
use access_identity_account::app::sealing::{open, seal, subject_key};
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::events::CredentialChange;
use access_identity_account::domain::password::Password;
use access_identity_account::domain::signal::{ChangeType, CredentialType, Initiator, Signal};
use access_identity_account::notify::message::Notice;
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::ceremony::{RegistrationResponse, RegistrationState};
use access_identity_webauthn::domain::ids::UserHandle;
use access_identity_webauthn::domain::options::UserEntity;
use access_identity_webauthn::domain::prf::PrfSalt;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::accounts::{NewCredential, Revoke, SealedSecret, SubjectRow};
use access_store::sessions::NewFlow;
use serde_json::Value;

use super::sessions::SessionStatus;
use super::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, RECOVERY_CODE, Resume, STEP_NOT_ALLOWED, Step,
    TOTP, audit, encode, gone, hex, hex_decode, i64_of, load, partition, refuse, save,
};
use access_identity_account::ports::AccountTx;

use super::Notifier;
use crate::SessionError;
use crate::domain::codes::{
    RECOVERY_CODE_BYTES, RECOVERY_CODES, base32, canonical_recovery_code, otpauth_uri,
    recovery_code,
};
use crate::domain::flow::{
    FlowState, Purpose, Registration, SealedBlob, device_digest, handle_digest,
};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// The stored algorithm name of a TOTP credential (RFC 6238 defaults).
pub const TOTP_ALGORITHM: &str = "totp-sha1-6";

/// Bytes of a TOTP seed: 160 bits (RFC 4226 §4).
pub const TOTP_SEED_BYTES: usize = 20;

/// A TOTP enrollment waiting for its first code.
pub struct TotpEnrollment {
    /// The flow handle to confirm with.
    pub handle: String,
    /// The seed in base32, for manual entry.
    pub secret: Secret<String>,
    /// The `otpauth://` URI, for the QR code.
    pub uri: Secret<String>,
}

/// A confirmed TOTP enrollment.
pub struct TotpConfirmed {
    /// The new credential.
    pub credential: [u8; 16],
    /// Recovery codes, shown once, when the account had none (§10.2.2: mandatory companion).
    pub recovery_codes: Option<Vec<Secret<String>>>,
    /// The subject's new epoch: every other session ended (TN-64).
    pub session_epoch: i64,
}

/// A TOTP enrollment started outside a browser flow (OP-149 m.26 (b)).
pub struct TotpStart {
    /// The seed sealed under the subject's DEK, finished against.
    pub sealed: SealedSecret,
    /// The seed, for the authenticator.
    pub seed: Secret<Vec<u8>>,
}

/// A TOTP enrollment finished outside a browser flow (OP-149 m.26 (b)).
pub struct TotpEnrolled {
    /// The new credential.
    pub credential: [u8; 16],
    /// Recovery codes, when the account had none (§10.2.2: mandatory companion).
    pub recovery_codes: Option<Vec<Secret<String>>>,
    /// The subject's new epoch: every session ended (TN-64).
    pub session_epoch: i64,
}

/// A passkey registration started outside a browser flow (OP-149 m.26 (e)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyStart {
    /// The ceremony state the registration is finished against.
    pub state: RegistrationState,
    /// `PublicKeyCredentialCreationOptionsJSON`.
    pub options: Value,
}

/// A started passkey registration.
#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyRegistration {
    /// The flow handle to finish with.
    pub handle: String,
    /// `PublicKeyCredentialCreationOptionsJSON`.
    pub options: Value,
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
    pub(crate) async fn session_flow(
        &self,
        tx: &mut D::Tx,
        state: &FlowState,
        cookie: &str,
        now: u64,
    ) -> Result<String, SessionError> {
        let handle = self.random32()?;
        let device = super::decode32(cookie).ok_or(SessionError::Invalid)?;
        let encoded = state.encode().map_err(|_| SessionError::Corrupt)?;
        tx.insert_flow(&NewFlow {
            day: partition(now)?,
            flow_hash: &handle_digest(&handle),
            device_hash: &device_digest(&device),
            resume_hash: None,
            expires_ms: i64_of(state.expires_ms)?,
            state: &encoded,
        })
        .await?;
        Ok(encode(&handle))
    }

    async fn new_recovery_codes(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        dek: &suiss_crypto::envelope::Dek,
    ) -> Result<Vec<Secret<String>>, SessionError> {
        let mut out = Vec::new();
        for _ in 0..RECOVERY_CODES {
            let mut raw = [0; RECOVERY_CODE_BYTES];
            self.random.fill(&mut raw)?;
            let code = recovery_code(&raw);
            let typed = Password::presented(&canonical_recovery_code(&code))
                .ok_or(SessionError::Corrupt)?;
            let salt = self.random.salt()?;
            let phc = self.hasher.hash(&typed, salt).await?;
            let sealed = seal(
                &self.realm,
                dek,
                &subject,
                RECOVERY_CODE,
                phc.expose().as_bytes(),
            )?;
            tx.insert_credential(&NewCredential {
                subject,
                kind: RECOVERY_CODE,
                algorithm: access_identity_account::domain::password::ALGORITHM,
                sealed: &sealed,
            })
            .await?;
            out.push(Secret::new(code));
        }
        // TN-59, OP-153 m.3 (d)
        tx.insert_code_set(subject).await?;
        Ok(out)
    }

    /// The owner's "I saved them" for the newest recovery codes (TN-59, OP-153 m.3 (d)); false
    /// when no set waits for it.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn acknowledge_recovery_codes(
        &self,
        cookie: &str,
        correlation: &str,
    ) -> Result<Result<bool, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let session = match self.live_session(&mut tx, cookie, now).await? {
            Ok(s) => s,
            Err(status) => {
                tx.commit().await?;
                return Ok(Err(status));
            }
        };
        let done = tx.acknowledge_code_set(session.subject).await?;
        if done {
            let target = self.external(session.subject)?;
            audit(
                &mut tx,
                "credential.recovery_codes.acknowledged",
                &target,
                &target,
                correlation,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Ok(done))
    }

    /// TN-64: carries `session` to the next epoch, then moves the subject's epoch, which ends
    /// every other session and refresh family in this transaction.
    async fn end_other_sessions(
        &self,
        tx: &mut D::Tx,
        session: &access_store::sessions::SessionRow,
        current: i64,
    ) -> Result<i64, SessionError> {
        let next = current.checked_add(1).ok_or(SessionError::Corrupt)?;
        if !tx
            .restamp_session(
                session.id,
                current,
                next,
                session.auth_time_ms,
                &session.assurance,
                false,
            )
            .await?
        {
            return Err(SessionError::Conflict);
        }
        let epoch = tx
            .end_sessions(session.subject)
            .await?
            .ok_or(SessionError::Corrupt)?;
        if epoch != next {
            return Err(SessionError::Conflict);
        }
        // TN-41, MD-7
        let s = Signal::session_revoked(fresh_id()?, session.subject, Initiator::User, self.now());
        signal(tx, &s).await?;
        // OP-151 m.3 (i)
        events::sessions_ended(tx, &self.realm, session.subject, epoch).await?;
        Ok(epoch)
    }

    /// Starts a TOTP enrollment (§10.2.2): a 160-bit seed, sealed under the subject's DEK
    /// while it waits for the first code. `Err` carries the status of a session that is not
    /// live.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn begin_totp(
        &self,
        cookie: &str,
        issuer: &str,
        account_label: &str,
    ) -> Result<Result<TotpEnrollment, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let session = match self.live_session(&mut tx, cookie, now).await? {
            Ok(s) => s,
            Err(status) => {
                tx.commit().await?;
                return Ok(Err(status));
            }
        };
        let subject = session.subject;
        let (seed, sealed) = self.new_seed(&mut tx, subject).await?;
        let mut state = FlowState::new(
            Purpose::EnrollTotp {
                session: session.id,
            },
            now,
        );
        state.subject = Some(subject);
        state.sealed = Some(SealedBlob {
            kek_id: sealed.kek_id,
            wrapped_dek: sealed.wrapped_dek,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        });
        let handle = self.session_flow(&mut tx, &state, cookie, now).await?;
        tx.commit().await?;
        let params = access_crypto::totp::TotpParams::DEFAULT;
        Ok(Ok(TotpEnrollment {
            handle,
            secret: Secret::new(base32(&seed)),
            uri: Secret::new(otpauth_uri(
                issuer,
                account_label,
                &seed,
                params.algorithm.uri_name(),
                params.digits,
            )),
        }))
    }

    /// Confirms a TOTP enrollment with its first code. In one transaction: the credential,
    /// the used step, recovery codes when there are none, and TN-64: the subject's epoch
    /// moves, every other session ends, this one is carried to the new epoch.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn confirm_totp(
        &self,
        cookie: &str,
        handle: &str,
        code: &str,
        correlation: &str,
    ) -> Result<Result<TotpConfirmed, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Ok(session) = self.live_session(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(refuse(FLOW_GONE)));
        };
        let flow = FlowRef {
            handle,
            device: cookie,
        };
        let mut l = match load(&mut tx, &flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        if l.state.purpose
            != (Purpose::EnrollTotp {
                session: session.id,
            })
        {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        }
        let subject = session.subject;
        let Some(blob) = l.state.sealed.clone() else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        let sealed = SealedSecret {
            kek_id: blob.kek_id,
            wrapped_dek: blob.wrapped_dek,
            nonce: blob.nonce,
            ciphertext: blob.ciphertext,
            pepper_version: None,
        };
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let Some((credential, recovery_codes)) = self
            .add_totp(&mut tx, subject, &row, &sealed, code, now)
            .await?
        else {
            tx.commit().await?;
            return Ok(Err(refuse(CODE_NOT_ACCEPTED)));
        };
        let epoch = self
            .end_other_sessions(&mut tx, &session, row.session_epoch)
            .await?;
        l.state.sealed = None;
        save(&mut tx, &l, "done", Resume::Clear).await?;
        let target = self
            .totp_announced(&mut tx, subject, now, correlation)
            .await?;
        audit(
            &mut tx,
            "session.ended_others",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(TotpConfirmed {
            credential,
            recovery_codes,
            session_epoch: epoch,
        }))
    }

    /// A fresh 160-bit seed for `subject`, sealed under its DEK (§10.2.2).
    async fn new_seed(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<([u8; TOTP_SEED_BYTES], SealedSecret), SessionError> {
        let row = tx
            .subject(subject, false)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let mut seed = [0; TOTP_SEED_BYTES];
        self.random.fill(&mut seed)?;
        let sealed = seal(&self.realm, &dek, &subject, TOTP, hex(&seed).as_bytes())?;
        Ok((seed, sealed))
    }

    /// The credential of the sealed seed once `code` matches it: its first step used, its
    /// binding Claim and signal queued, and recovery codes when the account has none; `None`
    /// when the code does not match.
    async fn add_totp(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        row: &SubjectRow,
        sealed: &SealedSecret,
        code: &str,
        now: u64,
    ) -> Result<Option<([u8; 16], Option<Vec<Secret<String>>>)>, SessionError> {
        let dek = subject_key(&self.realm, row)?;
        let seed = open(&self.realm, &dek, &subject, TOTP, sealed)?;
        let key = Secret::new(hex_decode(seed.expose()).ok_or(SessionError::Corrupt)?);
        let params = access_crypto::totp::TotpParams::DEFAULT;
        let Some(step) = access_crypto::totp::matching_step(&key, &params, now / 1000, code.trim())
        else {
            return Ok(None);
        };
        let credential = tx
            .insert_credential(&NewCredential {
                subject,
                kind: TOTP,
                algorithm: TOTP_ALGORITHM,
                sealed,
            })
            .await?;
        if !tx.use_otp_step(credential, i64_of(step)?).await? {
            return Err(SessionError::Corrupt);
        }
        totp_enrolled(tx, subject, credential, now).await?;
        // OP-151 m.3 (i)
        events::credential(tx, &self.realm, subject, TOTP, CredentialChange::Added).await?;
        let recovery_codes = if tx.credentials(subject, RECOVERY_CODE).await?.is_empty() {
            Some(self.new_recovery_codes(tx, subject, &dek).await?)
        } else {
            None
        };
        Ok(Some((credential, recovery_codes)))
    }

    /// The audit record and the account holder's notice of a confirmed TOTP; returns the
    /// subject's external id.
    async fn totp_announced(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        now: u64,
        correlation: &str,
    ) -> Result<String, SessionError> {
        let target = self.external(subject)?;
        audit(
            tx,
            "credential.totp.enrolled",
            &target,
            &target,
            correlation,
        )
        .await?;
        // OP-148, §7.9.8, E42
        self.account_notice(tx, subject, Notice::SecondFactorEnabled, now)
            .await?;
        Ok(target)
    }

    /// Starts a TOTP enrollment for `subject` outside a browser flow (OP-149 m.26 (b)): the
    /// seed [`Self::begin_totp`] makes, its sealed form kept by the caller.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn start_totp(&self, subject: [u8; 16]) -> Result<TotpStart, SessionError> {
        let mut tx = self.begin().await?;
        let (seed, sealed) = self.new_seed(&mut tx, subject).await?;
        tx.commit().await?;
        Ok(TotpStart {
            sealed,
            seed: Secret::new(seed.to_vec()),
        })
    }

    /// Finishes a TOTP enrollment [`Self::start_totp`] started with its first code, as
    /// [`Self::confirm_totp`] does; with no session to keep, TN-64 ends every session of the
    /// subject.
    ///
    /// # Errors
    /// [`SessionError`]; a code that does not match is a refused [`Step`].
    pub async fn register_totp(
        &self,
        subject: [u8; 16],
        start: &TotpStart,
        code: &str,
        correlation: &str,
    ) -> Result<Result<TotpEnrolled, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let Some((credential, recovery_codes)) = self
            .add_totp(&mut tx, subject, &row, &start.sealed, code, now)
            .await?
        else {
            tx.commit().await?;
            return Ok(Err(refuse(CODE_NOT_ACCEPTED)));
        };
        // TN-64
        let epoch = tx
            .end_sessions(subject)
            .await?
            .ok_or(SessionError::Corrupt)?;
        // TN-41, MD-7
        let s = Signal::session_revoked(fresh_id()?, subject, Initiator::System, now);
        signal(&mut tx, &s).await?;
        // OP-151 m.3 (i)
        events::sessions_ended(&mut tx, &self.realm, subject, epoch).await?;
        self.totp_announced(&mut tx, subject, now, correlation)
            .await?;
        tx.commit().await?;
        Ok(Ok(TotpEnrolled {
            credential,
            recovery_codes,
            session_epoch: epoch,
        }))
    }

    /// Replaces the recovery codes (TN-59): the new set is stored before the old one is
    /// revoked, and the account holder is told.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn regenerate_recovery_codes(
        &self,
        cookie: &str,
        correlation: &str,
    ) -> Result<Result<Vec<Secret<String>>, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let session = match self.live_session(&mut tx, cookie, now).await? {
            Ok(s) => s,
            Err(status) => {
                tx.commit().await?;
                return Ok(Err(status));
            }
        };
        let subject = session.subject;
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let old = tx.credentials(subject, RECOVERY_CODE).await?;
        let codes = self.new_recovery_codes(&mut tx, subject, &dek).await?;
        for c in old {
            if tx.revoke(subject, c.id).await? != Revoke::Done {
                return Err(SessionError::Corrupt);
            }
        }
        // OP-151 m.3 (i)
        events::credential(
            &mut tx,
            &self.realm,
            subject,
            RECOVERY_CODE,
            CredentialChange::Replaced,
        )
        .await?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "credential.recovery_codes.regenerated",
            &target,
            &target,
            correlation,
        )
        .await?;
        // OP-148, §7.9.8, E42, OP-153 m.3 (d)
        self.account_notice(
            &mut tx,
            subject,
            access_identity_account::notify::message::Notice::RecoveryCodesRegenerated,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(codes))
    }

    /// The subject's WebAuthn `user.id`: its random 64-byte handle, made on first use (§12.3.6
    /// invariant 10).
    async fn user_handle(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<[u8; 64], SessionError> {
        if let Some(h) = tx.user_handle(subject).await? {
            return Ok(h);
        }
        let mut h = [0; UserHandle::LEN];
        self.random.fill(&mut h)?;
        if !tx.insert_user_handle(subject, &h).await? {
            return Err(SessionError::Conflict);
        }
        Ok(h)
    }

    /// The creation options of a new passkey for the handle (§10.2.4).
    async fn creation(
        &self,
        handle: [u8; 64],
        name: &str,
        display_name: &str,
    ) -> Result<PasskeyStart, SessionError> {
        let user = UserHandle::from_bytes(handle);
        let start = self
            .webauthn()
            .start_registration(
                self.passkeys.rp,
                self.passkeys.policy,
                &UserEntity {
                    handle: &user,
                    name,
                    display_name,
                },
                false,
                None,
            )
            .await?;
        Ok(PasskeyStart {
            state: start.state,
            options: start.options,
        })
    }

    /// Starts a passkey registration for `subject` outside a browser flow (OP-149 m.26 (e)):
    /// the same ceremony as [`Self::begin_passkey`], its state kept by the caller.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn start_passkey(
        &self,
        subject: [u8; 16],
        name: &str,
        display_name: &str,
    ) -> Result<PasskeyStart, SessionError> {
        let mut tx = self.begin().await?;
        let handle = self.user_handle(&mut tx, subject).await?;
        tx.commit().await?;
        self.creation(handle, name, display_name).await
    }

    /// Starts a passkey registration for the session's subject (§10.2.4). The subject gets
    /// its random 64-byte `user.id` on first use (§12.3.6 invariant 10).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn begin_passkey(
        &self,
        cookie: &str,
        name: &str,
        display_name: &str,
    ) -> Result<Result<PasskeyRegistration, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let session = match self.live_session(&mut tx, cookie, now).await? {
            Ok(s) => s,
            Err(status) => {
                tx.commit().await?;
                return Ok(Err(status));
            }
        };
        let subject = session.subject;
        let handle = self.user_handle(&mut tx, subject).await?;
        let start = self.creation(handle, name, display_name).await?;
        let mut state = FlowState::new(
            Purpose::RegisterPasskey {
                session: session.id,
            },
            now,
        );
        state.subject = Some(subject);
        state.registration = Some(Registration {
            challenge: start.state.challenge,
            user: handle.to_vec(),
            conditional: start.state.conditional,
            expires_at_s: start.state.expires_at,
            prf_salt: start.state.prf_salt.map(|s| s.0),
        });
        let flow = self.session_flow(&mut tx, &state, cookie, now).await?;
        tx.commit().await?;
        Ok(Ok(PasskeyRegistration {
            handle: flow,
            options: start.options,
        }))
    }

    /// Finishes a passkey registration; the registration state is used once.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn finish_passkey(
        &self,
        cookie: &str,
        handle: &str,
        response: &RegistrationResponse<'_>,
        correlation: &str,
    ) -> Result<Result<RegistrationOutcome, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Ok(session) = self.live_session(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(refuse(FLOW_GONE)));
        };
        let flow = FlowRef {
            handle,
            device: cookie,
        };
        let mut l = match load(&mut tx, &flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let Some(reg) = l.state.registration.take().filter(|_| {
            l.state.purpose
                == Purpose::RegisterPasskey {
                    session: session.id,
                }
        }) else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        save(&mut tx, &l, "done", Resume::Clear).await?;
        tx.commit().await?;
        let state = RegistrationState {
            realm: self.wa_realm(),
            user: UserHandle::from_slice(&reg.user).ok_or(SessionError::Corrupt)?,
            challenge: reg.challenge,
            conditional: reg.conditional,
            expires_at: reg.expires_at_s,
            prf_salt: reg.prf_salt.map(PrfSalt),
        };
        Ok(Ok(self
            .register_passkey(session.subject, &state, response, correlation)
            .await?))
    }

    /// Registers the passkey `response` answers `state` with, for `subject` (§10.2.4, OP-150
    /// L2): the credential is verified and stored, its binding Claims are queued and the
    /// registration is audited. The hosted registration and a local bootstrap share this step
    /// (OP-149 m.26 (e)).
    ///
    /// # Errors
    /// [`SessionError`]; a refused credential is [`RegistrationOutcome::Rejected`].
    pub async fn register_passkey(
        &self,
        subject: [u8; 16],
        state: &RegistrationState,
        response: &RegistrationResponse<'_>,
        correlation: &str,
    ) -> Result<RegistrationOutcome, SessionError> {
        let now = self.now();
        let outcome = self
            .webauthn()
            .finish_registration(
                self.passkeys.rp,
                self.passkeys.policy,
                state,
                response,
                None,
            )
            .await?;
        if let RegistrationOutcome::Registered(record) = &outcome {
            let others =
                CredentialRegistry::list(self.passkeys.registry, record.realm, &record.user)
                    .await?;
            let mut tx = self.begin().await?;
            // IDP-2, TN-63, OP-150 L2
            if let Some(sibling) = tx.passkey_credential(record.id.as_bytes()).await? {
                super::claims::passkey_registered(&mut tx, subject, sibling, record, &others, now)
                    .await?;
            }
            // TN-41
            let s = Signal::credential_change(
                fresh_id()?,
                subject,
                CredentialType::Fido2,
                ChangeType::Create,
                now,
            );
            signal(&mut tx, &s).await?;
            let target = self.external(subject)?;
            audit(
                &mut tx,
                "credential.passkey.registered",
                &target,
                &target,
                correlation,
            )
            .await?;
            // SEC18, Ek B 3657
            self.account_notice(&mut tx, subject, Notice::NewMethod, now)
                .await?;
            tx.commit().await?;
        }
        Ok(outcome)
    }
}

/// The Claim and signal of a confirmed TOTP: its `authenticator_binding` line opens (§10.1.3,
/// OP-150 m.12 (j)) and a CAEP credential change is queued (TN-41).
async fn totp_enrolled<T: SessionTx>(
    tx: &mut T,
    subject: [u8; 16],
    credential: [u8; 16],
    now: u64,
) -> Result<(), SessionError> {
    access_identity_account::app::claims::emit(
        tx,
        &access_identity_account::domain::claims::secret_binding(
            subject,
            access_kernel::claim::body::AuthenticatorKind::Totp,
            &credential,
            now,
        ),
    )
    .await?;
    let s = Signal::credential_change(
        fresh_id()?,
        subject,
        CredentialType::App,
        ChangeType::Create,
        now,
    );
    signal(tx, &s).await?;
    Ok(())
}
