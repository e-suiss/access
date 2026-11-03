//! Session use cases (TN-36, TN-50, G57, EP-2, TN-44): check, sign out, sign out everywhere,
//! the session list (S10) and step-up. A session that is not valid issues nothing: no token,
//! no identity assertion (G57).

use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::sessions::{NewFlow, SessionRow};

use super::signin::{Started, StepOptions};
use super::{Auth, audit, decode32, encode, i64_of, partition, u64_of};
use access_identity_account::ports::AccountTx;

use super::Notifier;
use crate::SessionError;
use crate::domain::assurance::{Aal, AssuranceVector};
use crate::domain::flow::{FlowState, Purpose, device_digest, handle_digest};
use crate::domain::session::{
    SESSION_COOKIE, SessionCheck, SessionFacts, check, clear_cookie, cookie_digest,
};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// A live session as callers see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    /// Session id.
    pub id: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// The epoch it carries.
    pub session_epoch: i64,
    /// When the authentication happened.
    pub auth_time_ms: u64,
    /// The assurance of that authentication.
    pub assurance: AssuranceVector,
    /// "Keep me signed in".
    pub keep_signed_in: bool,
    /// "Signed in until …" (S10).
    pub expires_ms: u64,
}

/// The state of a presented cookie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    /// Live; its use was recorded.
    Valid(Box<SessionView>),
    /// Not live, and why: the reason is shown to the signed-out user ("Signed out because …").
    Invalid(SessionCheck),
    /// No such session.
    Unknown,
}

fn facts(r: &SessionRow) -> Result<SessionFacts, SessionError> {
    Ok(SessionFacts {
        session_epoch: r.session_epoch,
        subject_epoch: r.subject_epoch,
        subject_active: super::active(&r.subject_status),
        last_seen_ms: u64_of(r.last_seen_ms)?,
        idle_ms: u64_of(r.idle_ms)?,
        expires_ms: u64_of(r.expires_ms)?,
        ended: r.ended_ms.is_some(),
    })
}

pub(crate) fn view(r: &SessionRow) -> Result<SessionView, SessionError> {
    Ok(SessionView {
        id: r.id,
        subject: r.subject,
        session_epoch: r.session_epoch,
        auth_time_ms: u64_of(r.auth_time_ms)?,
        assurance: serde_json::from_slice(&r.assurance).map_err(|_| SessionError::Corrupt)?,
        keep_signed_in: r.keep_signed_in,
        expires_ms: u64_of(r.expires_ms)?,
    })
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
    pub(crate) async fn live_session(
        &self,
        tx: &mut D::Tx,
        cookie: &str,
        now: u64,
    ) -> Result<Result<SessionRow, SessionStatus>, SessionError> {
        let Some(value) = decode32(cookie) else {
            return Ok(Err(SessionStatus::Unknown));
        };
        let Some(row) = tx.session_by_cookie(&cookie_digest(&value)).await? else {
            return Ok(Err(SessionStatus::Unknown));
        };
        match check(&facts(&row)?, now) {
            SessionCheck::Valid => Ok(Ok(row)),
            other => {
                if other == SessionCheck::Revoked && row.ended_ms.is_none() {
                    tx.end_session(row.id, i64_of(now)?, "epoch").await?;
                }
                Ok(Err(SessionStatus::Invalid(other)))
            }
        }
    }

    /// Checks a session cookie against the primary (Δ = 0, MD-7). The database being
    /// unreachable is an error, never a valid session (G48).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn check_session(&self, cookie: &str) -> Result<SessionStatus, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let status = match self.live_session(&mut tx, cookie, now).await? {
            Ok(row) => {
                tx.touch_session(row.id, i64_of(now)?).await?;
                SessionStatus::Valid(Box::new(view(&row)?))
            }
            Err(status) => status,
        };
        tx.commit().await?;
        Ok(status)
    }

    /// Signs this browser out (§12.0.3): the session ends and issues nothing more (G57). The
    /// returned `Set-Cookie` clears the cookie. Ending the Instances behind it is Stage 6
    /// cleanup (OP-146 m.4 (i)); security rests on the session ending here.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sign_out(&self, cookie: &str, correlation: &str) -> Result<String, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        if let Some(value) = decode32(cookie)
            && let Some(row) = tx.session_by_cookie(&cookie_digest(&value)).await?
            && tx.end_session(row.id, i64_of(now)?, "logout").await?
        {
            let target = self.external(row.subject)?;
            audit(&mut tx, "session.signed_out", &target, &target, correlation).await?;
        }
        tx.commit().await?;
        Ok(clear_cookie(SESSION_COOKIE))
    }

    /// Signs the subject out everywhere: one `session_epoch` step ends every session and
    /// refresh family (TN-50, MD-7). Returns the new epoch.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sign_out_everywhere(
        &self,
        subject: [u8; 16],
        actor: &str,
        correlation: &str,
    ) -> Result<i64, SessionError> {
        let mut tx = self.begin().await?;
        let epoch = tx
            .end_sessions(subject)
            .await?
            .ok_or(SessionError::Account(
                access_identity_account::AccountError::NotFound,
            ))?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "session.ended_everywhere",
            actor,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// The subject's live sessions, newest first ("Sign-ins & instances", S10).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sessions(&self, subject: [u8; 16]) -> Result<Vec<SessionView>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let rows = tx.live_sessions(subject).await?;
        tx.commit().await?;
        let mut out = Vec::new();
        for r in rows {
            if check(&facts(&r)?, now) == SessionCheck::Valid {
                out.push(view(&r)?);
            }
        }
        Ok(out)
    }

    /// Starts a step-up for a live session (TN-44): `max_age` is mandatory; the flow must
    /// reach `min_aal` with fresh steps; completion restamps the session, never a new one.
    /// `Err` carries the status of a session that is not live.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn step_up(
        &self,
        cookie: &str,
        max_age_ms: u64,
        min_aal: Aal,
    ) -> Result<Result<Started, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = match self.live_session(&mut tx, cookie, now).await? {
            Ok(r) => r,
            Err(s) => {
                tx.commit().await?;
                return Ok(Err(s));
            }
        };
        let mut state = FlowState::new(
            Purpose::StepUp {
                session: row.id,
                max_age_ms,
                min_aal,
            },
            now,
        );
        state.subject = Some(row.subject);
        let user = tx
            .user_handle(row.subject)
            .await?
            .map(access_identity_webauthn::domain::ids::UserHandle::from_bytes);
        let start = self
            .webauthn()
            .start_authentication(
                self.passkeys.rp,
                self.passkeys.policy,
                access_identity_webauthn::app::Identified::Identifier {
                    normalized: "",
                    user,
                },
                min_aal >= Aal::Aal2,
            )
            .await?;
        state.ceremony = Some(crate::domain::flow::Ceremony {
            challenge: start.state.challenge,
            user: start.state.user.map(|u| u.as_bytes().to_vec()),
            allowed: start
                .state
                .allowed
                .iter()
                .map(|c| c.as_bytes().to_vec())
                .collect(),
            require_uv: start.state.require_user_verification,
            expires_at_s: start.state.expires_at,
        });
        let handle = self.random32()?;
        let device = decode32(cookie).ok_or(SessionError::Invalid)?;
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
        tx.commit().await?;
        Ok(Ok(Started {
            handle: encode(&handle),
            set_cookie: None,
            device: cookie.to_owned(),
            options: StepOptions {
                passkey: start.options,
                password: true,
                email_code: false,
                magic_link: false,
            },
        }))
    }

    /// Whether a session's authentication is fresh enough for `max_age_ms` (TN-44, OIDC
    /// `max_age`).
    #[must_use]
    pub fn fresh_enough(&self, view: &SessionView, max_age_ms: u64) -> bool {
        self.now().saturating_sub(view.auth_time_ms) <= max_age_ms
    }
}
