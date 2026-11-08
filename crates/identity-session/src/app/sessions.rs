//! Session use cases (TN-36, TN-50, G57, EP-2, TN-44): check, sign out, sign out everywhere,
//! the session list (S10) and step-up. A session that is not valid issues nothing: no token,
//! no identity assertion (G57).

use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::sessions::{NewFlow, SessionRow};

use super::signin::{Started, StepOptions};
use super::{Auth, audit, decode32, encode, i64_of, partition, u64_of};
use access_identity_account::app::claims::emit;
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::claims::authentication_ended;
use access_identity_account::domain::signal::{Initiator, Signal};
use access_identity_account::ports::AccountTx;

use super::Notifier;
use crate::SessionError;
use crate::domain::assurance::{Aal, AssuranceVector};
use crate::domain::dbsc::{bound_ok, split_cookie};
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
    /// When it last stepped up (OP-149 m.8).
    pub step_up_ms: Option<u64>,
    /// N5: tied to a device key (DBSC, TN-33).
    pub bound: bool,
    /// N5: the device Instance its active binding names, in the session list (X36).
    pub instance: Option<[u8; 16]>,
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
    /// N5: live, but tied to a device key and presented without its live bound cookie; the
    /// browser refreshes it with a proof first (TN-33). Nothing is ended.
    Unbound,
}

pub(crate) fn facts(r: &SessionRow) -> Result<SessionFacts, SessionError> {
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
        step_up_ms: r.step_up_ms.map(u64_of).transpose()?,
        bound: r.dbsc_key.is_some(),
        instance: None,
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
        let (cookie, bound) = split_cookie(cookie);
        let Some(value) = decode32(cookie) else {
            return Ok(Err(SessionStatus::Unknown));
        };
        let Some(row) = tx.session_by_cookie(&cookie_digest(&value)).await? else {
            return Ok(Err(SessionStatus::Unknown));
        };
        match check(&facts(&row)?, now) {
            // TN-33, OP-153 m.3 (y)
            SessionCheck::Valid
                if !bound_ok(
                    row.dbsc_key.is_some(),
                    row.dbsc_cookie.as_ref().map(|(d, e)| (d.as_slice(), *e)),
                    bound.and_then(decode32).map(|b| cookie_digest(&b)),
                    now,
                ) =>
            {
                Ok(Err(SessionStatus::Unbound))
            }
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

    /// Signs this browser out (§12.0.3, §8.5 S10, X36): the session ends and issues nothing
    /// more (G57), and its `authentication` line ends with it, so the Instances it bound meet no
    /// freshness term from this session (§7.1). Other sessions, Instances and delegations are
    /// untouched; the Instances themselves end only by their own `instance.terminate`. The
    /// returned `Set-Cookie` clears the cookie.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sign_out(&self, cookie: &str, correlation: &str) -> Result<String, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        if let Some(value) = decode32(split_cookie(cookie).0)
            && let Some(row) = tx.session_by_cookie(&cookie_digest(&value)).await?
            && tx.end_session(row.id, i64_of(now)?, "logout").await?
        {
            let target = self.external(row.subject)?;
            audit(&mut tx, "session.signed_out", &target, &target, correlation).await?;
            emit(&mut tx, &authentication_ended(row.subject, row.id, now)).await?;
            // TN-41
            let s = Signal::session_revoked(fresh_id()?, row.subject, Initiator::User, now);
            signal(&mut tx, &s).await?;
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
        let now = self.now();
        let mut tx = self.begin().await?;
        let live = tx.live_sessions(subject).await?;
        let epoch = tx
            .end_sessions(subject)
            .await?
            .ok_or(SessionError::Account(
                access_identity_account::AccountError::NotFound,
            ))?;
        // OP-151 m.3 (i)
        access_identity_account::app::events::sessions_ended(&mut tx, &self.realm, subject, epoch)
            .await?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "session.ended_everywhere",
            actor,
            &target,
            correlation,
        )
        .await?;
        for row in live {
            emit(&mut tx, &authentication_ended(subject, row.id, now)).await?;
        }
        // TN-41, MD-7
        let s = Signal::session_revoked(fresh_id()?, subject, Initiator::User, now);
        signal(&mut tx, &s).await?;
        tx.commit().await?;
        Ok(epoch)
    }

    /// N5: ends another sign-in of the same person (S10 "End this sign-in", X36, OP-153 m.3
    /// (y)): the session ends with reason `ended` and issues nothing more. Its device Instance,
    /// if it has one, ends only by its own `instance.terminate`, which the page signs next; the
    /// answer names it. `None` when `target` is not another live session of the subject.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn end_other(
        &self,
        me: &SessionView,
        target: [u8; 16],
        correlation: &str,
    ) -> Result<Option<Option<[u8; 16]>>, SessionError> {
        if target == me.id {
            return Ok(None);
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = tx
            .session_by_id(target)
            .await?
            .filter(|r| r.subject == me.subject && r.ended_ms.is_none());
        let Some(row) = row else {
            return Ok(None);
        };
        let instance = tx.session_instance(row.id).await?;
        if !tx.end_session(row.id, i64_of(now)?, "ended").await? {
            return Ok(None);
        }
        let name = self.external(row.subject)?;
        audit(
            &mut tx,
            "session.ended_elsewhere",
            &name,
            &name,
            correlation,
        )
        .await?;
        emit(&mut tx, &authentication_ended(row.subject, row.id, now)).await?;
        // TN-41
        let s = Signal::session_revoked(fresh_id()?, row.subject, Initiator::User, now);
        signal(&mut tx, &s).await?;
        tx.commit().await?;
        Ok(Some(instance))
    }

    /// N5: why the session behind `cookie` no longer carries the browser, from the closed list
    /// the signed-out page shows (OP-153 m.3 (y)): `password_changed`, `device_mismatch`,
    /// `admin_ended`, `recovery` or `expired`; `None` when the cause is not one of them or the
    /// session is live or unknown, so nothing unverified is said (§8.13).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn signed_out_reason(
        &self,
        cookie: &str,
    ) -> Result<Option<&'static str>, SessionError> {
        let now = self.now();
        let Some(value) = decode32(split_cookie(cookie).0) else {
            return Ok(None);
        };
        let mut tx = self.begin().await?;
        let row = tx.session_by_cookie(&cookie_digest(&value)).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(match row.end_reason.as_deref() {
            Some("password") => Some("password_changed"),
            Some("device") => Some("device_mismatch"),
            Some("admin") => Some("admin_ended"),
            Some("recovery") => Some("recovery"),
            Some(_) => None,
            None => match check(&facts(&row)?, now) {
                SessionCheck::Expired | SessionCheck::IdleExpired => Some("expired"),
                _ => None,
            },
        })
    }

    /// The subject's live sessions, newest first ("Sign-ins & instances", S10).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sessions(&self, subject: [u8; 16]) -> Result<Vec<SessionView>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let rows = tx.live_sessions(subject).await?;
        let mut out = Vec::new();
        for r in rows {
            if check(&facts(&r)?, now) == SessionCheck::Valid {
                let mut v = view(&r)?;
                v.instance = tx.session_instance(r.id).await?;
                out.push(v);
            }
        }
        tx.commit().await?;
        Ok(out)
    }

    /// Starts a step-up for a live session (TN-44): `max_age` is mandatory; the flow must
    /// reach `min_aal` with fresh steps; completion restamps the session, never a new one. The
    /// flow is bound to the browser's flow cookie `device`, a fresh one when it has none.
    /// `Err` carries the status of a session that is not live.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn step_up(
        &self,
        cookie: &str,
        device: Option<&str>,
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
        let (device, fresh) = match device.and_then(decode32) {
            Some(d) => (d, false),
            None => (self.random32()?, true),
        };
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
        let device = encode(&device);
        Ok(Ok(Started {
            handle: encode(&handle),
            set_cookie: fresh.then(|| {
                crate::domain::session::set_cookie(
                    crate::domain::session::FLOW_COOKIE,
                    &device,
                    None,
                )
            }),
            device,
            options: StepOptions {
                passkey: start.options,
                password: true,
                passkey_offered: true,
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
