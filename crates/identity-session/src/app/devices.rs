//! Device Instances and the `auth_context` artifact from a live session (OP-149 m.6, m.8): a
//! single-use challenge, the proof of possession that answers it, the step-up rule both
//! registration and termination need, and the facts the artifact is built from.

use access_identity_account::ports::AccountTx;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use suiss_crypto::cose::PublicKey;

use super::sessions::{SessionStatus, SessionView, view};
use super::{Auth, FlowRef, Notifier, audit, i64_of, load, save};
use crate::SessionError;
use crate::domain::auth_context::{AuthContext, Content};
use crate::domain::device::{
    Assurance, CHALLENGE_TTL_MS, KeyRejection, assurance, instance_key, kid, pop_challenge,
    verify_pop,
};
use crate::domain::flow::{FlowState, Purpose};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// A challenge for a device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The 32 challenge bytes, base64url: the device signs them (see
    /// [`crate::domain::device::pop_payload`]).
    pub challenge: String,
    /// When it stops being accepted, Unix milliseconds.
    pub expires_ms: u64,
}

/// Why a device request was refused; a decision, not an error (OP-64).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceRefusal {
    /// The session is not live.
    Session(SessionStatus),
    /// The session is below AAL2, or its last authentication is older than five minutes.
    Assurance(Assurance),
    /// The challenge is unknown, used, expired or another session's.
    Challenge,
    /// The key or the proof is refused.
    Key(KeyRejection),
}

/// A key the session's device proved it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenKey {
    /// The session.
    pub session: SessionView,
    /// The key.
    pub key: PublicKey,
    /// Its RFC 7638 `kid` (CR-24).
    pub kid: [u8; 32],
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
    /// A single-use challenge for a device key, bound to this session (OP-149 m.6).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn instance_challenge(
        &self,
        cookie: &str,
    ) -> Result<Result<Challenge, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = match self.live_session(&mut tx, cookie, now).await? {
            Ok(r) => r,
            Err(s) => {
                tx.commit().await?;
                return Ok(Err(s));
            }
        };
        let mut state = FlowState::new(Purpose::InstanceKey { session: row.id }, now);
        state.subject = Some(row.subject);
        state.expires_ms = now.saturating_add(CHALLENGE_TTL_MS);
        let challenge = self.session_flow(&mut tx, &state, cookie, now).await?;
        tx.commit().await?;
        Ok(Ok(Challenge {
            challenge,
            expires_ms: state.expires_ms,
        }))
    }

    async fn stepped_up(
        &self,
        tx: &mut D::Tx,
        cookie: &str,
        now: u64,
    ) -> Result<Result<SessionView, DeviceRefusal>, SessionError> {
        let row = match self.live_session(tx, cookie, now).await? {
            Ok(r) => r,
            Err(s) => return Ok(Err(DeviceRefusal::Session(s))),
        };
        let v = view(&row)?;
        match assurance(v.assurance.aal, v.auth_time_ms, now) {
            Assurance::Fresh => Ok(Ok(v)),
            other => Ok(Err(DeviceRefusal::Assurance(other))),
        }
    }

    /// OP-149 m.6: the session is live, AAL2 or more, and authenticated or stepped up within
    /// the last five minutes. Termination checks this before it acts.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn stepped_up_session(
        &self,
        cookie: &str,
    ) -> Result<Result<SessionView, DeviceRefusal>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let out = self.stepped_up(&mut tx, cookie, now).await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Answers a challenge (OP-149 m.6): the session passes the step-up rule, the challenge the
    /// proof names is this session's and still open, `cose_key` is an Ed25519 or P-256 key and
    /// `pop` is its `COSE_Sign1` over that challenge for `issuer`. The challenge is used up by
    /// any answer that reaches it, right or wrong.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn prove_instance_key(
        &self,
        cookie: &str,
        cose_key: &[u8],
        pop: &[u8],
        issuer: &str,
        correlation: &str,
    ) -> Result<Result<ProvenKey, DeviceRefusal>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let session = match self.stepped_up(&mut tx, cookie, now).await? {
            Ok(v) => v,
            Err(r) => {
                tx.commit().await?;
                return Ok(Err(r));
            }
        };
        let Some(bytes) = pop_challenge(pop) else {
            tx.commit().await?;
            return Ok(Err(DeviceRefusal::Challenge));
        };
        let handle = super::encode(&bytes);
        let flow = FlowRef {
            handle: &handle,
            device: cookie,
        };
        let Ok(loaded) = load(&mut tx, &flow, now).await? else {
            tx.commit().await?;
            return Ok(Err(DeviceRefusal::Challenge));
        };
        if loaded.state.purpose
            != (Purpose::InstanceKey {
                session: session.id,
            })
        {
            tx.commit().await?;
            return Ok(Err(DeviceRefusal::Challenge));
        }
        save(&mut tx, &loaded, "done", super::Resume::Clear).await?;
        let proven = instance_key(cose_key).and_then(|key| {
            verify_pop(&key, pop, issuer, &bytes)?;
            Ok(key)
        });
        let key = match proven {
            Ok(k) => k,
            Err(e) => {
                tx.commit().await?;
                return Ok(Err(DeviceRefusal::Key(e)));
            }
        };
        let target = self.external(session.subject)?;
        audit(
            &mut tx,
            "instance.key_proven",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(ProvenKey {
            session,
            kid: kid(&key),
            key,
        }))
    }

    /// The `auth_context` artifact of a live session (OP-149 m.8), bound to `content` when
    /// given. `Err` carries the status of a session that is not live.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn auth_context(
        &self,
        cookie: &str,
        issuer: &str,
        content: Option<Content>,
    ) -> Result<Result<AuthContext, SessionStatus>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = match self.live_session(&mut tx, cookie, now).await? {
            Ok(r) => r,
            Err(s) => {
                tx.commit().await?;
                return Ok(Err(s));
            }
        };
        tx.touch_session(row.id, i64_of(now)?).await?;
        tx.commit().await?;
        let v = view(&row)?;
        AuthContext::of(issuer, &v.id, &v.assurance, v.step_up_ms, content)
            .map(Ok)
            .map_err(|_| SessionError::Corrupt)
    }
}
