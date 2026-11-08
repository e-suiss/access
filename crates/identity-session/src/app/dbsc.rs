//! N5: DBSC use cases (TN-33, IDP-22, OP-153 m.3 (y)): the registration offer of a new
//! session, its registration with a key the browser cannot export, and the refresh of the
//! short-lived bound cookie with a fresh proof from that key. A refresh proof from any other
//! key ends the session ("Signed out because this device didn't match the sign-in").

use access_identity_account::ports::AccountTx as _;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::sessions::SessionRow;

use super::Notifier;
use super::{Auth, audit, decode32, encode, i64_of};
use crate::SessionError;
use crate::domain::dbsc::{
    BOUND_COOKIE, CHALLENGE_TTL_MS, COOKIE_TTL_MS, ProofError, parse, split_cookie,
};
use crate::domain::session::{SessionCheck, check, cookie_digest, set_cookie};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// Why a registration or refresh did not tie or renew the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbscRefusal {
    /// No live session behind the cookie.
    NoSession,
    /// The proof is malformed, answers no pending challenge, or carries no key.
    BadProof,
    /// Already tied (registration) or not tied (refresh).
    WrongState,
    /// The refresh proof came from another key; the session was ended.
    DeviceMismatch,
}

/// A tied or renewed session: its id and the bound cookie to set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The session.
    pub session: [u8; 16],
    /// `Set-Cookie` of the bound cookie.
    pub set_cookie: String,
}

fn challenge_digest(text: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(
        &[b"access/dbsc-challenge/v1\0".as_slice(), text.as_bytes()].concat(),
    )
}

fn challenge_matches(row: &SessionRow, jti: &str, now: u64) -> bool {
    let Some((stored, expires_ms)) = &row.dbsc_challenge else {
        return false;
    };
    let live = i64::try_from(now).is_ok_and(|n| n < *expires_ms);
    live && access_crypto::Secret::new(challenge_digest(jti)).ct_eq_bytes(stored)
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
    /// The live session behind `cookie`, tied or not; the bound cookie is not asked for, since
    /// registration and refresh are how it is obtained.
    async fn any_live(
        &self,
        tx: &mut D::Tx,
        cookie: &str,
        now: u64,
    ) -> Result<Option<SessionRow>, SessionError> {
        let Some(value) = decode32(split_cookie(cookie).0) else {
            return Ok(None);
        };
        let Some(row) = tx.session_by_cookie(&cookie_digest(&value)).await? else {
            return Ok(None);
        };
        Ok((check(&super::sessions::facts(&row)?, now) == SessionCheck::Valid).then_some(row))
    }

    async fn fresh_challenge(
        &self,
        tx: &mut D::Tx,
        id: [u8; 16],
        now: u64,
    ) -> Result<Option<String>, SessionError> {
        let text = encode(&self.random32()?);
        let expires = i64_of(now.saturating_add(CHALLENGE_TTL_MS))?;
        Ok(tx
            .dbsc_challenge(id, &challenge_digest(&text), expires)
            .await?
            .then_some(text))
    }

    /// The registration challenge a new session is offered with (TN-33); `None` when the
    /// session is gone.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn dbsc_offer(&self, session: [u8; 16]) -> Result<Option<String>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let out = self.fresh_challenge(&mut tx, session, now).await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Ties the session to the proof's key (TN-33): the proof answers the pending challenge,
    /// names its key and is signed by it. Once only.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn dbsc_register(
        &self,
        cookie: &str,
        proof: &str,
        correlation: &str,
    ) -> Result<Result<Bound, DbscRefusal>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(row) = self.any_live(&mut tx, cookie, now).await? else {
            return Ok(Err(DbscRefusal::NoSession));
        };
        if row.dbsc_key.is_some() {
            return Ok(Err(DbscRefusal::WrongState));
        }
        let checked = parse(proof).and_then(|p| {
            let key = p.key.ok_or(ProofError::Key)?;
            p.verify(&key)?;
            Ok((p, key))
        });
        let Ok((p, key)) = checked else {
            return Ok(Err(DbscRefusal::BadProof));
        };
        if !challenge_matches(&row, &p.jti, now) {
            return Ok(Err(DbscRefusal::BadProof));
        }
        let value = self.random32()?;
        let expires = i64_of(now.saturating_add(COOKIE_TTL_MS))?;
        if !tx
            .dbsc_bind(row.id, &key, i64_of(now)?, &cookie_digest(&value), expires)
            .await?
        {
            return Ok(Err(DbscRefusal::WrongState));
        }
        let target = self.external(row.subject)?;
        audit(
            &mut tx,
            "session.device_bound",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(Bound {
            session: row.id,
            set_cookie: set_cookie(BOUND_COOKIE, &encode(&value), Some(COOKIE_TTL_MS / 1000)),
        }))
    }

    /// A refresh challenge for a tied session (TN-33); `None` when there is no live tied
    /// session behind the cookie.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn dbsc_refresh_challenge(
        &self,
        cookie: &str,
    ) -> Result<Option<([u8; 16], String)>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(row) = self.any_live(&mut tx, cookie, now).await? else {
            return Ok(None);
        };
        if row.dbsc_key.is_none() {
            return Ok(None);
        }
        let out = self.fresh_challenge(&mut tx, row.id, now).await?;
        tx.commit().await?;
        Ok(out.map(|c| (row.id, c)))
    }

    /// Renews a tied session's bound cookie with a proof from its key (TN-33). A proof that
    /// answers the challenge but is signed by another key ends the session with reason
    /// `device`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn dbsc_refresh(
        &self,
        cookie: &str,
        proof: &str,
        correlation: &str,
    ) -> Result<Result<Bound, DbscRefusal>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(row) = self.any_live(&mut tx, cookie, now).await? else {
            return Ok(Err(DbscRefusal::NoSession));
        };
        let Some(stored) = row
            .dbsc_key
            .as_deref()
            .and_then(|k| <[u8; 65]>::try_from(k).ok())
        else {
            return Ok(Err(DbscRefusal::WrongState));
        };
        let Ok(p) = parse(proof) else {
            return Ok(Err(DbscRefusal::BadProof));
        };
        if !challenge_matches(&row, &p.jti, now) {
            return Ok(Err(DbscRefusal::BadProof));
        }
        let target = self.external(row.subject)?;
        if p.verify(&stored).is_err() {
            // OP-153 m.3 (y)
            tx.end_session(row.id, i64_of(now)?, "device").await?;
            audit(
                &mut tx,
                "session.device_mismatch",
                &target,
                &target,
                correlation,
            )
            .await?;
            tx.commit().await?;
            return Ok(Err(DbscRefusal::DeviceMismatch));
        }
        let value = self.random32()?;
        let expires = i64_of(now.saturating_add(COOKIE_TTL_MS))?;
        if !tx
            .dbsc_refresh(row.id, &cookie_digest(&value), expires)
            .await?
        {
            return Ok(Err(DbscRefusal::WrongState));
        }
        tx.commit().await?;
        Ok(Ok(Bound {
            session: row.id,
            set_cookie: set_cookie(BOUND_COOKIE, &encode(&value), Some(COOKIE_TTL_MS / 1000)),
        }))
    }
}
