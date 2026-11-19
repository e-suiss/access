//! N5: the sign-in methods of S11 (TN-99, TN-68, OP-148, §8.5 S11): the list, removing one
//! that is not the last, and setting or changing the password. Removing and changing need a
//! recent re-authentication, checked by the caller; a password change ends every sign-in of
//! the person with reason `password` (TN-50, OP-153 m.3 (y)).

use access_identity_account::AccountError;
use access_identity_account::app::Actor;
use access_identity_account::app::accounts::{remove_credential, store_password};
use access_identity_account::app::claims::emit;
use access_identity_account::app::events;
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::claims::authentication_ended;
use access_identity_account::domain::password::Password;
use access_identity_account::domain::signal::{Initiator, Signal};
use access_identity_account::notify::message::Notice;
use access_identity_account::ports::AccountTx as _;
use access_identity_risk::domain::assess::Breach;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::accounts::MethodRow;

use super::{Auth, Notifier};
use crate::SessionError;
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// Why a method change was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodRefusal {
    /// It is the account's last way to sign in (TN-68).
    LastMethod,
    /// No such active method of the account.
    NotFound,
    /// The password is outside policy or on the breach list (§10.2.1).
    PasswordRefused,
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
    /// The subject's active sign-in methods, oldest first.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sign_in_methods(&self, subject: [u8; 16]) -> Result<Vec<MethodRow>, SessionError> {
        let mut tx = self.begin().await?;
        let rows = tx.sign_in_methods(subject).await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// Whether the subject's newest recovery codes still wait for "I saved them".
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovery_codes_pending(&self, subject: [u8; 16]) -> Result<bool, SessionError> {
        let mut tx = self.begin().await?;
        let pending = tx.code_set_pending(subject).await?;
        tx.commit().await?;
        Ok(pending)
    }

    /// Removes one method of the subject unless the account could no longer sign in without it
    /// (TN-68, TN-148), and tells the account's address (TN-148).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn remove_method(
        &self,
        subject: [u8; 16],
        credential: [u8; 16],
        correlation: &str,
    ) -> Result<Result<(), MethodRefusal>, SessionError> {
        let target = self.external(subject)?;
        let who = Actor {
            actor: &target,
            correlation,
        };
        // TN-148
        let mailbox_signs_in = self.policy.email_otp || self.policy.magic_link;
        match remove_credential(
            self.db,
            &self.environment,
            subject,
            credential,
            mailbox_signs_in,
            &who,
        )
        .await
        {
            Ok(()) => {
                let now = self.now();
                let mut tx = self.begin().await?;
                self.account_notice(&mut tx, subject, Notice::MethodRemoved, now)
                    .await?;
                tx.commit().await?;
                Ok(Ok(()))
            }
            Err(AccountError::LastMethod) => Ok(Err(MethodRefusal::LastMethod)),
            Err(AccountError::NotFound) => Ok(Err(MethodRefusal::NotFound)),
            Err(e) => Err(e.into()),
        }
    }

    /// A new secret under the environment's rule: a six-digit PIN that is none of the easily
    /// guessed where the environment uses PINs (TN-157), otherwise a password under the policy
    /// that passes the mandatory breach check (§10.2.1).
    ///
    /// # Errors
    /// [`SessionError`]; a breach list that cannot be read is an error, never a pass.
    pub async fn check_secret(
        &self,
        raw: &str,
    ) -> Result<Result<Password, MethodRefusal>, SessionError> {
        self.check_secret_apart(raw, &[]).await
    }

    /// [`Self::check_secret`] for a PIN that may not repeat the account's own numbers or birth
    /// date in `facts` (TN-158 (7)).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn check_secret_apart(
        &self,
        raw: &str,
        facts: &[String],
    ) -> Result<Result<Password, MethodRefusal>, SessionError> {
        if self.policy.pin {
            let facts: Vec<&str> = facts.iter().map(String::as_str).collect();
            return Ok(
                Password::pin_apart_from(raw, &facts).map_err(|_| MethodRefusal::PasswordRefused)
            );
        }
        let Ok(password) = Password::new(raw) else {
            return Ok(Err(MethodRefusal::PasswordRefused));
        };
        match self.risk.services.breach.check(&password).await {
            Breach::Clean => Ok(Ok(password)),
            Breach::Listed => Ok(Err(MethodRefusal::PasswordRefused)),
            Breach::Unavailable | Breach::NotChecked => {
                Err(SessionError::Account(AccountError::BreachUnavailable))
            }
        }
    }

    /// Keeps the first secret of an account that has none, checked by [`Self::check_secret`]
    /// (TN-156, TN-157): a phone sign-up's PIN or password; no session ends.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn store_first_secret(
        &self,
        subject: [u8; 16],
        password: &Password,
        correlation: &str,
    ) -> Result<(), SessionError> {
        let phc = self.hasher.hash(password, self.random.salt()?).await?;
        let target = self.external(subject)?;
        let who = Actor {
            actor: &target,
            correlation,
        };
        let mut tx = self.begin().await?;
        store_password(&mut tx, &self.environment, subject, phc.expose(), &who).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Sets or changes the subject's password (§10.2.1): policy, the mandatory breach check,
    /// Argon2id; then every sign-in of the person ends with reason `password` (TN-50).
    ///
    /// # Errors
    /// [`SessionError`]; a breach list that cannot be read is an error, never a pass.
    pub async fn change_password(
        &self,
        subject: [u8; 16],
        raw: &str,
        correlation: &str,
    ) -> Result<Result<(), MethodRefusal>, SessionError> {
        let facts = {
            let mut tx = self.begin().await?;
            let f = tx.secret_facts(subject).await?;
            tx.commit().await?;
            f
        };
        let password = match self.check_secret_apart(raw, &facts).await? {
            Ok(p) => p,
            Err(r) => return Ok(Err(r)),
        };
        let phc = self.hasher.hash(&password, self.random.salt()?).await?;
        let now = self.now();
        let target = self.external(subject)?;
        let who = Actor {
            actor: &target,
            correlation,
        };
        let mut tx = self.begin().await?;
        store_password(&mut tx, &self.environment, subject, phc.expose(), &who).await?;
        let ended = tx.live_sessions(subject).await?;
        // TN-50, OP-153 m.3 (y)
        let epoch = tx
            .end_sessions_because(subject, "password")
            .await?
            .ok_or(SessionError::Account(AccountError::NotFound))?;
        events::sessions_ended(&mut tx, &self.environment, subject, epoch).await?;
        for s in ended {
            emit(&mut tx, &authentication_ended(subject, s.id, now)).await?;
        }
        let s = Signal::session_revoked(fresh_id()?, subject, Initiator::User, now);
        signal(&mut tx, &s).await?;
        tx.commit().await?;
        Ok(Ok(()))
    }
}
