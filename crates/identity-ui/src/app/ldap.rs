//! Directory app passwords on the account surface (S11, §10.6.3, IDP-16, OP-155 m.3 (n)): the
//! LDAP credential class. One per application, shown once, kept as Argon2id; creating and
//! revoking need a recent sign-in, and the person is told either way. Nothing is deleted
//! (OP-73).

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::ldap::{self, Context, Refused};
use access_identity_account::domain::login::Problem;
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::ports::Clock;
use serde_json::{Value, json};

use super::signup::STEP_UP_MAX_AGE_MS;
use super::{Body, Browser, Hosted, Reply};
use crate::domain::frontend::rfc3339;
use crate::ports::{Kits, Messages, RealmKit};

/// Prefix of an LDAP credential's external id.
pub const LDAP_CREDENTIAL_PREFIX: &str = "ldc";

const NO_CREDENTIAL: Problem = Problem {
    status: 404,
    code: "no-such-ldap-credential",
    title: "That app password isn't on this account",
    retry_after_s: None,
};

const BAD_APPLICATION: Problem = Problem {
    status: 400,
    code: "invalid-application-name",
    title: "Give the app a name of up to 200 characters",
    retry_after_s: None,
};

const TOO_MANY: Problem = Problem {
    status: 409,
    code: "ldap-credential-limit",
    title: "This account has as many app passwords as it can hold. Revoke one first.",
    retry_after_s: None,
};

const INACTIVE: Problem = Problem {
    status: 403,
    code: "account-inactive",
    title: "This account can't sign in right now",
    retry_after_s: None,
};

fn unavailable() -> Reply {
    Reply::problem(Problem {
        status: 503,
        code: "unavailable",
        title: "Temporarily unavailable",
        retry_after_s: Some(1),
    })
}

fn at(ms: Option<i64>) -> Value {
    ms.and_then(|m| u64::try_from(m).ok())
        .map_or(Value::Null, |m| Value::String(rfc3339(m)))
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn ldap_subject(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        fresh: bool,
    ) -> Result<(std::sync::Arc<RealmKit>, [u8; 16]), Reply> {
        let kit = self.kit(entry).await?;
        let (subject, _) = self
            .fresh(&kit, b, fresh.then_some(STEP_UP_MAX_AGE_MS))
            .await?;
        Ok((kit, subject))
    }

    /// `GET /v1/account/ldap-credentials`: the person's app passwords; never a password.
    pub async fn ldap_credentials(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, subject) = match self.ldap_subject(entry, b, false).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let read = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let rows = ldap::list(&mut tx, subject).await?;
            tx.commit().await?;
            Ok::<_, access_identity_account::AccountError>(rows)
        };
        let Ok(rows) = read.await else {
            return unavailable();
        };
        let list: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "id": kit.ids.encode(LDAP_CREDENTIAL_PREFIX, r.id).ok(),
                    "application": r.application,
                    "created_at": at(Some(r.created_ms)),
                    "last_used_at": at(r.last_used_ms),
                    "changed_at": at(r.rotated_ms),
                })
            })
            .collect();
        Reply::json(200, json!({ "credentials": list }))
    }

    /// `POST /v1/account/ldap-credentials`: a new app password for `application`, after a
    /// recent sign-in. The answer carries it once; the directory takes it as `dn=token` or under
    /// the person's own entry.
    pub async fn create_ldap_credential(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        application: &str,
    ) -> Reply {
        let (kit, subject) = match self.ldap_subject(entry, b, true).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let made = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let cx = Context {
                actor: &actor,
                correlation: b.correlation,
                at_ms: tx.server_time().await?,
            };
            let hasher = self.hasher.for_policy(kit.hash);
            let out = ldap::issue(
                &mut tx,
                &hasher,
                &SystemEntropy,
                &notifier,
                subject,
                application,
                cx,
            )
            .await?;
            if out.is_ok() {
                tx.commit().await?;
            }
            Ok::<_, access_identity_account::AccountError>(out)
        };
        match made.await {
            Ok(Ok(issued)) => Reply::json(
                201,
                json!({
                    "id": kit.ids.encode(LDAP_CREDENTIAL_PREFIX, issued.id).ok(),
                    "application": application.trim(),
                    "password": issued.token.expose(),
                    "bind_dn": "dn=token",
                }),
            ),
            Ok(Err(Refused::Application)) => Reply::problem(BAD_APPLICATION),
            Ok(Err(Refused::TooMany)) => Reply::problem(TOO_MANY),
            Ok(Err(Refused::Inactive)) => Reply::problem(INACTIVE),
            Ok(Err(Refused::Missing)) => Reply::problem(NO_CREDENTIAL),
            Err(access_identity_account::AccountError::Busy) => Reply::problem(Problem {
                status: 503,
                code: "busy",
                title: "Too many requests right now. Try again in a moment.",
                retry_after_s: Some(1),
            }),
            Err(_) => unavailable(),
        }
    }

    /// `POST /v1/account/ldap-credentials/{credential}/revoke`: after a recent sign-in.
    pub async fn revoke_ldap_credential(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        credential: &str,
    ) -> Reply {
        let (kit, subject) = match self.ldap_subject(entry, b, true).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Ok(id) = kit.ids.decode(LDAP_CREDENTIAL_PREFIX, credential) else {
            return Reply::problem(NO_CREDENTIAL);
        };
        let realm = kit.realm();
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let actor = kit.ids.encode("usr", subject).unwrap_or_default();
        let done = async {
            let mut tx = PgAccounts::sealed(self.db.clone(), kit.vault())
                .begin(kit.tenant, kit.realm)
                .await?;
            let cx = Context {
                actor: &actor,
                correlation: b.correlation,
                at_ms: tx.server_time().await?,
            };
            let out = ldap::revoke(&mut tx, &notifier, subject, id, cx).await?;
            if out.is_ok() {
                tx.commit().await?;
            }
            Ok::<_, access_identity_account::AccountError>(out)
        };
        match done.await {
            Ok(Ok(())) => Reply::new(204, Body::Empty),
            Ok(Err(_)) => Reply::problem(NO_CREDENTIAL),
            Err(_) => unavailable(),
        }
    }
}
