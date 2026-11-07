//! The console BFF's session store in PostgreSQL (TN-128, TN-129, OP-151 m.12 (b)): rows in
//! `access_ops.console_sessions`, ended softly (OP-73). A session is revoked when its subject's
//! `session_epoch` moved past the one it opened under or the account cannot authenticate (TN-50,
//! MD-7). Any store failure is `503` (Ek B "BFF session store failure is fail-closed"). The
//! signed-in user's own profile is the realm's account view of the subject (Ek B 3089).

use std::sync::Arc;

use access_http::console::ports::{
    ConsoleSession, ConsoleSessions, NewConsoleSession, Profiles, SessionInstance, SessionSummary,
    SignedIn, Unavailable,
};
use access_identity_account::domain::status::AccountStatus;
use access_identity_admin::app::rest::account_view;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::ports::Directory as _;
use access_identity_session::domain::console::{Binding, ConsoleFacts};
use access_identity_session::domain::device::instance_key;
use access_internal_api::instances::cose_key;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::thumbprint;
use access_store::Pool;
use access_store::console::{self, ConsoleSessionRow, EndReason};
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::ids::CellIds;

/// Most sessions of one account listed.
const MAX_LISTED: u32 = 100;

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

fn signed(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

fn unsigned(ms: i64) -> u64 {
    u64::try_from(ms).unwrap_or(0)
}

/// Console sessions over the application pool.
pub(crate) struct PgConsoleSessions {
    pub(crate) app: Pool,
    pub(crate) directory: PgDirectory,
    pub(crate) ids: Arc<CellIds>,
}

impl PgConsoleSessions {
    /// The subject's epoch now, when the account can authenticate.
    async fn epoch(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> Result<Option<i64>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let s = t.subject(subject, false).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(s.filter(|s| {
            AccountStatus::parse(&s.status).is_some_and(AccountStatus::can_authenticate)
        })
        .map(|s| s.session_epoch))
    }

    async fn session(&self, row: ConsoleSessionRow) -> Result<ConsoleSession, Unavailable> {
        let binding = Binding::decode(&row.binding).ok_or(Unavailable)?;
        let revoked =
            self.epoch(row.tenant, row.realm, row.subject).await? != Some(row.session_epoch);
        let instance = match &row.instance {
            Some((kid, key)) => {
                let key = instance_key(key).map_err(down)?;
                if thumbprint(&key) != *kid {
                    return Err(Unavailable);
                }
                Some(SessionInstance { kid: *kid, key })
            }
            None => None,
        };
        Ok(ConsoleSession {
            id: row.id,
            who: SignedIn {
                realm: row.slug.clone(),
                domain: Digest(row.domain),
                display_name: row.account.clone(),
                account: row.account.clone(),
                subject: row.subject,
                login_session: row.login_session,
                auth_time_ms: row.auth_time_ms,
            },
            facts: ConsoleFacts {
                created_ms: row.created_ms,
                last_seen_ms: row.last_seen_ms,
                revoked,
                ended: row.ended_ms.is_some(),
                binding,
            },
            instance,
            dbsc: row
                .dbsc
                .map(access_identity_session::domain::console::DbscKey),
        })
    }

    async fn row(&self, id: &[u8; 16]) -> Result<Option<ConsoleSessionRow>, Unavailable> {
        console::by_id(&self.app, id).await.map_err(down)
    }
}

impl ConsoleSessions for PgConsoleSessions {
    async fn open(&self, new: NewConsoleSession) -> Result<[u8; 16], Unavailable> {
        let Some(realm) = self.directory.by_slug(&new.who.realm).await.map_err(down)? else {
            return Err(Unavailable);
        };
        let epoch = self
            .epoch(realm.tenant, realm.realm, new.who.subject)
            .await?
            .ok_or(Unavailable)?;
        console::open(
            &self.app,
            &console::NewConsoleSession {
                cookie_digest: &new.cookie_digest,
                tenant: realm.tenant,
                realm: realm.realm,
                subject: new.who.subject,
                login_session: new.who.login_session,
                session_epoch: epoch,
                slug: &new.who.realm,
                domain: &new.who.domain.0,
                account: &new.who.account,
                binding: &new.binding.encode(),
                auth_time_ms: new.who.auth_time_ms,
                now_ms: new.now_ms,
            },
        )
        .await
        .map_err(down)
    }

    async fn find(&self, cookie_digest: [u8; 32]) -> Result<Option<ConsoleSession>, Unavailable> {
        let Some(row) = console::by_cookie(&self.app, &cookie_digest)
            .await
            .map_err(down)?
        else {
            return Ok(None);
        };
        self.session(row).await.map(Some)
    }

    async fn touch(&self, id: [u8; 16], now_ms: u64) -> Result<(), Unavailable> {
        console::touch(&self.app, &id, now_ms)
            .await
            .map(drop)
            .map_err(down)
    }

    async fn end(&self, id: [u8; 16], now_ms: u64) -> Result<(), Unavailable> {
        console::end(&self.app, &id, now_ms, EndReason::SignedOut)
            .await
            .map(drop)
            .map_err(down)
    }

    async fn attach(&self, id: [u8; 16], instance: SessionInstance) -> Result<(), Unavailable> {
        let key = cose_key(&instance.key);
        if console::attach(&self.app, &id, &instance.kid, &key)
            .await
            .map_err(down)?
        {
            Ok(())
        } else {
            Err(Unavailable)
        }
    }

    async fn list(&self, session: &ConsoleSession) -> Result<Vec<SessionSummary>, Unavailable> {
        let Some(row) = self.row(&session.id).await? else {
            return Ok(Vec::new());
        };
        let now = crate::admin::now_ms()?;
        let mut out: Vec<SessionSummary> =
            console::live_of(&self.app, row.tenant, row.realm, &row.subject, MAX_LISTED)
                .await
                .map_err(down)?
                .into_iter()
                .map(|s| SessionSummary {
                    id: s.id,
                    kind: "console",
                    created_ms: s.created_ms,
                    last_seen_ms: s.last_seen_ms,
                })
                .collect();
        let mut t = TenantTx::begin(&self.app, row.tenant, row.realm)
            .await
            .map_err(down)?;
        let logins = t.live_sessions(row.subject).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        out.extend(
            logins
                .into_iter()
                .filter(|s| unsigned(s.expires_ms) > now && s.session_epoch >= s.subject_epoch)
                .take(usize::try_from(MAX_LISTED).unwrap_or(usize::MAX))
                .map(|s| SessionSummary {
                    id: s.id,
                    kind: "login",
                    created_ms: unsigned(s.created_ms),
                    last_seen_ms: unsigned(s.last_seen_ms),
                }),
        );
        Ok(out)
    }

    async fn revoke(
        &self,
        session: &ConsoleSession,
        target: [u8; 16],
        now_ms: u64,
    ) -> Result<bool, Unavailable> {
        let Some(own) = self.row(&session.id).await? else {
            return Ok(false);
        };
        if let Some(t) = self.row(&target).await? {
            let mine = t.tenant == own.tenant && t.realm == own.realm && t.subject == own.subject;
            return if mine {
                console::end(&self.app, &target, now_ms, EndReason::Revoked)
                    .await
                    .map_err(down)
            } else {
                Ok(false)
            };
        }
        let mut t = TenantTx::begin(&self.app, own.tenant, own.realm)
            .await
            .map_err(down)?;
        let ended = match t.session_by_id(target).await.map_err(down)? {
            Some(s) if s.subject == own.subject && s.ended_ms.is_none() => t
                .end_session(target, signed(now_ms), "logout")
                .await
                .map_err(down)?,
            _ => false,
        };
        t.commit().await.map_err(down)?;
        Ok(ended)
    }
}

impl Profiles for PgConsoleSessions {
    async fn profile(
        &self,
        session: &ConsoleSession,
    ) -> Result<Option<serde_json::Value>, Unavailable> {
        let Some(row) = self.row(&session.id).await? else {
            return Ok(None);
        };
        let ids = self.ids.key().ok_or(Unavailable)?;
        let mut t = TenantTx::begin(&self.app, row.tenant, row.realm)
            .await
            .map_err(down)?;
        let account = access_store::idp::realm::account(&mut t, row.subject)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(account.map(|a| {
            let mut view = account_view(&a, &ids);
            if let Some(m) = view.as_object_mut() {
                m.insert("realm".into(), row.slug.clone().into());
            }
            view
        }))
    }
}
