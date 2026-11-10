//! The signed-in user's privacy surface (S11, OP-153 m.3 (bb)–(ff); IDP-37, OP-43, TN-78):
//! preferences and their history, document acceptances, the security history, the state of a
//! deletion with its honest statement and its cancellation, and data requests. Consent and
//! preferences are never authority (IDP-37). A session that is not live gets `401`.

use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::Actor;
use access_identity_account::app::privacy::{
    self, Acceptance, PreferenceChange, Scheduled, rfc3339,
};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::ports::Clock;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::ports::{Kits, Messages, RealmKit};

/// One preference in a `PUT /v1/account/preferences`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceItem {
    /// `email`, `sms`, `call` or `push`.
    pub channel: String,
    /// The topic.
    pub topic: String,
    /// Granted or withdrawn.
    pub granted: bool,
}

/// `PUT /v1/account/preferences`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferencesBody {
    /// The changes.
    pub changes: Vec<PreferenceItem>,
}

/// `POST /v1/account/documents`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentBody {
    /// Document type.
    pub document_type: String,
    /// Version label.
    pub version: String,
    /// SHA-256 of the text the person saw, base64url.
    pub document_digest: String,
    /// Locale of the text.
    pub locale: String,
    /// `click`, `checkbox` or `signature`.
    pub method: String,
}

fn account_failed(e: &AccountError) -> Reply {
    if !matches!(e, AccountError::NotFound | AccountError::Invalid) {
        tracing::warn!(error = %e, "privacy step failed");
    }
    Reply::problem(e.problem())
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The realm kit and the live session's subject; `401` without one (G57).
    pub(super) async fn me(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
    ) -> Result<(std::sync::Arc<RealmKit>, [u8; 16]), Reply> {
        let kit = self.kit(entry).await?;
        let Some(cookie) = b.session else {
            return Err(Reply::problem(SESSION_REQUIRED));
        };
        signin!(self, kit, auth);
        match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => Ok((kit.clone(), v.subject)),
            Ok(_) => Err(Reply::problem(SESSION_REQUIRED)),
            Err(e) => Err(failed(&e)),
        }
    }

    fn db(&self, kit: &RealmKit) -> PgAccounts {
        PgAccounts::sealed(self.db.clone(), kit.vault())
    }

    /// `GET /v1/account/preferences`: the preferences as they stand and every change.
    pub async fn preferences(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        match privacy::preferences(&self.db(&kit), &kit.realm(), me).await {
            Ok(v) => Reply::json(200, v),
            Err(e) => account_failed(&e),
        }
    }

    /// `PUT /v1/account/preferences` (IDP-37, OP-153 m.3 (ee)).
    pub async fn set_preferences(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &PreferencesBody,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let actor = match realm.external(me) {
            Ok(a) => a,
            Err(e) => return account_failed(&e),
        };
        let changes: Vec<PreferenceChange<'_>> = body
            .changes
            .iter()
            .map(|c| PreferenceChange {
                channel: &c.channel,
                topic: &c.topic,
                granted: c.granted,
            })
            .collect();
        let who = Actor {
            actor: &actor,
            correlation: b.correlation,
        };
        let db = self.db(&kit);
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        match privacy::set_preferences(&db, &realm, me, &changes, "self_service", &who, &notifier)
            .await
        {
            Ok(()) => match privacy::preferences(&db, &realm, me).await {
                Ok(v) => Reply::json(200, v),
                Err(e) => account_failed(&e),
            },
            Err(e) => account_failed(&e),
        }
    }

    /// `GET /v1/account/documents`: the content-free acceptance records (E60).
    pub async fn documents(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        match privacy::acceptances(&self.db(&kit), &kit.realm(), me).await {
            Ok(v) => Reply::json(200, json!({ "acceptances": v })),
            Err(e) => account_failed(&e),
        }
    }

    /// `POST /v1/account/documents` (IDP-37, TN-132).
    pub async fn accept_document(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        body: &DocumentBody,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let Some(digest) = access_kernel::json::b64url_decode(&body.document_digest)
            .ok()
            .and_then(|d| <[u8; 32]>::try_from(d).ok())
        else {
            return account_failed(&AccountError::Invalid);
        };
        if !["click", "checkbox", "signature"].contains(&body.method.as_str()) {
            return account_failed(&AccountError::Invalid);
        }
        let realm = kit.realm();
        let actor = match realm.external(me) {
            Ok(a) => a,
            Err(e) => return account_failed(&e),
        };
        let who = Actor {
            actor: &actor,
            correlation: b.correlation,
        };
        let a = Acceptance {
            document_type: &body.document_type,
            version: &body.version,
            document_digest: digest,
            locale: &body.locale,
            method: &body.method,
            client: None,
        };
        match privacy::accept_document(&self.db(&kit), &realm, me, &a, &who).await {
            Ok(()) => Reply::new(204, super::Body::Empty),
            Err(e) => account_failed(&e),
        }
    }

    /// `GET /v1/account/security-history` (OP-43): 90 days, the address masked, no risk score.
    pub async fn security_history(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        match privacy::security_history(&self.db(&kit), &kit.realm(), me).await {
            Ok(v) => Reply::json(200, v),
            Err(e) => account_failed(&e),
        }
    }

    /// `GET /v1/account/deletion`: the open deletion with its date and honest statement
    /// (X38, Ek B 3954), or `{"scheduled": false}`.
    pub async fn deletion(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let db = self.db(&kit);
        let open = async {
            let mut tx =
                access_identity_account::ports::AccountDb::begin(&db, kit.tenant, kit.realm)
                    .await?;
            let rows = tx.0.deletions(me).await?;
            access_identity_account::ports::AccountTx::commit(tx).await?;
            Ok::<_, AccountError>(rows.into_iter().rfind(|d| d.cancelled_ms.is_none()))
        };
        match open.await {
            Ok(Some(d)) => {
                let s = Scheduled {
                    effective_ms: d.effective_ms,
                    keys_destroyed_after_ms: d.destroy_after_ms.unwrap_or_else(|| {
                        d.effective_ms
                            .saturating_add(privacy::DESTROY_AFTER_S.saturating_mul(1_000))
                    }),
                };
                Reply::json(
                    200,
                    json!({
                        "scheduled": true,
                        "deleted_on": rfc3339(s.effective_ms),
                        "cancellable": d.deleted_ms.is_none(),
                        "statement": s.statement(),
                    }),
                )
            }
            Ok(None) => Reply::json(200, json!({ "scheduled": false })),
            Err(e) => account_failed(&e),
        }
    }

    /// `DELETE /v1/account/deletion`: cancels a deletion inside its window (OP-153 m.3 (bb)).
    pub async fn cancel_deletion(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let realm = kit.realm();
        let actor = match realm.external(me) {
            Ok(a) => a,
            Err(e) => return account_failed(&e),
        };
        let who = Actor {
            actor: &actor,
            correlation: b.correlation,
        };
        match privacy::cancel_deletion(&self.db(&kit), &realm, me, &who).await {
            Ok(true) => Reply::new(204, super::Body::Empty),
            Ok(false) => account_failed(&AccountError::NotFound),
            Err(e) => account_failed(&e),
        }
    }

    /// `GET /v1/account/data-requests`: the person's requests and their 30-day due dates
    /// (TN-78, Ek B 3953).
    pub async fn data_requests(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let db = self.db(&kit);
        let rows = async {
            let mut tx =
                access_identity_account::ports::AccountDb::begin(&db, kit.tenant, kit.realm)
                    .await?;
            let rows = tx.0.data_requests(Some(me), false, [0; 16], 200).await?;
            access_identity_account::ports::AccountTx::commit(tx).await?;
            Ok::<_, AccountError>(rows)
        };
        match rows.await {
            Ok(rows) => Reply::json(
                200,
                json!({
                    "requests": rows.iter().map(|r| json!({
                        "kind": r.kind,
                        "received_at": rfc3339(r.received_ms),
                        "due_at": rfc3339(r.due_ms),
                        "answered_at": r.answered_ms.map_or(Value::Null, rfc3339),
                        "outcome": r.outcome,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => account_failed(&e),
        }
    }
}
