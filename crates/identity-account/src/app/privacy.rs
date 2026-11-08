//! Data subject rights and the privacy records (OP-153 m.3 (bb)–(ff); IDP-37, TN-51, TN-76,
//! TN-77, TN-78, TN-79, OP-42, OP-43, OP-74, OP-147): preferences and document acceptances with
//! their history, deletion with its cancellation window, tombstone and destruction with proof,
//! the inactivity sweep on its own clock, the user's security history and the person export.
//!
//! Consent and preferences are never authority and never a decision input (IDP-37); a tombstone
//! never feeds a decision, a risk score or a fraud list (TN-76 m.6). Nothing here deletes a row
//! (OP-73): erasure is crypto-shredding of the subject's keys.

use core::time::Duration;

use access_store::audit::AuditEvent;
use access_store::privacy::{DeletionRow, HoldRow, NewAcceptance};
use serde_json::{Map, Value, json};
use suiss_crypto::digest::context_digest;
use suiss_retention::{
    Basis, Class, Decision, Event, Hold, HoldId, HoldKind, HoldScope, Length, Occurrence, Period,
    PolicyVersion, Record, Schedule, SubjectId, TenantId as RetTenant, Timestamp, may_destroy,
};

use crate::AccountError;
use crate::adapters::pg::{PgAccounts, PgTx};
use crate::app::accounts::status_moved;
use crate::app::vault::{self, PiiClass};
use crate::app::{Actor, Realm};
use crate::domain::status::AccountStatus;
use crate::ports::{AccountDb, AccountTx};

/// The channels a preference names (OP-153 m.3 (ee)).
pub const CHANNELS: [&str; 4] = ["email", "sms", "call", "push"];

/// The topics every realm has (OP-153 m.3 (ee)); a realm adds its own with
/// `idp.realm.preference_topics`.
pub const BUILT_IN_TOPICS: [&str; 3] = ["campaign", "newsletter", "product_news"];

/// How a preference or acceptance was given.
pub const METHODS: [&str; 4] = ["self_service", "admin", "import", "app"];

/// The destruction delay after the tombstone (OP-153 m.3 (aa), TN-77): 30 days.
pub const DESTROY_AFTER_S: i64 = 30 * 86_400;

/// The shortest destruction delay a realm may set (TN-77): 24 hours.
pub const DESTROY_AFTER_MIN_S: i64 = 86_400;

/// A data subject request is answered within this many days (KVKK m.13, TN-78).
pub const ANSWER_DAYS: i32 = 30;

/// How far back the user's security history reaches (OP-153 m.3 (ff)): 90 days.
pub const HISTORY_DAYS: i64 = 90;

/// The most entries a security history shows.
pub const HISTORY_LIMIT: i64 = 200;

const PREFERENCE_CONTEXT: &str = "access/preference/v1";
const ACCEPTANCE_CONTEXT: &str = "access/document-acceptance/v1";
const DESTRUCTION_CONTEXT: &str = "access/destruction-proof/v1";

fn hex(b: &[u8]) -> String {
    use core::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

async fn audit(
    tx: &mut PgTx,
    event_type: &str,
    who: &Actor<'_>,
    target: &str,
) -> Result<(), AccountError> {
    tx.audit(&AuditEvent {
        event_type,
        actor: who.actor,
        target,
        correlation: who.correlation,
    })
    .await
}

async fn outbox(tx: &mut PgTx, kind: &str, payload: Value) -> Result<(), AccountError> {
    let id = crate::app::events::new_id()?;
    let bytes = serde_json::to_vec(&json!({
        "id": access_kernel::json::b64url_encode(&id),
        "payload": payload,
    }))
    .map_err(|_| AccountError::Corrupt)?;
    tx.outbox(kind, &bytes).await
}

fn realm_uuid(realm: &Realm<'_>) -> String {
    let b = realm.realm.as_bytes();
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// A live subject's status, or [`AccountError::NotFound`] for a missing or tombstoned one
/// (TN-76 m.2: a deleted account is not found, never "gone").
async fn live(tx: &mut PgTx, subject: [u8; 16], lock: bool) -> Result<AccountStatus, AccountError> {
    let row = tx
        .subject(subject, lock)
        .await?
        .ok_or(AccountError::NotFound)?;
    let status = AccountStatus::parse(&row.status).ok_or(AccountError::Corrupt)?;
    if matches!(status, AccountStatus::Tombstone | AccountStatus::Purging) {
        return Err(AccountError::NotFound);
    }
    Ok(status)
}

/// One preference to set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferenceChange<'a> {
    /// The channel.
    pub channel: &'a str,
    /// The topic.
    pub topic: &'a str,
    /// Granted or withdrawn.
    pub granted: bool,
}

/// The digest of one preference record: what its audit row binds (tamper evidence, IDP-37).
#[must_use]
pub fn preference_digest(account: &str, c: &PreferenceChange<'_>, method: &str) -> [u8; 32] {
    let body = json!({
        "account": account,
        "channel": c.channel,
        "topic": c.topic,
        "granted": c.granted,
        "method": method,
    });
    context_digest(PREFERENCE_CONTEXT, body.to_string().as_bytes()).0
}

/// Records preference changes in one transaction: a row, an audit row binding its digest, and
/// one `preference.changed` event naming the topics (IDP-37, OP-153 m.3 (ee)).
///
/// # Errors
/// [`AccountError::Invalid`] for an unknown channel, topic or method; [`AccountError`].
pub async fn set_preferences(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
    changes: &[PreferenceChange<'_>],
    method: &str,
    who: &Actor<'_>,
) -> Result<(), AccountError> {
    if changes.is_empty()
        || changes.len() > 32
        || !METHODS.contains(&method)
        || changes
            .iter()
            .any(|c| !CHANNELS.contains(&c.channel) || !BUILT_IN_TOPICS.contains(&c.topic))
    {
        return Err(AccountError::Invalid);
    }
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, true).await?;
    let account = realm.external(subject)?;
    let mut topics: Vec<&str> = Vec::new();
    let mut at = 0_i64;
    for c in changes {
        let d = preference_digest(&account, c, method);
        at =
            tx.0.insert_preference(subject, c.channel, c.topic, c.granted, method, &d)
                .await?;
        audit(
            &mut tx,
            "preference.changed",
            who,
            &format!("{account}:pref:{}", hex(&d)),
        )
        .await?;
        if !topics.contains(&c.topic) {
            topics.push(c.topic);
        }
    }
    outbox(
        &mut tx,
        "event.preference.changed",
        json!({
            "realm": realm_uuid(realm),
            "account": account,
            "topics": topics,
            "at": u64::try_from(at).unwrap_or_default(),
        }),
    )
    .await?;
    tx.commit().await
}

/// The subject's preferences as they stand and their history, oldest first.
///
/// # Errors
/// [`AccountError`].
pub async fn preferences(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<Value, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, false).await?;
    let rows = tx.0.preferences(subject).await?;
    tx.commit().await?;
    let mut current: Map<String, Value> = Map::new();
    for c in CHANNELS {
        for t in BUILT_IN_TOPICS {
            current.insert(format!("{c}:{t}"), Value::Bool(false));
        }
    }
    let mut history = Vec::with_capacity(rows.len());
    for r in &rows {
        current.insert(format!("{}:{}", r.channel, r.topic), Value::Bool(r.granted));
        history.push(json!({
            "channel": r.channel,
            "topic": r.topic,
            "granted": r.granted,
            "method": r.method,
            "at": rfc3339(r.changed_ms),
            "record_digest": hex(&r.record_digest),
        }));
    }
    Ok(json!({ "current": current, "history": history }))
}

/// A document acceptance to record.
#[derive(Clone, Copy, Debug)]
pub struct Acceptance<'a> {
    /// Document type, such as `terms`, `privacy`, `kvkk_notice`.
    pub document_type: &'a str,
    /// Version label.
    pub version: &'a str,
    /// SHA-256 of the accepted text.
    pub document_digest: [u8; 32],
    /// Locale of the text.
    pub locale: &'a str,
    /// `click`, `checkbox`, `signature`, `import` or `app`.
    pub method: &'a str,
    /// The client it was accepted in.
    pub client: Option<&'a str>,
}

/// Records a document acceptance, its audit row binding its digest, and `document.accepted`
/// (IDP-37, E60, OP-153 m.3 (ee)).
///
/// # Errors
/// [`AccountError::Invalid`] for a malformed field; [`AccountError`].
pub async fn accept_document(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
    a: &Acceptance<'_>,
    who: &Actor<'_>,
) -> Result<(), AccountError> {
    let word = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '+'))
    };
    if !word(a.document_type, 64)
        || !word(a.version, 64)
        || !word(a.locale, 35)
        || !["click", "checkbox", "signature", "import", "app"].contains(&a.method)
        || a.client.is_some_and(|c| c.is_empty() || c.len() > 255)
    {
        return Err(AccountError::Invalid);
    }
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, true).await?;
    let account = realm.external(subject)?;
    let body = json!({
        "account": account,
        "document_type": a.document_type,
        "version": a.version,
        "document_digest": hex(&a.document_digest),
        "locale": a.locale,
        "method": a.method,
        "client": a.client,
    });
    let record = context_digest(ACCEPTANCE_CONTEXT, body.to_string().as_bytes()).0;
    let at =
        tx.0.insert_acceptance(
            subject,
            &NewAcceptance {
                document_type: a.document_type,
                version: a.version,
                document_digest: &a.document_digest,
                locale: a.locale,
                method: a.method,
                client: a.client,
                record_digest: &record,
            },
        )
        .await
        .map_err(|e| match e {
            access_store::StoreError::Db(_) => AccountError::Invalid,
            other => AccountError::Store(other),
        })?;
    audit(
        &mut tx,
        "document.accepted",
        who,
        &format!("{account}:doc:{}", hex(&record)),
    )
    .await?;
    outbox(
        &mut tx,
        "event.document.accepted",
        json!({
            "realm": realm_uuid(realm),
            "account": account,
            "document": a.document_type,
            "version": a.version,
            "at": u64::try_from(at).unwrap_or_default(),
        }),
    )
    .await?;
    tx.commit().await
}

/// Whether the subject must accept `version` of `document_type` again: it never accepted that
/// version (TN-132, OP-153 m.3 (ee)). A realm marks a version `requires_reacceptance` with
/// `idp.realm.consent_documents`.
///
/// # Errors
/// [`AccountError`].
pub async fn must_accept(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
    document_type: &str,
    version: &str,
) -> Result<bool, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let rows = tx.0.acceptances(subject).await?;
    tx.commit().await?;
    Ok(!rows
        .iter()
        .any(|r| r.document_type == document_type && r.version == version))
}

/// The subject's document acceptances, oldest first: content-free records (E60).
///
/// # Errors
/// [`AccountError`].
pub async fn acceptances(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<Vec<Value>, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let rows = tx.0.acceptances(subject).await?;
    tx.commit().await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "document_type": r.document_type,
                "version": r.version,
                "document_digest": hex(&r.document_digest),
                "locale": r.locale,
                "method": r.method,
                "client": r.client,
                "at": rfc3339(r.accepted_ms),
                "record_digest": hex(&r.record_digest),
            })
        })
        .collect())
}

/// RFC 3339 of Unix milliseconds, UTC.
#[must_use]
pub fn rfc3339(ms: i64) -> Value {
    use time::format_description::well_known::Rfc3339;
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|ns| time::OffsetDateTime::from_unix_timestamp_nanos(ns).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// Who asked for a deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionSource {
    /// A realm administrator's `idp.account.delete`.
    Admin,
    /// The person's own `idp.account.delete`.
    SelfService,
    /// A provisioning `DELETE`.
    Scim,
}

impl DeletionSource {
    const fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::SelfService => "self_service",
            Self::Scim => "scim",
        }
    }
}

/// A scheduled deletion, as the person is told (OP-153 m.3 (bb), X38).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheduled {
    /// When the account is deleted unless cancelled, Unix milliseconds.
    pub effective_ms: i64,
    /// The earliest the personal data's keys are destroyed, Unix milliseconds.
    pub keys_destroyed_after_ms: i64,
}

impl Scheduled {
    /// The honest statement of what happens (X38, CR-32, Ek B 3954): never "deleted
    /// instantly", never "all data gone".
    #[must_use]
    pub fn statement(&self) -> String {
        let day = |ms: i64| {
            rfc3339(ms)
                .as_str()
                .and_then(|s| s.get(..10))
                .map(String::from)
                .unwrap_or_default()
        };
        format!(
            "Your account will be deleted on {}. You can cancel until then. After that, your \
             personal data becomes unreadable no earlier than {}; some records are kept until \
             their legal period ends, and history entries are redacted, not removed.",
            day(self.effective_ms),
            day(self.keys_destroyed_after_ms)
        )
    }
}

/// Schedules the deletion of `subject` after its cancellation window `window_s` (the CT3
/// delay, OP-153 m.3 (bb)) and records the erasure request (TN-78). An open deletion is
/// answered as it stands.
///
/// # Errors
/// [`AccountError::NotFound`] for a missing or already deleted account; [`AccountError`].
pub async fn request_deletion(
    tx: &mut PgTx,
    realm: &impl crate::app::Naming,
    subject: [u8; 16],
    source: DeletionSource,
    exercise: Option<&[u8; 32]>,
    window_s: u64,
    who: &Actor<'_>,
) -> Result<Scheduled, AccountError> {
    live(tx, subject, true).await?;
    let now = i64::try_from(tx.server_time().await?).map_err(|_| AccountError::Corrupt)?;
    let window =
        i64::try_from(window_s.saturating_mul(1_000)).map_err(|_| AccountError::Corrupt)?;
    let effective = now.saturating_add(window);
    if tx
        .0
        .insert_deletion(subject, source.name(), who.actor, exercise, effective)
        .await?
        .is_some()
    {
        tx.0.insert_data_request(subject, "erasure", ANSWER_DAYS)
            .await?;
        audit(
            tx,
            "account.deletion_requested",
            who,
            &realm.external(subject)?,
        )
        .await?;
    }
    let open =
        tx.0.deletions(subject)
            .await?
            .into_iter()
            .rfind(|d| d.cancelled_ms.is_none())
            .ok_or(AccountError::Corrupt)?;
    Ok(Scheduled {
        effective_ms: open.effective_ms,
        keys_destroyed_after_ms: open
            .destroy_after_ms
            .unwrap_or_else(|| open.effective_ms.saturating_add(DESTROY_AFTER_S * 1_000)),
    })
}

/// Cancels the subject's deletion inside its window; false when there is none to cancel.
///
/// # Errors
/// [`AccountError`].
pub async fn cancel_deletion(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
    who: &Actor<'_>,
) -> Result<bool, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, true).await?;
    let done = tx.0.cancel_deletion(subject).await?;
    if done {
        audit(
            &mut tx,
            "account.deletion_cancelled",
            who,
            &realm.external(subject)?,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(done)
}

/// Writes the tombstones that are due (TN-76, TN-78): the account leaves every state that signs
/// in, its sessions end, it becomes `tombstone` with its `account_status` Claim, and its keys
/// wait out the destruction delay. Returns how many were written.
///
/// # Errors
/// [`AccountError`].
pub async fn tombstone_due(
    db: &PgAccounts,
    realm: &Realm<'_>,
    who: &Actor<'_>,
) -> Result<u32, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let due = tx.0.due_tombstones(64).await?;
    let mut n = 0_u32;
    for d in due {
        let row = tx
            .subject(d.subject, true)
            .await?
            .ok_or(AccountError::Corrupt)?;
        let mut from = AccountStatus::parse(&row.status).ok_or(AccountError::Corrupt)?;
        if from.can_move(AccountStatus::Deactivated) {
            if !tx
                .set_status(d.subject, from, AccountStatus::Deactivated)
                .await?
            {
                return Err(AccountError::Corrupt);
            }
            status_moved(
                &mut tx,
                realm,
                d.subject,
                (from, AccountStatus::Deactivated),
                who,
            )
            .await?;
            from = AccountStatus::Deactivated;
        }
        if from == AccountStatus::Deactivated {
            if !tx
                .set_status(d.subject, from, AccountStatus::Tombstone)
                .await?
            {
                return Err(AccountError::Corrupt);
            }
            status_moved(
                &mut tx,
                realm,
                d.subject,
                (from, AccountStatus::Tombstone),
                who,
            )
            .await?;
        }
        if tx.0.mark_deleted(d.id, DESTROY_AFTER_S).await?.is_some() {
            n = n.saturating_add(1);
        }
    }
    tx.commit().await?;
    Ok(n)
}

/// What one destruction pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Destroyed {
    /// Subjects whose keys were destroyed.
    pub destroyed: u32,
    /// Subjects a hold or an unknown state kept.
    pub kept: u32,
}

fn hold_of(tenant: [u8; 16], realm: &Realm<'_>, h: &HoldRow) -> Option<Hold> {
    let scope = match h.scope.as_str() {
        "subject" => HoldScope::Subject(SubjectId::new(subject_ref(realm, h.subject?))),
        "classes" => HoldScope::Classes(
            h.classes
                .iter()
                .map(|c| c.parse::<Class>())
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
        ),
        "tenant" => HoldScope::Tenant,
        _ => return None,
    };
    Some(Hold {
        id: HoldId::new(hex(&h.id)),
        tenant: RetTenant::new(hex(&tenant)),
        scope,
        placed_at: Timestamp::from_unix_millis(u64::try_from(h.placed_ms).ok()?),
        until: h
            .until_ms
            .and_then(|u| u64::try_from(u).ok())
            .map(Timestamp::from_unix_millis),
        kind: match h.kind.as_str() {
            "regulator" => HoldKind::Regulator,
            "law_enforcement" => HoldKind::LawEnforcement,
            _ => HoldKind::Litigation,
        },
        suspicious_activity: h.suspicious_activity,
    })
}

fn subject_ref(realm: &Realm<'_>, subject: [u8; 16]) -> String {
    format!("{}/{}", hex(realm.realm.as_bytes()), hex(&subject))
}

/// The schedule the destruction delay is under: `class` for `delay_s` after the tombstone
/// (OP-153 m.3 (aa), TN-77; Ek C rule resolution per tenant replaces it, OP-147 m.1).
#[must_use]
pub fn schedule(tenant: [u8; 16], class: Class, delay_s: i64) -> Schedule {
    Schedule {
        tenant: RetTenant::new(hex(&tenant)),
        class,
        basis: Basis::new("OP-153 m.3 (aa), TN-77"),
        length: Length::For(Period::Days(
            u32::try_from(delay_s / 86_400).unwrap_or(u32::MAX),
        )),
        start: Event::Removed,
        max: None,
        version: PolicyVersion::new(1),
    }
}

/// Whether every key class of a tombstoned subject may go: `suiss_retention::may_destroy` with
/// the tenant's holds and a fresh snapshot, per class (OP-147 m.2). Anything else keeps it.
pub fn may_destroy_subject(
    tenant: [u8; 16],
    realm: &Realm<'_>,
    d: &DeletionRow,
    holds: &[HoldRow],
    now_ms: u64,
) -> Decision {
    let holds: Vec<Hold> = holds
        .iter()
        .filter_map(|h| hold_of(tenant, realm, h))
        .collect();
    let Some(deleted) = d.deleted_ms.and_then(|m| u64::try_from(m).ok()) else {
        return Decision::Defer(suiss_retention::Defer::UnknownStart);
    };
    let delay = d
        .destroy_after_ms
        .zip(d.deleted_ms)
        .map_or(DESTROY_AFTER_S, |(a, b)| a.saturating_sub(b) / 1_000);
    let mut out = Decision::Destroy;
    for class in [
        PiiClass::Profile,
        PiiClass::Contact,
        PiiClass::SecurityHistory,
    ]
    .map(PiiClass::retention)
    {
        let record = Record {
            tenant: RetTenant::new(hex(&tenant)),
            class,
            subject: Some(SubjectId::new(subject_ref(realm, d.subject))),
            start: Occurrence::At(Timestamp::from_unix_millis(deleted)),
            end: Occurrence::NotYet,
        };
        let decision = may_destroy(
            &schedule(tenant, class, delay),
            &record,
            &holds,
            Some(Duration::ZERO),
            Timestamp::from_unix_millis(now_ms),
        );
        if !decision.is_destroy() {
            out = decision;
            break;
        }
    }
    out
}

/// The destruction proof: `SHA-256("access/destruction-proof/v1" ‖ 0x00 ‖ …)` over the subject,
/// the deletion and the digest of each destroyed wrapped key, so the audit chain proves which
/// keys went without keeping them (TN-77).
#[must_use]
pub fn destruction_proof(
    subject: [u8; 16],
    deletion: [u8; 16],
    shredded: &[(String, Vec<u8>)],
) -> [u8; 32] {
    let mut body = Vec::new();
    body.extend_from_slice(&subject);
    body.extend_from_slice(&deletion);
    for (class, wrapped) in shredded {
        body.extend_from_slice(class.as_bytes());
        body.push(0);
        body.extend_from_slice(&context_digest(DESTRUCTION_CONTEXT, wrapped).0);
    }
    context_digest(DESTRUCTION_CONTEXT, &body).0
}

/// Destroys the keys of tombstoned subjects whose delay ran out and that no hold covers
/// (TN-77, TN-78, OP-74 m.3, OP-147 m.2): the subject becomes `purging`, every class DEK and its
/// own DEK are shredded, the deletion fact is completed with its proof and the audit row binds
/// the proof. The rows, blind indexes and ciphertexts stay (U58, OP-73).
///
/// # Errors
/// [`AccountError`].
pub async fn destroy_due(
    db: &PgAccounts,
    realm: &Realm<'_>,
    who: &Actor<'_>,
) -> Result<Destroyed, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let now = tx.server_time().await?;
    let holds = tx.0.holds().await?;
    let due = tx.0.due_destructions(64).await?;
    let mut out = Destroyed::default();
    for d in due {
        if !may_destroy_subject(*realm.tenant.as_bytes(), realm, &d, &holds, now).is_destroy() {
            out.kept = out.kept.saturating_add(1);
            continue;
        }
        let row = tx
            .subject(d.subject, true)
            .await?
            .ok_or(AccountError::Corrupt)?;
        let from = AccountStatus::parse(&row.status).ok_or(AccountError::Corrupt)?;
        if from == AccountStatus::Tombstone {
            if !tx
                .set_status(d.subject, from, AccountStatus::Purging)
                .await?
            {
                return Err(AccountError::Corrupt);
            }
            status_moved(
                &mut tx,
                realm,
                d.subject,
                (from, AccountStatus::Purging),
                who,
            )
            .await?;
        }
        let shredded = tx.0.shred_subject(d.subject).await?;
        let proof = destruction_proof(d.subject, d.id, &shredded);
        if tx.0.mark_destroyed(d.id, &proof).await? {
            audit(
                &mut tx,
                "account.destroyed",
                who,
                &format!("{}:proof:{}", realm.external(d.subject)?, hex(&proof)),
            )
            .await?;
            out.destroyed = out.destroyed.saturating_add(1);
        }
    }
    tx.commit().await?;
    Ok(out)
}

/// Seals up to `limit` identifiers of the realm still written in plaintext (OP-153 m.3 (aa)).
///
/// # Errors
/// [`AccountError`].
pub async fn seal_plaintext(
    db: &PgAccounts,
    realm: &Realm<'_>,
    limit: i64,
) -> Result<u64, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let v = tx.vault()?.clone();
    let n = vault::seal_plaintext(&mut tx.0, &v, limit).await?;
    tx.commit().await?;
    Ok(n)
}

/// When a realm's inactivity sweep notifies and deactivates (TN-51, OP-153 m.3 (dd)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InactivityPolicy {
    /// Idle seconds before the notice.
    pub notify_after_s: i64,
    /// Idle seconds before deactivation.
    pub deactivate_after_s: i64,
}

impl InactivityPolicy {
    /// Consumers: notice in month 23, deactivation in month 24 (OP-153 m.3 (dd)).
    pub const CONSUMER: Self = Self {
        notify_after_s: 700 * 86_400,
        deactivate_after_s: 730 * 86_400,
    };
    /// Workforce and B2B templates: notice on day 30, deactivation on day 45 (CIS 5.3).
    pub const WORKFORCE: Self = Self {
        notify_after_s: 30 * 86_400,
        deactivate_after_s: 45 * 86_400,
    };
    /// The PCI template's ceiling: deactivation by day 90 (PCI DSS 8.2.6).
    pub const PCI: Self = Self {
        notify_after_s: 75 * 86_400,
        deactivate_after_s: 90 * 86_400,
    };
}

/// What one inactivity sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Accounts told they will be deactivated.
    pub notified: u32,
    /// Accounts deactivated.
    pub deactivated: u32,
}

/// The inactivity sweep (TN-51, OP-153 m.3 (dd)): accounts idle past the policy are deactivated
/// along TN-49 (sessions end, `account_status` Claim, events); those idle past the notice point
/// get an audit row once a sweep. Break-glass accounts are exempt; the sweep never erases
/// anything, the destruction clock is separate (TN-78).
///
/// # Errors
/// [`AccountError`].
pub async fn inactivity_sweep(
    db: &PgAccounts,
    realm: &Realm<'_>,
    policy: InactivityPolicy,
    exempt: &[[u8; 16]],
    who: &Actor<'_>,
) -> Result<Swept, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let statuses = vec![String::from("active"), String::from("locked")];
    let mut out = Swept::default();
    for (subject, _) in
        tx.0.idle_subjects(&statuses, policy.deactivate_after_s, 256)
            .await?
    {
        if exempt.contains(&subject) {
            continue;
        }
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(AccountError::Corrupt)?;
        let from = AccountStatus::parse(&row.status).ok_or(AccountError::Corrupt)?;
        if !from.can_move(AccountStatus::Deactivated)
            || !tx
                .set_status(subject, from, AccountStatus::Deactivated)
                .await?
        {
            continue;
        }
        status_moved(
            &mut tx,
            realm,
            subject,
            (from, AccountStatus::Deactivated),
            who,
        )
        .await?;
        out.deactivated = out.deactivated.saturating_add(1);
    }
    for (subject, _) in
        tx.0.idle_subjects(&statuses, policy.notify_after_s, 256)
            .await?
    {
        if exempt.contains(&subject) {
            continue;
        }
        audit(
            &mut tx,
            "account.inactivity_notice",
            who,
            &realm.external(subject)?,
        )
        .await?;
        out.notified = out.notified.saturating_add(1);
    }
    tx.commit().await?;
    Ok(out)
}

/// The category a security history entry is shown under, or `None` for an audit row the
/// history does not show (OP-43: sign-in, second factor, key, session, OAuth consent).
#[must_use]
pub fn history_category(event_type: &str) -> Option<&'static str> {
    Some(match event_type {
        "session.created" => "sign_in",
        "session.signed_out"
        | "session.ended_others"
        | "session.ended_everywhere"
        | "session.revoked" => "session",
        "session.stepped_up"
        | "credential.totp.enrolled"
        | "credential.recovery_codes.regenerated" => "second_factor",
        "credential.passkey.registered"
        | "credential.removed"
        | "credential.password.set"
        | "credential.changed" => "key",
        "account.locked"
        | "account.suspended"
        | "account.reactivated"
        | "account.deactivated"
        | "account.deletion_requested"
        | "account.deletion_cancelled" => "account",
        t if t.starts_with("oauth.consent") => "oauth_consent",
        _ => return None,
    })
}

/// The user's security history (OP-43, OP-153 m.3 (ff)): the last 90 days of sign-in, second
/// factor, key, session and account events, newest first; the address only as the /24 or /48 of
/// the last sign-in; never a risk score or risk signal. Entries are read from the audit log as
/// they were written and never rewritten (XI-21).
///
/// # Errors
/// [`AccountError`].
pub async fn security_history(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<Value, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, false).await?;
    let now = i64::try_from(tx.server_time().await?).map_err(|_| AccountError::Corrupt)?;
    let since = now.saturating_sub(HISTORY_DAYS * 86_400_000);
    let who = realm.external(subject)?;
    let rows = tx.0.history(&who, since, HISTORY_LIMIT).await?;
    let last = tx.0.last_sign_in(subject).await?;
    tx.commit().await?;
    let entries: Vec<Value> = rows
        .iter()
        .filter_map(|r| {
            history_category(&r.event_type)
                .map(|c| json!({"at": rfc3339(r.at_ms), "category": c, "event": r.event_type}))
        })
        .collect();
    let last = last.map(|l| {
        json!({
            "at": rfc3339(l.at_ms),
            "network": l.ip_prefix,
            "country": l.country,
        })
    });
    Ok(json!({
        "days": HISTORY_DAYS,
        "entries": entries,
        "last_sign_in": last,
    }))
}

/// The person export (GDPR Art. 15/20, TN-79, OP-43, OP-153 m.3 (cc)): identifiers, profile,
/// authenticator metadata, sign-in and status history, preferences, document acceptances,
/// data requests and deletions. Observed data only: what is derived (risk level, keyed
/// pseudonyms, blind indexes) is left out and named under `derived_excluded`; no password hash,
/// TOTP seed, recovery code or WebAuthn private material is ever read (TN-79).
///
/// # Errors
/// [`AccountError`].
pub async fn person_export(
    db: &PgAccounts,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<Value, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    live(&mut tx, subject, false).await?;
    let v = tx.vault()?.clone();
    let mut identifiers = Vec::new();
    for row in tx.0.identifiers(subject).await? {
        let value = vault::reveal(&mut tx.0, &v, subject, &row.stored).await?;
        identifiers.push(json!({
            "kind": row.kind,
            "value": value,
            "live": row.live,
            "added_at": rfc3339(row.created_ms),
        }));
    }
    let profile: Map<String, Value> = vault::profile(&mut tx.0, &v, subject)
        .await?
        .into_iter()
        .map(|(k, val)| (k, Value::String(val)))
        .collect();
    let authenticators: Vec<Value> =
        tx.0.authenticator_metadata(subject)
            .await?
            .iter()
            .map(|a| {
                json!({
                    "kind": a.kind,
                    "algorithm": a.algorithm,
                    "status": a.status,
                    "added_at": rfc3339(a.created_ms),
                    "last_used_at": a.last_used_ms.map_or(Value::Null, rfc3339),
                })
            })
            .collect();
    let sessions: Vec<Value> =
        tx.0.session_metadata(subject, 500)
            .await?
            .iter()
            .map(|s| {
                json!({
                    "started_at": rfc3339(s.created_ms),
                    "authenticated_at": rfc3339(s.auth_time_ms),
                    "ended_at": s.ended_ms.map_or(Value::Null, rfc3339),
                    "end_reason": s.end_reason,
                })
            })
            .collect();
    let who = realm.external(subject)?;
    let status_history: Vec<Value> =
        tx.0.history(&who, 0, 1_000)
            .await?
            .iter()
            .filter(|r| r.event_type.starts_with("account."))
            .map(|r| json!({"at": rfc3339(r.at_ms), "event": r.event_type}))
            .collect();
    let requests: Vec<Value> =
        tx.0.data_requests(Some(subject), false, [0; 16], 1_000)
            .await?
            .iter()
            .map(|r| {
                json!({
                    "kind": r.kind,
                    "received_at": rfc3339(r.received_ms),
                    "due_at": rfc3339(r.due_ms),
                    "answered_at": r.answered_ms.map_or(Value::Null, rfc3339),
                    "outcome": r.outcome,
                })
            })
            .collect();
    let row = tx
        .subject(subject, false)
        .await?
        .ok_or(AccountError::Corrupt)?;
    tx.commit().await?;
    let preferences = preferences(db, realm, subject).await?;
    let documents = acceptances(db, realm, subject).await?;
    Ok(json!({
        "format": "urn:suiss:access:person-export:1",
        "account": {"id": who, "status": row.status},
        "identifiers": identifiers,
        "profile": profile,
        "authenticators": authenticators,
        "sessions": sessions,
        "status_history": status_history,
        "preferences": preferences,
        "documents": documents,
        "data_requests": requests,
        "derived_excluded": ["risk_level", "ip_pseudonym", "identifier_index"],
    }))
}
