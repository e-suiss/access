//! The HR-sourced lifecycle (OP-156 m.3 (q), IDP-35, TN-95, TN-109, AG-41): `idp.hr.*` changes
//! written under their committed ALLOW, an import's records written in the decision's
//! transaction, and the HR job.
//!
//! The job runs every 5 minutes. It states each record version's values as the source's HR
//! Claims through Claim Ingest, unsigned over the source's own channel with the source's issuer
//! Party, and applies the start and end dates that came:
//! - on the start date a `staged` account becomes active and gets a one-use passkey setup
//!   invitation for 7 days through Relay;
//! - on the end date the account is suspended, its sessions end at a new `session_epoch` with
//!   the CAEP `session-revoked`, and each agent it sponsored alone is suspended (AG-41).
//!
//! Nothing here writes a Grant or any authority state: an HR Claim selects holders only through
//! the domain's own `subject-selection` Acceptance of the source's issuer (INV-16).

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::accounts::status_moved;
use access_identity_account::app::hr::{self as records, Next};
use access_identity_account::app::vault::Vault;
use access_identity_account::app::{Actor, Named, Naming as _, Realm};
use access_identity_account::domain::claims::{ClaimOrder, Placement};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::AccountTx as _;
use access_identity_events::domain::catalog::{HrChange as DueChange, IdentityEvent};
use access_internal_api::claims::{
    Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict, Quarantine,
};
use access_internal_api::idp::Unavailable;
use access_kernel::claim::{self, Channel, Unsigned};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;
use access_store::Pool;
use access_store::hr::{DueRow, SourceRow};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{self, Bound};
use access_store::issuer::{self as issued, IssuedClaim};
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::hr::{HrChange, HrImport};

/// Digest context of an HR source's issuer Party.
pub const ISSUER_CONTEXT: &str = "access/hr-issuer/v1";

/// Digest context of an HR source's Claim channel.
pub const CHANNEL_CONTEXT: &str = "access/hr-channel/v1";

/// How often the HR job runs (OP-156 m.3 (q)): every 5 minutes.
pub const INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// The actor the HR job's audit rows name.
pub const JOB_ACTOR: &str = "hr-job";

/// Realms, people and dates the job takes per run.
const BATCH: u32 = 256;

/// The issuer Party of source `name` of the transaction's realm: the same for every version of
/// it, different for every realm and name.
///
/// # Errors
/// [`AdminError::NoRealm`] outside a realm.
pub fn issuer_party(t: &TenantTx, name: &str) -> Result<[u8; 16], AdminError> {
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let mut input = t.tenant().as_bytes().to_vec();
    input.extend_from_slice(realm.as_bytes());
    input.extend_from_slice(name.as_bytes());
    let d = suiss_crypto::digest::context_digest(ISSUER_CONTEXT, &input).0;
    let mut id = [0; 16];
    id.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    Ok(id)
}

/// The unsigned Claim channel of a source with issuer Party `issuer`: its HR Claims are
/// attributable to it and to nothing else (L2-CLM-5).
#[must_use]
pub fn channel(issuer: &[u8; 16]) -> Channel {
    Channel::Scim(suiss_crypto::digest::context_digest(CHANNEL_CONTEXT, issuer).0)
}

async fn live_source(t: &mut TenantTx, name: &str) -> Result<SourceRow, AdminError> {
    t.hr_source(name)
        .await?
        .filter(|s| s.live)
        .ok_or_else(|| Invalid::NoHrSource.into())
}

/// What must hold now for `change`: a new source's or connector's name was never used; a
/// retired one, an import's source and a connector's source are live.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &HrChange) -> Result<(), AdminError> {
    match change {
        HrChange::SourceRegister(name) => {
            if t.hr_source(name).await?.is_some() {
                return Err(Invalid::HrSourceExists.into());
            }
        }
        HrChange::SourceRetire(name) => {
            live_source(t, name).await?;
        }
        HrChange::Import(i) => {
            live_source(t, &i.source).await?;
        }
        HrChange::ConnectorRegister { name, source, .. } => {
            if t.hr_connectors().await?.iter().any(|c| c.name == *name) {
                return Err(Invalid::HrConnectorExists.into());
            }
            live_source(t, source).await?;
        }
        HrChange::ConnectorRetire(name) => {
            if !t
                .hr_connectors()
                .await?
                .iter()
                .any(|c| c.name == *name && c.live)
            {
                return Err(Invalid::NoHrConnector.into());
            }
        }
    }
    Ok(())
}

/// Writes `change` under `bound`; an import's records follow in [`import`].
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &HrChange,
) -> Result<bool, AdminError> {
    match change {
        HrChange::SourceRegister(name) => {
            let issuer = issuer_party(t, name)?;
            t.put_hr_source(bound, name, true, &issuer).await?;
        }
        HrChange::SourceRetire(name) => {
            let row = live_source(t, name).await?;
            t.put_hr_source(bound, name, false, &row.issuer).await?;
        }
        HrChange::ConnectorRegister {
            name,
            source,
            vendor,
        } => {
            t.put_hr_connector(bound, name, true, (source, vendor))
                .await?;
        }
        HrChange::ConnectorRetire(name) => {
            let row = t
                .hr_connectors()
                .await?
                .into_iter()
                .find(|c| c.name == *name)
                .ok_or(Invalid::NoHrConnector)?;
            t.put_hr_connector(bound, name, false, (&row.source, &row.vendor))
                .await?;
        }
        HrChange::Import(i) => {
            t.insert_hr_import(bound, &i.source, (i.format.name(), &i.file, i.records))
                .await?;
        }
    }
    Ok(true)
}

/// Writes the records of import `i` bound by `bound` in the decision's transaction `t` with the
/// realm's vault: one bad write rolls back the decision's whole application (OP-156 m.3 (q)).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn import(
    t: &mut PgTx,
    (vault, ids): (Vault, &IdKey),
    i: &HrImport,
    (bound, exercise, now): (&Bound, &Digest, u64),
) -> Result<records::Imported, AdminError> {
    let tenant = t.0.tenant();
    let realm_id = t.0.realm().ok_or(AdminError::NoRealm)?;
    let kek = vault.kek.clone();
    t.1 = Some(vault);
    let realm = Realm {
        tenant,
        realm: realm_id,
        kek: &*kek,
        ids,
    };
    let correlation = b64url_encode(&exercise.0);
    let who = Actor {
        actor: "idp-decision",
        correlation: &correlation,
    };
    let out = records::apply(t, &realm, (&i.source, bound), &i.lines, (now, &who))
        .await
        .map_err(|e| match e {
            access_identity_account::AccountError::Store(s) => AdminError::from(s),
            access_identity_account::AccountError::IdentifierTaken => AdminError::Conflict,
            other => AdminError::Unavailable(format!("hr import: {other}")),
        })?;
    t.1 = None;
    Ok(out)
}

/// The HR sources as administrators read them: issuer Party, status and how many people have a
/// record. A source's HR Claims select through the domain's `subject-selection` Acceptance of
/// its issuer: a role a rule over them holds shows "Sync from HR" (§8.17.9.8).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn sources(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let mut out = Vec::new();
    for s in t.hr_sources().await? {
        if key.is_some_and(|k| k != s.name) {
            continue;
        }
        let people = t.hr_people(&s.name).await?;
        out.push((
            json!({
                "name": s.name,
                "issuer": b64url_encode(&s.issuer),
                "status": if s.live { "live" } else { "retired" },
                "classes": records::CLASSES,
                "people": people,
                "version": s.version,
            }),
            s.position,
        ));
    }
    Ok(out)
}

/// The HR connectors as administrators read them.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn connectors(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    Ok(t.hr_connectors()
        .await?
        .into_iter()
        .filter(|c| key.is_none_or(|k| k == c.name))
        .map(|c| {
            (
                json!({
                    "name": c.name,
                    "source": c.source,
                    "vendor": c.vendor,
                    "status": if c.live { "live" } else { "retired" },
                    "version": c.version,
                }),
                c.position,
            )
        })
        .collect())
}

/// The realm vaults the job seals and opens records with.
pub trait Vaults: Send + Sync {
    /// The realm's vault, or `None` when its keys are not here.
    fn vault(&self, realm: RealmId) -> Option<Vault>;
}

/// What one run of the job did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ran {
    /// HR Claims Claim Ingest answered.
    pub claims: u32,
    /// Start and end dates that came.
    pub due: u32,
    /// ...of which applied.
    pub applied: u32,
}

/// A start date: `status` (`staged` or `pending_user_action`) moves along TN-49 to `active`.
async fn started(
    t: &mut PgTx,
    (named, who): (&Named<'_>, &Actor<'_>),
    subject: [u8; 16],
    status: AccountStatus,
) -> Result<(), Unavailable> {
    let mut from = status;
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        if from == to {
            continue;
        }
        if !t
            .set_status(subject, from, to)
            .await
            .map_err(account_down)?
        {
            return Err(Unavailable(String::from("hr job: status moved")));
        }
        status_moved(t, named, subject, (from, to), who)
            .await
            .map_err(account_down)?;
        from = to;
    }
    Ok(())
}

/// An end date: an account that signs in is suspended, one that never started is deactivated;
/// its sessions end with their signals, and each agent it sponsored alone is suspended (TN-49,
/// TN-41, AG-41). `false` when the account was already out.
async fn ended(
    t: &mut PgTx,
    (named, who): (&Named<'_>, &Actor<'_>),
    (realm, subject): (RealmId, [u8; 16]),
    status: AccountStatus,
    now: u64,
) -> Result<bool, Unavailable> {
    let to = match status {
        AccountStatus::Active | AccountStatus::Locked => AccountStatus::Suspended,
        AccountStatus::Staged | AccountStatus::PendingUserAction => AccountStatus::Deactivated,
        _ => return Ok(false),
    };
    if to == AccountStatus::Deactivated {
        if !t
            .set_status(subject, status, to)
            .await
            .map_err(account_down)?
        {
            return Err(Unavailable(String::from("hr job: status moved")));
        }
        status_moved(t, named, subject, (status, to), who)
            .await
            .map_err(account_down)?;
        return Ok(true);
    }
    if !t
        .set_status(subject, status, to)
        .await
        .map_err(account_down)?
    {
        return Err(Unavailable(String::from("hr job: status moved")));
    }
    // TN-49, TN-41, AG-41
    status_moved(t, named, subject, (status, to), who)
        .await
        .map_err(account_down)?;
    super::agents::sponsor_left(t, realm, subject, now)
        .await
        .map_err(down)?;
    Ok(true)
}

/// The HR job.
pub struct HrJob<'a, I, V> {
    /// `access_app`.
    pub app: &'a Pool,
    /// `access_outbox_reader`, to find the realms with work.
    pub reader: &'a Pool,
    /// Claim Ingest of the authority plane.
    pub ingest: &'a I,
    /// The realms' vaults.
    pub vaults: &'a V,
    /// The cell's opaque id key.
    pub ids: &'a IdKey,
}

fn down(e: impl std::fmt::Display) -> Unavailable {
    Unavailable(format!("hr job: {e}"))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "a map_err adapter takes the error it is handed"
)]
fn account_down(e: access_identity_account::AccountError) -> Unavailable {
    Unavailable(format!("hr job: {e}"))
}

/// What became of one HR Claim order.
enum Issued {
    Answered(ClaimVerdict),
    NoParty,
}

impl<I: ClaimIngest, V: Vaults> HrJob<'_, I, V> {
    async fn sealed(&self, tenant: TenantId, realm: RealmId) -> Result<Option<PgTx>, Unavailable> {
        let Some(vault) = self.vaults.vault(realm) else {
            return Ok(None);
        };
        let t = TenantTx::begin(self.app, tenant, realm)
            .await
            .map_err(down)?;
        Ok(Some(PgTx(t, Some(vault))))
    }

    async fn issue(
        &self,
        (tenant, realm): (TenantId, RealmId),
        source: &SourceRow,
        order: &ClaimOrder,
        now: u64,
    ) -> Result<Issued, Unavailable> {
        let mut tx = TenantTx::begin(self.app, tenant, realm)
            .await
            .map_err(down)?;
        let g = idp::governance(&mut tx)
            .await
            .map_err(down)?
            .ok_or_else(|| Unavailable(String::from("hr job: no realm")))?;
        let Some(party) = idp::subject_party(&mut tx, &order.subject)
            .await
            .map_err(down)?
        else {
            return Ok(Issued::NoParty);
        };
        let supersedes = match &order.line {
            Some(l) => issued::last_in_line(&mut tx, &order.subject, &g.domain, l)
                .await
                .map_err(down)?,
            None => None,
        };
        tx.commit().await.map_err(down)?;
        let p = Placement {
            domain: Digest(*g.domain.as_bytes()),
            issuer: Id(source.issuer),
            subject: Id(party),
            instance: None,
            supersedes: supersedes.map(Id),
            now,
        };
        let prepared = order
            .prepare(&p)
            .map_err(|_| Unavailable(String::from("hr job: order")))?;
        let channel = channel(&source.issuer);
        let bytes = Unsigned {
            statement: prepared.statement,
            channel,
        }
        .to_bytes()
        .map_err(|_| Unavailable(String::from("hr job: encode")))?;
        let id = claim::claim_id(&bytes);
        let verdict = self
            .ingest
            .ingest(ClaimSubmission {
                domain: p.domain,
                carrier: Carrier::Unsigned(channel),
                claim: bytes,
                body: prepared.body,
                evidence: None,
            })
            .await?;
        let disposition = match &verdict {
            ClaimVerdict::Admitted { .. } => String::from("admitted"),
            ClaimVerdict::Quarantined { reason, .. } => format!("quarantined-{}", reason.word()),
            ClaimVerdict::Rejected { code } => format!("rejected-{code}"),
        };
        let mut t = TenantTx::begin(self.app, tenant, realm)
            .await
            .map_err(down)?;
        issued::record_issued(
            &mut t,
            &IssuedClaim {
                subject: order.subject,
                class: &order.class,
                line: order.line.unwrap_or_default(),
                domain: access_store::scope::DomainId::from_bytes(p.domain.0),
                claim: id.0,
                disposition: &disposition,
            },
        )
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(Issued::Answered(verdict))
    }

    /// States the next HR Claims of `(source, person)`; returns how many Claim Ingest answered.
    async fn person(
        &self,
        (tenant, realm): (TenantId, RealmId),
        (source, person): (&str, &[u8; 32]),
        now: u64,
    ) -> Result<u32, Unavailable> {
        let mut answered = 0_u32;
        for _ in 0..8 {
            let Some(mut tx) = self.sealed(tenant, realm).await? else {
                return Ok(answered);
            };
            let row = tx.0.hr_source(source).await.map_err(down)?;
            let next = records::next(&mut tx, source, person, now)
                .await
                .map_err(account_down)?;
            tx.0.commit().await.map_err(down)?;
            let (version, outcome) = match next {
                Next::Done | Next::Wait { .. } => return Ok(answered),
                Next::Skip { version } | Next::Shredded { version } => (version, "skipped"),
                Next::Issue {
                    version, orders, ..
                } => match row.filter(|s| s.live) {
                    None => (version, "skipped"),
                    Some(s) => {
                        let mut quarantined = false;
                        for o in &orders {
                            match self.issue((tenant, realm), &s, o, now).await? {
                                Issued::NoParty => return Ok(answered),
                                Issued::Answered(v) => {
                                    answered = answered.saturating_add(1);
                                    // INV-16, TN-95
                                    quarantined |= matches!(
                                        v,
                                        ClaimVerdict::Quarantined {
                                            reason: Quarantine::SourceNotAccepted,
                                            ..
                                        }
                                    );
                                }
                            }
                        }
                        (version, if quarantined { "quarantined" } else { "issued" })
                    }
                },
            };
            let mut t = TenantTx::begin(self.app, tenant, realm)
                .await
                .map_err(down)?;
            t.hr_record_dealt((source, person, version), outcome, now)
                .await
                .map_err(down)?;
            t.commit().await.map_err(down)?;
        }
        Ok(answered)
    }

    /// Applies one date that came, at most once: its newest version must still be pending.
    async fn apply_due(
        &self,
        (tenant, realm): (TenantId, RealmId),
        due: &DueRow,
        now: u64,
    ) -> Result<bool, Unavailable> {
        let Some(mut t) = self.sealed(tenant, realm).await? else {
            return Ok(false);
        };
        let current =
            t.0.hr_due_of(&due.source, &due.person, &due.change)
                .await
                .map_err(down)?;
        if current.as_ref() != Some(due) {
            return Ok(false);
        }
        let live =
            t.0.hr_source(&due.source)
                .await
                .map_err(down)?
                .is_some_and(|s| s.live);
        let g = idp::governance(&mut t.0)
            .await
            .map_err(down)?
            .ok_or_else(|| Unavailable(String::from("hr job: no realm")))?;
        let subject = due.subject;
        let row = t.subject(subject, true).await.map_err(account_down)?;
        let status = row
            .as_ref()
            .and_then(|r| AccountStatus::parse(&r.status))
            .ok_or_else(|| Unavailable(String::from("hr job: subject")))?;
        let named = Named {
            realm,
            ids: self.ids,
        };
        let correlation = format!("hr:{}:{}", due.source, due.change);
        let who = Actor {
            actor: JOB_ACTOR,
            correlation: &correlation,
        };
        let (change, applied) = if due.change == "start" {
            // a retired source starts nobody; an end still applies (fail-closed)
            let applied = live
                && matches!(
                    status,
                    AccountStatus::Staged | AccountStatus::PendingUserAction
                );
            if applied {
                started(&mut t, (&named, &who), subject, status).await?;
                self.invite(&mut t, (tenant, realm), &g, due, now).await?;
            }
            (DueChange::Start, applied)
        } else {
            let applied = ended(&mut t, (&named, &who), (realm, subject), status, now).await?;
            (DueChange::End, applied)
        };
        t.0.put_hr_due(
            (&due.source, &due.person, &due.change),
            subject,
            due.due_ms,
            if applied { "applied" } else { "void" },
        )
        .await
        .map_err(down)?;
        let account = named.external(subject).map_err(account_down)?;
        t.audit(&access_store::audit::AuditEvent {
            event_type: "hr.record_applied",
            actor: JOB_ACTOR,
            target: &account,
            correlation: &correlation,
        })
        .await
        .map_err(account_down)?;
        let id = access_crypto::random::bytes::<32>().map_err(|_| down("random"))?;
        let event = IdentityEvent::hr_record_due(
            id,
            realm.as_bytes(),
            (&due.source, &account, change),
            due.due_ms,
            now,
        );
        access_identity_events::app::emit(&mut t.0, &event)
            .await
            .map_err(down)?;
        t.0.commit().await.map_err(down)?;
        Ok(applied)
    }

    /// The passkey setup invitation of a person who starts: a one-use reset intent good for 7
    /// days, sent through Relay to their work address (OP-156 m.3 (q), TN-61).
    async fn invite(
        &self,
        t: &mut PgTx,
        (tenant, realm): (TenantId, RealmId),
        g: &idp::Governing,
        due: &DueRow,
        now: u64,
    ) -> Result<(), Unavailable> {
        use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
        use access_identity_account::domain::recovery_token as tokens;
        use access_identity_account::notify::message::{Address, Body, Message};
        use access_identity_account::notify::notifier::OutboxNotifier;
        use access_identity_account::notify::ports::Notifier as _;
        let versions =
            t.0.hr_record_versions(&due.source, &due.person)
                .await
                .map_err(down)?;
        let Some(newest) = versions.last() else {
            return Ok(());
        };
        let Some(record) = records::open(t, newest.subject, &newest.sealed)
            .await
            .map_err(account_down)?
        else {
            return Ok(());
        };
        let Some(base) = g.issuer.as_deref() else {
            return Ok(());
        };
        let token =
            b64url_encode(&access_crypto::random::bytes::<32>().map_err(|_| down("random"))?);
        let expires = now.saturating_add(records::INVITE_TTL_MS);
        t.0.insert_recovery_token(&access_store::recovery::NewToken {
            subject: due.subject,
            kind: tokens::RESET_INTENT,
            token_hash: &tokens::digest(&token),
            attempt: None,
            exercise: None,
            address: None,
            entropy_bits: 256,
            one_time: true,
            at_ms: i64::try_from(now).map_err(down)?,
            expires_ms: i64::try_from(expires).map_err(down)?,
        })
        .await
        .map_err(down)?;
        let vault = t.vault().map_err(account_down)?.clone();
        let named = Realm {
            tenant,
            realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let message = Message {
            subject: due.subject,
            to: Address::Email(record.email),
            locale: None,
            valid_since_ms: None,
            body: Body::PasskeySetupInvite {
                link: access_crypto::Secret::new(format!(
                    "{}/login/recovery#intent={token}",
                    base.trim_end_matches('/')
                )),
                organization: g.slug.clone(),
                expires_at_ms: expires,
            },
        };
        OutboxNotifier::new(&named, &SystemEntropy, &SystemClock)
            .notify(&mut t.0, &message)
            .await
            .map(drop)
            .map_err(down)
    }

    /// One run at `now`: every realm with work states its next HR Claims and applies its dates
    /// that came.
    ///
    /// # Errors
    /// [`Unavailable`]; what was done stays done and the rest runs next time.
    pub async fn run_once(&self, now: u64) -> Result<Ran, Unavailable> {
        let mut ran = Ran::default();
        for (tenant, realm) in access_store::hr::realms_with_work(self.reader, now, BATCH)
            .await
            .map_err(down)?
        {
            let Some(mut tx) = self.sealed(tenant, realm).await? else {
                continue;
            };
            let people = tx.0.hr_unissued(BATCH).await.map_err(down)?;
            let due = tx.0.hr_due_now(now, BATCH).await.map_err(down)?;
            tx.0.commit().await.map_err(down)?;
            for (source, person) in &people {
                let n = self.person((tenant, realm), (source, person), now).await?;
                ran.claims = ran.claims.saturating_add(n);
            }
            for d in &due {
                ran.due = ran.due.saturating_add(1);
                if self.apply_due((tenant, realm), d, now).await? {
                    ran.applied = ran.applied.saturating_add(1);
                }
            }
        }
        tracing::info!(
            event = "hr.job.run",
            due = ran.due,
            applied = ran.applied,
            "HR job ran (OP-156 m.3 (q))"
        );
        Ok(ran)
    }
}
