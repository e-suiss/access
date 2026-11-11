//! The access review period notice (OP-157 m.3 (w), m.18, IDP-39 (3)): when a live campaign's
//! period starts, each manager whose team shows at least one Grant is sent the
//! `review_campaign` Relay body, a link to the view and never a queue. It runs through the jobs
//! table (OP-129 m.2): one job per campaign and period, so one node sends the period's notices
//! once. A team is read at the domain's leader; a node that does not lead the domain leaves the
//! job for the one that does.
//!
//! The managers are the Parties a campaign item names as its issuer: the holder a Grant was
//! issued from, or the root of the Anchor it was issued on, among the live Grants the domain
//! root's lineage holds. A manager without an account has no address and is not sent anything.

use std::collections::BTreeSet;
use std::future::Future;
use std::time::Duration;

use access_authority_core::app::review::Reviewed;
use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::notify::message::Body;
use access_identity_account::notify::notices::queue_body;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, AnchorState, GrantBasis, Root, kind};
use access_kernel::model::Id;
use access_store::Pool;
use access_store::identity::TenantTx;
use access_store::jobs::{claim_kind, complete, schedule};
use access_store::scope::DomainId;
use access_store::tenancy::{RealmRoute, routes};
use suiss_crypto::dcbor::{self, Limits};

/// The job kind: one campaign period of one realm.
pub(crate) const KIND: &str = "review.period";

/// How often a node schedules and claims (PD).
pub(crate) const INTERVAL: Duration = Duration::from_secs(600);

/// How long a claim holds (PD).
const LEASE: Duration = Duration::from_secs(300);

/// Jobs one step claims (PD).
const BATCH: u32 = 16;

/// Where the console shows a manager's campaigns.
pub(crate) const CONSOLE_PATH: &str = "/console/admin/reviews";

const DAY_MS: u64 = 86_400_000;

/// Reads a reviewer's team at the domain's leader.
pub(crate) trait Teams: Send + Sync {
    /// The live Grants in `reviewer`'s lineage in `domain`.
    fn team(
        &self,
        domain: Digest,
        reviewer: Id,
    ) -> impl Future<Output = Result<Vec<Reviewed>, String>> + Send;
}

impl<K, B, S, C> Teams for access_authority_core::adapters::Domains<K, B, S, C>
where
    K: access_authority_core::ports::Keys + Send + Sync,
    B: access_authority_core::ports::Binding + Clone + Send + Sync,
    S: access_authority_core::ports::Salts + Clone + Send + Sync,
    C: access_authority_sequencer::ports::Clock + Clone + Send + Sync,
{
    async fn team(&self, domain: Digest, reviewer: Id) -> Result<Vec<Reviewed>, String> {
        self.review_items(domain, reviewer)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The pools and keys the notice runs over.
pub(crate) struct Inputs<'a, K> {
    /// `access_app`.
    pub(crate) app: &'a Pool,
    /// `access_router`, for the live realms.
    pub(crate) router: &'a Pool,
    /// The realms' KEKs.
    pub(crate) keks: &'a K,
    /// The cell's opaque-id key.
    pub(crate) ids: &'a IdKey,
    /// The management origin the console is served at, when there is one.
    pub(crate) console: Option<&'a str>,
}

/// The period of a campaign first run at `first_ms` every `period_days` that holds `now`: its
/// index and when it ends.
#[must_use]
pub(crate) fn period(first_ms: u64, period_days: u32, now: u64) -> Option<(u64, u64)> {
    let len = u64::from(period_days).checked_mul(DAY_MS)?.max(1);
    let k = now.checked_sub(first_ms)?.checked_div(len)?;
    let due = first_ms.checked_add(k.checked_add(1)?.checked_mul(len)?)?;
    Some((k, due))
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// A job's subject: the realm, the period and the campaign. A campaign's name is lower-case
/// letters, digits and `-`, so `:` separates.
fn subject(realm: &[u8; 16], k: u64, name: &str) -> String {
    format!("{}:{k}:{name}", hex(realm))
}

fn parse(subject: &str) -> Option<(String, u64, String)> {
    let mut parts = subject.splitn(3, ':');
    let realm = parts.next()?.to_owned();
    let k = parts.next()?.parse().ok()?;
    let name = parts.next()?.to_owned();
    Some((realm, k, name))
}

/// The roots of the Anchor `anchor` in `domain`.
async fn roots(app: &Pool, domain: &DomainId, anchor: &Id) -> Result<Vec<Id>, String> {
    let rows = access_store::authority::state_of(app, domain, &[meta::key(kind::ANCHOR, anchor)])
        .await
        .map_err(|e| e.to_string())?;
    let state = rows
        .first()
        .and_then(|r| r.value.as_deref())
        .and_then(|v| dcbor::decode(v, Limits::CEILING).ok())
        .and_then(|v| AnchorState::from_value(&v).ok());
    Ok(match state.map(|s| s.root) {
        Some(Root::Sole(p)) => vec![p],
        Some(Root::Joint { parties, .. }) => parties.into_iter().collect(),
        None => Vec::new(),
    })
}

/// The managers of `domain`'s live Grants, as the domain root's lineage holds them.
async fn managers<T: Teams>(teams: &T, app: &Pool, domain: Digest) -> Result<BTreeSet<Id>, String> {
    let d = DomainId::from_bytes(domain.0);
    let mut out = BTreeSet::new();
    for root in roots(app, &d, &meta::meta_anchor(&domain)).await? {
        for item in teams.team(domain, root).await? {
            match item.basis {
                GrantBasis::Holding(h) => {
                    out.insert(h.holder);
                }
                GrantBasis::Anchor(a) => out.extend(roots(app, &d, &a).await?),
            }
        }
    }
    Ok(out)
}

/// Sends the period `k` notices of campaign `name` in the realm of `route`; how many.
async fn notify<T: Teams, K: access_identity_events::adapters::RealmKek>(
    teams: &T,
    inputs: &Inputs<'_, K>,
    route: &RealmRoute,
    (k, name): (u64, &str),
) -> Result<u32, String> {
    let e = |x: access_store::StoreError| x.to_string();
    let Some(kek) = inputs.keks.kek(route.tenant, route.realm) else {
        return Err(String::from("realm KEK"));
    };
    let mut t = TenantTx::begin(inputs.app, route.tenant, route.realm)
        .await
        .map_err(e)?;
    let governing = access_store::idp::governance(&mut t).await.map_err(e)?;
    let campaign = t
        .review_schedules()
        .await
        .map_err(e)?
        .into_iter()
        .find(|r| r.name == name && r.live);
    t.commit().await.map_err(e)?;
    let (Some(g), Some(c)) = (governing, campaign) else {
        return Ok(0);
    };
    let Some(due_ms) = u64::from(c.period_days)
        .checked_mul(DAY_MS)
        .and_then(|len| len.checked_mul(k.checked_add(1)?))
        .and_then(|d| c.first_ms.checked_add(d))
    else {
        return Ok(0);
    };
    let domain = Digest(*g.domain.as_bytes());
    let link = match inputs.console {
        Some(origin) => format!("{}{CONSOLE_PATH}", origin.trim_end_matches('/')),
        None => format!("{}{CONSOLE_PATH}", route.issuer.trim_end_matches('/')),
    };
    let mut counted = Vec::new();
    for m in managers(teams, inputs.app, domain).await? {
        let items = teams.team(domain, m).await?.len();
        if items > 0 {
            counted.push((m, u32::try_from(items).unwrap_or(u32::MAX)));
        }
    }
    let mut sent = 0_u32;
    let mut t = TenantTx::begin(inputs.app, route.tenant, route.realm)
        .await
        .map_err(e)?;
    for (m, items) in counted {
        let Some(subject) = access_store::idp::party_subject(&mut t, &m.0)
            .await
            .map_err(e)?
        else {
            continue;
        };
        // OP-157 m.3 (w), m.18
        let body = Body::ReviewCampaign {
            campaign: c.name.clone(),
            items,
            link: Secret::new(link.clone()),
            due_ms,
        };
        if queue_body(
            &mut t,
            (&*kek, inputs.ids),
            &SystemEntropy,
            &SystemClock,
            subject,
            body,
        )
        .await
        .map_err(|x| x.to_string())?
        .is_some()
        {
            sent = sent.saturating_add(1);
        }
    }
    t.commit().await.map_err(e)?;
    Ok(sent)
}

/// Schedules the running period of every live campaign of every live realm and sends the
/// notices of the periods this node claims; how many were sent.
///
/// # Errors
/// A store failure reading the realms or the jobs table.
pub(crate) async fn step<T: Teams, K: access_identity_events::adapters::RealmKek>(
    teams: &T,
    inputs: &Inputs<'_, K>,
    worker: &str,
    now: u64,
) -> Result<u32, String> {
    let e = |x: access_store::StoreError| x.to_string();
    let live = routes(inputs.router).await.map_err(e)?;
    for r in &live {
        let mut t = TenantTx::begin(inputs.app, r.tenant, r.realm)
            .await
            .map_err(e)?;
        let campaigns = t.review_schedules().await.map_err(e)?;
        t.commit().await.map_err(e)?;
        for c in campaigns.iter().filter(|c| c.live) {
            let Some((k, _)) = period(c.first_ms, c.period_days, now) else {
                continue;
            };
            let s = subject(r.realm.as_bytes(), k, &c.name);
            schedule(inputs.app, KIND, &s, &format!("{KIND}:{s}"), Duration::ZERO)
                .await
                .map_err(e)?;
        }
    }
    let mut sent = 0_u32;
    for job in claim_kind(inputs.app, worker, KIND, BATCH, LEASE)
        .await
        .map_err(e)?
    {
        let found = parse(&job.subject).and_then(|(realm, k, name)| {
            live.iter()
                .find(|r| hex(r.realm.as_bytes()) == realm)
                .map(|r| (r, k, name))
        });
        let done = match found {
            None => true,
            Some((route, k, name)) => match notify(teams, inputs, route, (k, &name)).await {
                Ok(n) => {
                    sent = sent.saturating_add(n);
                    true
                }
                Err(error) => {
                    tracing::warn!(%error, job = KIND, "review period notice not sent; retried");
                    false
                }
            },
        };
        if done {
            complete(inputs.app, job.id, worker).await.map_err(e)?;
        }
    }
    Ok(sent)
}

/// Runs [`step`] every [`INTERVAL`] until the task is aborted.
pub(crate) async fn run<T: Teams, K: access_identity_events::adapters::RealmKek>(
    teams: std::sync::Arc<T>,
    (app, router): (Pool, Pool),
    (keks, ids): (K, std::sync::Arc<crate::ids::CellIds>),
    (console, worker): (Option<String>, String),
) {
    let mut every = tokio::time::interval(INTERVAL);
    loop {
        every.tick().await;
        let Some(key) = ids.key() else {
            continue;
        };
        let Ok(now) = access_store::authority::server_time(&app).await else {
            continue;
        };
        let inputs = Inputs {
            app: &app,
            router: &router,
            keks: &keks,
            ids: &key,
            console: console.as_deref(),
        };
        if let Err(error) = step(&*teams, &inputs, &worker, now).await {
            tracing::warn!(%error, job = KIND, "review period notices not run");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-157 m.3 (w), m.18
    #[test]
    fn a_period_is_counted_from_the_first_run() {
        let first = 1_000;
        assert_eq!(period(first, 7, first), Some((0, first + 7 * DAY_MS)));
        assert_eq!(
            period(first, 7, first + 7 * DAY_MS),
            Some((1, first + 14 * DAY_MS))
        );
        assert_eq!(period(first, 7, first - 1), None);
        let s = subject(&[0xab; 16], 3, "q4-review");
        assert_eq!(
            parse(&s),
            Some((hex(&[0xab; 16]), 3, String::from("q4-review")))
        );
    }
}
