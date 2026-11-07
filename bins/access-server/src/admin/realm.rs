//! The realm-admin surface's ports in this process (OP-151 m.2 M1): a realm's slug resolves to
//! its governing domain, a write's AIS key is a live Instance key of that domain from the
//! authority plane's key index, and the realm resources are read and written through the
//! identity plane's `idp.*` path (TN-110, PI-4, INV-2).

use std::fmt::Write as _;
use std::sync::Arc;

use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::ports::{
    Draft, Drafted, Item, JobItem, JobView, Jobs, Listing, NewJob, Pending, RealmResources,
    ResourceKind, ResourceQuery, ResourceWrite, Surfaces, Unavailable, Written,
};
use access_http::api::realm::problem_of;
use access_http::problem::codes;
use access_identity_admin::AdminError;
use access_identity_admin::app::rest::{
    self, Kind, Op, acknowledged_passkeys, compile, default_validity,
};
use access_identity_admin::app::{Admin, Applied, Proposal};
use access_identity_admin::domain::{Change, HOOK_PREFIX, Invalid, WEBHOOK_PREFIX};
use access_identity_admin::ports::{Decider, Governance, Instances};
use access_identity_events::adapters::KekSealer;
use access_identity_oauth::adapters::outbound::{DeclaredTargets, Outbound};
use access_identity_oauth::domain::issuer::RealmBase;
use access_identity_risk::ports::{GeoResolver, GeoStatus};
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Window;
use access_kernel::verify::cose::PublicKey;
use access_store::Pool;
use access_store::admin_jobs;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::tenancy;
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits};

use crate::idp::RealmKeyring;
use crate::ids::CellIds;
use crate::login::RealmKeks;

/// The identity plane behind the realm-admin surface.
pub(crate) struct Realms<P> {
    pub(crate) app: Pool,
    /// Admin listing (OP-27, §17.4.6): the read replica when one is configured, else `app`.
    /// One resource, which a conditional write compares against, is read from `app`.
    pub(crate) reads: Pool,
    pub(crate) router: Pool,
    pub(crate) ids: Arc<CellIds>,
    pub(crate) plane: P,
    pub(crate) base: RealmBase,
    pub(crate) keys: Arc<RealmKeyring>,
    pub(crate) declared: DeclaredTargets,
    /// The platform realm's slug: its governing domain governs the platform-admin surface
    /// (OP-151 m.2 M2); without it the platform surface finds no domain.
    pub(crate) platform: Option<String>,
    /// Fetches sector identifier documents (MD-10, OIDC Core §8.1).
    pub(crate) outbound: Outbound,
    /// Seals hook and webhook keys under the realm KEKs (TN-135, TN-136).
    pub(crate) vault: KekSealer<RealmKeks>,
    /// The process's `GeoIP` source, whose state the signals read states (OP-151 m.3 (o)).
    pub(crate) geo: Arc<dyn GeoResolver>,
}

/// The `GeoIP` source's state as the signals read names it (§8.13): never `configured` unless
/// a source is loaded.
fn geoip(status: &GeoStatus) -> &'static str {
    match status {
        GeoStatus::Ready { .. } => "configured",
        GeoStatus::NotConfigured => "not_configured",
        GeoStatus::Unreadable => "unreadable",
    }
}

/// Largest sector identifier document read.
const MAX_SECTOR_DOCUMENT: usize = 64 * 1024;

fn kind(k: ResourceKind) -> Kind {
    match k {
        ResourceKind::Clients => Kind::Clients,
        ResourceKind::Groups => Kind::Groups,
        ResourceKind::Accounts => Kind::Accounts,
        ResourceKind::UpstreamIdps => Kind::Upstreams,
        ResourceKind::Settings => Kind::Settings,
        ResourceKind::Hooks => Kind::Hooks,
        ResourceKind::Webhooks => Kind::Webhooks,
        ResourceKind::Signals => Kind::Signals,
        ResourceKind::Analytics => Kind::Analytics,
        ResourceKind::Deliveries => Kind::Deliveries,
    }
}

fn unavailable(e: &AdminError) -> Unavailable {
    tracing::warn!(event = "api.realm.unavailable", outcome = "error", error = %e, "realm resources unavailable");
    Unavailable
}

/// A refusal is the write's problem; a failure of a dependency is `503` (MD-8).
fn refusal(e: &AdminError) -> Result<&'static access_http::problem::Code, Unavailable> {
    let code = problem_of(e);
    if code == &codes::UNAVAILABLE {
        Err(unavailable(e))
    } else {
        Ok(code)
    }
}

/// What a write compiled to, in its realm.
struct Compiled {
    tenant: TenantId,
    realm: RealmId,
    change: Change,
    validity: Window,
    body: Value,
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Realms<P> {
    pub(super) fn admin<'a>(
        &'a self,
        ids: &'a access_crypto::opaque_id::IdKey,
    ) -> Admin<'a, P, P, RealmKeyring> {
        self.admin_on(&self.app, ids)
    }

    fn admin_on<'a>(
        &'a self,
        app: &'a Pool,
        ids: &'a access_crypto::opaque_id::IdKey,
    ) -> Admin<'a, P, P, RealmKeyring> {
        Admin {
            app,
            ids,
            decider: &self.plane,
            governance: &self.plane,
            pep: IDENTITY_PEP,
            base: &self.base,
            keys: self.keys.as_ref(),
            // OP-149 m.4: platform product clients are not written on the realm-admin surface
            platform_tenant: None,
            declared: self.declared.clone(),
            vault: Some(&self.vault),
        }
    }

    pub(super) async fn locate(
        &self,
        slug: &str,
    ) -> Result<Option<(TenantId, RealmId)>, Unavailable> {
        let route = tenancy::route_by_slug(&self.router, slug)
            .await
            .map_err(|_| Unavailable)?;
        Ok(route.map(|r| (r.tenant, r.realm)))
    }

    /// The governing domain of the realm `slug` (PI-7, TN-119).
    pub(crate) async fn domain(&self, slug: &str) -> Result<Option<Digest>, Unavailable> {
        let Some((tenant, realm)) = self.locate(slug).await? else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(|_| Unavailable)?;
        let g = access_store::idp::governance(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(g.map(|g| Digest(*g.domain.as_bytes())))
    }

    /// Compiles `w` into its one change (TN-110); `draft` fills in the validity and a new
    /// client's id.
    async fn compile(
        &self,
        ids: &access_crypto::opaque_id::IdKey,
        w: &ResourceWrite,
        draft: bool,
    ) -> Result<Result<Compiled, &'static access_http::problem::Code>, Unavailable> {
        let Some(op) = Op::from_operation(w.operation) else {
            return Ok(Err(&codes::realm::UNKNOWN_OPERATION));
        };
        let Some((tenant, realm)) = self.locate(&w.slug).await? else {
            return Ok(Err(&codes::NOT_FOUND));
        };
        let admin = self.admin(ids);
        let mut body = w.body.clone();
        if let Some(o) = body.as_object_mut()
            && draft
        {
            o.entry(rest::VALIDITY)
                .or_insert_with(|| default_validity(w.now_ms));
            if op == Op::CreateClient && !o.contains_key("client_id") {
                let id = admin.new_client_id().await.map_err(|e| unavailable(&e))?;
                o.insert(
                    "client_id".to_owned(),
                    Value::String(id.as_str().to_owned()),
                );
            }
            // TN-135, TN-136: a new hook's or webhook's id is assigned with its draft
            let assigned = match op {
                Op::RegisterHook => Some(("hook_id", HOOK_PREFIX)),
                Op::RegisterWebhook => Some(("webhook_id", WEBHOOK_PREFIX)),
                _ => None,
            };
            if let Some((member, prefix)) = assigned
                && !o.contains_key(member)
            {
                let id = admin
                    .new_extension_id(prefix)
                    .await
                    .map_err(|e| unavailable(&e))?;
                o.insert(member.to_owned(), Value::String(id));
            }
        }
        let validity = match rest::validity(&body) {
            Ok(v) => v,
            Err(i) => return Ok(Err(problem_of(&AdminError::Invalid(i)))),
        };
        let change = match compile(op, w.key.as_deref(), &body, ids) {
            Ok(c) => c,
            Err(i) => return Ok(Err(problem_of(&AdminError::Invalid(i)))),
        };
        let change = match admin.resolve(tenant, realm, change).await {
            Ok(c) => c,
            Err(e) => return refusal(&e).map(Err),
        };
        // MD-10, OIDC Core §8.1: the sector document lists every redirect URI, on each write
        if let Change::ClientRegister(c) | Change::ClientUpdate(c) = &change
            && let Some(uri) = &c.subject.sector_identifier_uri
            && let Err(i) = self.sector(uri, c).await?
        {
            return Ok(Err(problem_of(&AdminError::Invalid(i))));
        }
        // IDI-4: an RP ID change makes every registered passkey unusable; the caller says so
        if matches!(change, Change::RpId(_)) {
            let n = match admin.passkey_count(tenant, realm).await {
                Ok(n) => n,
                Err(e) => return refusal(&e).map(Err),
            };
            if n > 0 && acknowledged_passkeys(&body) != Some(n) {
                return Ok(Err(problem_of(&AdminError::Invalid(Invalid::PasskeyLoss))));
            }
        }
        Ok(Ok(Compiled {
            tenant,
            realm,
            change,
            validity,
            body,
        }))
    }

    /// Fetches the sector identifier document `uri` through the SSRF-guarded client and checks
    /// it covers `c`'s redirect URIs; unreachable is `503` (MD-8), anything else a refusal.
    async fn sector(
        &self,
        uri: &str,
        c: &access_identity_admin::domain::Client,
    ) -> Result<Result<(), Invalid>, Unavailable> {
        let answer = match self
            .outbound
            .get(uri, "application/json", MAX_SECTOR_DOCUMENT)
            .await
        {
            Ok(a) => a,
            Err(e) if e.transient() => {
                tracing::warn!(event = "api.realm.unavailable", outcome = "error", error = %e, "sector identifier document unreachable");
                return Err(Unavailable);
            }
            Err(_) => return Ok(Err(Invalid::SectorIdentifier)),
        };
        if answer.status != 200 {
            return Ok(Err(Invalid::SectorIdentifier));
        }
        Ok(access_identity_admin::domain::sector_covers(
            &answer.body,
            &c.redirect_uris,
        ))
    }

    fn proposal(
        c: &Compiled,
        nonce: Vec<u8>,
        basis: ExerciseBasis,
        capacity: Capacity,
    ) -> Proposal {
        Proposal {
            tenant: c.tenant,
            realm: c.realm,
            change: c.change.clone(),
            nonce,
            validity: c.validity,
            basis,
            capacity,
            // OP-151 m.2 M1: a REST caller has no realm session; its Instance is the actor
            subject: None,
        }
    }

    async fn draft_inner(&self, w: ResourceWrite) -> Result<Drafted, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let c = match self.compile(&ids, &w, true).await? {
            Ok(c) => c,
            Err(code) => return Ok(Drafted::Rejected(code)),
        };
        let admin = self.admin(&ids);
        let p = Self::proposal(
            &c,
            Vec::new(),
            ExerciseBasis::Anchor(access_kernel::model::Id([0; 16])),
            Capacity::Own,
        );
        let prepared = match admin.prepare(&p).await {
            Ok(p) => p,
            Err(e) => return refusal(&e).map(Drafted::Rejected),
        };
        if prepared.domain != w.domain {
            return Ok(Drafted::Rejected(&codes::NOT_FOUND));
        }
        let intent =
            dcbor::encode(&prepared.intent.to_value(), Limits::CEILING).map_err(|_| Unavailable)?;
        Ok(Drafted::Draft(Draft {
            body: c.body,
            domain: prepared.domain,
            intent,
            intent_digest: prepared.digest,
            pep: IDENTITY_PEP.to_owned(),
        }))
    }

    async fn commit_inner(
        &self,
        w: ResourceWrite,
        caller: WriteCaller,
    ) -> Result<Written, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let compiled = match self.compile(&ids, &w, false).await? {
            Ok(c) => c,
            Err(code) => return Ok(Written::Rejected(code)),
        };
        let admin = self.admin(&ids);
        let statement = &caller.statement;
        let proposal = Self::proposal(
            &compiled,
            statement.nonce.clone(),
            statement.basis,
            statement.capacity,
        );
        let applied = Box::pin(admin.apply(&proposal, caller.ais)).await;
        let (exercise_id, position, secret) = match applied {
            Ok(Applied::Written {
                exercise,
                position,
                secret,
            }) => (exercise, position, secret.map(|s| s.expose().to_owned())),
            Ok(Applied::AlreadyWritten { exercise, position }) => (exercise, position, None),
            Ok(Applied::NotAllowed { .. }) => return Ok(Written::NotAllowed),
            Err(e) => return refusal(&e).map(Written::Rejected),
        };
        let resource = self.after(&ids, &compiled, &w).await;
        Ok(Written::Committed {
            exercise_id,
            position,
            resource,
            secret,
        })
    }

    /// The resource as it is after the write, when the write names one with a view.
    async fn after(
        &self,
        ids: &access_crypto::opaque_id::IdKey,
        c: &Compiled,
        w: &ResourceWrite,
    ) -> Option<Item> {
        let (k, _) = access_http::api::realm::spec(w.operation)?;
        let key = match k {
            ResourceKind::Settings => None,
            _ => w.key.clone().or_else(|| {
                c.body
                    .get(access_http::api::realm::id_member(k))
                    .and_then(Value::as_str)
                    .map(String::from)
            }),
        };
        let read = self
            .admin(ids)
            .read(c.tenant, c.realm, kind(k), key.as_deref(), None, 1)
            .await
            .ok()?;
        read.items
            .into_iter()
            .next()
            .map(|(body, version)| Item { body, version })
    }

    async fn read_inner(&self, q: ResourceQuery) -> Result<Option<Listing>, Unavailable> {
        let Some((tenant, realm)) = self.locate(&q.slug).await? else {
            return Ok(None);
        };
        let ids = self.ids.key().ok_or(Unavailable)?;
        // OP-27: a page of a collection may come from the replica; never a security read
        let pool = if q.key.is_none() {
            &self.reads
        } else {
            &self.app
        };
        let read = self
            .admin_on(pool, &ids)
            .read(
                tenant,
                realm,
                kind(q.kind),
                q.key.as_deref(),
                q.after.as_deref(),
                q.limit,
            )
            .await;
        let geo = (q.kind == ResourceKind::Signals).then(|| geoip(&self.geo.status()));
        match read {
            Ok(r) => Ok(Some(Listing {
                items: r
                    .items
                    .into_iter()
                    .map(|(mut body, version)| {
                        if let (Some(g), Some(o)) = (geo, body.as_object_mut()) {
                            o.insert(String::from("geoip"), Value::String(String::from(g)));
                        }
                        Item { body, version }
                    })
                    .collect(),
                last: r.last,
            })),
            Err(AdminError::NoRealm | AdminError::Invalid(Invalid::NoWebhook)) => Ok(None),
            Err(e) => Err(unavailable(&e)),
        }
    }
}

/// A live Instance key of a governing domain, from the authority plane's key index.
pub(crate) trait LiveKeys: Send + Sync {
    /// The key `kid` while an Instance of `domain` holds it at the head; `None` otherwise.
    fn live_key(
        &self,
        domain: Digest,
        kid: [u8; 32],
    ) -> impl std::future::Future<Output = Result<Option<PublicKey>, Unavailable>> + Send;
}

impl<P> Surfaces for Realms<P>
where
    P: Decider + Governance + Instances + LiveKeys + Clone + Send + Sync + 'static,
{
    async fn domain(&self, scope: &SurfaceScope) -> Result<Option<Digest>, Unavailable> {
        match scope {
            SurfaceScope::Realm(slug) => Realms::domain(self, slug).await,
            // OP-151 m.2 M2, TN-119: the platform surface is governed by the platform realm's domain
            SurfaceScope::Platform => match self.platform.as_deref() {
                Some(slug) => Realms::domain(self, slug).await,
                None => Ok(None),
            },
        }
    }

    async fn instance_key(
        &self,
        domain: Digest,
        kid: [u8; 32],
        _at_ms: u64,
    ) -> Result<Option<PublicKey>, Unavailable> {
        self.plane.live_key(domain, kid).await
    }
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> RealmResources
    for Realms<P>
{
    fn read(&self, query: ResourceQuery) -> Pending<'_, Option<Listing>> {
        Box::pin(self.read_inner(query))
    }

    fn draft(&self, write: ResourceWrite) -> Pending<'_, Drafted> {
        Box::pin(self.draft_inner(write))
    }

    fn commit(&self, write: ResourceWrite, caller: WriteCaller) -> Pending<'_, Written> {
        Box::pin(self.commit_inner(write, caller))
    }
}

/// A job id as the API shows it: the UUID in its hyphenated form.
fn job_text(id: [u8; 16]) -> String {
    let hex = id.iter().fold(String::with_capacity(32), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// The id of a job's text; `None` for anything that is not a UUID in that form.
fn job_id(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.split('-').collect();
    if text.len() != 36 || hex.len() != 32 {
        return None;
    }
    let mut out = [0; 16];
    for (o, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *o = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (job_text(out) == text).then_some(out)
}

fn job_view(j: admin_jobs::JobRow) -> JobView {
    JobView {
        id: job_text(j.id),
        mode: j.mode,
        status: j.status,
        items: j.items,
        committed: j.committed,
        failed: j.failed,
        throttled: j.throttled,
        created_ms: j.created_ms,
        finished_ms: j.finished_ms,
        expires_ms: j.expires_ms,
    }
}

fn store_down(e: &access_store::StoreError) -> Unavailable {
    tracing::warn!(event = "api.realm.unavailable", outcome = "error", error = %e, "job store unavailable");
    Unavailable
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Realms<P> {
    /// A transaction in the realm `slug`'s scope (TN-113); `None` when there is no such realm.
    async fn scoped(&self, slug: &str) -> Result<Option<TenantTx>, Unavailable> {
        let Some((tenant, realm)) = self.locate(slug).await? else {
            return Ok(None);
        };
        TenantTx::begin(&self.app, tenant, realm)
            .await
            .map(Some)
            .map_err(|e| store_down(&e))
    }

    async fn create_job(&self, slug: String, job: NewJob) -> Result<Option<String>, Unavailable> {
        let Some(mut t) = self.scoped(&slug).await? else {
            return Ok(None);
        };
        let id = admin_jobs::create(
            &mut t,
            &admin_jobs::NewJob {
                mode: job.mode,
                actor: job.actor,
                items: &job.items,
                created_ms: job.created_ms,
                expires_ms: job.expires_ms,
            },
        )
        .await
        .map_err(|e| store_down(&e))?;
        t.commit().await.map_err(|e| store_down(&e))?;
        Ok(Some(job_text(id)))
    }

    async fn record_item(&self, slug: String, job: String, i: JobItem) -> Result<(), Unavailable> {
        let id = job_id(&job).ok_or(Unavailable)?;
        let mut t = self.scoped(&slug).await?.ok_or(Unavailable)?;
        let row = admin_jobs::ItemRow {
            index: i.index,
            operation: i.operation,
            key: i.key,
            status: i.status,
            http_status: i.http_status,
            problem: i.problem,
            exercise_id: i.exercise_id,
            position: i.position,
        };
        admin_jobs::record(&mut t, id, &row)
            .await
            .map_err(|e| store_down(&e))?;
        t.commit().await.map_err(|e| store_down(&e))
    }

    async fn finish_job(
        &self,
        slug: String,
        job: String,
        status: &'static str,
        now_ms: u64,
    ) -> Result<(), Unavailable> {
        let id = job_id(&job).ok_or(Unavailable)?;
        let mut t = self.scoped(&slug).await?.ok_or(Unavailable)?;
        admin_jobs::finish(&mut t, id, status, now_ms)
            .await
            .map_err(|e| store_down(&e))?;
        t.commit().await.map_err(|e| store_down(&e))
    }

    async fn read_job(
        &self,
        slug: String,
        job: String,
        now_ms: u64,
    ) -> Result<Option<JobView>, Unavailable> {
        let Some(id) = job_id(&job) else {
            return Ok(None);
        };
        let Some(mut t) = self.scoped(&slug).await? else {
            return Ok(None);
        };
        let j = admin_jobs::job(&mut t, id, now_ms)
            .await
            .map_err(|e| store_down(&e))?;
        t.commit().await.map_err(|e| store_down(&e))?;
        Ok(j.map(job_view))
    }

    async fn job_items(
        &self,
        slug: String,
        job: String,
        after: Option<u32>,
        limit: u32,
    ) -> Result<Vec<JobItem>, Unavailable> {
        let id = job_id(&job).ok_or(Unavailable)?;
        let mut t = self.scoped(&slug).await?.ok_or(Unavailable)?;
        let rows = admin_jobs::items(&mut t, id, after, limit)
            .await
            .map_err(|e| store_down(&e))?;
        t.commit().await.map_err(|e| store_down(&e))?;
        Ok(rows
            .into_iter()
            .map(|r| JobItem {
                index: r.index,
                operation: r.operation,
                key: r.key,
                status: r.status,
                http_status: r.http_status,
                problem: r.problem,
                exercise_id: r.exercise_id,
                position: r.position,
            })
            .collect())
    }
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Jobs for Realms<P> {
    fn create(&self, slug: String, job: NewJob) -> Pending<'_, Option<String>> {
        Box::pin(self.create_job(slug, job))
    }

    fn record(&self, slug: String, job: String, item: JobItem) -> Pending<'_, ()> {
        Box::pin(self.record_item(slug, job, item))
    }

    fn finish(
        &self,
        slug: String,
        job: String,
        status: &'static str,
        now_ms: u64,
    ) -> Pending<'_, ()> {
        Box::pin(self.finish_job(slug, job, status, now_ms))
    }

    fn read(&self, slug: String, job: String, now_ms: u64) -> Pending<'_, Option<JobView>> {
        Box::pin(self.read_job(slug, job, now_ms))
    }

    fn items(
        &self,
        slug: String,
        job: String,
        after: Option<u32>,
        limit: u32,
    ) -> Pending<'_, Vec<JobItem>> {
        Box::pin(self.job_items(slug, job, after, limit))
    }
}

#[cfg(test)]
mod job_ids {
    use super::*;

    // TN-125: a job id reads back only in its one canonical form
    #[test]
    fn job_ids_round_trip_in_one_form() {
        let id = [0xab; 16];
        let text = job_text(id);
        assert_eq!(text, "abababab-abab-abab-abab-abababababab");
        assert_eq!(job_id(&text), Some(id));
        assert_eq!(job_id(&text.to_uppercase()), None);
        assert_eq!(job_id("abababababababababababababababab"), None);
        assert_eq!(job_id("not-a-job"), None);
    }
}
