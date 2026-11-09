//! The realm-admin surface's ports in this process (OP-151 m.2 M1): a realm's slug resolves to
//! its governing domain, a write's AIS key is a live Instance key of that domain from the
//! authority plane's key index, and the realm resources are read and written through the
//! identity plane's `idp.*` path (TN-110, PI-4, INV-2).

use std::fmt::Write as _;
use std::sync::Arc;

use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::ports::{
    AuditFormat, AuditProofQuery, AuditQuery, Draft, Drafted, Item, JobItem, JobView, Jobs,
    Listing, MetaTarget, NewJob, Pending, RealmResources, ResourceKind, ResourceQuery,
    ResourceWrite, Surfaces, Unavailable, Written,
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
    /// The checkpointer role, which alone reads when an audit row was checkpointed (OP-38).
    pub(crate) checkpointer: Pool,
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
    /// The cell's address pseudonyms: a console device registration's bootstrap rate context
    /// (OP-152 m.5 (b)).
    pub(crate) ips: Arc<dyn access_identity_risk::ports::IpPseudonyms>,
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
        ResourceKind::SocialProviders => Kind::Socials,
        ResourceKind::Organizations => Kind::Organizations,
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
            // OP-149 m.4
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
            // TN-135, TN-136
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
        // OP-153 m.18 (e)
        if op == Op::BindAccount
            && let Some(o) = body.as_object_mut()
        {
            let Some(peer) = o
                .get("peer_realm")
                .and_then(Value::as_str)
                .map(String::from)
            else {
                return Ok(Err(problem_of(&AdminError::Invalid(Invalid::Body))));
            };
            match self.locate(&peer).await? {
                Some((t, r)) if t == tenant && r != realm => {
                    o.insert(
                        String::from("peer_realm_id"),
                        Value::String(access_kernel::json::b64url_encode(r.as_bytes())),
                    );
                }
                _ => return Ok(Err(&codes::NOT_FOUND)),
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
        // MD-10, OIDC §8.1
        if let Change::ClientRegister(c) | Change::ClientUpdate(c) = &change
            && let Some(uri) = &c.subject.sector_identifier_uri
            && let Err(i) = self.sector(uri, c).await?
        {
            return Ok(Err(problem_of(&AdminError::Invalid(i))));
        }
        // IDI-4
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
            // OP-151 m.2 M1
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

    /// E17, TN-125: one meta-action item of a bulk job, its own Exercise.
    async fn exercise_inner(
        &self,
        w: access_http::api::ports::MetaWrite,
        caller: WriteCaller,
    ) -> Result<Written, Unavailable> {
        let Some(place) = self.locate(&w.slug).await? else {
            return Ok(Written::Rejected(&codes::NOT_FOUND));
        };
        let ids = self.ids.key().ok_or(Unavailable)?;
        let r = w.request;
        let submission = access_internal_api::idp::Submission {
            domain: r.domain,
            nonce: r.nonce,
            intent: r.intent,
            payload: r.payload.map(Box::new),
            basis: r.basis,
            capacity: r.capacity,
            ais: caller.ais,
            contributions: Vec::new(),
            pep: IDENTITY_PEP.to_owned(),
            actor: None,
        };
        let subject = |account: &str| {
            ids.decode(access_identity_account::app::SUBJECT_PREFIX, account)
                .ok()
        };
        let applied = match &w.target {
            // TN-89 (3)
            Some(MetaTarget::Role(org, account)) => {
                let Some(subject) = subject(account) else {
                    return Ok(Written::Rejected(&codes::NOT_FOUND));
                };
                self.admin(&ids)
                    .issue_role_grant(place, (*org, subject), submission)
                    .await
            }
            // TN-91
            Some(MetaTarget::ProposeHandover(org, from, to)) => {
                let (Some(from), Some(to)) = (subject(from), subject(to)) else {
                    return Ok(Written::Rejected(&codes::NOT_FOUND));
                };
                return match self
                    .admin(&ids)
                    .propose_transfer(place, *org, (from, to), &submission)
                    .await
                {
                    Ok(p) => Ok(Written::Accepted {
                        record: access_kernel::json::b64url_encode(&p.transfer),
                    }),
                    Err(e) => refusal(&e).map(Written::Rejected),
                };
            }
            // TN-90, OP-153 m.25 (i) (3)
            Some(MetaTarget::Autojoin(org)) => {
                self.admin(&ids)
                    .issue_autojoin_grant(place, *org, submission)
                    .await
            }
            Some(MetaTarget::CompleteHandover(org, handover)) => {
                self.admin(&ids)
                    .complete_transfer(place, *org, *handover, submission)
                    .await
            }
            None => self.admin(&ids).meta(place, submission).await,
        };
        match applied {
            Ok(
                Applied::Written {
                    exercise, position, ..
                }
                | Applied::AlreadyWritten { exercise, position },
            ) => Ok(Written::Committed {
                exercise_id: exercise,
                position,
                resource: None,
                secret: None,
            }),
            Ok(Applied::NotAllowed { .. }) => Ok(Written::NotAllowed),
            Err(e) => refusal(&e).map(Written::Rejected),
        }
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
        // TN-85, TN-86, OP-153 m.19 (d)
        let mut report = None;
        let mut bundle = None;
        let applied = if matches!(compiled.change, Change::AccountBind(_)) {
            let offer = compiled.body.get("offer").and_then(Value::as_str);
            Box::pin(admin.bind_account(&proposal, caller.ais, offer)).await
        } else if matches!(compiled.change, Change::MigrationExport(_)) {
            match Box::pin(admin.export_accounts(&proposal, caller.ais)).await {
                Ok((a, b)) => {
                    bundle = b.map(|b| access_kernel::json::b64url_encode(&b));
                    Ok(a)
                }
                Err(e) => Err(e),
            }
        } else if matches!(compiled.change, Change::AccountImport(_)) {
            let content = compiled
                .body
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match Box::pin(admin.import_accounts(&proposal, caller.ais, content)).await {
                Ok((a, r)) => {
                    report = r;
                    Ok(a)
                }
                Err(e) => Err(e),
            }
        } else {
            Box::pin(admin.apply(&proposal, caller.ais)).await
        };
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
        let resource = match report {
            Some(r) => serde_json::to_value(&r)
                .ok()
                .map(|body| Item { body, version: 0 }),
            None if bundle.is_some() => None,
            None => self.after(&ids, &compiled, &w).await,
        };
        let secret = secret.or(bundle);
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
        // OP-27
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
            // OP-151 m.2 M2, TN-119
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

    fn audit(&self, query: AuditQuery) -> Pending<'_, Option<Listing>> {
        Box::pin(self.audit_inner(query))
    }

    fn audit_proof(&self, query: AuditProofQuery) -> Pending<'_, Option<Value>> {
        Box::pin(self.audit_proof_inner(query))
    }

    fn exercise(
        &self,
        write: access_http::api::ports::MetaWrite,
        caller: WriteCaller,
    ) -> Pending<'_, Written> {
        Box::pin(self.exercise_inner(write, caller))
    }
}

/// The `audit.read` event of a channel B read (OP-44, U53).
const AUDIT_READ: &str = access_authority_core::adapters::AUDIT_EVENT_READ;

/// One audit row rendered as channel B carries it (OP-41, §17.6.8); `None` for an event
/// outside the taxonomy, which is never rendered.
fn rendered(
    row: &access_store::audit::AuditRow,
    checkpoint_at_ms: Option<u64>,
    format: AuditFormat,
) -> Option<Value> {
    use access_identity_audit::adapters::{cef, ocsf, set};
    use access_identity_audit::domain::record::{AuditRecord, uuid_text};
    let record = AuditRecord::identity(row, checkpoint_at_ms).ok()?;
    match format {
        AuditFormat::Ocsf => ocsf::render(&record).ok(),
        AuditFormat::Cef => cef::render(&record).ok().map(Value::String),
        AuditFormat::Set => set::claims(
            &record,
            &format!("urn:suiss:access:realm:{}", uuid_text(&row.realm)),
        )
        .ok(),
    }
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Realms<P> {
    /// A page of the realm's audit stream; the read is written to the operational audit
    /// stream first, and without that row nothing is answered (OP-44, U53).
    async fn audit_inner(&self, q: AuditQuery) -> Result<Option<Listing>, Unavailable> {
        let Some((tenant, realm)) = self.locate(&q.slug).await? else {
            return Ok(None);
        };
        let Some(domain) = self.domain(&q.slug).await? else {
            return Ok(None);
        };
        let after = match q.after.as_deref() {
            None => None,
            Some(a) => Some(a.parse::<i64>().map_err(|_| Unavailable)?),
        };
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Unavailable)?
                .as_millis(),
        )
        .map_err(|_| Unavailable)?;
        let reader = access_authority_core::adapters::audit_text(&q.reader);
        let target = format!("audit:{}", q.slug);
        let correlation = access_authority_core::adapters::audit_text(&format!(
            "{}:{}",
            q.slug,
            after.unwrap_or(0)
        ));
        access_store::operational::record_operational(
            &self.app,
            &access_store::operational::OperationalEvent {
                occurred_at_ms: now,
                tenant: Some(*tenant.as_bytes()),
                domain: Some(domain.0),
                event_type: AUDIT_READ,
                actor: &reader,
                target: &access_authority_core::adapters::audit_text(&target),
                reason: "",
                correlation: &correlation,
            },
        )
        .await
        .map_err(|_| Unavailable)?;
        let mut t = TenantTx::begin(&self.reads, tenant, realm)
            .await
            .map_err(|_| Unavailable)?;
        let rows = t
            .audit_page(after, q.limit)
            .await
            .map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        let cursors: Vec<access_store::identity::Cursor> = rows
            .iter()
            .map(|r| access_store::identity::Cursor {
                xid: r.xid,
                id: r.id,
            })
            .collect();
        let at = access_store::audit::checkpointed_at(&self.checkpointer, &cursors)
            .await
            .map_err(|_| Unavailable)?;
        let full = rows.len() == usize::try_from(q.limit).unwrap_or(usize::MAX);
        let last = rows.last().map(|r| r.id.to_string()).filter(|_| full);
        let items = rows
            .iter()
            .zip(at)
            .filter_map(|(row, at)| rendered(row, at, q.format))
            .map(|body| Item { body, version: 0 })
            .collect();
        Ok(Some(Listing { items, last }))
    }

    /// The inclusion proof of audit event `q.event` in its realm's own tree, at the realm's
    /// latest signed checkpoint (OP-152 m.7 (d), Ek B 2527); the read is written to the
    /// operational audit stream first (OP-44). `None` for an unknown realm or event, or one no
    /// realm checkpoint covers yet.
    async fn audit_proof_inner(&self, q: AuditProofQuery) -> Result<Option<Value>, Unavailable> {
        use access_identity_audit::domain::{leaf, realm};
        let Ok(event) = q.event.parse::<i64>() else {
            return Ok(None);
        };
        let Some((tenant, realm_id)) = self.locate(&q.slug).await? else {
            return Ok(None);
        };
        let Some(domain) = self.domain(&q.slug).await? else {
            return Ok(None);
        };
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Unavailable)?
                .as_millis(),
        )
        .map_err(|_| Unavailable)?;
        let reader = access_authority_core::adapters::audit_text(&q.reader);
        access_store::operational::record_operational(
            &self.app,
            &access_store::operational::OperationalEvent {
                occurred_at_ms: now,
                tenant: Some(*tenant.as_bytes()),
                domain: Some(domain.0),
                event_type: AUDIT_READ,
                actor: &reader,
                target: &access_authority_core::adapters::audit_text(&format!(
                    "audit:{}:proof",
                    q.slug
                )),
                reason: "",
                correlation: &access_authority_core::adapters::audit_text(&format!(
                    "{}:{event}",
                    q.slug
                )),
            },
        )
        .await
        .map_err(|_| Unavailable)?;
        let Some(checkpoint) = access_store::audit_realm::last_realm_checkpoint(
            &self.checkpointer,
            *tenant.as_bytes(),
            *realm_id.as_bytes(),
        )
        .await
        .map_err(|_| Unavailable)?
        else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(&self.reads, tenant, realm_id)
            .await
            .map_err(|_| Unavailable)?;
        let rows = t
            .realm_audit_leaves(checkpoint.size)
            .await
            .map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        let leaves = rows
            .iter()
            .map(leaf)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Unavailable)?;
        if u64::try_from(leaves.len()).ok() != Some(checkpoint.size)
            || realm::tree_hash(&leaves) != checkpoint.root
        {
            return Err(Unavailable);
        }
        let Some(index) = rows.iter().position(|r| r.id == event) else {
            return Ok(None);
        };
        let path = realm::inclusion_path(&leaves, index).ok_or(Unavailable)?;
        let b64 = access_kernel::json::b64url_encode;
        Ok(Some(serde_json::json!({
            "event_id": event.to_string(),
            "origin": checkpoint.note.lines().next().unwrap_or_default(),
            "index": index,
            "size": checkpoint.size,
            "leaf": b64(leaves.get(index).ok_or(Unavailable)?),
            "path": path.iter().map(|h| b64(h)).collect::<Vec<_>>(),
            "checkpoint": checkpoint.note,
        })))
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

    // TN-125
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
