//! The realm-admin surface's ports in this process (OP-151 m.2 M1): a realm's slug resolves to
//! its governing domain, a write's AIS key is a live Instance key of that domain from the
//! authority plane's key index, and the realm resources are read and written through the
//! identity plane's `idp.*` path (TN-110, PI-4, INV-2).

use std::sync::Arc;

use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::ports::{
    Draft, Drafted, Item, Listing, Pending, RealmResources, ResourceKind, ResourceQuery,
    ResourceWrite, Surfaces, Unavailable, Written,
};
use access_http::api::realm::problem_of;
use access_http::problem::codes;
use access_identity_admin::AdminError;
use access_identity_admin::app::rest::{
    self, Kind, Op, acknowledged_passkeys, compile, default_validity,
};
use access_identity_admin::app::{Admin, Applied, Proposal};
use access_identity_admin::domain::{Change, Invalid};
use access_identity_admin::ports::{Decider, Governance, Instances};
use access_identity_oauth::adapters::outbound::{DeclaredTargets, Outbound};
use access_identity_oauth::domain::issuer::RealmBase;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Window;
use access_kernel::verify::cose::PublicKey;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::tenancy;
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits};

use crate::idp::RealmKeyring;
use crate::ids::CellIds;

/// The identity plane behind the realm-admin surface.
pub(crate) struct Realms<P> {
    pub(crate) app: Pool,
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
        Admin {
            app: &self.app,
            ids,
            decider: &self.plane,
            governance: &self.plane,
            pep: IDENTITY_PEP,
            base: &self.base,
            keys: self.keys.as_ref(),
            // OP-149 m.4: platform product clients are not written on the realm-admin surface
            platform_tenant: None,
            declared: self.declared.clone(),
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
                    .get("client_id")
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
        let read = self
            .admin(&ids)
            .read(
                tenant,
                realm,
                kind(q.kind),
                q.key.as_deref(),
                q.after.as_deref(),
                q.limit,
            )
            .await;
        match read {
            Ok(r) => Ok(Some(Listing {
                items: r
                    .items
                    .into_iter()
                    .map(|(body, version)| Item { body, version })
                    .collect(),
                last: r.last,
            })),
            Err(AdminError::NoRealm) => Ok(None),
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
