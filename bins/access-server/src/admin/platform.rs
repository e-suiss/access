//! The platform-admin surface's resources in this process (OP-151 m.2 M2): tenant and realm
//! metadata read across tenants by the router role, never realm content (INV-29, X31), the state
//! of a realm's signing keys (CR-25, CR-59), and provisioning writes that are `idp.platform.*`
//! Exercises in the platform realm's governing domain (TN-110), each followed by the Genesis it
//! names (TN-111).

use std::collections::BTreeSet;

use access_crypto::opaque_id::IdKey;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::ports::{
    Draft, Drafted, Item, Listing, Pending, PlatformKind, PlatformQuery, PlatformResources,
    PlatformWrite, Unavailable, Written,
};
use access_http::api::realm::problem_of;
use access_http::problem::{Code, codes};
use access_identity_admin::app::provision::{
    Created, Order, Platform, ProvisionError, Provisioned, style,
};
use access_identity_admin::app::rest::{self, default_validity, rfc3339};
use access_identity_admin::domain::provision::{
    DEFAULT_PLACEMENT, PlatformChange, ProvisionInvalid, RealmOrder, Recovery, RecoveryKey,
    RecoveryKeys,
};
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::codec::Canonical;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::Root;
use access_kernel::model::Id;
use access_store::identity::TenantId;
use access_store::sandbox::{self, Budget, RealmMeta, TenantMeta};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::rotation::Policy;

use super::realm::Realms;
use crate::idp::RealmKeyring;

/// The members a tenant creation takes.
const TENANT_BODY: &[&str] = &["tenant_id", "placement", rest::VALIDITY];

/// The members a realm or sandbox creation takes.
const REALM_BODY: &[&str] = &[
    "slug",
    "issuer_style",
    "placement",
    "root",
    "ct3_delay_s",
    "causal_binding",
    "acknowledge_no_recovery",
    "recovery",
    "sandbox",
    rest::VALIDITY,
];

/// Most recovery keys a realm creation names (§13.6).
const MAX_RECOVERY_KEYS: usize = 16;

fn invalid(i: ProvisionInvalid) -> &'static Code {
    use codes::platform as p;
    match i {
        ProvisionInvalid::Slug => &p::INVALID_SLUG,
        ProvisionInvalid::Placement => &p::INVALID_PLACEMENT,
        ProvisionInvalid::Root => &p::INVALID_ROOT,
        ProvisionInvalid::RecoveryNotAcknowledged => &p::RECOVERY_NOT_ACKNOWLEDGED,
        ProvisionInvalid::TimeLock => &p::INVALID_TIME_LOCK,
        ProvisionInvalid::NoTenant => &codes::NOT_FOUND,
        ProvisionInvalid::SlugTaken => &p::SLUG_TAKEN,
    }
}

fn unavailable(e: &dyn std::fmt::Display) -> Unavailable {
    tracing::warn!(event = "api.platform.unavailable", outcome = "error", error = %e, "platform resources unavailable");
    Unavailable
}

/// A refusal is the write's problem; a failure of a dependency is `503` (MD-8).
fn refusal(e: &ProvisionError) -> Result<&'static Code, Unavailable> {
    let code = match e {
        ProvisionError::Invalid(i) => invalid(*i),
        ProvisionError::Admin(a) => problem_of(a),
    };
    if code == &codes::UNAVAILABLE {
        Err(unavailable(e))
    } else {
        Ok(code)
    }
}

fn only(m: &Map<String, Value>, allowed: &[&str]) -> Result<(), &'static Code> {
    if m.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(&codes::realm::INVALID_BODY)
    }
}

fn party(v: &Value) -> Option<Id> {
    let bytes = b64url_decode(v.as_str()?).ok()?;
    Some(Id(<[u8; 16]>::try_from(bytes.as_slice()).ok()?))
}

/// `{"sole": <party>}` or `{"joint": {"k": n, "parties": [<party>, …]}}` (TN-111).
fn root(v: Option<&Value>) -> Result<Root, &'static Code> {
    let bad = &codes::platform::INVALID_ROOT;
    let o = v.and_then(Value::as_object).ok_or(bad)?;
    match (o.get("sole"), o.get("joint"), o.len()) {
        (Some(p), None, 1) => party(p).map(Root::Sole).ok_or(bad),
        (None, Some(Value::Object(j)), 1) => {
            only(j, &["k", "parties"]).map_err(|_| bad)?;
            let k = j.get("k").and_then(Value::as_u64).ok_or(bad)?;
            let list = j.get("parties").and_then(Value::as_array).ok_or(bad)?;
            let parties: BTreeSet<Id> = list.iter().map(party).collect::<Option<_>>().ok_or(bad)?;
            if parties.len() != list.len() {
                return Err(bad);
            }
            Ok(Root::Joint { parties, k })
        }
        _ => Err(bad),
    }
}

/// `{"held_on": "device" | "offline", "keys": [{"party": <party>, "kid": <thumbprint>}, …]}`: the
/// founders' recovery keys by thumbprint only (§13.6, SEC20, OP-158 m.3 (m)).
fn recovery_keys(v: Option<&Value>) -> Result<Option<RecoveryKeys>, &'static Code> {
    let bad = &codes::realm::INVALID_BODY;
    let o = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(bad),
    };
    only(o, &["held_on", "keys"])?;
    let held_on = match o.get("held_on").and_then(Value::as_str) {
        None | Some("device") => access_kernel::recovery::KeyHolding::Device,
        Some("offline") => access_kernel::recovery::KeyHolding::Offline,
        Some(_) => return Err(bad),
    };
    let list = o.get("keys").and_then(Value::as_array).ok_or(bad)?;
    if list.len() > MAX_RECOVERY_KEYS {
        return Err(bad);
    }
    let mut keys = Vec::with_capacity(list.len());
    for k in list {
        let k = k.as_object().ok_or(bad)?;
        only(k, &["party", "kid"])?;
        let kid = k
            .get("kid")
            .and_then(Value::as_str)
            .and_then(|t| b64url_decode(t).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(bad)?;
        keys.push(RecoveryKey {
            party: k.get("party").and_then(party).ok_or(bad)?,
            kid,
        });
    }
    Ok(Some(RecoveryKeys { held_on, keys }))
}

fn text<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, &'static Code> {
    match m.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(&codes::realm::INVALID_BODY),
    }
}

fn tenant_of(ids: &IdKey, text: Option<&str>) -> Option<[u8; 16]> {
    ids.decode(TENANT_PREFIX, text?).ok()
}

/// The change a provisioning write compiles to (TN-110).
fn change(
    ids: &IdKey,
    operation: &str,
    tenant: Option<&str>,
    body: &Map<String, Value>,
) -> Result<PlatformChange, &'static Code> {
    let placement = String::from(text(body, "placement")?.unwrap_or(DEFAULT_PLACEMENT));
    if operation == "createTenant" {
        only(body, TENANT_BODY)?;
        let tenant = tenant_of(ids, text(body, "tenant_id")?).ok_or(&codes::realm::INVALID_BODY)?;
        return Ok(PlatformChange::Tenant { tenant, placement });
    }
    only(body, REALM_BODY)?;
    let tenant = tenant_of(ids, tenant).ok_or(&codes::NOT_FOUND)?;
    let order = RealmOrder {
        tenant,
        slug: String::from(text(body, "slug")?.ok_or(&codes::platform::INVALID_SLUG)?),
        style: style(text(body, "issuer_style")?).ok_or(&codes::realm::INVALID_BODY)?,
        placement,
        root: root(body.get("root"))?,
        ct3_delay_s: match body.get("ct3_delay_s") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_u64().ok_or(&codes::platform::INVALID_TIME_LOCK)?),
        },
        // OP-152 m.7 (d) E11
        causal_binding: match body.get("causal_binding") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(&codes::realm::INVALID_BODY),
        },
        acknowledge_no_recovery: match body.get("acknowledge_no_recovery") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(&codes::realm::INVALID_BODY),
        },
        // §13.6, OP-158 m.3 (m)
        recovery: recovery_keys(body.get("recovery"))?,
    };
    // OP-151 m.3 (m)
    let sandbox = match body.get("sandbox") {
        None | Some(Value::Null) => operation == "createSandboxDomain",
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(&codes::realm::INVALID_BODY),
    };
    match (operation, sandbox) {
        ("createRealm", false) => Ok(PlatformChange::Realm(order)),
        ("createRealm" | "createSandboxDomain", true) => Ok(PlatformChange::Sandbox(order)),
        ("createSandboxDomain", false) => Err(&codes::realm::INVALID_BODY),
        _ => Err(&codes::realm::UNKNOWN_OPERATION),
    }
}

fn root_view(r: &Root) -> Value {
    match r {
        Root::Sole(_) => json!({ "kind": "sole", "k": 1, "n": 1 }),
        Root::Joint { parties, k } => json!({ "kind": "joint", "k": k, "n": parties.len() }),
    }
}

fn budget_view(b: Option<Budget>) -> Value {
    b.map_or(Value::Null, |b| {
        json!({
            "exercises_per_day": b.exercises_per_day.to_string(),
            "projections_per_day": b.projections_per_day.to_string(),
        })
    })
}

/// CR-25: the latest a realm's first key may sign; CR-59 may make it sooner.
const fn signing_available_ms(created_ms: u64) -> u64 {
    created_ms.saturating_add(Policy::REALM.publish_lead_ms)
}

/// What the realm's JWKS says about its keys at `now_ms` (CR-25, SAI-46, OP-148).
async fn key_state(keys: &RealmKeyring, m: &RealmMeta, now_ms: u64) -> &'static str {
    match keys.jwks(m.realm).await {
        Ok(doc) if access_identity_admin::app::jwks_kids(&doc).is_empty() => "pending",
        Ok(_) if now_ms >= signing_available_ms(m.created_ms) => "signing",
        Ok(_) => "published",
        Err(_) => "unavailable",
    }
}

fn realm_view(ids: &IdKey, m: &RealmMeta) -> Result<Value, Unavailable> {
    Ok(json!({
        "slug": m.slug,
        "tenant_id": ids.encode(TENANT_PREFIX, *m.tenant.as_bytes()).map_err(|e| unavailable(&e))?,
        "issuer": m.issuer,
        "status": "active",
        "placement": m.placement,
        "domain": b64url_encode(&m.domain),
        "sandbox": m.sandbox.is_some(),
        "budget": budget_view(m.sandbox),
        "created_at": rfc3339(m.created_ms),
        "signing_available_at": rfc3339(signing_available_ms(m.created_ms)),
    }))
}

fn tenant_view(ids: &IdKey, t: &TenantMeta) -> Result<Value, Unavailable> {
    Ok(json!({
        "tenant_id": ids.encode(TENANT_PREFIX, *t.tenant.as_bytes()).map_err(|e| unavailable(&e))?,
        "status": t.status,
        "placement": t.placement,
        "created_at": rfc3339(t.created_ms),
    }))
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Realms<P> {
    async fn platform(&self) -> Result<Option<Platform<'_>>, Unavailable> {
        let Some(slug) = self.platform.as_deref() else {
            return Ok(None);
        };
        Ok(self.locate(slug).await?.map(|(tenant, realm)| Platform {
            tenant,
            realm,
            router: &self.router,
        }))
    }

    fn page<T>(rows: Vec<T>, limit: u32, key: impl Fn(&T) -> String) -> (Vec<T>, Option<String>) {
        let mut rows = rows;
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        if rows.len() > limit {
            rows.truncate(limit);
            let last = rows.last().map(key);
            (rows, last)
        } else {
            (rows, None)
        }
    }

    async fn tenant_exists(&self, tenant: [u8; 16]) -> Result<bool, Unavailable> {
        let found = sandbox::tenants(
            (&self.router, &self.app),
            Some(TenantId::from_bytes(tenant)),
            None,
            1,
        )
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(!found.is_empty())
    }

    async fn platform_read(&self, q: PlatformQuery) -> Result<Option<Listing>, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let more = q.limit.saturating_add(1);
        match q.kind {
            PlatformKind::Tenants => {
                let only = match q.key.as_deref() {
                    Some(k) => match tenant_of(&ids, Some(k)) {
                        Some(t) => Some(TenantId::from_bytes(t)),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let after = q
                    .after
                    .as_deref()
                    .and_then(|a| tenant_of(&ids, Some(a)))
                    .map(TenantId::from_bytes);
                let rows = sandbox::tenants((&self.router, &self.app), only, after, more)
                    .await
                    .map_err(|e| unavailable(&e))?;
                if only.is_some() && rows.is_empty() {
                    return Ok(None);
                }
                let (rows, last) = Self::page(rows, q.limit, |t| {
                    ids.encode(TENANT_PREFIX, *t.tenant.as_bytes())
                        .unwrap_or_default()
                });
                let items = rows
                    .iter()
                    .map(|t| tenant_view(&ids, t).map(|body| Item { body, version: 0 }))
                    .collect::<Result<_, _>>()?;
                Ok(Some(Listing { items, last }))
            }
            PlatformKind::Realms | PlatformKind::SandboxDomains => {
                let sandbox_only = q.kind == PlatformKind::SandboxDomains;
                if let Some(slug) = q.key.as_deref() {
                    let rows = sandbox::realms(
                        (&self.router, &self.app),
                        Some(slug),
                        None,
                        None,
                        (1, false),
                    )
                    .await
                    .map_err(|e| unavailable(&e))?;
                    let Some(m) = rows.first() else {
                        return Ok(None);
                    };
                    let mut body = realm_view(&ids, m)?;
                    let now = crate::admin::WallClock::now();
                    if let Value::Object(o) = &mut body {
                        o.insert(
                            "key_state".to_owned(),
                            json!(key_state(&self.keys, m, now).await),
                        );
                    }
                    return Ok(Some(Listing {
                        items: vec![Item { body, version: 0 }],
                        last: None,
                    }));
                }
                let Some(tenant) = tenant_of(&ids, q.tenant.as_deref()) else {
                    return Ok(None);
                };
                if !self.tenant_exists(tenant).await? {
                    return Ok(None);
                }
                let rows = sandbox::realms(
                    (&self.router, &self.app),
                    None,
                    Some(TenantId::from_bytes(tenant)),
                    q.after.as_deref(),
                    (more, sandbox_only),
                )
                .await
                .map_err(|e| unavailable(&e))?;
                let (rows, last) = Self::page(rows, q.limit, |m| m.slug.clone());
                let items = rows
                    .iter()
                    .map(|m| realm_view(&ids, m).map(|body| Item { body, version: 0 }))
                    .collect::<Result<_, _>>()?;
                Ok(Some(Listing { items, last }))
            }
            PlatformKind::Health => Ok(Some(Listing {
                items: vec![Item {
                    body: self.health().await,
                    version: 0,
                }],
                last: None,
            })),
        }
    }

    /// The deployment's readiness by check name; no addresses or secrets.
    async fn health(&self) -> Value {
        let database = sandbox::tenants((&self.router, &self.app), None, None, 1)
            .await
            .is_ok();
        let platform = matches!(self.platform().await, Ok(Some(_)));
        let signer = self.keys.ping().await;
        let ids = self.ids.key().is_some();
        let checks = [
            ("database", database),
            ("identity-signer", signer),
            ("platform-realm", platform),
            ("opaque-id-key", ids),
        ];
        let ok = checks.iter().all(|(_, ok)| *ok);
        json!({
            "status": if ok { "ready" } else { "degraded" },
            "checks": checks.iter().map(|(n, ok)| json!({ "name": n, "ok": ok })).collect::<Vec<_>>(),
        })
    }

    /// The write's change and its body as the caller signs it.
    async fn platform_compile(
        &self,
        ids: &IdKey,
        w: &PlatformWrite,
        draft: bool,
    ) -> Result<Result<(PlatformChange, Value), &'static Code>, Unavailable> {
        let Some(mut body) = w.body.as_object().cloned() else {
            return Ok(Err(&codes::realm::INVALID_BODY));
        };
        if draft {
            body.entry(rest::VALIDITY)
                .or_insert_with(|| default_validity(w.now_ms));
            if w.operation == "createTenant" && !body.contains_key("tenant_id") {
                let id = access_store::idp::new_uuid(&self.app)
                    .await
                    .map_err(|e| unavailable(&e))?;
                let text = ids.encode(TENANT_PREFIX, id).map_err(|e| unavailable(&e))?;
                body.insert("tenant_id".to_owned(), Value::String(text));
            }
        }
        Ok(change(ids, w.operation, w.tenant.as_deref(), &body).map(|c| (c, Value::Object(body))))
    }

    async fn platform_draft(&self, w: PlatformWrite) -> Result<Drafted, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let (change, body) = match self.platform_compile(&ids, &w, true).await? {
            Ok(c) => c,
            Err(code) => return Ok(Drafted::Rejected(code)),
        };
        let Ok(validity) = rest::validity(&body) else {
            return Ok(Drafted::Rejected(&codes::realm::INVALID_VALIDITY));
        };
        let Some(platform) = self.platform().await? else {
            return Ok(Drafted::Rejected(&codes::NOT_FOUND));
        };
        let prepared = match self
            .admin(&ids)
            .prepare_provision(&platform, &change, validity)
            .await
        {
            Ok(p) => p,
            Err(e) => return refusal(&e).map(Drafted::Rejected),
        };
        if prepared.domain != w.domain {
            return Ok(Drafted::Rejected(&codes::NOT_FOUND));
        }
        let intent = dcbor::encode(&prepared.intent.to_value(), Limits::CEILING)
            .map_err(|e| unavailable(&e))?;
        Ok(Drafted::Draft(Draft {
            body,
            domain: prepared.domain,
            intent,
            intent_digest: prepared.digest,
            pep: IDENTITY_PEP.to_owned(),
        }))
    }

    async fn platform_commit(
        &self,
        w: PlatformWrite,
        caller: WriteCaller,
    ) -> Result<Written, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let (change, body) = match self.platform_compile(&ids, &w, false).await? {
            Ok(c) => c,
            Err(code) => return Ok(Written::Rejected(code)),
        };
        let Ok(validity) = rest::validity(&body) else {
            return Ok(Written::Rejected(&codes::realm::INVALID_VALIDITY));
        };
        let Some(platform) = self.platform().await? else {
            return Ok(Written::Rejected(&codes::NOT_FOUND));
        };
        let statement = &caller.statement;
        let order = Order {
            change: &change,
            nonce: statement.nonce.clone(),
            validity,
            basis: statement.basis,
            capacity: statement.capacity,
        };
        let done = Box::pin(self.admin(&ids).provision(&platform, order, caller.ais)).await;
        let (exercise_id, position, created) = match done {
            Ok(Provisioned::Done {
                exercise,
                position,
                created,
            }) => (exercise, position, created),
            Ok(Provisioned::NotAllowed { .. }) => return Ok(Written::NotAllowed),
            Err(e) => return refusal(&e).map(Written::Rejected),
        };
        let resource = self.created_view(&ids, &change, created).await?;
        Ok(Written::Committed {
            exercise_id,
            position,
            resource: Some(resource),
            secret: None,
        })
    }

    /// The created tenant or realm as the platform shows it, and a realm's Genesis summary.
    async fn created_view(
        &self,
        ids: &IdKey,
        change: &PlatformChange,
        created: Created,
    ) -> Result<Item, Unavailable> {
        let body = match created {
            Created::Tenant(t) => {
                let rows = sandbox::tenants((&self.router, &self.app), Some(t), None, 1)
                    .await
                    .map_err(|e| unavailable(&e))?;
                let t = rows.first().ok_or(Unavailable)?;
                tenant_view(ids, t)?
            }
            Created::Realm {
                domain, recovery, ..
            } => {
                let slug = match change {
                    PlatformChange::Realm(o) | PlatformChange::Sandbox(o) => o.slug.as_str(),
                    PlatformChange::Tenant { .. } => return Err(Unavailable),
                };
                let rows = sandbox::realms(
                    (&self.router, &self.app),
                    Some(slug),
                    None,
                    None,
                    (1, false),
                )
                .await
                .map_err(|e| unavailable(&e))?;
                let m = rows.first().ok_or(Unavailable)?;
                let mut view = realm_view(ids, m)?;
                let root = match change {
                    PlatformChange::Realm(o) | PlatformChange::Sandbox(o) => root_view(&o.root),
                    PlatformChange::Tenant { .. } => Value::Null,
                };
                if let Value::Object(o) = &mut view {
                    o.insert(
                        "key_state".to_owned(),
                        json!(key_state(&self.keys, m, crate::admin::WallClock::now()).await),
                    );
                    // TN-111, §13.6, §13.7.7, OP-158 m.3 (m)
                    let mut genesis = json!({
                        "digest": b64url_encode(&domain.0),
                        "root": root,
                        "recovery": recovery.name(),
                    });
                    match recovery {
                        Recovery::Available { threshold, keys } => {
                            genesis["recovery_threshold"] = json!({ "k": threshold, "n": keys });
                        }
                        Recovery::NotAvailable(r) => {
                            genesis["recovery_reason"] = json!(r.code());
                        }
                    }
                    o.insert("genesis".to_owned(), genesis);
                }
                view
            }
        };
        Ok(Item { body, version: 0 })
    }
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> PlatformResources
    for Realms<P>
{
    fn read(&self, query: PlatformQuery) -> Pending<'_, Option<Listing>> {
        Box::pin(self.platform_read(query))
    }

    fn draft(&self, write: PlatformWrite) -> Pending<'_, Drafted> {
        Box::pin(self.platform_draft(write))
    }

    fn commit(&self, write: PlatformWrite, caller: WriteCaller) -> Pending<'_, Written> {
        Box::pin(self.platform_commit(write, caller))
    }
}

/// Which side of the sandbox line a domain is on, read by the router role (OP-151 m.3 (m)).
pub(crate) struct SandboxRegimes(pub(crate) access_store::Pool);

impl access_http::adp::sandbox::Regimes for SandboxRegimes {
    async fn regime(
        &self,
        domain: access_kernel::digest::Digest,
    ) -> Result<access_identity_admin::domain::provision::Regime, access_authority_core::CoreError>
    {
        use access_identity_admin::domain::provision::Regime;
        match sandbox::budget(&self.0, &domain.0).await {
            Ok(Some(_)) => Ok(Regime::Sandbox),
            Ok(None) => Ok(Regime::Production),
            Err(e) => {
                tracing::warn!(event = "adp.sandbox_line.unavailable", outcome = "error", error = %e, "sandbox regime unavailable");
                Err(access_authority_core::CoreError::Unavailable(
                    "sandbox-line",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests;
