//! The platform-admin surface's resources in this process (OP-151 m.2 M2, OP-159 m.47 (c), (h)):
//! tenant and environment metadata read across tenants by the router role, never environment
//! content (INV-29, X31), the state of an environment's signing keys (CR-25, CR-59), and
//! provisioning writes that are `idp.platform.*` Exercises in the platform environment's governing
//! domain (TN-110): a tenant with its founder's invitation, its suspension and its placement.

use access_crypto::opaque_id::IdKey;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::environment::problem_of;
use access_http::api::ports::{
    Draft, Drafted, Item, Listing, Pending, PlatformKind, PlatformQuery, PlatformResources,
    PlatformWrite, Unavailable, Written,
};
use access_http::problem::{Code, codes};
use access_identity_admin::app::provision::{
    Created, FounderMail, FoundingSecrets, Order, Platform, ProvisionError, Provisioned,
};
use access_identity_admin::app::rest::{self, default_validity, rfc3339};
use access_identity_admin::domain::provision::{
    DEFAULT_PLACEMENT, PlatformChange, ProvisionInvalid, TenantOrder,
};
use access_identity_admin::ports::{Decider, EnvironmentKeys, Governance, Instances};
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::codec::Canonical;
use access_kernel::json::b64url_encode;
use access_store::identity::TenantId;
use access_store::sandbox::{self, Budget, EnvironmentMeta, TenantMeta};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::rotation::Policy;

use super::environment::Environments;
use crate::idp::EnvironmentKeyring;

/// The members a tenant creation takes (OP-159 m.47 (c)).
const TENANT_BODY: &[&str] = &[
    "tenant_id",
    "display_name",
    "management_slug",
    "founder_email",
    "placement",
    rest::VALIDITY,
];

/// The members a founder reinvitation takes (TN-141).
const REINVITE_BODY: &[&str] = &["founder_email", rest::VALIDITY];

/// The members a suspension or a reactivation takes.
const STATE_BODY: &[&str] = &[rest::VALIDITY];

/// The members a placement move takes.
const PLACEMENT_BODY: &[&str] = &["placement", rest::VALIDITY];

pub(super) fn invalid(i: ProvisionInvalid) -> &'static Code {
    use codes::platform as p;
    match i {
        ProvisionInvalid::Slug => &p::INVALID_SLUG,
        ProvisionInvalid::Placement => &p::INVALID_PLACEMENT,
        ProvisionInvalid::Root => &p::INVALID_ROOT,
        ProvisionInvalid::RecoveryNotAcknowledged => &p::RECOVERY_NOT_ACKNOWLEDGED,
        ProvisionInvalid::TimeLock => &p::INVALID_TIME_LOCK,
        ProvisionInvalid::NoTenant => &codes::NOT_FOUND,
        ProvisionInvalid::SlugTaken => &p::SLUG_TAKEN,
        ProvisionInvalid::Name => &p::INVALID_TENANT_NAME,
        ProvisionInvalid::Email => &p::INVALID_EMAIL,
        ProvisionInvalid::TenantState => &p::TENANT_STATE,
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
        Err(&codes::environment::INVALID_BODY)
    }
}

fn text<'a>(m: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, &'static Code> {
    match m.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(&codes::environment::INVALID_BODY),
    }
}

fn tenant_of(ids: &IdKey, text: Option<&str>) -> Option<[u8; 16]> {
    ids.decode(TENANT_PREFIX, text?).ok()
}

/// A provisioning write as its body names it, before the founder commitment (TN-110).
#[derive(PartialEq, Eq)]
enum Parsed {
    /// `createTenant`.
    Tenant {
        tenant: [u8; 16],
        display_name: String,
        slug: String,
        email: String,
        placement: String,
    },
    /// `reinviteFounder`.
    Reinvite { tenant: [u8; 16], email: String },
    /// `suspendTenant`.
    Suspend { tenant: [u8; 16] },
    /// `reactivateTenant`.
    Reactivate { tenant: [u8; 16] },
    /// `moveTenantPlacement`.
    Placement { tenant: [u8; 16], placement: String },
}

impl core::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tenant { tenant, slug, .. } => f
                .debug_struct("Tenant")
                .field("tenant", tenant)
                .field("slug", slug)
                .finish_non_exhaustive(),
            Self::Reinvite { tenant, .. } => f
                .debug_struct("Reinvite")
                .field("tenant", tenant)
                .finish_non_exhaustive(),
            Self::Suspend { tenant } => f.debug_struct("Suspend").field("tenant", tenant).finish(),
            Self::Reactivate { tenant } => f
                .debug_struct("Reactivate")
                .field("tenant", tenant)
                .finish(),
            Self::Placement { tenant, placement } => f
                .debug_struct("Placement")
                .field("tenant", tenant)
                .field("placement", placement)
                .finish(),
        }
    }
}

fn email(m: &Map<String, Value>) -> Result<String, &'static Code> {
    let raw = text(m, "founder_email")?.ok_or(&codes::platform::INVALID_EMAIL)?;
    access_identity_admin::domain::tenant::folded_email(raw).ok_or(&codes::platform::INVALID_EMAIL)
}

/// What a provisioning write's body names (TN-110).
fn parse(
    ids: &IdKey,
    operation: &str,
    tenant: Option<&str>,
    body: &Map<String, Value>,
) -> Result<Parsed, &'static Code> {
    if operation == "createTenant" {
        only(body, TENANT_BODY)?;
        let tenant =
            tenant_of(ids, text(body, "tenant_id")?).ok_or(&codes::environment::INVALID_BODY)?;
        return Ok(Parsed::Tenant {
            tenant,
            display_name: String::from(
                text(body, "display_name")?.ok_or(&codes::platform::INVALID_TENANT_NAME)?,
            ),
            slug: String::from(
                text(body, "management_slug")?.ok_or(&codes::platform::INVALID_SLUG)?,
            ),
            email: email(body)?,
            placement: String::from(text(body, "placement")?.unwrap_or(DEFAULT_PLACEMENT)),
        });
    }
    let tenant = tenant_of(ids, tenant).ok_or(&codes::NOT_FOUND)?;
    match operation {
        "reinviteFounder" => {
            only(body, REINVITE_BODY)?;
            Ok(Parsed::Reinvite {
                tenant,
                email: email(body)?,
            })
        }
        "suspendTenant" => {
            only(body, STATE_BODY)?;
            Ok(Parsed::Suspend { tenant })
        }
        "reactivateTenant" => {
            only(body, STATE_BODY)?;
            Ok(Parsed::Reactivate { tenant })
        }
        "moveTenantPlacement" => {
            only(body, PLACEMENT_BODY)?;
            Ok(Parsed::Placement {
                tenant,
                placement: String::from(
                    text(body, "placement")?.ok_or(&codes::platform::INVALID_PLACEMENT)?,
                ),
            })
        }
        _ => Err(&codes::environment::UNKNOWN_OPERATION),
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

/// CR-25: the latest an environment's first key may sign; CR-59 may make it sooner.
const fn signing_available_ms(created_ms: u64) -> u64 {
    created_ms.saturating_add(Policy::ENVIRONMENT.publish_lead_ms)
}

/// What the environment's JWKS says about its keys at `now_ms` (CR-25, SAI-46, OP-148).
async fn key_state(keys: &EnvironmentKeyring, m: &EnvironmentMeta, now_ms: u64) -> &'static str {
    match keys.jwks(m.environment).await {
        Ok(doc) if access_identity_admin::app::jwks_kids(&doc).is_empty() => "pending",
        Ok(_) if now_ms >= signing_available_ms(m.created_ms) => "signing",
        Ok(_) => "published",
        Err(_) => "unavailable",
    }
}

fn environment_view(ids: &IdKey, m: &EnvironmentMeta) -> Result<Value, Unavailable> {
    Ok(json!({
        "slug": m.slug,
        "kind": m.kind,
        "tenant_id": ids.encode(TENANT_PREFIX, *m.tenant.as_bytes()).map_err(|e| unavailable(&e))?,
        "issuer": m.issuer,
        "status": "active",
        "placement": m.placement,
        "domain": b64url_encode(&m.domain),
        "sandbox": m.sandbox.is_some(),
        "budget": budget_view(m.sandbox),
        "created_at": rfc3339(m.created_ms),
        "signing_available_at": rfc3339(signing_available_ms(m.created_ms)),
        // CR-12 m.3, OP-159 m.3 (t)
        "kex_share": m.kex_share,
    }))
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Environments<P> {
    async fn platform(&self) -> Result<Option<Platform<'_>>, Unavailable> {
        let Some(slug) = self.platform.as_deref() else {
            return Ok(None);
        };
        Ok(self
            .locate(slug)
            .await?
            .map(|(tenant, environment)| Platform {
                tenant,
                environment,
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
                let mut items = Vec::with_capacity(rows.len());
                for t in &rows {
                    items.push(Item {
                        body: self.tenant_view(&ids, t).await?,
                        version: 0,
                    });
                }
                Ok(Some(Listing { items, last }))
            }
            PlatformKind::Environments | PlatformKind::SandboxDomains => {
                let sandbox_only = q.kind == PlatformKind::SandboxDomains;
                if let Some(slug) = q.key.as_deref() {
                    let rows = sandbox::environments(
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
                    let mut body = environment_view(&ids, m)?;
                    let now = crate::admin::WallClock::now();
                    if let Value::Object(o) = &mut body {
                        o.insert(
                            "key_state".to_owned(),
                            json!(key_state(&self.keys, m, now).await),
                        );
                        // HL-8, HL-17, OP-159 m.3 (s)
                        o.insert("hosting".to_owned(), self.hosting(m.domain).await);
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
                let rows = sandbox::environments(
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
                    .map(|m| environment_view(&ids, m).map(|body| Item { body, version: 0 }))
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
            ("platform-environment", platform),
            ("opaque-id-key", ids),
        ];
        let ok = checks.iter().all(|(_, ok)| *ok);
        json!({
            "status": if ok { "ready" } else { "degraded" },
            "checks": checks.iter().map(|(n, ok)| json!({ "name": n, "ok": ok })).collect::<Vec<_>>(),
        })
    }

    /// The write's change and its body as the caller signs it, with the founder's address and
    /// secrets for a tenant creation or a reinvitation (TN-141): the commitment is derived the
    /// same way at the draft and at the write.
    async fn platform_compile(
        &self,
        ids: &IdKey,
        w: &PlatformWrite,
        draft: bool,
    ) -> Result<Result<Compiled, &'static Code>, Unavailable> {
        let Some(mut body) = w.body.as_object().cloned() else {
            return Ok(Err(&codes::environment::INVALID_BODY));
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
        let parsed = match parse(ids, w.operation, w.tenant.as_deref(), &body) {
            Ok(p) => p,
            Err(code) => return Ok(Err(code)),
        };
        let admin = self.admin(ids);
        let commit = |tenant: [u8; 16], email: &str, round: u32| {
            admin
                .founder_commitment(tenant, email, round)
                .map_err(|e| unavailable(&e))
        };
        let (change, mail) = match parsed {
            Parsed::Tenant {
                tenant,
                display_name,
                slug,
                email,
                placement,
            } => {
                let (founder, secrets) = commit(tenant, &email, 0)?;
                (
                    PlatformChange::Tenant(TenantOrder {
                        tenant,
                        display_name,
                        management_slug: slug,
                        placement,
                        founder,
                    }),
                    Some((email, secrets)),
                )
            }
            Parsed::Reinvite { tenant, email } => {
                let round = admin
                    .founding_round(TenantId::from_bytes(tenant))
                    .await
                    .map_err(|e| unavailable(&e))?;
                let Some(round) = round else {
                    return Ok(Err(&codes::platform::TENANT_STATE));
                };
                let (founder, secrets) = commit(tenant, &email, round.saturating_add(1))?;
                (
                    PlatformChange::Reinvite { tenant, founder },
                    Some((email, secrets)),
                )
            }
            Parsed::Suspend { tenant } => (PlatformChange::Suspend { tenant }, None),
            Parsed::Reactivate { tenant } => (PlatformChange::Reactivate { tenant }, None),
            Parsed::Placement { tenant, placement } => {
                (PlatformChange::Placement { tenant, placement }, None)
            }
        };
        Ok(Ok(Compiled {
            change,
            body: Value::Object(body),
            mail,
        }))
    }

    async fn platform_draft(&self, w: PlatformWrite) -> Result<Drafted, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let Compiled { change, body, .. } = match self.platform_compile(&ids, &w, true).await? {
            Ok(c) => c,
            Err(code) => return Ok(Drafted::Rejected(code)),
        };
        let Ok(validity) = rest::validity(&body) else {
            return Ok(Drafted::Rejected(&codes::environment::INVALID_VALIDITY));
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
        let Compiled { change, body, mail } = match self.platform_compile(&ids, &w, false).await? {
            Ok(c) => c,
            Err(code) => return Ok(Written::Rejected(code)),
        };
        let Ok(validity) = rest::validity(&body) else {
            return Ok(Written::Rejected(&codes::environment::INVALID_VALIDITY));
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
            mail: mail.as_ref().map(|(email, secrets)| FounderMail {
                email,
                secrets,
                console: self.console.as_deref(),
            }),
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
        let resource = self.created_view(&ids, created).await?;
        Ok(Written::Committed {
            exercise_id,
            position,
            resource: Some(resource),
            secret: None,
        })
    }

    /// The created or changed tenant as the platform shows it.
    async fn created_view(&self, ids: &IdKey, created: Created) -> Result<Item, Unavailable> {
        let Created::Tenant(t) = created;
        let rows = sandbox::tenants((&self.router, &self.app), Some(t), None, 1)
            .await
            .map_err(|e| unavailable(&e))?;
        let t = rows.first().ok_or(Unavailable)?;
        let body = self.tenant_view(ids, t).await?;
        Ok(Item { body, version: 0 })
    }

    /// A tenant's metadata (INV-29): its state, placement, display name, the slug of its
    /// management environment and its founding's state; never its content.
    async fn tenant_view(&self, ids: &IdKey, t: &TenantMeta) -> Result<Value, Unavailable> {
        let mut tx = access_store::identity::TenantTx::begin_tenant(&self.app, t.tenant)
            .await
            .map_err(|e| unavailable(&e))?;
        let profile = access_store::tenant_admin::tenant_profile(&mut tx)
            .await
            .map_err(|e| unavailable(&e))?;
        let founding = access_store::tenant_admin::founding(&mut tx)
            .await
            .map_err(|e| unavailable(&e))?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        let now = crate::admin::WallClock::now();
        let state = founding.as_ref().map(|f| {
            if f.founder.is_some() {
                "completed"
            } else if now >= f.expires_ms {
                "expired"
            } else {
                "pending"
            }
        });
        Ok(json!({
            "tenant_id": ids.encode(TENANT_PREFIX, *t.tenant.as_bytes()).map_err(|e| unavailable(&e))?,
            "display_name": profile.and_then(|(n, _)| n),
            "management_slug": founding.map(|f| f.slug),
            "founding": state,
            "status": t.status,
            "placement": t.placement,
            "created_at": rfc3339(t.created_ms),
        }))
    }
}

/// A compiled provisioning write: its change, the body the caller signs and, for a founding,
/// the founder's address and secrets.
struct Compiled {
    change: PlatformChange,
    body: Value,
    mail: Option<(String, FoundingSecrets)>,
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> PlatformResources
    for Environments<P>
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
