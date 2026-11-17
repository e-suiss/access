//! A tenant's administration on its management environment's admin surface (OP-159 m.47 (e),
//! (f), (h), TN-140): the environment creation, administrator invitation, owner addition and
//! administrator removal writes, each one `idp.tenant.*` Exercise in the management environment's
//! governing domain, drafted with `POST …/intents` and sent with the caller's AIS (TN-110). A
//! removal ends the administrator's `tenant_administration` Claims in every domain at once.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_http::api::domain::caller::WriteCaller;
use access_http::api::environment::problem_of;
use access_http::api::ports::{Draft, Drafted, Item, ResourceWrite, Unavailable, Written};
use access_http::problem::{Code, codes};
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_admin::app::Applied;
use access_identity_admin::app::rest::{self, default_validity};
use access_identity_admin::app::tenant::{TenantError, TenantOrder};
use access_identity_admin::domain::tenant::{
    AdminInvite, INVITE_DAYS, NewTenantEnvironment, TenantChange, TenantInvalid, folded_email,
};
use access_identity_admin::ports::{Decider, Governance, Instances};
use access_identity_oauth::domain::issuer::IssuerStyle;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_kernel::codec::Canonical;
use access_store::identity::{EnvironmentId, TenantId};
use serde_json::{Map, Value};
use suiss_crypto::dcbor::{self, Limits};

use super::environment::Environments;

/// The tenant writes of the management environment's surface.
pub(crate) const OPERATIONS: [&str; 4] = [
    "createTenantEnvironment",
    "inviteTenantAdmin",
    "addTenantOwner",
    "removeTenantAdmin",
];

const ENVIRONMENT_BODY: &[&str] = &["slug", "sandbox", "issuer_style", rest::VALIDITY];
const INVITE_BODY: &[&str] = &["email", rest::VALIDITY];
const ADMIN_BODY: &[&str] = &[rest::VALIDITY];

/// Ends an administrator's `tenant_administration` Claims in every domain it administered
/// (OP-159 m.47 (f)): what a removal or its account's suspension does at once.
pub(crate) trait EndAdministration: Send + Sync {
    /// Ends the lines of `subject` of the management environment `place`; the number of Claims
    /// ended.
    fn end(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<u32, access_internal_api::idp::Unavailable>> + Send + '_>>;

    /// Opens a new episode of each ended line of `subject` once its account is reactivated (OP-159
    /// m.48 (d)); the number of lines stated.
    fn revive(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<u32, access_internal_api::idp::Unavailable>> + Send + '_>>;
}

impl<S, I, C> EndAdministration
    for access_identity_account::app::administration::Administration<S, I, C>
where
    S: access_identity_account::app::claims::ClaimSigner + Send + Sync,
    I: access_internal_api::claims::ClaimIngest + Send + Sync,
    C: access_identity_account::ports::Clock + Send + Sync,
{
    fn end(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<u32, access_internal_api::idp::Unavailable>> + Send + '_>>
    {
        Box::pin(async move { Self::end(self, place, &subject).await })
    }

    fn revive(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) -> Pin<Box<dyn Future<Output = Result<u32, access_internal_api::idp::Unavailable>> + Send + '_>>
    {
        Box::pin(async move { Self::revive(self, place, &subject).await })
    }
}

/// The administration ender a process wires, if any.
pub(crate) type Ender = Option<Arc<dyn EndAdministration>>;

fn invalid(i: TenantInvalid) -> &'static Code {
    use codes::platform as p;
    match i {
        TenantInvalid::Provision(p) => super::platform::invalid(p),
        TenantInvalid::NotManagement => &p::MANAGEMENT_ENVIRONMENT,
        TenantInvalid::Email => &p::INVALID_EMAIL,
        TenantInvalid::Lifetime => &codes::environment::INVALID_BODY,
        TenantInvalid::NoAdmin => &codes::NOT_FOUND,
        TenantInvalid::LastOwner => &p::LAST_TENANT_OWNER,
        TenantInvalid::InviteLimit => &codes::RATE_LIMITED,
    }
}

fn unavailable(e: &dyn std::fmt::Display) -> Unavailable {
    tracing::warn!(event = "api.tenant.unavailable", outcome = "error", error = %e, "tenant administration unavailable");
    Unavailable
}

/// A refusal is the write's problem; a failure of a dependency is `503` (MD-8).
fn refusal(e: &TenantError) -> Result<&'static Code, Unavailable> {
    let code = match e {
        TenantError::Invalid(i) => invalid(*i),
        TenantError::Admin(a) => problem_of(a),
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

/// The change a tenant write's key and body name (TN-110).
fn parse(
    ids: &IdKey,
    operation: &str,
    key: Option<&str>,
    body: &Value,
) -> Result<TenantChange, &'static Code> {
    let m = body.as_object().ok_or(&codes::environment::INVALID_BODY)?;
    let admin = || {
        key.and_then(|k| ids.decode(SUBJECT_PREFIX, k).ok())
            .ok_or(&codes::NOT_FOUND)
    };
    match operation {
        "createTenantEnvironment" => {
            only(m, ENVIRONMENT_BODY)?;
            let slug = m
                .get("slug")
                .and_then(Value::as_str)
                .ok_or(&codes::platform::INVALID_SLUG)?;
            let sandbox = match m.get("sandbox") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(&codes::environment::INVALID_BODY),
            };
            let style = match m.get("issuer_style") {
                None | Some(Value::Null) => IssuerStyle::Path,
                Some(Value::String(s)) if s == "path" => IssuerStyle::Path,
                Some(Value::String(s)) if s == "subdomain" => IssuerStyle::Subdomain,
                Some(_) => return Err(&codes::environment::INVALID_BODY),
            };
            Ok(TenantChange::EnvironmentCreate(NewTenantEnvironment {
                slug: String::from(slug),
                style,
                sandbox,
                schemas: Vec::new(),
                acceptances: Vec::new(),
                issuer_predicate_input: Vec::new(),
            }))
        }
        "inviteTenantAdmin" => {
            only(m, INVITE_BODY)?;
            let email = m
                .get("email")
                .and_then(Value::as_str)
                .and_then(folded_email)
                .ok_or(&codes::platform::INVALID_EMAIL)?;
            Ok(TenantChange::AdminInvite(AdminInvite {
                email,
                days: INVITE_DAYS,
                inviter_name: None,
            }))
        }
        "addTenantOwner" => {
            only(m, ADMIN_BODY)?;
            Ok(TenantChange::OwnerAdd { subject: admin()? })
        }
        "removeTenantAdmin" => {
            only(m, ADMIN_BODY)?;
            Ok(TenantChange::AdminRemove { subject: admin()? })
        }
        _ => Err(&codes::environment::UNKNOWN_OPERATION),
    }
}

impl<P: Decider + Governance + Instances + Clone + Send + Sync + 'static> Environments<P> {
    async fn tenant_place(
        &self,
        slug: &str,
    ) -> Result<Result<(TenantId, EnvironmentId), &'static Code>, Unavailable> {
        Ok(self.locate(slug).await?.ok_or(&codes::NOT_FOUND))
    }

    /// The intent a tenant write compiles to (TN-110); nothing is decided or changed.
    pub(super) async fn tenant_draft(&self, w: ResourceWrite) -> Result<Drafted, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let place = match self.tenant_place(&w.slug).await? {
            Ok(p) => p,
            Err(code) => return Ok(Drafted::Rejected(code)),
        };
        let mut body = w.body.clone();
        if let Some(o) = body.as_object_mut() {
            o.entry(rest::VALIDITY)
                .or_insert_with(|| default_validity(w.now_ms));
        }
        let change = match parse(&ids, w.operation, w.key.as_deref(), &body) {
            Ok(c) => c,
            Err(code) => return Ok(Drafted::Rejected(code)),
        };
        let validity = match rest::validity(&body) {
            Ok(v) => v,
            Err(i) => return Ok(Drafted::Rejected(problem_of(&i.into()))),
        };
        let prepared = match self
            .admin(&ids)
            .prepare_tenant(place, &change, validity)
            .await
        {
            Ok(p) => p,
            Err(e) => return refusal(&e).map(Drafted::Rejected),
        };
        if prepared.domain != w.domain {
            return Ok(Drafted::Rejected(&codes::NOT_FOUND));
        }
        let intent =
            dcbor::encode(&prepared.intent.to_value(), Limits::CEILING).map_err(|_| Unavailable)?;
        Ok(Drafted::Draft(Draft {
            body,
            domain: prepared.domain,
            intent,
            intent_digest: prepared.digest,
            pep: IDENTITY_PEP.to_owned(),
        }))
    }

    /// Commits a tenant write with the caller's AIS (TN-110, PI-4); a removal then ends the
    /// administrator's Claims at once (OP-159 m.47 (f)).
    pub(super) async fn tenant_commit(
        &self,
        w: ResourceWrite,
        caller: WriteCaller,
    ) -> Result<Written, Unavailable> {
        let ids = self.ids.key().ok_or(Unavailable)?;
        let place = match self.tenant_place(&w.slug).await? {
            Ok(p) => p,
            Err(code) => return Ok(Written::Rejected(code)),
        };
        let change = match parse(&ids, w.operation, w.key.as_deref(), &w.body) {
            Ok(c) => c,
            Err(code) => return Ok(Written::Rejected(code)),
        };
        let validity = match rest::validity(&w.body) {
            Ok(v) => v,
            Err(i) => return Ok(Written::Rejected(problem_of(&i.into()))),
        };
        let statement = &caller.statement;
        let applied = Box::pin(self.admin(&ids).apply_tenant(
            TenantOrder {
                tenant: place.0,
                environment: place.1,
                change: &change,
                subject: None,
                nonce: statement.nonce.clone(),
                validity,
                basis: statement.basis,
                capacity: statement.capacity,
                console: self.console.as_deref(),
            },
            caller.ais,
        ))
        .await;
        let (applied, opened) = match applied {
            Ok(a) => a,
            Err(e) => return refusal(&e).map(Written::Rejected),
        };
        let (exercise_id, position) = match applied {
            Applied::Written {
                exercise, position, ..
            }
            | Applied::AlreadyWritten { exercise, position } => (exercise, position),
            Applied::NotAllowed { .. } => return Ok(Written::NotAllowed),
        };
        // OP-159 m.47 (f)
        if let TenantChange::AdminRemove { subject } = &change {
            self.end_administration(place, *subject).await;
        }
        let resource = match (&opened, &change) {
            (Some(_), TenantChange::EnvironmentCreate(e)) => self
                .admin(&ids)
                .tenant_environments_view(place)
                .await
                .ok()
                .and_then(|l| l.into_iter().find(|v| v["slug"] == e.slug.as_str()))
                .map(|body| Item { body, version: 0 }),
            _ => None,
        };
        Ok(Written::Committed {
            exercise_id,
            position,
            resource,
            secret: None,
        })
    }

    /// Ends the `tenant_administration` Claims of `subject` at once; a failure leaves them to
    /// the restate job, which ends them within its interval (OP-159 m.47 (f)).
    pub(super) async fn end_administration(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) {
        let Some(ender) = &self.administration else {
            return;
        };
        if let Err(e) = ender.end(place, subject).await {
            tracing::warn!(event = "administration.end", outcome = "error", error = %e.0, "administration end left to the restate job");
        }
    }

    /// Revives the `tenant_administration` lines of a reactivated `subject` (OP-159 m.48 (d)); a
    /// failure leaves them to the console, which opens the new episode when the administrator next
    /// enters the environment.
    pub(super) async fn revive_administration(
        &self,
        place: (TenantId, EnvironmentId),
        subject: [u8; 16],
    ) {
        let Some(ender) = &self.administration else {
            return;
        };
        if let Err(e) = ender.revive(place, subject).await {
            tracing::warn!(event = "administration.revive", outcome = "error", error = %e.0, "administration revival left to the console");
        }
    }
}
