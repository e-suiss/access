//! The platform-admin resources under `/admin/v1/platform/…` (OP-151 m.2 M2, OP-159 m.47 (c), (h)):
//! tenants with an invited founder, their suspension and placement, environment metadata with the
//! state of its keys (CR-25, CR-59), sandbox domains (OP-151 m.3 (m), X21) and the operator's
//! health. The platform opens no environment: a tenant's founder and administrators do (TN-140).
//!
//! Every read is metadata: no route returns account, client, grant, record or claim content, and
//! no route reads an environment's settings or authority state (INV-29, X31, TN-119). The handler keeps
//! only each kind's listed members of what the port returns. Every write compiles to exactly
//! one `idp.platform.*` Exercise in the platform environment's governing domain through
//! [`PlatformResources`] (TN-110, PI-4, INV-2): a caller drafts it (`POST …/intents`, a read) and
//! sends the drafted body with its AIS. There is no route that acts as a user (TN-130).

mod handlers;

use super::domain::Surface;
use super::domain::page::{CURSOR, FILTER, PAGE_SIZE};
use super::manifest::{Access, Answer, Builder, Guard, ManifestError, Route, Verb, Visibility};
use super::ports::{PlatformKind, PlatformResources};

pub use handlers::serve;

const LIST: &[&str] = &[PAGE_SIZE, CURSOR, FILTER];

const fn read(path: &'static str, operation_id: &'static str, summary: &'static str) -> Route {
    Route {
        verb: Verb::Get,
        path,
        surface: Surface::Platform,
        access: Access::Read {
            scope: "platform.read",
        },
        visibility: Visibility::Forbidden,
        operation_id,
        summary,
        query: &[],
        answer: Answer::Replay,
        lifecycle: None,
    }
}

const fn list(path: &'static str, operation_id: &'static str, summary: &'static str) -> Route {
    Route {
        query: LIST,
        ..read(path, operation_id, summary)
    }
}

const fn create(path: &'static str, operation_id: &'static str, summary: &'static str) -> Route {
    Route {
        verb: Verb::Post,
        path,
        surface: Surface::Platform,
        access: Access::Write,
        visibility: Visibility::Forbidden,
        operation_id,
        summary,
        query: &[],
        answer: Answer::Replay,
        lifecycle: None,
    }
}

const fn act(path: &'static str, operation_id: &'static str, summary: &'static str) -> Route {
    create(path, operation_id, summary)
}

const T: &str = "/admin/v1/platform/tenants";
const TR: &str = "/admin/v1/platform/tenants/{tenant_id}/envs";
const TS: &str = "/admin/v1/platform/tenants/{tenant_id}/sandbox-domains";

/// Every platform resource route, in contract order.
pub const ROWS: &[Route] = &[
    Route {
        verb: Verb::Post,
        ..read(
            "/admin/v1/platform/intents",
            "draftPlatformIntent",
            "Drafts the intent a provisioning write compiles to, for the caller's AIS; changes nothing.",
        )
    },
    list(T, "listTenants", "Tenants and their states; metadata only."),
    create(
        T,
        "createTenant",
        "Creates a tenant awaiting its founder: its display name, the slug its management environment will take, the founder's address and its placement; the founder's invitation goes out with it (OP-159 m.47 (c)).",
    ),
    read(
        "/admin/v1/platform/tenants/{tenant_id}",
        "getTenant",
        "One tenant's metadata.",
    ),
    act(
        "/admin/v1/platform/tenants/{tenant_id}/reinvite-founder",
        "reinviteFounder",
        "Sends a tenant whose founding did not complete a new founder invitation; the old link and code stop working (TN-141).",
    ),
    act(
        "/admin/v1/platform/tenants/{tenant_id}/suspend",
        "suspendTenant",
        "Suspends a tenant: its environments stop serving (OP-159 m.47 (h)).",
    ),
    act(
        "/admin/v1/platform/tenants/{tenant_id}/reactivate",
        "reactivateTenant",
        "Lifts a tenant's suspension (OP-159 m.47 (h)).",
    ),
    act(
        "/admin/v1/platform/tenants/{tenant_id}/placement",
        "moveTenantPlacement",
        "Moves where a tenant's new environments are placed (OP-40, OP-159 m.47 (h)).",
    ),
    list(
        TR,
        "listTenantEnvironments",
        "A tenant's environments; metadata only.",
    ),
    list(TS, "listSandboxDomains", "A tenant's sandbox domains."),
    read(
        "/admin/v1/platform/envs/{environment_slug}",
        "getEnvironmentMetadata",
        "One environment's metadata and the state of its signing keys; never its settings or content.",
    ),
    read(
        "/admin/v1/platform/operator/health",
        "getOperatorHealth",
        "The deployment's readiness checks, by name; no secrets.",
    ),
];

/// How a row is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A page of a collection, with these filterable attributes.
    List(&'static [&'static str]),
    /// One resource.
    Get,
    /// A provisioning write; a success creates (`201`).
    Create,
    /// A provisioning write that changes a tenant; a success answers `200`.
    Act,
    /// The intent draft.
    Draft,
}

/// The members a platform tenant may show (INV-29: metadata only).
pub const TENANT_FIELDS: &[&str] = &[
    "tenant_id",
    "display_name",
    "management_slug",
    "founding",
    "status",
    "placement",
    "created_at",
];

/// The members a platform environment or sandbox domain may show (INV-29, X31: no settings, no
/// content).
pub const ENVIRONMENT_FIELDS: &[&str] = &[
    "slug",
    "kind",
    "tenant_id",
    "issuer",
    "status",
    "placement",
    "domain",
    "sandbox",
    "budget",
    "created_at",
    "key_state",
    "signing_available_at",
    "kex_share",
    "hosting",
];

/// The members the health summary may show.
pub const HEALTH_FIELDS: &[&str] = &["status", "checks"];

/// Members no platform answer carries, at any depth (INV-29, X31): account, client, grant,
/// record and claim content.
pub const CONTENT_FIELDS: &[&str] = &[
    "email",
    "phone",
    "sub",
    "redirect_uris",
    "grant",
    "record",
    "claims",
];

impl PlatformKind {
    /// The members an item of this kind may show.
    #[must_use]
    pub const fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Tenants => TENANT_FIELDS,
            Self::Environments | Self::SandboxDomains => ENVIRONMENT_FIELDS,
            Self::Health => HEALTH_FIELDS,
        }
    }
}

/// The resource kind and shape of a platform row.
#[must_use]
pub fn spec(operation_id: &str) -> Option<(PlatformKind, Shape)> {
    use PlatformKind::{Environments, Health, SandboxDomains, Tenants};
    Some(match operation_id {
        "draftPlatformIntent" => (Tenants, Shape::Draft),
        "listTenants" => (Tenants, Shape::List(&["tenant_id", "status", "placement"])),
        "createTenant" => (Tenants, Shape::Create),
        "getTenant" => (Tenants, Shape::Get),
        "reinviteFounder" | "suspendTenant" | "reactivateTenant" | "moveTenantPlacement" => {
            (Tenants, Shape::Act)
        }
        "listTenantEnvironments" => (Environments, Shape::List(&["slug", "status", "sandbox"])),
        "listSandboxDomains" => (SandboxDomains, Shape::List(&["slug", "status"])),
        "getEnvironmentMetadata" => (Environments, Shape::Get),
        "getOperatorHealth" => (Health, Shape::Get),
        _ => return None,
    })
}

/// Serves every platform row with [`serve`].
///
/// # Errors
/// [`ManifestError`].
pub fn register<G: Guard, E: super::ports::Env>(
    mut builder: Builder<G>,
) -> Result<Builder<G>, ManifestError> {
    for row in ROWS {
        builder = builder.handle(row.operation_id, serve::<E>)?;
    }
    Ok(builder)
}

/// Keeps only `fields` of a JSON object; anything else is no object at all (INV-29, X31: the
/// platform shows metadata it names, never what a port happens to return).
#[must_use]
pub fn project(value: serde_json::Value, fields: &[&str]) -> serde_json::Value {
    match value {
        serde_json::Value::Object(mut o) => {
            o.retain(|k, _| fields.contains(&k.as_str()));
            serde_json::Value::Object(o)
        }
        _ => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// The resources behind `env`, for handlers.
pub(crate) fn resources<E: super::ports::Env>(env: &E) -> &dyn PlatformResources {
    env.platform()
}
