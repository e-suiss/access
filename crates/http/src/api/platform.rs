//! The platform-admin resources under `/admin/v1/platform/…` (OP-151 m.2 M2): tenants, realm
//! creation (a Genesis of the realm's governing domain, TN-111), realm metadata with the state
//! of its keys (CR-25, CR-59), sandbox domains (OP-151 m.3 (m), X21) and the operator's health.
//!
//! Every read is metadata: no route returns account, client, grant, record or claim content, and
//! no route reads a realm's settings or authority state (INV-29, X31, TN-119). The handler keeps
//! only each kind's listed members of what the port returns. Every write compiles to exactly
//! one `idp.platform.*` Exercise in the platform realm's governing domain through
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

const T: &str = "/admin/v1/platform/tenants";
const TR: &str = "/admin/v1/platform/tenants/{tenant_id}/realms";
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
    create(T, "createTenant", "Creates a tenant."),
    read(
        "/admin/v1/platform/tenants/{tenant_id}",
        "getTenant",
        "One tenant's metadata.",
    ),
    list(TR, "listTenantRealms", "A tenant's realms; metadata only."),
    create(
        TR,
        "createRealm",
        "Creates a realm by a Genesis of its governing domain with the caller's founding root; Joint(k >= 2) is recommended, a sole root must acknowledge that it cannot be recovered.",
    ),
    list(TS, "listSandboxDomains", "A tenant's sandbox domains."),
    create(
        TS,
        "createSandboxDomain",
        "Creates a sandbox realm whose governing domain is a separate AuthorityDomain from the sandbox template, with its fixed budget.",
    ),
    read(
        "/admin/v1/platform/realms/{realm_slug}",
        "getRealmMetadata",
        "One realm's metadata and the state of its signing keys; never its settings or content.",
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
    /// The intent draft.
    Draft,
}

/// The members a platform tenant may show (INV-29: metadata only).
pub const TENANT_FIELDS: &[&str] = &["tenant_id", "status", "placement", "created_at"];

/// The members a platform realm or sandbox domain may show (INV-29, X31: no settings, no
/// content).
pub const REALM_FIELDS: &[&str] = &[
    "slug",
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
];

/// The members the health summary may show.
pub const HEALTH_FIELDS: &[&str] = &["status", "checks"];

/// The members a realm creation's `genesis` may show (TN-111).
pub const GENESIS_FIELDS: &[&str] = &["digest", "root", "recovery", "recovery_reason"];

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
            Self::Realms | Self::SandboxDomains => REALM_FIELDS,
            Self::Health => HEALTH_FIELDS,
        }
    }
}

/// The resource kind and shape of a platform row.
#[must_use]
pub fn spec(operation_id: &str) -> Option<(PlatformKind, Shape)> {
    use PlatformKind::{Health, Realms, SandboxDomains, Tenants};
    Some(match operation_id {
        "draftPlatformIntent" => (Tenants, Shape::Draft),
        "listTenants" => (Tenants, Shape::List(&["tenant_id", "status", "placement"])),
        "createTenant" => (Tenants, Shape::Create),
        "getTenant" => (Tenants, Shape::Get),
        "listTenantRealms" => (Realms, Shape::List(&["slug", "status", "sandbox"])),
        "createRealm" => (Realms, Shape::Create),
        "listSandboxDomains" => (SandboxDomains, Shape::List(&["slug", "status"])),
        "createSandboxDomain" => (SandboxDomains, Shape::Create),
        "getRealmMetadata" => (Realms, Shape::Get),
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
