//! The realm-admin resources under `/admin/v1/realms/{slug}/…` (OP-151 m.2 M1): clients,
//! groups and their members, accounts, upstream identity providers, mappers and the settings
//! singleton with its sign-in, session, branding and RP ID sections.
//!
//! Every write compiles to exactly one `idp.*` Exercise through [`RealmResources`] (TN-110,
//! PI-4, INV-2) and answers with `exercise_id` and `position`. A caller first drafts the write
//! (`POST …/intents`, a read: it changes nothing) to learn the intent its AIS signs, then sends
//! the drafted body with the AIS. `PUT` and `PATCH` (JSON Merge Patch) need `If-Match` with the
//! resource's `ETag`, the position of the decision that last changed it; a retire is a `POST`
//! to `…/{key}/retire`, never a `DELETE` (OP-73). No route writes a credential (TN-61).

mod handlers;

use access_identity_admin::AdminError;
use access_identity_admin::domain::Invalid;
use access_parse::scim::{Filter, Op as FilterOp, Value as FilterValue};
use serde_json::Value;

use super::domain::Surface;
use super::domain::page::{CURSOR, FILTER, PAGE_SIZE};
use super::manifest::{Access, Answer, Builder, Guard, ManifestError, Route, Verb, Visibility};
use super::ports::ResourceKind;
use crate::problem::{Code, codes};

pub use handlers::serve;

const LIST: &[&str] = &[PAGE_SIZE, CURSOR, FILTER];

const fn read(path: &'static str, operation_id: &'static str, summary: &'static str) -> Route {
    Route {
        verb: Verb::Get,
        path,
        surface: Surface::Realm,
        access: Access::Read {
            scope: "realm.read",
        },
        visibility: Visibility::Hidden,
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

const fn write(
    verb: Verb,
    path: &'static str,
    operation_id: &'static str,
    summary: &'static str,
) -> Route {
    Route {
        verb,
        path,
        surface: Surface::Realm,
        access: Access::Write,
        visibility: Visibility::Hidden,
        operation_id,
        summary,
        query: &[],
        answer: Answer::Replay,
        lifecycle: None,
    }
}

const fn secret(verb: Verb, path: &'static str, id: &'static str, summary: &'static str) -> Route {
    Route {
        answer: Answer::Secret,
        ..write(verb, path, id, summary)
    }
}

const C: &str = "/admin/v1/realms/{slug}/clients";
const G: &str = "/admin/v1/realms/{slug}/groups";

/// Every realm resource route, in contract order.
pub const ROWS: &[Route] = &[
    Route {
        verb: Verb::Post,
        ..read(
            "/admin/v1/realms/{slug}/intents",
            "draftIntent",
            "Drafts the intent a write compiles to, for the caller's AIS; changes nothing.",
        )
    },
    list(C, "listClients", "The realm's clients."),
    secret(
        Verb::Post,
        C,
        "createClient",
        "Registers a client; a client_secret_basic client's secret is shown once.",
    ),
    read(
        "/admin/v1/realms/{slug}/clients/{client_id}",
        "getClient",
        "One client.",
    ),
    secret(
        Verb::Put,
        "/admin/v1/realms/{slug}/clients/{client_id}",
        "putClient",
        "Replaces a client's registration.",
    ),
    secret(
        Verb::Patch,
        "/admin/v1/realms/{slug}/clients/{client_id}",
        "patchClient",
        "Changes a client's registration by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/clients/{client_id}/retire",
        "retireClient",
        "Retires a client; its client_id is never reused.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/realms/{slug}/clients/{client_id}/secret/rotate",
        "rotateClientSecret",
        "Issues a new client_secret, shown once; the old one stays valid for 24 hours.",
    ),
    list(G, "listGroups", "The realm's groups."),
    read(
        "/admin/v1/realms/{slug}/groups/{name}",
        "getGroup",
        "One group.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/groups/{name}",
        "putGroup",
        "Creates a group with its one membership issuer, or renames it.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/groups/{name}",
        "patchGroup",
        "Renames a group by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/groups/{name}/retire",
        "retireGroup",
        "Retires a group and ends its memberships.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/groups/{name}/members",
        "addGroupMembers",
        "Adds accounts to a group the administration issues members of.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/groups/{name}/members/remove",
        "removeGroupMembers",
        "Removes accounts from a group the administration issues members of.",
    ),
    list(
        "/admin/v1/realms/{slug}/accounts",
        "listAccounts",
        "The realm's accounts and their states.",
    ),
    read(
        "/admin/v1/realms/{slug}/accounts/{account_id}",
        "getAccount",
        "One account's state.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/suspend",
        "suspendAccount",
        "Suspends an account and ends its sessions.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/reactivate",
        "reactivateAccount",
        "Reactivates a suspended account.",
    ),
    list(
        "/admin/v1/realms/{slug}/upstream-idps",
        "listUpstreamIdps",
        "The realm's upstream identity providers.",
    ),
    read(
        "/admin/v1/realms/{slug}/upstream-idps/{name}",
        "getUpstreamIdp",
        "One upstream identity provider.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/upstream-idps/{name}",
        "putUpstreamIdp",
        "Registers or replaces an upstream identity provider (reserved).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/upstream-idps/{name}",
        "patchUpstreamIdp",
        "Changes an upstream identity provider by JSON Merge Patch (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/upstream-idps/{name}/retire",
        "retireUpstreamIdp",
        "Retires an upstream identity provider.",
    ),
    read(
        "/admin/v1/realms/{slug}/settings",
        "getSettings",
        "The realm's settings: sign-in, session, branding, RP ID, mappers.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/signin-policy",
        "putSigninPolicy",
        "Sets the sign-in requirements.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/signin-policy",
        "patchSigninPolicy",
        "Changes the sign-in requirements by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/session-policy",
        "putSessionPolicy",
        "Sets the console session policy.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/session-policy",
        "patchSessionPolicy",
        "Changes the console session policy by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/branding",
        "putBranding",
        "Sets the hosted pages' branding.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/branding",
        "patchBranding",
        "Changes the hosted pages' branding by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/rp-id",
        "putRpId",
        "Pins or changes the WebAuthn RP ID: irreversible, reserved.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/mappers/{claim}",
        "putMapper",
        "Sets or removes the profile attribute a claim is taken from.",
    ),
];

/// How a row is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A page of a collection, with these filterable attributes.
    List(&'static [&'static str]),
    /// One resource.
    Get,
    /// A write; `PUT` and `PATCH` are conditional on the resource's `ETag`.
    Write {
        /// For a `PATCH`, the members the patch may touch.
        patch: Option<&'static [&'static str]>,
        /// The section of the settings view the write replaces, for settings writes.
        section: Option<&'static str>,
        /// Whether `If-Match` applies.
        conditional: bool,
        /// Whether a success creates (`201`).
        creates: bool,
    },
    /// The intent draft.
    Draft,
}

const CLIENT_PATCH: &[&str] = &[
    "display_name",
    "token_endpoint_auth_method",
    "jwks_uri",
    "redirect_uris",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
    "require_pushed_authorization_requests",
];
const GROUP_PATCH: &[&str] = &["display_name"];
const UPSTREAM_PATCH: &[&str] = &[
    "issuer",
    "client_id",
    "client_secret_ref",
    "jwks_uri",
    "ssf_configuration_uri",
];
const SIGNIN_PATCH: &[&str] = &[
    "methods",
    "required_fields",
    "mfa_required",
    "domain_allow",
    "domain_deny",
];
const SESSION_PATCH: &[&str] = &["absolute_ms", "idle_ms", "binding"];
const BRANDING_PATCH: &[&str] = &[
    "display_name",
    "logo_uri",
    "primary_color",
    "background_color",
    "csp_origins",
];

const fn w(conditional: bool) -> Shape {
    Shape::Write {
        patch: None,
        section: None,
        conditional,
        creates: false,
    }
}

const fn patch(members: &'static [&'static str], section: Option<&'static str>) -> Shape {
    Shape::Write {
        patch: Some(members),
        section,
        conditional: true,
        creates: false,
    }
}

const fn put(section: &'static str) -> Shape {
    Shape::Write {
        patch: None,
        section: Some(section),
        conditional: true,
        creates: false,
    }
}

/// The resource kind and shape of a realm row.
#[must_use]
pub fn spec(operation_id: &str) -> Option<(ResourceKind, Shape)> {
    use ResourceKind::{Accounts, Clients, Groups, Settings, UpstreamIdps};
    Some(match operation_id {
        "draftIntent" => (Settings, Shape::Draft),
        "listClients" => (
            Clients,
            Shape::List(&["client_id", "display_name", "status"]),
        ),
        "getClient" => (Clients, Shape::Get),
        "createClient" => (
            Clients,
            Shape::Write {
                patch: None,
                section: None,
                conditional: false,
                creates: true,
            },
        ),
        "putClient" => (Clients, w(true)),
        "patchClient" => (Clients, patch(CLIENT_PATCH, None)),
        "retireClient" | "rotateClientSecret" => (Clients, w(false)),
        "listGroups" => (Groups, Shape::List(&["name", "display_name", "status"])),
        "getGroup" => (Groups, Shape::Get),
        "putGroup" => (Groups, w(true)),
        "patchGroup" => (Groups, patch(GROUP_PATCH, None)),
        "retireGroup" | "addGroupMembers" | "removeGroupMembers" => (Groups, w(false)),
        "listAccounts" => (Accounts, Shape::List(&["account_id", "status"])),
        "getAccount" => (Accounts, Shape::Get),
        "suspendAccount" | "reactivateAccount" => (Accounts, w(false)),
        "listUpstreamIdps" => (UpstreamIdps, Shape::List(&["name", "issuer", "status"])),
        "getUpstreamIdp" => (UpstreamIdps, Shape::Get),
        "putUpstreamIdp" => (UpstreamIdps, w(true)),
        "patchUpstreamIdp" => (UpstreamIdps, patch(UPSTREAM_PATCH, None)),
        "retireUpstreamIdp" => (UpstreamIdps, w(false)),
        "getSettings" => (Settings, Shape::Get),
        "putSigninPolicy" => (Settings, put("signin_policy")),
        "patchSigninPolicy" => (Settings, patch(SIGNIN_PATCH, Some("signin_policy"))),
        "putSessionPolicy" => (Settings, put("session_policy")),
        "patchSessionPolicy" => (Settings, patch(SESSION_PATCH, Some("session_policy"))),
        "putBranding" => (Settings, put("branding")),
        "patchBranding" => (Settings, patch(BRANDING_PATCH, Some("branding"))),
        "putRpId" => (Settings, put("rp_id")),
        "putMapper" => (Settings, put("mappers")),
        _ => return None,
    })
}

/// Serves every realm row with [`serve`].
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

/// The problem an identity plane refusal answers with (OP-64: a refused write is a problem; a
/// missing resource is `not_found` like a hidden one, TN-113).
#[must_use]
pub fn problem_of(e: &AdminError) -> &'static Code {
    use codes::realm as r;
    match e {
        AdminError::Invalid(i) => match i {
            Invalid::ClientId => &r::INVALID_CLIENT_ID,
            Invalid::DisplayName => &r::INVALID_DISPLAY_NAME,
            Invalid::RedirectUri | Invalid::RedirectUris => &r::INVALID_REDIRECT_URI,
            Invalid::JwksUri => &r::INVALID_JWKS_URI,
            Invalid::Host => &r::INVALID_HOST,
            Invalid::Claim => &r::RESERVED_CLAIM,
            Invalid::Attribute => &r::INVALID_ATTRIBUTE,
            Invalid::Argon2 => &r::ARGON2_LOWERED,
            Invalid::RpId => &r::INVALID_RP_ID,
            Invalid::PlatformTenant | Invalid::PlatformAuth => &r::PLATFORM_FIELDS_READ_ONLY,
            Invalid::PublicKey | Invalid::ClientKey => &r::INVALID_PUBLIC_KEY,
            Invalid::EventReceiver => &r::INVALID_EVENT_RECEIVER,
            Invalid::Branding => &r::INVALID_BRANDING,
            Invalid::KeyPolicy => &r::INVALID_KEY_POLICY,
            Invalid::Name => &r::INVALID_NAME,
            Invalid::MembershipIssuer => &r::INVALID_MEMBERSHIP_ISSUER,
            Invalid::Members => &r::INVALID_MEMBERS,
            Invalid::Upstream => &r::INVALID_UPSTREAM,
            Invalid::SigninPolicy => &r::INVALID_SIGNIN_POLICY,
            Invalid::SessionPolicy => &r::INVALID_SESSION_POLICY,
            Invalid::ClientExists | Invalid::GroupExists | Invalid::UpstreamExists => {
                &r::RESOURCE_EXISTS
            }
            Invalid::UpstreamMembership => &r::MEMBERSHIP_ISSUED_UPSTREAM,
            Invalid::AccountState => &r::ACCOUNT_STATE_CONFLICT,
            Invalid::NoSecret => &r::CLIENT_HAS_NO_SECRET,
            Invalid::PasskeyLoss => &r::PASSKEY_LOSS_NOT_ACKNOWLEDGED,
            Invalid::Body => &r::INVALID_BODY,
            Invalid::Validity => &r::INVALID_VALIDITY,
            Invalid::NoClient
            | Invalid::NoKey
            | Invalid::NoGroup
            | Invalid::NoAccount
            | Invalid::NoUpstream => &codes::NOT_FOUND,
        },
        AdminError::Issuer(_) | AdminError::NoRealm => &codes::NOT_FOUND,
        AdminError::Refused(_) => &codes::EXERCISE_REFUSED,
        AdminError::Conflict => &r::CONFLICT,
        AdminError::Unbound => &codes::INTERNAL,
        AdminError::Unavailable(_)
        | AdminError::Store(_)
        | AdminError::OpaqueId(_)
        | AdminError::Encode => &codes::UNAVAILABLE,
    }
}

fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Whether `item` satisfies the SCIM filter subset (OP-65): comparisons over the item's
/// top-level members; text compares exactly, as stored.
#[must_use]
pub fn matches(filter: &Filter, item: &Value) -> bool {
    match filter {
        Filter::And(a, b) => matches(a, item) && matches(b, item),
        Filter::Or(a, b) => matches(a, item) || matches(b, item),
        Filter::Present(attr) => item.get(*attr).is_some_and(|v| !v.is_null()),
        Filter::Compare { attr, op, value } => {
            let have = item.get(*attr).and_then(text_of);
            let want = match value {
                FilterValue::Text(s) | FilterValue::Number(s) => Some(s.clone()),
                FilterValue::Bool(b) => Some(b.to_string()),
                FilterValue::Null => None,
            };
            match (op, have, want) {
                (FilterOp::Eq, h, w) => h == w,
                (FilterOp::Ne, h, w) => h != w,
                (FilterOp::Co, Some(h), Some(w)) => h.contains(&w),
                (FilterOp::Sw, Some(h), Some(w)) => h.starts_with(&w),
                _ => false,
            }
        }
    }
}
