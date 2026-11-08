//! The realm-admin resources under `/admin/v1/realms/{slug}/…` (OP-151 m.2 M1): clients,
//! groups and their members, accounts, upstream identity providers, mappers, inline hooks and
//! webhooks (TN-135, TN-136), and the settings singleton with its sign-in, session, branding, RP
//! ID and extension policy sections.
//!
//! Every write compiles to exactly one `idp.*` Exercise through [`RealmResources`] (TN-110,
//! PI-4, INV-2) and answers with `exercise_id` and `position`. A caller first drafts the write
//! (`POST …/intents`, a read: it changes nothing) to learn the intent its AIS signs, then sends
//! the drafted body with the AIS. `PUT` and `PATCH` (JSON Merge Patch) need `If-Match` with the
//! resource's `ETag`, the position of the decision that last changed it; a retire is a `POST`
//! to `…/{key}/retire`, never a `DELETE` (OP-73). No route writes a credential (TN-61).
//!
//! `GET …/audit/events` is the realm's full-taxonomy audit stream (channel B, OP-41) as OCSF
//! events, CEF lines or SET claims (`format`), oldest first, each with the time it occurred, was
//! recorded and was checkpointed; every read is first written as an `audit.read` event (OP-44).

mod handlers;
pub mod jobs;

use access_identity_admin::AdminError;
use access_identity_admin::domain::Invalid;
use access_parse::scim::{Filter, Op as FilterOp, Value as FilterValue};
use serde_json::Value;

use super::domain::Surface;
use super::domain::page::{CURSOR, FILTER, PAGE_SIZE};
use super::manifest::{Access, Answer, Builder, Guard, ManifestError, Route, Verb, Visibility};
use super::ports::ResourceKind;
use crate::problem::{Code, codes};

pub use handlers::{id_member, serve};

const LIST: &[&str] = &[PAGE_SIZE, CURSOR, FILTER];

/// The query parameter naming the audit stream's rendering.
pub const FORMAT: &str = "format";

const FEED: &[&str] = &[PAGE_SIZE, CURSOR, FORMAT];

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
const H: &str = "/admin/v1/realms/{slug}/hooks";
const W: &str = "/admin/v1/realms/{slug}/webhooks";
const WK: &str = "/admin/v1/realms/{slug}/webhooks/{webhook_id}";

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
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations",
        "createOrganization",
        "Creates an organization bound to the Party its founder's client registered; the founder becomes its first owner (TN-5).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/members/remove",
        "removeOrganizationMember",
        "Removes a member from an organization; its last active owner is kept (TN-91).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/upstream-idps/{name}/links",
        "linkUpstreamSubject",
        "Links a subject of the upstream identity provider to an account; its inbound signals then reach the account.",
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
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/jose-alg",
        "putJoseAlg",
        "Sets the realm's JOSE signing algorithm: ES256 or Ed25519.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/cimd-policy",
        "putCimdPolicy",
        "Sets which Client ID Metadata Document clients the realm accepts.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/cimd-policy",
        "patchCimdPolicy",
        "Changes the CIMD acceptance policy by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/protection-mode",
        "putProtectionMode",
        "Sets the attack protections' modes; loosening anything is a higher tier.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/protection-mode",
        "patchProtectionMode",
        "Changes the attack protections' modes by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/canary",
        "markCanaryAccount",
        "Makes an account a canary: a sign-in with it never opens a session.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/delete",
        "deleteAccount",
        "Deletes an account after its cancellation window; its personal data becomes unreadable when its keys are destroyed later (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/reset-intents",
        "createResetIntent",
        "Issues a one-time reset intent sent to the account's own registered address; the person chooses their new sign-in method themselves (TN-61).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/temporary-access-passes",
        "createTemporaryAccessPass",
        "Issues a temporary access pass, shown once to read out, in a realm that allows them; its session binds an authenticator only (TN-62).",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/recovery-policy",
        "putRecoveryPolicy",
        "Sets the recovery policy; anything that loosens it is a higher tier and only applies to recoveries started later (TN-55).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/jobs",
        "createJob",
        "Starts a bulk job: each item is its own write under its own AIS, and `revokeGrant` or `amendGrant` items are Grant revokes or amends, each its own Exercise (E17); answers 202.",
    ),
    read(
        "/admin/v1/realms/{slug}/jobs/{job_id}",
        "getJob",
        "A bulk job's state and counts, throttled items included.",
    ),
    list(
        "/admin/v1/realms/{slug}/jobs/{job_id}/items",
        "listJobItems",
        "A bulk job's per-item results: the Exercise or the problem that refused it.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/rehome",
        "rehomeRealm",
        "Moves the realm to another governing domain: declared and reserved, never applied.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/extension-policy",
        "putExtensionPolicy",
        "Sets whether hooks and webhooks may reach declared private targets and what hooks may receive.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/settings/extension-policy",
        "patchExtensionPolicy",
        "Changes the extension policy by JSON Merge Patch.",
    ),
    list(H, "listHooks", "The realm's inline hooks."),
    secret(
        Verb::Post,
        H,
        "registerHook",
        "Registers an inline hook at one call point; its verification key is shown once.",
    ),
    read(
        "/admin/v1/realms/{slug}/hooks/{hook_id}",
        "getHook",
        "One inline hook.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/hooks/{hook_id}/retire",
        "retireHook",
        "Retires an inline hook; a URL change is a retirement and a new registration.",
    ),
    list(W, "listWebhooks", "The realm's webhooks."),
    secret(
        Verb::Post,
        W,
        "registerWebhook",
        "Registers a webhook; its verification key is shown once.",
    ),
    read(WK, "getWebhook", "One webhook."),
    write(
        Verb::Put,
        WK,
        "putWebhook",
        "Replaces a webhook's URL and events.",
    ),
    write(
        Verb::Patch,
        WK,
        "patchWebhook",
        "Changes a webhook's URL or events by JSON Merge Patch.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/realms/{slug}/webhooks/{webhook_id}/rotate",
        "rotateWebhookKey",
        "Issues a new signing key, its verification key shown once; the old key signs too for 24 hours.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/webhooks/{webhook_id}/retire",
        "retireWebhook",
        "Retires a webhook; its pending deliveries fail.",
    ),
    list(
        "/admin/v1/realms/{slug}/webhooks/{webhook_id}/deliveries",
        "listWebhookDeliveries",
        "A webhook's delivery log, newest first: state, attempts and the last answer; never the event body.",
    ),
    read(
        "/admin/v1/realms/{slug}/signals",
        "getSignals",
        "The realm's signal sources: delayed transmitters, the GeoIP source, verifier reports.",
    ),
    read(
        "/admin/v1/realms/{slug}/analytics",
        "getAnalytics",
        "The realm's daily sign-in counts of the last 30 days and failed sign-in surges; never a decision input.",
    ),
    Route {
        query: FEED,
        ..read(
            "/admin/v1/realms/{slug}/audit/events",
            "listAuditEvents",
            "The realm's full-taxonomy audit stream, oldest first, as OCSF, CEF or SET claims; a copy, not the record. Each read is itself audited.",
        )
    },
    read(
        "/admin/v1/realms/{slug}/audit/events/{event_id}/proof",
        "getAuditEventProof",
        "The event's inclusion proof in the realm's own audit tree, checkpointed by the cell key under the realm's origin; it shows nothing of other realms. Each read is itself audited.",
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
    /// A bulk job's start (TN-125).
    JobCreate,
    /// A bulk job's envelope.
    JobGet,
    /// A bulk job's per-item results.
    JobItems,
    /// A page of the audit stream, channel B (OP-41).
    Audit,
    /// One audit event's inclusion proof in the realm's own tree (OP-152 m.7 (d)).
    AuditProof,
}

const CLIENT_PATCH: &[&str] = &[
    "display_name",
    "token_endpoint_auth_method",
    "jwks_uri",
    "redirect_uris",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
    "require_pushed_authorization_requests",
    "subject_type",
    "public_sub_opt_in",
    "sector_identifier_uri",
];
const GROUP_PATCH: &[&str] = &["display_name"];
const UPSTREAM_PATCH: &[&str] = &[
    "issuer",
    "client_id",
    "client_secret_ref",
    "jwks_uri",
    "ssf",
];
const SIGNIN_PATCH: &[&str] = &[
    "methods",
    "required_fields",
    "mfa_required",
    "domain_allow",
    "domain_deny",
];
const SESSION_PATCH: &[&str] = &["absolute_ms", "idle_ms", "binding"];
const CIMD_PATCH: &[&str] = &["enabled", "domains"];
const PROTECTION_PATCH: &[&str] = &[
    "bot",
    "suspicious_ip",
    "breached_password",
    "brute_force",
    "sl2",
    "denied_asns",
];
const EXTENSION_PATCH: &[&str] = &["allow_private_targets", "hook_disclosure"];
const WEBHOOK_PATCH: &[&str] = &["url", "events"];
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
    use ResourceKind::{
        Accounts, Analytics, Clients, Deliveries, Groups, Hooks, Settings, Signals, UpstreamIdps,
        Webhooks,
    };
    const CREATE: Shape = Shape::Write {
        patch: None,
        section: None,
        conditional: false,
        creates: true,
    };
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
        "suspendAccount"
        | "reactivateAccount"
        | "markCanaryAccount"
        | "deleteAccount"
        | "createResetIntent"
        | "createOrganization"
        | "removeOrganizationMember"
        | "createTemporaryAccessPass" => (Accounts, w(false)),
        "listUpstreamIdps" => (UpstreamIdps, Shape::List(&["name", "issuer", "status"])),
        "getUpstreamIdp" => (UpstreamIdps, Shape::Get),
        "putUpstreamIdp" => (UpstreamIdps, w(true)),
        "patchUpstreamIdp" => (UpstreamIdps, patch(UPSTREAM_PATCH, None)),
        "retireUpstreamIdp" | "linkUpstreamSubject" => (UpstreamIdps, w(false)),
        "getSettings" => (Settings, Shape::Get),
        "putSigninPolicy" => (Settings, put("signin_policy")),
        "patchSigninPolicy" => (Settings, patch(SIGNIN_PATCH, Some("signin_policy"))),
        "putSessionPolicy" => (Settings, put("session_policy")),
        "patchSessionPolicy" => (Settings, patch(SESSION_PATCH, Some("session_policy"))),
        "putBranding" => (Settings, put("branding")),
        "patchBranding" => (Settings, patch(BRANDING_PATCH, Some("branding"))),
        "putRpId" => (Settings, put("rp_id")),
        "putMapper" => (Settings, put("mappers")),
        "putJoseAlg" => (Settings, put("jose_alg")),
        "putCimdPolicy" => (Settings, put("cimd")),
        "patchCimdPolicy" => (Settings, patch(CIMD_PATCH, Some("cimd"))),
        "putProtectionMode" => (Settings, put("protection_mode")),
        "patchProtectionMode" => (Settings, patch(PROTECTION_PATCH, Some("protection_mode"))),
        "rehomeRealm" | "putRecoveryPolicy" => (Settings, w(false)),
        "createJob" => (Settings, Shape::JobCreate),
        "getJob" => (Settings, Shape::JobGet),
        "listJobItems" => (Settings, Shape::JobItems),
        "putExtensionPolicy" => (Settings, put("extension_policy")),
        "patchExtensionPolicy" => (Settings, patch(EXTENSION_PATCH, Some("extension_policy"))),
        "listHooks" => (Hooks, Shape::List(&["hook_id", "point", "status"])),
        "getHook" => (Hooks, Shape::Get),
        "registerHook" => (Hooks, CREATE),
        "retireHook" => (Hooks, w(false)),
        "listWebhooks" => (Webhooks, Shape::List(&["webhook_id", "url", "status"])),
        "getWebhook" => (Webhooks, Shape::Get),
        "registerWebhook" => (Webhooks, CREATE),
        "putWebhook" => (Webhooks, w(true)),
        "patchWebhook" => (Webhooks, patch(WEBHOOK_PATCH, None)),
        "rotateWebhookKey" | "retireWebhook" => (Webhooks, w(false)),
        "listWebhookDeliveries" => (Deliveries, Shape::List(&["event", "state"])),
        "getSignals" => (Signals, Shape::Get),
        "getAnalytics" => (Analytics, Shape::Get),
        // OP-41
        "listAuditEvents" => (Analytics, Shape::Audit),
        "getAuditEventProof" => (Analytics, Shape::AuditProof),
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
/// missing resource is `not-found` like a hidden one, TN-113).
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
            Invalid::UpstreamSubject => &r::INVALID_UPSTREAM_SUBJECT,
            Invalid::UpstreamSubjectLinked => &r::UPSTREAM_SUBJECT_LINKED,
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
            Invalid::PublicSub => &r::PUBLIC_SUB_NOT_OPTED_IN,
            Invalid::SectorIdentifier => &r::INVALID_SECTOR_IDENTIFIER_URI,
            Invalid::Reserved => &r::RESERVED_OPERATION,
            Invalid::JoseAlg => &r::INVALID_JOSE_ALG,
            Invalid::ProtectionMode => &r::INVALID_PROTECTION_MODE,
            Invalid::ExtensionTarget => &r::INVALID_EXTENSION_TARGET,
            Invalid::Hook => &r::INVALID_HOOK,
            Invalid::Disclosure => &r::DISCLOSURE_NOT_PERMITTED,
            Invalid::WebhookEvents => &r::INVALID_WEBHOOK_EVENTS,
            Invalid::ExtensionPolicy => &r::INVALID_EXTENSION_POLICY,
            Invalid::HookPointTaken => &r::HOOK_POINT_TAKEN,
            Invalid::CatalogUpgradeRequired => &r::CATALOG_UPGRADE_REQUIRED,
            Invalid::OrgExists => &r::RESOURCE_EXISTS,
            Invalid::LastOwner => &r::LAST_OWNER,
            Invalid::RecoveryPolicy => &r::INVALID_RECOVERY_POLICY,
            Invalid::RecoveryOption => &r::RECOVERY_OPTION_OFF,
            Invalid::SelfIssue => &r::SELF_ISSUE_REFUSED,
            Invalid::NotOrganization => &r::NOT_AN_ORGANIZATION,
            Invalid::OrgLimit => &codes::RATE_LIMITED,
            Invalid::NoClient
            | Invalid::NoKey
            | Invalid::NoGroup
            | Invalid::NoAccount
            | Invalid::NoUpstream
            | Invalid::NoHook
            | Invalid::NoWebhook
            | Invalid::NoOrg
            | Invalid::NoMember => &codes::NOT_FOUND,
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
