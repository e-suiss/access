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

const AG: &str = "/admin/v1/realms/{slug}/agents";
const AGK: &str = "/admin/v1/realms/{slug}/agents/{agent}";
const C: &str = "/admin/v1/realms/{slug}/clients";
const G: &str = "/admin/v1/realms/{slug}/groups";
const H: &str = "/admin/v1/realms/{slug}/hooks";
const W: &str = "/admin/v1/realms/{slug}/webhooks";
const WK: &str = "/admin/v1/realms/{slug}/webhooks/{webhook_id}";

/// The Stage 9 realm routes, declared before their lanes serve them (OP-154 m.4): each answers
/// `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE9: [Route; 20] = [
    list(
        AG,
        "listAgents",
        "The realm's agents: kind, operator, sponsors and status (OP-154 m.3 (c), (e)).",
    ),
    write(
        Verb::Post,
        AG,
        "registerAgent",
        "Registers an agent bound to one self-registered agent Party: idp.agent.register (OP-154 m.3 (c)).",
    ),
    read(
        AGK,
        "getAgent",
        "One agent: kind, operator, sponsors, status, authority, connected accounts and last run.",
    ),
    write(
        Verb::Patch,
        AGK,
        "patchAgent",
        "Changes an agent's name and description by JSON Merge Patch: idp.agent.update.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/agents/{agent}/retire",
        "retireAgent",
        "Retires an agent: idp.agent.retire; nothing is deleted (OP-73).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/agents/{agent}/revoke-all",
        "revokeAllAgentInstances",
        "Ends every Instance of the agent as a bulk job of the caller's signed instance_terminate items (OP-154 m.3 (f), P59).",
    ),
    list(
        "/admin/v1/realms/{slug}/agents/{agent}/sponsors",
        "listAgentSponsors",
        "The agent's human sponsors (AG-41).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/agents/{agent}/sponsors",
        "assignAgentSponsor",
        "Assigns a human sponsor: idp.agent.sponsor_assign (OP-154 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/agents/{agent}/sponsors/{sponsor}/remove",
        "removeAgentSponsor",
        "Removes a sponsor: idp.agent.sponsor_remove; the last one leaving suspends the agent (OP-154 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/agent-templates",
        "defineAgentTemplate",
        "Defines an agent Grant template; one without a budget is refused (OP-154 m.3 (g)).",
    ),
    list(
        "/admin/v1/realms/{slug}/resources",
        "listProtectedResources",
        "The realm's protected resources and MCP servers, by canonical URI.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/resources",
        "registerProtectedResource",
        "Registers a protected resource or MCP server for `resource` validation: idp.client.resource_register.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/dcr-policy",
        "putDcrPolicy",
        "Sets the dynamic client registration profile: idp.client.dcr_policy, or dcr_policy_tighten when it only narrows (OP-154 m.3 (j)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/cross-app-connections",
        "createCrossAppConnection",
        "Records a cross-app connection for ID-JAG: idp.client.cross_app_connection (OP-154 m.3 (n)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/cross-app-connections/{connection}/retire",
        "retireCrossAppConnection",
        "Retires a cross-app connection: idp.client.cross_app_connection_retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/device-code",
        "putDeviceCode",
        "Turns the device authorization grant on (idp.realm.device_code) or off (device_code_close) (OP-154 m.3 (p)).",
    ),
    list(
        "/admin/v1/realms/{slug}/vault/resources",
        "listVaultResources",
        "The realm's vault Resources: the catalog upstreams it enabled and its own (OP-154 m.3 (t)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/vault/resources/{resource}",
        "putVaultResource",
        "Enables a catalog upstream (idp.vault.resource_enable) or registers the realm's own (resource_register, reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/vault/resources/{resource}/disable",
        "disableVaultResource",
        "Disables a vault Resource: idp.vault.resource_disable.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/vault-release-mode",
        "putVaultReleaseMode",
        "Opens release path (b) for CT0-CT1 classes (idp.vault.release_mode_open) or closes it (release_mode_close) (OP-154 m.3 (t)).",
    ),
];

/// Every realm resource route, in contract order.
pub const ROWS: &[Route] = &ALL_ROWS;

const BASE_LEN: usize = BASE.len();

#[expect(
    clippy::indexing_slicing,
    reason = "evaluated at compile time; an out-of-range index fails the build"
)]
const ALL_ROWS: [Route; BASE_LEN + STAGE9.len()] = {
    let mut out = [BASE[0]; BASE_LEN + STAGE9.len()];
    let mut i = 0;
    while i < BASE_LEN {
        out[i] = BASE[i];
        i += 1;
    }
    let mut j = 0;
    while j < STAGE9.len() {
        out[BASE_LEN + j] = STAGE9[j];
        j += 1;
    }
    out
};

/// Whether a realm row is a Stage 9 declaration (OP-154 m.4).
fn declared(operation_id: &str) -> bool {
    STAGE9.iter().any(|r| r.operation_id == operation_id)
}

/// Whether a realm row is declared and not served yet (OP-154 m.4).
#[must_use]
pub fn planned(operation_id: &str) -> bool {
    declared(operation_id) && matches!(spec(operation_id), Some((_, Shape::Planned(_))))
}

const BASE: &[Route] = &[
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
        "/admin/v1/realms/{slug}/accounts/import",
        "importAccounts",
        "Imports accounts from another identity provider (idp.account.import, TN-85): `content` is the JSON Lines file of `access-server import-accounts`, `file` its SHA-256 and `accounts` its line count, which the signed change names; each line becomes its own account or is reported as skipped, never echoed.",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/guardianships",
        "recordGuardianship",
        "Records that `guardian_account_id` stands for this ward on `basis` (`parent`, `legal_guardian`) in `country` (idp.account.guardianship_record, CT2, E53): its guardianship Claim holds until the ward's majority by the country table and ends then without anyone's signature; the ward's date of birth must be on file.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/{account_id}/bind",
        "bindAccount",
        "Binds the account and `peer_account_id` of the tenant's realm `peer_realm` (its slug) as one person (idp.account.bind, CT2): the realm that binds first answers with its realm-signed `offer`, shown once; the peer realm's administrator binds the same pair sending that `offer`, which the peer realm verifies against this realm's keys.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/realms/{slug}/accounts/migration-export",
        "exportAccounts",
        "Exports every active account to another deployment (idp.account.migration_export, reserved, TN-86): sealed to the P-256 `recipient` key (SEC1, base64url) it names; the `bundle` (dCBOR, base64url) is shown once and holds the import lines that deployment's importAccounts takes.",
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
    list(
        "/admin/v1/realms/{slug}/social-providers",
        "listSocialProviders",
        "The social presets the realm enabled, with their warnings (IDP-31, TN-87).",
    ),
    read(
        "/admin/v1/realms/{slug}/social-providers/{preset}",
        "getSocialProvider",
        "One social preset the realm enabled.",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/social-providers/{preset}",
        "putSocialProvider",
        "Enables or changes a social preset; only a sandbox realm may omit its own client (idp.social.enable, update).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/realms/{slug}/social-providers/{preset}",
        "patchSocialProvider",
        "Changes a social preset's client by JSON Merge Patch (idp.social.update).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/social-providers/{preset}/disable",
        "disableSocialProvider",
        "Stops offering a social preset; linked sign-ins stay (idp.social.disable).",
    ),
    list(
        "/admin/v1/realms/{slug}/organizations",
        "listOrganizations",
        "The realm's live organizations (§8.5 S7).",
    ),
    read(
        "/admin/v1/realms/{slug}/organizations/{organization}",
        "getOrganization",
        "One organization: its roots and members with each membership source and role, its domain claims, ownership handovers and connection drafts (§8.5 S7, TN-91).",
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
        Verb::Patch,
        "/admin/v1/realms/{slug}/organizations/{organization}",
        "patchOrganization",
        "Renames an organization or turns home realm discovery to it on or off; on needs a verified domain no other organization claims (TN-98).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/invitations",
        "createInvitation",
        "Invites a person into an organization by e-mail: the link and its magic code go only in the mail, the role comes from the invitation (TN-89).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/invitations/revoke",
        "revokeInvitation",
        "Revokes an open invitation (OP-153 m.3 (o)).",
    ),
    secret(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/domains",
        "claimOrganizationDomain",
        "Claims a domain for an organization; its challenge, shown once, is published as a DNS TXT record or an HTTPS document, and the domain counts as verified only while its time-limited domain_verification Claim holds (TN-90).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/domains/release",
        "releaseOrganizationDomain",
        "Releases an organization's domain claim and retracts its verification (TN-90).",
    ),
    write(
        Verb::Post,
        "/admin/v1/realms/{slug}/organizations/{organization}/connection-drafts",
        "draftOrganizationConnection",
        "Drafts an enterprise connection; only idp.upstream.register (CT3) at the organization's root puts it into effect (TN-120).",
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
        "/admin/v1/realms/{slug}/settings/csp-mode",
        "putCspMode",
        "Sets the hosted pages' CSP mode: `enforce`, or `report_only`, which loosens the page and is a higher tier (OP-153 m.22 (g)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/related-origins",
        "putRelatedOrigins",
        "Sets the realm's Related Origins: https origins under the organizations' verified domains, at most five registrable labels with the RP ID's (TN-18).",
    ),
    write(
        Verb::Put,
        "/admin/v1/realms/{slug}/settings/locale-overrides",
        "putLocaleOverrides",
        "Sets the realm's texts for the hosted pages by locale and message key: plain text, known keys only, never a protected one (X35).",
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
        "Starts a bulk job: each item is its own write under its own AIS, and `revokeGrant` or `amendGrant` items are Grant revokes or amends, each its own Exercise (E17); `issueRoleGrant` issues an accepted invitation's role (TN-89), `proposeOwnershipHandover` (accepted, nothing decided yet) and `completeOwnershipHandover` carry an organization's `anchor_transfer` (TN-91), and `issueAutojoinGrant` (key: the organization) an owner's `grant_issue` of the autojoin role, held by the organization's `org_member` Claims (TN-90); answers 202.",
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
    /// A declared route its lane does not serve yet: `501 not-yet-served` behind its
    /// permission (OP-154 m.4); the response schema it will answer with.
    Planned(&'static str),
    /// An agent's `revoke-all`: a bulk job of the caller's signed `instance_terminate` items,
    /// one per live Instance of the agent (OP-154 m.3 (f), P59).
    RevokeAll,
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
    "spiffe_id",
    "spiffe_bundle_endpoint",
    "agent",
];
const GROUP_PATCH: &[&str] = &["display_name"];
const AGENT_PATCH: &[&str] = &["display_name", "description"];
const UPSTREAM_PATCH: &[&str] = &[
    "issuer",
    "client_id",
    "client_secret_ref",
    "jwks_uri",
    "ssf",
];
const SOCIAL_PATCH: &[&str] = &["client_id", "client_secret_ref"];
const SIGNIN_PATCH: &[&str] = &[
    "dbsc",
    "methods",
    "required_fields",
    "mfa_required",
    "domain_allow",
    "domain_deny",
    "enumeration",
    "email_keep_days",
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
#[expect(
    clippy::too_many_lines,
    reason = "one match over the realm rows, each arm one row"
)]
pub fn spec(operation_id: &str) -> Option<(ResourceKind, Shape)> {
    use ResourceKind::{
        Accounts, AgentSponsors, Agents, Analytics, Clients, Deliveries, Groups, Hooks,
        Organizations, ProtectedResources, Settings, Signals, SocialProviders, UpstreamIdps,
        VaultResources, Webhooks,
    };
    const CREATE: Shape = Shape::Write {
        patch: None,
        section: None,
        conditional: false,
        creates: true,
    };
    Some(match operation_id {
        "draftIntent" => (Settings, Shape::Draft),
        // OP-154 m.3 (c), (e), (f), (g)
        "listAgents" => (
            Agents,
            Shape::List(&["agent", "display_name", "agent_kind", "status"]),
        ),
        "getAgent" => (Agents, Shape::Get),
        "registerAgent" => (Agents, CREATE),
        "patchAgent" => (Agents, patch(AGENT_PATCH, None)),
        "retireAgent" | "assignAgentSponsor" | "removeAgentSponsor" => (Agents, w(false)),
        "listAgentSponsors" => (AgentSponsors, Shape::List(&["account_id"])),
        // OP-154 m.3 (g), (j)
        "defineAgentTemplate" | "putDcrPolicy" => (Settings, w(false)),
        "revokeAllAgentInstances" => (Agents, Shape::RevokeAll),
        // OP-154 m.3 (t)
        "listVaultResources" => (
            VaultResources,
            Shape::List(&["resource", "upstream", "status"]),
        ),
        "putVaultResource" => (VaultResources, w(true)),
        "disableVaultResource" | "putVaultReleaseMode" => (VaultResources, w(false)),
        // AG-8, OP-154 m.3 (a)
        "listProtectedResources" => (
            ProtectedResources,
            Shape::List(&["resource", "display_name"]),
        ),
        "registerProtectedResource" => (ProtectedResources, CREATE),
        o if declared(o) => (Settings, Shape::Planned("WriteResult")),
        "listClients" => (
            Clients,
            Shape::List(&["client_id", "display_name", "status"]),
        ),
        "getClient" => (Clients, Shape::Get),
        "createClient" => (Clients, CREATE),
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
        | "createTemporaryAccessPass"
        | "createInvitation"
        | "revokeInvitation"
        | "patchOrganization"
        | "claimOrganizationDomain"
        | "releaseOrganizationDomain"
        | "draftOrganizationConnection"
        | "importAccounts"
        | "exportAccounts"
        | "bindAccount"
        | "recordGuardianship" => (Accounts, w(false)),
        "listUpstreamIdps" => (UpstreamIdps, Shape::List(&["name", "issuer", "status"])),
        "getUpstreamIdp" => (UpstreamIdps, Shape::Get),
        "putUpstreamIdp" => (UpstreamIdps, w(true)),
        "patchUpstreamIdp" => (UpstreamIdps, patch(UPSTREAM_PATCH, None)),
        "retireUpstreamIdp" | "linkUpstreamSubject" => (UpstreamIdps, w(false)),
        "listOrganizations" => (
            Organizations,
            Shape::List(&["organization", "display_name"]),
        ),
        "getOrganization" => (Organizations, Shape::Get),
        "listSocialProviders" => (SocialProviders, Shape::List(&["preset", "status"])),
        "getSocialProvider" => (SocialProviders, Shape::Get),
        "putSocialProvider" => (SocialProviders, w(true)),
        "patchSocialProvider" => (SocialProviders, patch(SOCIAL_PATCH, None)),
        "disableSocialProvider" => (SocialProviders, w(false)),
        "getSettings" => (Settings, Shape::Get),
        "putSigninPolicy" => (Settings, put("signin_policy")),
        "patchSigninPolicy" => (Settings, patch(SIGNIN_PATCH, Some("signin_policy"))),
        "putSessionPolicy" => (Settings, put("session_policy")),
        "patchSessionPolicy" => (Settings, patch(SESSION_PATCH, Some("session_policy"))),
        "putBranding" => (Settings, put("branding")),
        "patchBranding" => (Settings, patch(BRANDING_PATCH, Some("branding"))),
        "putRpId" => (Settings, put("rp_id")),
        "putCspMode" => (Settings, put("csp_mode")),
        "putRelatedOrigins" => (Settings, put("related_origins")),
        "putLocaleOverrides" => (Settings, put("locale_overrides")),
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
#[expect(
    clippy::too_many_lines,
    reason = "one match over the identity plane refusals, each arm one problem"
)]
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
            Invalid::RelatedOrigins => &r::INVALID_RELATED_ORIGINS,
            Invalid::LocaleOverrides => &r::INVALID_LOCALE_OVERRIDES,
            Invalid::KeyPolicy => &r::INVALID_KEY_POLICY,
            Invalid::Name => &r::INVALID_NAME,
            Invalid::MembershipIssuer => &r::INVALID_MEMBERSHIP_ISSUER,
            Invalid::Members => &r::INVALID_MEMBERS,
            Invalid::Upstream => &r::INVALID_UPSTREAM,
            Invalid::UpstreamSubject => &r::INVALID_UPSTREAM_SUBJECT,
            Invalid::UpstreamSubjectLinked => &r::UPSTREAM_SUBJECT_LINKED,
            Invalid::SigninPolicy => &r::INVALID_SIGNIN_POLICY,
            Invalid::SessionPolicy => &r::INVALID_SESSION_POLICY,
            Invalid::ProtectedResource => &r::INVALID_PROTECTED_RESOURCE,
            Invalid::DcrPolicy => &r::INVALID_DCR_POLICY,
            Invalid::ClientExists
            | Invalid::GroupExists
            | Invalid::UpstreamExists
            | Invalid::OrgExists
            | Invalid::SocialExists
            | Invalid::ResourceExists => &r::RESOURCE_EXISTS,
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
            Invalid::LastOwner => &r::LAST_OWNER,
            Invalid::RecoveryPolicy => &r::INVALID_RECOVERY_POLICY,
            Invalid::RecoveryOption => &r::RECOVERY_OPTION_OFF,
            Invalid::SelfIssue => &r::SELF_ISSUE_REFUSED,
            Invalid::NotOrganization => &r::NOT_AN_ORGANIZATION,
            Invalid::OrgLimit | Invalid::InviteLimit | Invalid::InviteReputation => {
                &codes::RATE_LIMITED
            }
            Invalid::Invitation => &r::INVALID_INVITATION,
            Invalid::HrdUnverified => &r::HRD_NEEDS_VERIFIED_DOMAIN,
            Invalid::Social => &r::INVALID_SOCIAL_PROVIDER,
            Invalid::SharedSocialKey => &r::SHARED_SOCIAL_KEY_IN_PRODUCTION,
            Invalid::RecoveryGrace => &r::RECOVERY_GRACE,
            Invalid::DomainClaim => &r::INVALID_DOMAIN_CLAIM,
            Invalid::ConsumerDomain => &r::CONSUMER_DOMAIN,
            Invalid::DomainContested => &r::DOMAIN_CONTESTED,
            Invalid::DomainUnverified => &r::DOMAIN_NOT_VERIFIED,
            Invalid::SsoDraft => &r::INVALID_CONNECTION_DRAFT,
            Invalid::Agent => &r::INVALID_AGENT,
            Invalid::AgentTemplate => &r::INVALID_AGENT_TEMPLATE,
            Invalid::Workload => &r::INVALID_WORKLOAD_CLIENT,
            Invalid::VaultResource => &r::INVALID_VAULT_RESOURCE,
            Invalid::NoClient
            | Invalid::NoAgent
            | Invalid::NoKey
            | Invalid::NoGroup
            | Invalid::NoAccount
            | Invalid::NoUpstream
            | Invalid::NoHook
            | Invalid::NoWebhook
            | Invalid::NoOrg
            | Invalid::NoMember
            | Invalid::NoInvitation
            | Invalid::NoSocial
            | Invalid::NoVaultResource
            | Invalid::NoDomain => &codes::NOT_FOUND,
        },
        AdminError::Issuer(_) | AdminError::NoRealm => &codes::NOT_FOUND,
        // TN-91
        AdminError::Refused(c) if c == "owner-only" => &r::OWNER_ONLY,
        AdminError::Refused(c) if c == "transfer-waiting" => &r::HANDOVER_WAITING,
        AdminError::Refused(c) if c == "not-the-transfer" => &r::NOT_THE_HANDOVER,
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
