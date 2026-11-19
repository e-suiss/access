//! The environment-admin resources under `/admin/v1/envs/{slug}/…` (OP-151 m.2 M1): clients,
//! groups and their members, accounts, upstream identity providers, mappers, inline hooks and
//! webhooks (TN-135, TN-136), and the settings singleton with its sign-in, session, branding, RP
//! ID and extension policy sections.
//!
//! Every write compiles to exactly one `idp.*` Exercise through [`EnvironmentResources`] (TN-110,
//! PI-4, INV-2) and answers with `exercise_id` and `position`. A caller first drafts the write
//! (`POST …/intents`, a read: it changes nothing) to learn the intent its AIS signs, then sends
//! the drafted body with the AIS. `PUT` and `PATCH` (JSON Merge Patch) need `If-Match` with the
//! resource's `ETag`, the position of the decision that last changed it; a retire is a `POST`
//! to `…/{key}/retire`, never a `DELETE` (OP-73). No route writes a credential (TN-61).
//!
//! `GET …/audit/events` is the environment's full-taxonomy audit stream (channel B, OP-41) as OCSF
//! events, CEF lines or SET claims (`format`), oldest first, each with the time it occurred, was
//! recorded and was checkpointed; every read is first written as an `audit.read` event (OP-44).

mod handlers;
pub mod jobs;
// OP-157 m.3 (v)
pub mod offboarding;
// OP-157 m.3 (w)
pub mod review;

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
        surface: Surface::Environment,
        access: Access::Read {
            scope: "environment.read",
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
        surface: Surface::Environment,
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

const AG: &str = "/admin/v1/envs/{slug}/agents";
const AGK: &str = "/admin/v1/envs/{slug}/agents/{agent}";
const C: &str = "/admin/v1/envs/{slug}/clients";
const G: &str = "/admin/v1/envs/{slug}/groups";
const H: &str = "/admin/v1/envs/{slug}/hooks";
const W: &str = "/admin/v1/envs/{slug}/webhooks";
const WK: &str = "/admin/v1/envs/{slug}/webhooks/{webhook_id}";

/// The Stage 9 environment routes, declared before their lanes serve them (OP-154 m.4): each answers
/// `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE9: [Route; 20] = [
    list(
        AG,
        "listAgents",
        "The environment's agents: kind, operator, sponsors and status (OP-154 m.3 (c), (e)).",
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
        "/admin/v1/envs/{slug}/agents/{agent}/retire",
        "retireAgent",
        "Retires an agent: idp.agent.retire; nothing is deleted (OP-73).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/agents/{agent}/revoke-all",
        "revokeAllAgentInstances",
        "Ends every Instance of the agent as a bulk job of the caller's signed instance_terminate items (OP-154 m.3 (f), P59).",
    ),
    list(
        "/admin/v1/envs/{slug}/agents/{agent}/sponsors",
        "listAgentSponsors",
        "The agent's human sponsors (AG-41).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/agents/{agent}/sponsors",
        "assignAgentSponsor",
        "Assigns a human sponsor: idp.agent.sponsor_assign (OP-154 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/agents/{agent}/sponsors/{sponsor}/remove",
        "removeAgentSponsor",
        "Removes a sponsor: idp.agent.sponsor_remove; the last one leaving suspends the agent (OP-154 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/agent-templates",
        "defineAgentTemplate",
        "Defines an agent Grant template; one without a budget is refused (OP-154 m.3 (g)).",
    ),
    list(
        "/admin/v1/envs/{slug}/resources",
        "listProtectedResources",
        "The environment's protected resources and MCP servers, by canonical URI.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/resources",
        "registerProtectedResource",
        "Registers a protected resource or MCP server for `resource` validation: idp.client.resource_register.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/dcr-policy",
        "putDcrPolicy",
        "Sets the dynamic client registration profile: idp.client.dcr_policy, or dcr_policy_tighten when it only narrows (OP-154 m.3 (j)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/cross-app-connections",
        "createCrossAppConnection",
        "Records a cross-app connection for ID-JAG: idp.client.cross_app_connection (OP-154 m.3 (n)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/cross-app-connections/{connection}/retire",
        "retireCrossAppConnection",
        "Retires a cross-app connection: idp.client.cross_app_connection_retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/device-code",
        "putDeviceCode",
        "Turns the device authorization grant on (idp.environment.device_code) or off (device_code_close) (OP-154 m.3 (p)).",
    ),
    list(
        "/admin/v1/envs/{slug}/vault/resources",
        "listVaultResources",
        "The environment's vault Resources: the catalog upstreams it enabled and its own (OP-154 m.3 (t)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/vault/resources/{resource}",
        "putVaultResource",
        "Enables a catalog upstream (idp.vault.resource_enable) or registers the environment's own (resource_register, reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/vault/resources/{resource}/disable",
        "disableVaultResource",
        "Disables a vault Resource: idp.vault.resource_disable.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/vault-release-mode",
        "putVaultReleaseMode",
        "Opens release path (b) for CT0-CT1 classes (idp.vault.release_mode_open) or closes it (release_mode_close) (OP-154 m.3 (t)).",
    ),
];

/// The Stage 10 environment routes, declared before their lanes serve them (OP-155 m.4): each answers
/// `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE10: [Route; 45] = [
    list(
        "/admin/v1/envs/{slug}/saml-sps",
        "listSamlSps",
        "The environment's SAML service providers and WS-Federation relying parties: entity ID, template, status (OP-155 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/saml-sps",
        "registerSamlSp",
        "Registers a SAML service provider from its metadata or SSO catalog template: idp.saml.sp_register, or sp_mapping (reserved) when the template maps a Claim that selects authority.",
    ),
    read(
        "/admin/v1/envs/{slug}/saml-sps/{sp}",
        "getSamlSp",
        "One SAML service provider: entity ID, ACS and SLO endpoints, NameID format, attribute release, signing algorithm and its interop profile.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/saml-sps/{sp}",
        "putSamlSp",
        "Replaces a SAML service provider's registration: idp.saml.sp_update.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/saml-sps/{sp}/retire",
        "retireSamlSp",
        "Retires a SAML service provider: idp.saml.sp_retire; its entity ID is never reused and nothing is deleted (OP-73).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/saml-certificate",
        "putSamlCertificatePolicy",
        "Sets the SAML signing certificate rotation policy: idp.saml.cert_policy (OP-155 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/settings/saml-certificate/replace",
        "replaceSamlCertificate",
        "Replaces the SAML signing certificate at once, outside the policy: idp.saml.cert_emergency (reserved).",
    ),
    list(
        "/admin/v1/envs/{slug}/scim-clients",
        "listScimClients",
        "The environment's inbound SCIM clients: name, tolerance profile, status, last request (OP-155 m.3 (g)).",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/scim-clients",
        "registerScimClient",
        "Registers an inbound SCIM client: idp.scim.client_register; its opaque bearer secret is shown once and only its SHA-256 is kept.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/scim-clients/{scim_client}/secret/rotate",
        "rotateScimSecret",
        "Replaces an inbound SCIM client's bearer secret, shown once; the old one stops working at once (OP-155 m.3 (g)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/scim-clients/{scim_client}/retire",
        "retireScimClient",
        "Retires an inbound SCIM client: idp.scim.client_retire.",
    ),
    list(
        "/admin/v1/envs/{slug}/scim-targets",
        "listScimTargets",
        "The environment's outbound SCIM targets and their last results; never a secret.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/scim-targets",
        "registerScimTarget",
        "Registers an outbound SCIM target whose secret is sealed in the vault: idp.scim.outbound_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/scim-targets/{target}/retire",
        "retireScimTarget",
        "Retires an outbound SCIM target: idp.scim.outbound_retire.",
    ),
    list(
        "/admin/v1/envs/{slug}/gateways",
        "listGateways",
        "The environment's edge gateways (SAML, LDAP, RADIUS, Kerberos) with their internal identity and status (OP-155 m.3 (c)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/gateways",
        "registerGateway",
        "Registers an edge gateway and its mTLS identity urn:suiss:access:gw:<kind>:<name>: idp.gateway.register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/gateways/{gateway}/retire",
        "retireGateway",
        "Retires an edge gateway; its identity is never reused: idp.gateway.retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/gateways/{gateway}/keytab-policy",
        "putKeytabPolicy",
        "Sets a Kerberos gateway's keytab rotation policy: idp.gateway.keytab_policy (OP-155 m.3 (o)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/gateways/{gateway}/keytab/replace",
        "replaceKeytab",
        "Replaces a Kerberos gateway's keytab at once: idp.gateway.keytab_emergency (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/gateways/{gateway}/radius-clients",
        "registerRadiusClient",
        "Registers a RadSec client of a RADIUS gateway; RADIUS over UDP is never answered: idp.gateway.radius_client_register (OP-155 m.3 (f)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/federation",
        "putFederation",
        "Turns OpenID Federation on as a leaf (idp.federation.enable) or off (disable) (OP-155 m.3 (j)).",
    ),
    list(
        "/admin/v1/envs/{slug}/federation/trust-anchors",
        "listTrustAnchors",
        "The trust anchors the environment trusts and each chain's state.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/federation/trust-anchors",
        "addTrustAnchor",
        "Trusts a federation's trust anchor: idp.federation.trust_anchor_add (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/federation/trust-anchors/{anchor}/remove",
        "removeTrustAnchor",
        "Stops trusting a trust anchor: idp.federation.trust_anchor_remove.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/federation-authority",
        "putFederationAuthority",
        "Turns on the intermediate or trust anchor role, off by default: idp.federation.ta_enable.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/federation-registration",
        "putFederationRegistration",
        "Opens (idp.federation.registration_open) or closes (registration_close) OIDF client registration.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/vc-verifier",
        "putVcVerifier",
        "Turns the OID4VP verifier on (idp.vc.verifier_enable) or off (verifier_disable) (OP-155 m.3 (p)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/vc-trusted-lists",
        "putVcTrustedLists",
        "Sets the trusted lists whose issuers the verifier accepts: idp.vc.trusted_list (reserved).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/vc-issuer",
        "putVcIssuer",
        "Turns the person-attribute OID4VCI issuer on (idp.vc.issuer_enable) or off (issuer_disable).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/profile",
        "putClientProfile",
        "Puts a client under FAPI 2.0 (idp.client.profile) or takes it out (profile_loosen) (OP-155 m.3 (k)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/legacy-authentication",
        "putClientLegacyAuthentication",
        "Allows a client client_secret_post or client_secret_jwt: idp.client.auth_method_legacy.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/signing-alg",
        "putClientSigningAlg",
        "Lets a client take RS256 identity assertions: idp.client.alg_rs256; the environment's RSA-3072 key is made on first use (MD-6).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/encryption",
        "putClientEncryption",
        "Turns on JWE for a client's identity assertions, userinfo or JARM: idp.client.encryption; RSA1_5 is never offered.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/saml-bearer",
        "putClientSamlBearer",
        "Allows a client the SAML 2.0 bearer grant from an accepted SAML upstream: idp.client.saml_bearer.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}/legacy-bearer",
        "putClientLegacyBearer",
        "Grants a client the legacy bearer exception, never advertised: idp.client.legacy_bearer.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/ciba",
        "putCiba",
        "Turns CIBA poll and ping on (idp.environment.ciba) or off (ciba_close) (OP-155 m.3 (l)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/certificate-login",
        "putCertificateLogin",
        "Turns on certificate, PIV and CAC sign-in: idp.environment.certificate_login (OP-155 m.3 (m)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/mtls-aliases",
        "putMtlsAliases",
        "Publishes mtls_endpoint_aliases on the mTLS listener: idp.environment.mtls_aliases.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/hrd",
        "putHrd",
        "Turns home environment discovery on (idp.environment.hrd) or off (hrd_close) (OP-155 m.3 (h)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/frontchannel-logout",
        "putFrontchannelLogout",
        "Lets the environment's clients opt in to front-channel logout: idp.environment.frontchannel_logout. Browsers that block third-party cookies (Safari, Firefox) often drop it; use back-channel logout wherever the app supports it (TN-150).",
    ),
    read(
        "/admin/v1/envs/{slug}/organizations/{organization}/sso-enforcement/preview",
        "previewSsoEnforcement",
        "What enforcing SSO on the organization would end: members' local sign-in methods, API keys, sign-ins and refresh families, service accounts included, and the pending invitations (OP-155 m.3 (i)); changes nothing.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/sso-enforcement",
        "enforceOrganizationSso",
        "Enforces SSO on the organization: idp.org.sso_enforce; the body names the pending invitations' fate (cancel or redirect_to_sso), there is no default.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/sso-enforcement/lift",
        "liftOrganizationSso",
        "Lifts the organization's SSO enforcement: idp.org.sso_enforce_lift.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/setup-links",
        "createOrganizationSetupLink",
        "Issues the organization's one-use SSO setup link, valid 72 hours and sent by Relay: idp.org.setup_link.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/upstream-idps/{name}/assurance-map",
        "putUpstreamAssuranceMap",
        "Maps an upstream's acr, amr or AuthnContextClassRef onto assurance; unmapped values count as the lowest class: idp.upstream.assurance_map (reserved).",
    ),
];

/// The Stage 11 environment routes, declared before their lanes serve them (OP-156 m.4): each answers
/// `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE11: [Route; 38] = [
    list(
        "/admin/v1/envs/{slug}/proxies",
        "listProxies",
        "The environment's forward-auth proxies and Access Proxy instances, each a PEP (OP-156 m.3 (l), (m)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/proxies",
        "registerProxy",
        "Registers a proxy as a PEP with its application, engine and upstream: idp.proxy.register.",
    ),
    read(
        "/admin/v1/envs/{slug}/proxies/{proxy}",
        "getProxy",
        "One proxy: application, engine, decision cache bound, header mode, MCP pins.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/proxies/{proxy}",
        "putProxy",
        "Replaces a proxy's registration: idp.proxy.update.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/proxies/{proxy}/retire",
        "retireProxy",
        "Retires a proxy: idp.proxy.retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/proxies/{proxy}/plain-headers",
        "putProxyPlainHeaders",
        "Turns the plain identity headers on (idp.proxy.plain_headers) after the setup check proves the application unreachable except through the proxy, or off (plain_headers_close).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/proxies/{proxy}/mcp-pins",
        "pinMcpTools",
        "Pins an MCP server's tool list by the SHA-256 of each tool's canonical definition; a changed or new tool is blocked until pinned again: idp.proxy.mcp_pin (OP-156 m.3 (n)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/ssh-ca",
        "putSshCa",
        "Turns the environment's Ed25519 SSH user CA on (idp.ssh.ca_enable) or off (ca_disable) (OP-156 m.3 (o)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/settings/ssh-ca/rotate",
        "rotateSshCa",
        "Rotates the SSH CA key on its schedule: idp.ssh.ca_rotate.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/settings/ssh-ca/replace",
        "replaceSshCa",
        "Replaces the SSH CA key at once: idp.ssh.ca_emergency (reserved).",
    ),
    list(
        "/admin/v1/envs/{slug}/ssh-host-groups",
        "listSshHostGroups",
        "The environment's SSH server groups, the resources of ssh.login Grants.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/ssh-host-groups",
        "registerSshHostGroup",
        "Registers an SSH server group: idp.ssh.host_group_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/ssh-host-groups/{host_group}/retire",
        "retireSshHostGroup",
        "Retires an SSH server group: idp.ssh.host_group_retire.",
    ),
    list(
        "/admin/v1/envs/{slug}/linux-hosts",
        "listLinuxHosts",
        "The environment's Linux client hosts with their server group, offline limits and break-glass switch (OP-156 m.3 (p)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/linux-hosts",
        "registerLinuxHost",
        "Registers a Linux host of the Linux client: idp.linux.host_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/linux-hosts/{host}/retire",
        "retireLinuxHost",
        "Retires a Linux host: idp.linux.host_retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/linux-hosts/{host}/offline-policy",
        "putLinuxOfflinePolicy",
        "Sets a host's offline cache limits within its ValidityContract horizon: NSS data at most 12 hours, console sign-in at most 8, no step-up offline: idp.linux.offline_policy.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/linux-hosts/{host}/break-glass-policy",
        "putLinuxBreakGlassPolicy",
        "Sets a host's local break-glass policy over a one-use offline PAP slice: idp.linux.break_glass_policy (reserved).",
    ),
    list(
        "/admin/v1/envs/{slug}/hr-sources",
        "listHrSources",
        "The environment's HR sources, each a Claim issuer whose selection effect is a CT3 subject-selection Acceptance (OP-156 m.3 (q)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-sources",
        "registerHrSource",
        "Registers an HR source: idp.hr.source_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-sources/{source}/retire",
        "retireHrSource",
        "Retires an HR source: idp.hr.source_retire.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-sources/{source}/records:batch",
        "importHrBatch",
        "Imports at most 10 000 JSONL HR records into the source's Claims: idp.hr.import.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-sources/{source}/records:csv",
        "importHrCsv",
        "Imports an RFC 4180 CSV file of at most 10 MB with the fixed columns and a header row: idp.hr.import.",
    ),
    list(
        "/admin/v1/envs/{slug}/hr-connectors",
        "listHrConnectors",
        "The environment's HR connectors of services/hr-connector and their last pull.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-connectors",
        "registerHrConnector",
        "Registers an HR connector: idp.hr.connector_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hr-connectors/{connector}/retire",
        "retireHrConnector",
        "Retires an HR connector: idp.hr.connector_retire.",
    ),
    list(
        "/admin/v1/envs/{slug}/signal-sources",
        "listSignalSources",
        "The environment's signal sources (KYC, MDM, risk, DLP), each a Claim issuer whose effect needs an Acceptance (OP-156 m.3 (r)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/signal-sources",
        "registerSignalSource",
        "Registers a signal source: idp.signal.source_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/signal-sources/{source}/retire",
        "retireSignalSource",
        "Retires a signal source: idp.signal.source_retire.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/push",
        "putPush",
        "Turns push verification with number matching on (idp.environment.push) or off (push_close) (OP-156 m.3 (d)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/sms-otp",
        "putSmsOtp",
        "Turns the restricted SMS one-time code on (idp.environment.sms_otp) or off (sms_otp_close) (OP-156 m.3 (f)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/spc",
        "putSpc",
        "Opens Permissions-Policy: payment on the approval surface for Secure Payment Confirmation: idp.environment.spc (OP-156 m.3 (g)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/coordinator",
        "putCoordinator",
        "Names the coordinator URL the hub links pending approvals to: idp.environment.coordinator (OP-156 m.3 (t)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/iys",
        "putIys",
        "Turns the İYS consent registry events on (idp.environment.iys) or off (iys_close).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/preference-topics",
        "putPreferenceTopics",
        "Sets the environment's own preference topics beside campaign, newsletter and product_news: idp.environment.preference_topics (OP-153 m.3 (ee)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/security-notices",
        "putSecurityNotices",
        "Turns the immediate security authority notices on (idp.environment.security_notices) or off (security_notices_close); on by default (OP-156 m.3 (c)).",
    ),
    list(
        "/admin/v1/envs/{slug}/relay/undelivered",
        "listUndeliveredRelayMessages",
        "The environment's Relay messages the courier gave up on, without their sealed content (OP-156 m.3 (c)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/relay/undelivered/{event_id}/resend",
        "resendRelayMessage",
        "Resends an undelivered Relay message as a new outbox row citing the original: idp.relay.resend. A crypto-shredded message answers content-shredded, an expired one message-expired.",
    ),
];

/// The Stage 12 environment routes, declared before their lanes serve them (OP-157 m.4 (a)): each
/// answers `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE12: [Route; 22] = [
    list(
        "/admin/v1/envs/{slug}/support/case-systems",
        "listCaseSystems",
        "The environment's support case systems, each a registered issuer of support_case Claims (OP-157 m.3 (e)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/support/case-systems",
        "registerCaseSystem",
        "Registers a support case system {name, issuer, provider, format} as a Claim issuer: idp.support.case_system_register.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/support/case-systems/{case_system}/retire",
        "retireCaseSystem",
        "Retires a support case system; its open cases no longer hold any support Grant: idp.support.case_system_retire.",
    ),
    list(
        "/admin/v1/envs/{slug}/support/grants",
        "listSupportGrants",
        "The environment's support Grants with operator, subject, case, scope and end, a read of the Grants the caller may see (OP-157 m.3 (c)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/support-artifacts",
        "putSupportArtifactPolicy",
        "Opens support artifact uploads with their size and retention limits (idp.support.artifact_policy) or closes them (artifact_policy_close) (OP-157 m.3 (g)).",
    ),
    list(
        "/admin/v1/envs/{slug}/breakglass/accounts",
        "listBreakglassAccounts",
        "The environment's accounts marked as break-glass accounts, with their last sign-in; the mark carries no authority (INV-28, OP-157 m.3 (h)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/breakglass/accounts",
        "markBreakglassAccount",
        "Marks an organization member's account as a break-glass account {organization, member}: idp.org.member_breakglass.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/breakglass/accounts/{account}/clear",
        "clearBreakglassAccount",
        "Clears an account's break-glass mark: idp.org.member_breakglass_clear.",
    ),
    list(
        "/admin/v1/envs/{slug}/breakglass/drills",
        "listBreakglassDrills",
        "The environment's break-glass drills, each a real Exercise with PurposeRef drill, and when the next is due (OP-157 m.3 (h)).",
    ),
    list(
        "/admin/v1/envs/{slug}/breakglass/reviews",
        "listBreakglassReviews",
        "Each use of a break-glass Grant with its review {exercise, classification: drill, emergency or misuse}, or overdue (OP-157 m.3 (h)).",
    ),
    list(
        "/admin/v1/envs/{slug}/reviews",
        "listReviews",
        "The environment's access review campaigns: period, scope and next run; a campaign is a view, never a queue (IDP-39 (3), OP-157 m.3 (w)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/reviews",
        "scheduleReview",
        "Schedules an access review campaign {name, period_days, scope}: idp.review.schedule.",
    ),
    read(
        "/admin/v1/envs/{slug}/reviews/{review}",
        "getReview",
        "One access review campaign.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/reviews/{review}/close",
        "closeReview",
        "Ends an access review campaign: idp.review.schedule_close.",
    ),
    list(
        "/admin/v1/envs/{slug}/reviews/{review}/items",
        "listReviewItems",
        "The campaign's items for the caller: the Grants of the caller's team, re-checked against what the caller may see; removing one is the caller's own grant.revoke Exercise.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/reviews/{review}/items/{item}/keep",
        "keepReviewItem",
        "Records the reviewer's keep, signed with the reviewer's AIS, as a review.kept identity audit record; writes no authority (OP-157 m.3 (w)).",
    ),
    read(
        "/admin/v1/envs/{slug}/offboarding/{party}/preview",
        "previewOffboarding",
        "What offboarding a Party would touch, channel by channel: direct Grants (keep or revoke), Instances (terminate), rule-shaped holdings (retain, exclude or restrict), the self-anchor (retire or hand over) and re-entry (allowed or blocked); there are no defaults and it changes nothing (OP-157 m.3 (v)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/offboarding/{party}/commit",
        "commitOffboarding",
        "Commits a previewed offboarding as the caller's signed Exercises; a missing channel choice answers 422 offboarding-disposition-missing, and the Party reads as offboarded only after the departure commits.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/delegated-admin",
        "putDelegatedAdmin",
        "Opens delegated administration through meta-action role Grants (idp.environment.delegated_admin) or closes it for new admin Grants (delegated_admin_close); existing admin Grants stay (OP-157 m.3 (t)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/approval-inline",
        "putApprovalInline",
        "Opens CT1 approval inside the approver notification (idp.environment.approval_inline) or closes it (approval_inline_close) (OP-157 m.3 (m)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/approval-batch",
        "putApprovalBatch",
        "Opens CT1 batch approval of at most 10 requests (idp.environment.approval_batch) or closes it (approval_batch_close) (OP-157 m.3 (m)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/breakglass/reviews/{exercise}",
        "reviewBreakglassUse",
        "Another Party's review of one break-glass use {classification: drill, emergency or misuse}: idp.org.breakglass_review; the Party that used the Grant cannot review it, and a review grants nothing (OP-157 m.3 (h)).",
    ),
];

/// The Stage 13 environment routes, declared before their lanes serve them (OP-158 m.4 (a)): each
/// answers `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE13: [Route; 10] = [
    read(
        "/admin/v1/envs/{slug}/placement",
        "getPlacement",
        "The cell the environment and its governing domain are placed in, with residency; the placement routes requests and is never a decision input (TI-17, OP-158 m.3 (o)).",
    ),
    read(
        "/admin/v1/envs/{slug}/durability",
        "getDurability",
        "The environment's durability profile (replicated or single-node), DR class, RPO and the witnesses and replicas its domain declares (HL-40, OP-158 m.3 (n), (p)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/residency",
        "putResidency",
        "Declares the environment's residency {region, class}: idp.environment.residency, reserved; a change is a cell move (OP-158 m.3 (o)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/dr-profile",
        "putDrProfile",
        "Declares the async DR profile {rpo_s} (idp.environment.dr_profile, CT3) or returns to the synchronous class with {} (dr_profile_close, CT1) (OP-158 m.3 (r)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/rate-limit",
        "putRateLimit",
        "Sets the environment's rate limit {rps}: idp.environment.rate_limit (OP-35, OP-158 m.3 (v)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/crypto-profile",
        "putCryptoProfile",
        "Sets the environment's crypto profile {fips}: idp.environment.crypto_profile; the FIPS profile allows only FIPS-approved algorithms (CR-15, OP-158 m.3 (y)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/hash-profile",
        "putHashProfile",
        "Raises the environment's Argon2id hash profile {profile}; it is never lowered, and a lower profile answers 409 hash-profile-downgrade (OP-33, OP-158 m.3 (a)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/audit-tier",
        "putAuditTier",
        "Sets the cold audit tier {hot_days, target} (idp.environment.audit_tier) or closes it with {} (audit_tier_close); a hot window under 30 days answers 422 audit-tier-too-short (OP-158 m.3 (w)).",
    ),
    // OP-158 m.4 (b) (W11)
    read(
        "/admin/v1/envs/{slug}/rate-limits",
        "getRateLimits",
        "The environment's rate limits and their use: each bucket's share in use now and over 1 h and 24 h, the 10 heaviest consumers as digests, refusals by type and the warning threshold; never labelled by the request (§12.5.4, TN-127, OP-158 m.3 (v)).",
    ),
    // OP-158 m.4 (b) (W6)
    read(
        "/admin/v1/envs/{slug}/recovery",
        "getRecovery",
        "Whether the environment's governing domain can be recovered (\"Recovery not available\" otherwise), and its handovers and forced recoveries with the record position each took effect at and, for a recovery, the time after which changes may be lost (§8.17.9.7, §13.6, OP-158 m.3 (m)).",
    ),
];

/// The Stage 14 environment routes, declared before their lanes serve them (OP-159 m.4 (a)): each
/// answers `501 not-yet-served` behind its permission until its lane fills the handler.
const STAGE14: [Route; 3] = [
    read(
        "/admin/v1/envs/{slug}/signing",
        "getSigning",
        "The environment's signing profile: its classical and ML-DSA signing keys and algorithms, the key exchange share policy, whether the FIPS module is in use and why FIPS and post-quantum profiles cannot be combined (OP-159 m.3 (o), (r), (t)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/signing-profile",
        "putSigningProfile",
        "Adds ML-DSA to the environment's accept and signing set {profile: ml-dsa-65 | ml-dsa-44 | ml-dsa-87} (idp.environment.signing_profile, reserved, CT3) or takes it out with {} (signing_profile_close, CT1); the classical algorithms stay. With the FIPS profile on it answers 409 fips-pq-exclusive; without an HSM ML-DSA mechanism, 409 pq-key-unavailable (CR-41, OP-159 m.3 (a), (d), (o), (r)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/kex-share",
        "putKexShare",
        "Sets the environment's hybrid key exchange share policy {mode: optimistic | advertise-only}: idp.environment.kex_share, CT2; both offer the post-quantum group (CR-12 m.3, OP-159 m.3 (a), (t)).",
    ),
];

/// Every environment resource route, in contract order.
pub const ROWS: &[Route] = &ALL_ROWS;

const BASE_LEN: usize = BASE.len();

#[expect(
    clippy::indexing_slicing,
    reason = "evaluated at compile time; an out-of-range index fails the build"
)]
#[expect(
    clippy::large_const_arrays,
    reason = "composed at compile time into the manifest, which a static cannot be"
)]
const ALL_ROWS: [Route;
    BASE_LEN
        + STAGE9.len()
        + STAGE10.len()
        + STAGE11.len()
        + STAGE12.len()
        + STAGE13.len()
        + STAGE14.len()] = {
    let mut out = [BASE[0];
        BASE_LEN
            + STAGE9.len()
            + STAGE10.len()
            + STAGE11.len()
            + STAGE12.len()
            + STAGE13.len()
            + STAGE14.len()];
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
    let mut k = 0;
    while k < STAGE10.len() {
        out[BASE_LEN + STAGE9.len() + k] = STAGE10[k];
        k += 1;
    }
    let mut l = 0;
    while l < STAGE11.len() {
        out[BASE_LEN + STAGE9.len() + STAGE10.len() + l] = STAGE11[l];
        l += 1;
    }
    let mut m = 0;
    while m < STAGE12.len() {
        out[BASE_LEN + STAGE9.len() + STAGE10.len() + STAGE11.len() + m] = STAGE12[m];
        m += 1;
    }
    let mut n = 0;
    while n < STAGE13.len() {
        out[BASE_LEN + STAGE9.len() + STAGE10.len() + STAGE11.len() + STAGE12.len() + n] =
            STAGE13[n];
        n += 1;
    }
    let mut o = 0;
    while o < STAGE14.len() {
        out[BASE_LEN
            + STAGE9.len()
            + STAGE10.len()
            + STAGE11.len()
            + STAGE12.len()
            + STAGE13.len()
            + o] = STAGE14[o];
        o += 1;
    }
    out
};

/// Whether an environment row is a Stage 9, 10, 11, 12, 13 or 14 declaration (OP-154 m.4, OP-155 m.4,
/// OP-156 m.4, OP-157 m.4, OP-158 m.4, OP-159 m.4).
fn declared(operation_id: &str) -> bool {
    STAGE9
        .iter()
        .chain(STAGE10.iter())
        .chain(STAGE11.iter())
        .chain(STAGE12.iter())
        .chain(STAGE13.iter())
        .chain(STAGE14.iter())
        .any(|r| r.operation_id == operation_id)
}

/// The response schema a declared route will answer with: a page for a list, a declared
/// resource for a read, the write result for a write (OP-155 m.4).
fn planned_body(operation_id: &str) -> &'static str {
    match STAGE10
        .iter()
        .chain(STAGE11.iter())
        .find(|r| r.operation_id == operation_id)
    {
        Some(r) if r.verb == Verb::Get && !r.query.is_empty() => "Page",
        Some(r) if r.verb == Verb::Get => "Declared",
        _ => "WriteResult",
    }
}

/// Largest body of an HR import (OP-156 m.3 (q)): a 10 MB CSV file or 10 000 JSONL records as
/// one JSON string, escaped.
pub const HR_IMPORT_BODY: usize = 24 * 1024 * 1024;

/// The body limit of an environment row above the surface's, if it has one: only the HR imports
/// (OP-156 m.3 (q)).
#[must_use]
pub fn body_limit(operation_id: &str) -> Option<usize> {
    matches!(operation_id, "importHrBatch" | "importHrCsv").then_some(HR_IMPORT_BODY)
}

/// Whether an environment row is declared and not served yet (OP-154 m.4).
#[must_use]
pub fn planned(operation_id: &str) -> bool {
    declared(operation_id) && matches!(spec(operation_id), Some((_, Shape::Planned(_))))
}

const BASE: &[Route] = &[
    Route {
        verb: Verb::Post,
        ..read(
            "/admin/v1/envs/{slug}/intents",
            "draftIntent",
            "Drafts the intent a write compiles to, for the caller's AIS; changes nothing.",
        )
    },
    list(C, "listClients", "The environment's clients."),
    secret(
        Verb::Post,
        C,
        "createClient",
        "Registers a client; a client_secret_basic client's secret is shown once.",
    ),
    read(
        "/admin/v1/envs/{slug}/clients/{client_id}",
        "getClient",
        "One client.",
    ),
    secret(
        Verb::Put,
        "/admin/v1/envs/{slug}/clients/{client_id}",
        "putClient",
        "Replaces a client's registration.",
    ),
    secret(
        Verb::Patch,
        "/admin/v1/envs/{slug}/clients/{client_id}",
        "patchClient",
        "Changes a client's registration by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/clients/{client_id}/retire",
        "retireClient",
        "Retires a client; its client_id is never reused.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/clients/{client_id}/secret/rotate",
        "rotateClientSecret",
        "Issues a new client_secret, shown once; the old one stays valid for 24 hours.",
    ),
    list(G, "listGroups", "The environment's groups."),
    read(
        "/admin/v1/envs/{slug}/groups/{name}",
        "getGroup",
        "One group.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/groups/{name}",
        "putGroup",
        "Creates a group with its one membership issuer, or renames it.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/groups/{name}",
        "patchGroup",
        "Renames a group by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/groups/{name}/retire",
        "retireGroup",
        "Retires a group and ends its memberships.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/groups/{name}/members",
        "addGroupMembers",
        "Adds accounts to a group the administration issues members of.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/groups/{name}/members/remove",
        "removeGroupMembers",
        "Removes accounts from a group the administration issues members of.",
    ),
    list(
        "/admin/v1/envs/{slug}/accounts",
        "listAccounts",
        "The environment's accounts and their states.",
    ),
    read(
        "/admin/v1/envs/{slug}/accounts/{account_id}",
        "getAccount",
        "One account's state.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/import",
        "importAccounts",
        "Imports accounts from another identity provider (idp.account.import, TN-85): `content` is the JSON Lines file of `access-server import-accounts`, `file` its SHA-256 and `accounts` its line count, which the signed change names; each line becomes its own account or is reported as skipped, never echoed.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/guardianships",
        "recordGuardianship",
        "Records that `guardian_account_id` stands for this ward on `basis` (`parent`, `legal_guardian`) in `country` (idp.account.guardianship_record, CT2, E53): its guardianship Claim holds until the ward's majority by the country table and ends then without anyone's signature; the ward's date of birth must be on file.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/bind",
        "bindAccount",
        "Binds the account and `peer_account_id` of the tenant's environment `peer_environment` (its slug) as one person (idp.account.bind, CT2): the environment that binds first answers with its environment-signed `offer`, shown once; the peer environment's administrator binds the same pair sending that `offer`, which the peer environment verifies against this environment's keys.",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/migration-export",
        "exportAccounts",
        "Exports every active account to another deployment (idp.account.migration_export, reserved, TN-86): sealed to the P-256 `recipient` key (SEC1, base64url) it names; the `bundle` (dCBOR, base64url) is shown once and holds the import lines that deployment's importAccounts takes.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/suspend",
        "suspendAccount",
        "Suspends an account and ends its sessions.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/reactivate",
        "reactivateAccount",
        "Reactivates a suspended account.",
    ),
    list(
        "/admin/v1/envs/{slug}/upstream-idps",
        "listUpstreamIdps",
        "The environment's upstream identity providers.",
    ),
    read(
        "/admin/v1/envs/{slug}/upstream-idps/{name}",
        "getUpstreamIdp",
        "One upstream identity provider.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/upstream-idps/{name}",
        "putUpstreamIdp",
        "Registers or replaces an upstream identity provider (reserved).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/upstream-idps/{name}",
        "patchUpstreamIdp",
        "Changes an upstream identity provider by JSON Merge Patch (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/upstream-idps/{name}/retire",
        "retireUpstreamIdp",
        "Retires an upstream identity provider.",
    ),
    list(
        "/admin/v1/envs/{slug}/social-providers",
        "listSocialProviders",
        "The social presets the environment enabled, with their warnings (IDP-31, TN-87).",
    ),
    read(
        "/admin/v1/envs/{slug}/social-providers/{preset}",
        "getSocialProvider",
        "One social preset the environment enabled.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/social-providers/{preset}",
        "putSocialProvider",
        "Enables or changes a social preset; only a sandbox environment may omit its own client (idp.social.enable, update).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/social-providers/{preset}",
        "patchSocialProvider",
        "Changes a social preset's client by JSON Merge Patch (idp.social.update).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/social-providers/{preset}/disable",
        "disableSocialProvider",
        "Stops offering a social preset; linked sign-ins stay (idp.social.disable).",
    ),
    list(
        "/admin/v1/envs/{slug}/organizations",
        "listOrganizations",
        "The environment's live organizations (§8.5 S7).",
    ),
    read(
        "/admin/v1/envs/{slug}/organizations/{organization}",
        "getOrganization",
        "One organization: its roots and members with each membership source and role, its domain claims, ownership handovers and connection drafts (§8.5 S7, TN-91).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations",
        "createOrganization",
        "Creates an organization bound to the Party its founder's client registered; the founder becomes its first owner (TN-5).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/members/remove",
        "removeOrganizationMember",
        "Removes a member from an organization; its last active owner is kept (TN-91).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/organizations/{organization}",
        "patchOrganization",
        "Renames an organization or turns home environment discovery to it on or off; on needs a verified domain no other organization claims (TN-98).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/invitations",
        "createInvitation",
        "Invites a person into an organization by e-mail: the link and its magic code go only in the mail, the role comes from the invitation (TN-89).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/invitations/revoke",
        "revokeInvitation",
        "Revokes an open invitation (OP-153 m.3 (o)).",
    ),
    secret(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/domains",
        "claimOrganizationDomain",
        "Claims a domain for an organization; its challenge, shown once, is published as a DNS TXT record or an HTTPS document, and the domain counts as verified only while its time-limited domain_verification Claim holds (TN-90).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/domains/release",
        "releaseOrganizationDomain",
        "Releases an organization's domain claim and retracts its verification (TN-90).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/organizations/{organization}/connection-drafts",
        "draftOrganizationConnection",
        "Drafts an enterprise connection; only idp.upstream.register (CT3) at the organization's root puts it into effect (TN-120).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/upstream-idps/{name}/links",
        "linkUpstreamSubject",
        "Links a subject of the upstream identity provider to an account; its inbound signals then reach the account.",
    ),
    read(
        "/admin/v1/envs/{slug}/settings",
        "getSettings",
        "The environment's settings: sign-in, session, branding, RP ID, mappers.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/signin-policy",
        "putSigninPolicy",
        "Sets the sign-in requirements; `registration: open | invite_only` (default open) refuses open registration and account creation by a social or enterprise sign-in when invite_only (OP-159 m.48 (c)).",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/signin-policy",
        "patchSigninPolicy",
        "Changes the sign-in requirements by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/session-policy",
        "putSessionPolicy",
        "Sets the console session policy.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/session-policy",
        "patchSessionPolicy",
        "Changes the console session policy by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/branding",
        "putBranding",
        "Sets the hosted pages' branding.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/branding",
        "patchBranding",
        "Changes the hosted pages' branding by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/csp-mode",
        "putCspMode",
        "Sets the hosted pages' CSP mode: `enforce`, or `report_only`, which loosens the page and is a higher tier (OP-153 m.22 (g)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/related-origins",
        "putRelatedOrigins",
        "Sets the environment's Related Origins: https origins under the organizations' verified domains, at most five registrable labels with the RP ID's (TN-18).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/locale-overrides",
        "putLocaleOverrides",
        "Sets the environment's texts for the hosted pages by locale and message key: plain text, known keys only, never a protected one (X35).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/rp-id",
        "putRpId",
        "Pins or changes the WebAuthn RP ID: irreversible, reserved.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/mappers/{claim}",
        "putMapper",
        "Sets or removes the profile attribute a claim is taken from.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/jose-alg",
        "putJoseAlg",
        "Sets the environment's JOSE signing algorithm: ES256 or Ed25519.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/cimd-policy",
        "putCimdPolicy",
        "Sets which Client ID Metadata Document clients the environment accepts.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/cimd-policy",
        "patchCimdPolicy",
        "Changes the CIMD acceptance policy by JSON Merge Patch.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/protection-mode",
        "putProtectionMode",
        "Sets the attack protections' modes; loosening anything is a higher tier.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/protection-mode",
        "patchProtectionMode",
        "Changes the attack protections' modes by JSON Merge Patch.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/canary",
        "markCanaryAccount",
        "Makes an account a canary: a sign-in with it never opens a session.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/delete",
        "deleteAccount",
        "Deletes an account after its cancellation window; its personal data becomes unreadable when its keys are destroyed later (reserved).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/reset-intents",
        "createResetIntent",
        "Issues a one-time reset intent sent to the account's own registered address; the person chooses their new sign-in method themselves (TN-61).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/accounts/{account_id}/temporary-access-passes",
        "createTemporaryAccessPass",
        "Issues a temporary access pass, shown once to read out, in an environment that allows them; its session binds an authenticator only (TN-62).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/recovery-policy",
        "putRecoveryPolicy",
        "Sets the recovery policy; anything that loosens it is a higher tier and only applies to recoveries started later (TN-55).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/jobs",
        "createJob",
        "Starts a bulk job: each item is its own write under its own AIS, and `revokeGrant` or `amendGrant` items are Grant revokes or amends, each its own Exercise (E17); `issueRoleGrant` issues an accepted invitation's role (TN-89), `proposeOwnershipHandover` (accepted, nothing decided yet) and `completeOwnershipHandover` carry an organization's `anchor_transfer` (TN-91), and `issueAutojoinGrant` (key: the organization) an owner's `grant_issue` of the autojoin role, held by the organization's `org_member` Claims (TN-90); answers 202.",
    ),
    read(
        "/admin/v1/envs/{slug}/jobs/{job_id}",
        "getJob",
        "A bulk job's state and counts, throttled items included.",
    ),
    list(
        "/admin/v1/envs/{slug}/jobs/{job_id}/items",
        "listJobItems",
        "A bulk job's per-item results: the Exercise or the problem that refused it.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/rehome",
        "rehomeEnvironment",
        "Moves the environment to another governing domain {domain}: idp.environment.rehome, reserved and CT3; it needs an Exercise in both the old and the new governing domain, or the environment stays (OP-158 m.3 (o)).",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/settings/extension-policy",
        "putExtensionPolicy",
        "Sets whether hooks and webhooks may reach declared private targets and what hooks may receive.",
    ),
    write(
        Verb::Patch,
        "/admin/v1/envs/{slug}/settings/extension-policy",
        "patchExtensionPolicy",
        "Changes the extension policy by JSON Merge Patch.",
    ),
    list(H, "listHooks", "The environment's inline hooks."),
    secret(
        Verb::Post,
        H,
        "registerHook",
        "Registers an inline hook at one call point; its verification key is shown once.",
    ),
    read(
        "/admin/v1/envs/{slug}/hooks/{hook_id}",
        "getHook",
        "One inline hook.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/hooks/{hook_id}/retire",
        "retireHook",
        "Retires an inline hook; a URL change is a retirement and a new registration.",
    ),
    list(W, "listWebhooks", "The environment's webhooks."),
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
        "/admin/v1/envs/{slug}/webhooks/{webhook_id}/rotate",
        "rotateWebhookKey",
        "Issues a new signing key, its verification key shown once; the old key signs too for 24 hours.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/webhooks/{webhook_id}/retire",
        "retireWebhook",
        "Retires a webhook; its pending deliveries fail.",
    ),
    list(
        "/admin/v1/envs/{slug}/webhooks/{webhook_id}/deliveries",
        "listWebhookDeliveries",
        "A webhook's delivery log, newest first: state, attempts and the last answer; never the event body.",
    ),
    read(
        "/admin/v1/envs/{slug}/signals",
        "getSignals",
        "The environment's signal sources: delayed transmitters, the GeoIP source, verifier reports.",
    ),
    read(
        "/admin/v1/envs/{slug}/analytics",
        "getAnalytics",
        "The environment's daily sign-in counts of the last 30 days and failed sign-in surges; never a decision input.",
    ),
    Route {
        query: FEED,
        ..read(
            "/admin/v1/envs/{slug}/audit/events",
            "listAuditEvents",
            "The environment's full-taxonomy audit stream, oldest first, as OCSF, CEF or SET claims; a copy, not the record. Each read is itself audited.",
        )
    },
    read(
        "/admin/v1/envs/{slug}/audit/events/{event_id}/proof",
        "getAuditEventProof",
        "The event's inclusion proof in the environment's own audit tree, checkpointed by the cell key under the environment's origin; it shows nothing of other environments. Each read is itself audited.",
    ),
    // OP-156 m.3 (i)
    list(
        "/admin/v1/envs/{slug}/domains",
        "listDomains",
        "The environment's custom domains: host, verification state, next re-check, certificate expiry (OP-156 m.3 (i)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/domains",
        "registerDomain",
        "Registers a custom domain to verify by DNS TXT `_access-challenge.<host>` and a CNAME to `<slug>.<base>`: idp.domain.register.",
    ),
    read(
        "/admin/v1/envs/{slug}/domains/{domain}",
        "getDomain",
        "One custom domain: the TXT value and CNAME target to publish, the verification state and the ACME certificate.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/domains/{domain}/retire",
        "retireDomain",
        "Retires a custom domain; it is no longer served and nothing is deleted (OP-73): idp.domain.retire.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/domains/{domain}/issuer-bind",
        "bindDomainIssuer",
        "Binds the issuer or passkey RP ID to a verified custom domain, irreversibly (§10.2.4, TN-16): idp.domain.issuer_bind (reserved).",
    ),
    // OP-156 m.3 (s)
    list(
        "/admin/v1/envs/{slug}/export-sinks",
        "listExportSinks",
        "The environment's export sinks for the read-only SIEM projection and their cursors; a copy, not the record (OP-156 m.3 (s)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/export-sinks",
        "registerExportSink",
        "Registers an export sink (OCSF Parquet on S3, OTLP logs, HTTP collector, syslog CEF or LEEF): idp.export.sink_register.",
    ),
    write(
        Verb::Put,
        "/admin/v1/envs/{slug}/export-sinks/{sink}",
        "putExportSink",
        "Replaces an export sink's configuration: idp.export.sink_update.",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/export-sinks/{sink}/retire",
        "retireExportSink",
        "Retires an export sink: idp.export.sink_retire.",
    ),
    // OP-159 m.47 (a), (e), (f), (h)
    list(
        TE,
        "listManagedEnvironments",
        "The tenant's environments, read in its primary environment: slug, kind, issuer, creation time and whether it is a sandbox (OP-159 m.47 (a)); `404` outside a primary environment.",
    ),
    write(
        Verb::Post,
        TE,
        "createTenantEnvironment",
        "Opens an environment of the tenant {slug, sandbox, issuer_style: path | subdomain}, rooted in its owners with the administrator rule in its Genesis and bound as consuming the primary environment's Claims: idp.tenant.environment_create (CT2). Refused with `primary-environment` outside the tenant's primary environment (OP-159 m.47 (d), (h), TN-140).",
    ),
    list(
        TA,
        "listTenantAdmins",
        "The tenant's administrators and pending invitations, read in its primary environment: id (`usr_…` or `inv_…`), identifier, role (owner | admin), status (invited | active | removed), since when and the slugs of the environments it administers (`environments`, null for the whole tenant); a pending invitation shows only `@` and its domain (OP-159 m.47 (e), (f), m.49 (d), TN-89 (1)).",
    ),
    write(
        Verb::Post,
        TA,
        "inviteTenantAdmin",
        "Invites a tenant administrator {email, environments?}; the invitee becomes an administrator, never an owner, on accepting, and one from another domain than the inviter's holds nothing for 24 hours. `environments` names the slugs of the environments it administers; without it, the whole tenant (`invalid-admin-scope`): idp.tenant.admin_invite (CT2, OP-159 m.47 (f), m.49 (d), TN-89, TN-109, TN-144).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/tenant/admins/{admin}/owner",
        "addTenantOwner",
        "Makes an administrator an owner, a root of the tenant's new environments: idp.tenant.owner_add (reserved, CT3; the owners' own, OP-159 m.47 (e)).",
    ),
    // OP-159 m.48 (b)
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/settings/primary-binding",
        "bindPrimaryEnvironment",
        "Binds this standard environment to its tenant's primary environment {primary: slug}, so the tenant's administrators administer it: idp.environment.consumer_bind (CT2), signed by the environment's root on its Anchor and never by the operator or the platform (`root-required`, INV-29). The environment must already accept the primary environment's tenant_administration Claims for subject selection (`primary-acceptance-required`); the binding holds after a 24-hour cool-down (TN-4, OP-159 m.48 (b)).",
    ),
    write(
        Verb::Post,
        "/admin/v1/envs/{slug}/tenant/admins/{admin}/remove",
        "removeTenantAdmin",
        "Removes an administrator: its tenant_administration Claims end in every environment at once; the last owner stays (`last-tenant-owner`): idp.tenant.admin_remove (CT1, OP-159 m.47 (e), (f)).",
    ),
];

const TE: &str = "/admin/v1/envs/{slug}/tenant/environments";
const TA: &str = "/admin/v1/envs/{slug}/tenant/admins";

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
    /// One audit event's inclusion proof in the environment's own tree (OP-152 m.7 (d)).
    AuditProof,
    /// A declared route its lane does not serve yet: `501 not-yet-served` behind its
    /// permission (OP-154 m.4); the response schema it will answer with.
    Planned(&'static str),
    /// An agent's `revoke-all`: a bulk job of the caller's signed `instance_terminate` items,
    /// one per live Instance of the agent (OP-154 m.3 (f), P59).
    RevokeAll,
    /// V9, OP-157 m.4 (b): an offboarding's commit, the caller's signed Exercises in order with
    /// one explicit choice for every channel (OP-157 m.3 (v)).
    Offboarding,
    /// V10, OP-157 m.4 (b): a campaign's items for the reading account alone (OP-157 m.3 (w)).
    ReviewItems,
    /// V10, OP-157 m.4 (b): the reviewer's keep, signed with the reviewer's AIS; no Exercise
    /// (OP-157 m.3 (w), m.6 (a)).
    ReviewKeep,
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
    "profile",
    "methods",
    "required_fields",
    "mfa_required",
    "domain_allow",
    "domain_deny",
    "enumeration",
    "email_keep_days",
    "attestation",
    "registration",
    "self_deletion",
    "default_country",
    "pin",
    "national_id",
    "min_age",
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

/// The resource kind and shape of an environment row.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one match over the environment rows, each arm one row"
)]
pub fn spec(operation_id: &str) -> Option<(ResourceKind, Shape)> {
    use ResourceKind::{
        Accounts, AgentSponsors, Agents, Analytics, Clients, CustomDomains, Deliveries, Groups,
        Hooks, HrConnectors, HrSources, LinuxHosts, Organizations, ProtectedResources, Proxies,
        RelayUndelivered, SamlSps, Settings, SignalSources, Signals, SocialProviders,
        SshHostGroups, SsoEnforcementPreviews, TrustAnchors, UpstreamIdps, VaultResources,
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
        // OP-154 m.3 (g), (j), (p), OP-157 m.3 (t)
        "putDelegatedAdmin"
        | "defineAgentTemplate"
        | "putDcrPolicy"
        | "putDeviceCode"
        // OP-156 m.3 (c)
        | "putSecurityNotices"
        | "putCiba"
        // OP-156 m.3 (d)
        | "putPush"
        // OP-156 m.3 (f), (g)
        | "putSmsOtp"
        | "putSpc"
        | "putCertificateLogin"
        | "putMtlsAliases"
        // OP-155 m.3 (f), (o)
        | "registerRadiusClient"
        | "putKeytabPolicy"
        | "replaceKeytab"
        // OP-155 m.3 (h)
        | "putHrd"
        // OP-156 m.3 (c), OP-153 m.3 (ee)
        | "putIys"
        | "putPreferenceTopics"
        | "createCrossAppConnection"
        | "retireCrossAppConnection"
        // OP-155 m.3 (g)
        | "registerScimClient"
        | "rotateScimSecret"
        | "retireScimClient"
        | "registerScimTarget"
        | "retireScimTarget"
        | "putFrontchannelLogout"
        // OP-155 m.3 (j)
        | "putFederation"
        | "addTrustAnchor"
        | "removeTrustAnchor"
        | "putFederationAuthority"
        | "putFederationRegistration"
        // OP-155 m.3 (a), (c), (e), m.6 (h)
        | "putSamlCertificatePolicy"
        | "replaceSamlCertificate"
        | "retireGateway"
        // OP-156 m.3 (t)
        | "putCoordinator"
        // OP-156 m.3 (o)
        | "putSshCa"
        | "rotateSshCa"
        | "replaceSshCa"
        // OP-157 m.3 (g)
        | "putSupportArtifactPolicy"
        | "putCryptoProfile"
        | "putHashProfile"
        // OP-159 m.3 (a), (o), (t), m.7 (b)
        | "putSigningProfile"
        | "putKexShare"
        // OP-159 m.48 (b)
        | "bindPrimaryEnvironment" => (Settings, w(false)),
        "revokeAllAgentInstances" => (Agents, Shape::RevokeAll),
        // OP-154 m.3 (t)
        "listVaultResources" => (
            VaultResources,
            Shape::List(&["resource", "upstream", "status"]),
        ),
        "putVaultResource" => (VaultResources, w(true)),
        // IDP-27, OP-155 m.3 (h)
        "putUpstreamAssuranceMap" => (UpstreamIdps, w(false)),
        "disableVaultResource" | "putVaultReleaseMode" => (VaultResources, w(false)),
        // AG-8, OP-154 m.3 (a)
        "listProtectedResources" => (
            ProtectedResources,
            Shape::List(&["resource", "display_name"]),
        ),
        "registerProtectedResource" => (ProtectedResources, CREATE),
        // OP-155 m.3 (k)
        "putClientProfile"
        | "putClientLegacyAuthentication"
        | "putClientSigningAlg"
        | "putClientEncryption"
        | "putClientSamlBearer"
        | "putClientLegacyBearer" => (Clients, w(false)),
        // OP-155 m.3 (j)
        "listTrustAnchors" => (
            TrustAnchors,
            Shape::List(&["anchor", "entity_id", "status"]),
        ),
        // OP-155 m.3 (a), (c), (e), m.6 (h)
        "listSamlSps" => (SamlSps, Shape::List(&["name", "entity_id", "status"])),
        "getSamlSp" => (SamlSps, Shape::Get),
        "registerSamlSp" => (SamlSps, CREATE),
        "putSamlSp" => (SamlSps, w(true)),
        "retireSamlSp" => (SamlSps, w(false)),
        "registerGateway" => (Settings, CREATE),
        // OP-156 m.3 (o)
        "listSshHostGroups" => (SshHostGroups, Shape::List(&["name", "status"])),
        // OP-156 m.3 (q)
        "listHrSources" => (HrSources, Shape::List(&["name", "status"])),
        "registerHrSource" => (HrSources, CREATE),
        "retireHrSource" | "importHrBatch" | "importHrCsv" => (HrSources, w(false)),
        "listHrConnectors" => (HrConnectors, Shape::List(&["name", "source", "status"])),
        "registerHrConnector" => (HrConnectors, CREATE),
        "retireHrConnector" => (HrConnectors, w(false)),
        "registerSshHostGroup" => (SshHostGroups, CREATE),
        "retireSshHostGroup" => (SshHostGroups, w(false)),
        // OP-156 m.3 (r)
        "listSignalSources" => (
            SignalSources,
            Shape::List(&["name", "kind", "provider", "status"]),
        ),
        "registerSignalSource" => (SignalSources, CREATE),
        "retireSignalSource" => (SignalSources, w(false)),
        // OP-156 m.3 (l)
        "listProxies" => (Proxies, Shape::List(&["name", "host", "status"])),
        "getProxy" => (Proxies, Shape::Get),
        "registerProxy" => (Proxies, CREATE),
        "putProxy" | "retireProxy" | "putProxyPlainHeaders" | "pinMcpTools" => {
            (Proxies, w(false))
        }
        // OP-156 m.3 (s)
        "listExportSinks" => (
            ResourceKind::ExportSinks,
            Shape::List(&["name", "adapter", "status"]),
        ),
        "registerExportSink" => (ResourceKind::ExportSinks, CREATE),
        "putExportSink" => (ResourceKind::ExportSinks, w(true)),
        "retireExportSink" => (ResourceKind::ExportSinks, w(false)),
        // OP-156 m.3 (p)
        "listLinuxHosts" => (LinuxHosts, Shape::List(&["name", "status"])),
        "registerLinuxHost" => (LinuxHosts, CREATE),
        "retireLinuxHost" | "putLinuxOfflinePolicy" | "putLinuxBreakGlassPolicy" => {
            (LinuxHosts, w(false))
        }
        // OP-155 m.3 (i)
        "previewSsoEnforcement" => (SsoEnforcementPreviews, Shape::Get),
        "enforceOrganizationSso" | "liftOrganizationSso" | "createOrganizationSetupLink" => {
            (Accounts, w(false))
        }
        // OP-156 m.3 (i)
        "listDomains" => (CustomDomains, Shape::List(&["host", "status"])),
        "getDomain" => (CustomDomains, Shape::Get),
        "registerDomain" => (CustomDomains, CREATE),
        "retireDomain" | "bindDomainIssuer" => (CustomDomains, w(false)),
        // OP-156 m.3 (c)
        "listUndeliveredRelayMessages" => (
            RelayUndelivered,
            Shape::List(&["event_id", "kind", "reason"]),
        ),
        "resendRelayMessage" => (RelayUndelivered, w(false)),
        // OP-158 m.4 (a)
        // OP-158 m.3 (o), (p)
        "getPlacement" => (ResourceKind::Placement, Shape::Get),
        "getDurability" => (ResourceKind::Durability, Shape::Get),
        // OP-158 m.4 (b) (W11)
        "getRateLimits" => (ResourceKind::RateLimits, Shape::Get),
        // OP-158 m.3 (o), (r)
        "putResidency" | "putDrProfile" => (Settings, w(true)),
        // OP-158 m.4 (b) (W6)
        "getRecovery" => (ResourceKind::Recovery, Shape::Get),
        // OP-159 m.3 (a), (o), (t), m.7 (b)
        "getSigning" => (ResourceKind::Signing, Shape::Get),
        // OP-157 m.4 (a)
        "listCaseSystems" => (
            ResourceKind::CaseSystems,
            Shape::List(&["name", "provider", "status"]),
        ),
        "registerCaseSystem" => (ResourceKind::CaseSystems, CREATE),
        "retireCaseSystem" => (ResourceKind::CaseSystems, w(false)),
        "listSupportGrants" => (ResourceKind::SupportGrants, Shape::Planned("Page")),
        // OP-157 m.3 (m)
        "putApprovalInline" | "putApprovalBatch" | "putAuditTier" | "putRateLimit" => {
            (Settings, w(true))
        }
        // OP-157 m.3 (h)
        "listBreakglassAccounts" => (ResourceKind::BreakglassAccounts, Shape::List(&[])),
        "markBreakglassAccount" => (ResourceKind::BreakglassAccounts, CREATE),
        "clearBreakglassAccount" => (ResourceKind::BreakglassAccounts, w(false)),
        "listBreakglassDrills" => (ResourceKind::BreakglassDrills, Shape::List(&[])),
        "listBreakglassReviews" => (ResourceKind::BreakglassReviews, Shape::List(&[])),
        // OP-157 m.3 (w), m.6 (a)
        "listReviews" => (
            ResourceKind::Reviews,
            Shape::List(&["name", "status", "scope"]),
        ),
        "scheduleReview" => (ResourceKind::Reviews, CREATE),
        "closeReview" => (ResourceKind::Reviews, w(false)),
        "getReview" => (ResourceKind::Reviews, Shape::Get),
        "listReviewItems" => (ResourceKind::ReviewItems, Shape::ReviewItems),
        "keepReviewItem" => (ResourceKind::ReviewItems, Shape::ReviewKeep),
        // OP-157 m.3 (v), m.6 (a)
        "previewOffboarding" => (ResourceKind::OffboardingPreviews, Shape::Get),
        "commitOffboarding" => (ResourceKind::OffboardingPreviews, Shape::Offboarding),
        // OP-157 m.3 (h), m.4 (b)
        "reviewBreakglassUse" => (ResourceKind::BreakglassReviews, w(false)),
        o if declared(o) => (Settings, Shape::Planned(planned_body(o))),
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
        "rehomeEnvironment" | "putRecoveryPolicy" => (Settings, w(false)),
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
        // OP-159 m.47 (a), (e), (f), (h)
        "listManagedEnvironments" => (
            ResourceKind::TenantEnvironments,
            Shape::List(&["slug", "kind", "sandbox"]),
        ),
        "createTenantEnvironment" => (ResourceKind::TenantEnvironments, CREATE),
        "listTenantAdmins" => (
            ResourceKind::TenantAdmins,
            Shape::List(&["id", "role", "status"]),
        ),
        "inviteTenantAdmin" => (ResourceKind::TenantAdmins, CREATE),
        "addTenantOwner" | "removeTenantAdmin" => (ResourceKind::TenantAdmins, w(false)),
        // OP-41
        "listAuditEvents" => (Analytics, Shape::Audit),
        "getAuditEventProof" => (Analytics, Shape::AuditProof),
        _ => return None,
    })
}

/// Serves every environment row with [`serve`].
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
    use codes::environment as r;
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
            Invalid::Name | Invalid::ScimClient => &r::INVALID_NAME,
            Invalid::MembershipIssuer => &r::INVALID_MEMBERSHIP_ISSUER,
            Invalid::Members => &r::INVALID_MEMBERS,
            Invalid::Upstream => &r::INVALID_UPSTREAM,
            Invalid::UpstreamSubject => &r::INVALID_UPSTREAM_SUBJECT,
            Invalid::UpstreamSubjectLinked => &r::UPSTREAM_SUBJECT_LINKED,
            Invalid::SigninPolicy => &r::INVALID_SIGNIN_POLICY,
            Invalid::SessionPolicy => &r::INVALID_SESSION_POLICY,
            Invalid::ProtectedResource => &r::INVALID_PROTECTED_RESOURCE,
            Invalid::DcrPolicy => &r::INVALID_DCR_POLICY,
            Invalid::ClientProfile => &r::INVALID_CLIENT_PROFILE,
            Invalid::CrossAppConnection => &r::INVALID_CROSS_APP_CONNECTION,
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
            Invalid::Body | Invalid::Federation => &r::INVALID_BODY,
            Invalid::Validity => &r::INVALID_VALIDITY,
            Invalid::PublicSub => &r::PUBLIC_SUB_NOT_OPTED_IN,
            Invalid::SectorIdentifier => &r::INVALID_SECTOR_IDENTIFIER_URI,
            Invalid::Reserved => &r::RESERVED_OPERATION,
            Invalid::JoseAlg => &r::INVALID_JOSE_ALG,
            Invalid::CertificateLogin => &r::INVALID_CERTIFICATE_LOGIN,
            Invalid::ProtectionMode => &r::INVALID_PROTECTION_MODE,
            Invalid::ExtensionTarget => &r::INVALID_EXTENSION_TARGET,
            Invalid::Hook => &r::INVALID_HOOK,
            Invalid::Disclosure => &r::DISCLOSURE_NOT_PERMITTED,
            Invalid::WebhookEvents => &r::INVALID_WEBHOOK_EVENTS,
            Invalid::ExtensionPolicy => &r::INVALID_EXTENSION_POLICY,
            Invalid::HookPointTaken => &r::HOOK_POINT_TAKEN,
            Invalid::CatalogUpgradeRequired => &r::CATALOG_UPGRADE_REQUIRED,
            // OP-159 m.48 (b)
            Invalid::PrimaryBinding => &codes::platform::PRIMARY_BINDING,
            Invalid::PrimaryAcceptanceRequired => &codes::platform::PRIMARY_ACCEPTANCE_REQUIRED,
            Invalid::RootRequired => &codes::platform::ROOT_REQUIRED,
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
            Invalid::CustomDomain => &r::INVALID_CUSTOM_DOMAIN,
            Invalid::IssuerFixed => &r::ISSUER_FIXED,
            Invalid::SsoDraft => &r::INVALID_CONNECTION_DRAFT,
            Invalid::ScimAuthoritative => &r::INVITATIONS_CLOSED_BY_SCIM,
            Invalid::SetupLink => &r::INVALID_SETUP_LINK,
            Invalid::Agent => &r::INVALID_AGENT,
            Invalid::AgentTemplate => &r::INVALID_AGENT_TEMPLATE,
            Invalid::Workload => &r::INVALID_WORKLOAD_CLIENT,
            Invalid::VaultResource => &r::INVALID_VAULT_RESOURCE,
            Invalid::SamlSp => &r::INVALID_SAML_SP,
            Invalid::SamlSpExists => &r::SAML_SP_EXISTS,
            Invalid::SamlCertificate => &r::INVALID_SAML_CERTIFICATE_POLICY,
            Invalid::Gateway => &r::INVALID_GATEWAY,
            Invalid::SshCa => &r::INVALID_SSH_CA,
            Invalid::SshHostGroup => &r::INVALID_SSH_HOST_GROUP,
            Invalid::SshHostGroupExists => &r::SSH_HOST_GROUP_EXISTS,
            Invalid::SignalSource => &r::INVALID_SIGNAL_SOURCE,
            Invalid::SignalSourceExists => &r::SIGNAL_SOURCE_EXISTS,
            Invalid::Proxy => &r::INVALID_PROXY,
            Invalid::ProxyExists => &r::PROXY_EXISTS,
            Invalid::ProxyClient => &r::INVALID_PROXY_CLIENT,
            Invalid::ProxyDirectlyReachable => &r::PROXY_REACHABLE_DIRECTLY,
            Invalid::ExportSink => &r::INVALID_EXPORT_SINK,
            Invalid::ExportSinkExists => &r::EXPORT_SINK_EXISTS,
            Invalid::LinuxHost => &r::INVALID_LINUX_HOST,
            Invalid::LinuxHostExists => &r::LINUX_HOST_EXISTS,
            Invalid::HrSource => &r::INVALID_HR_SOURCE,
            Invalid::HrSourceExists => &r::HR_SOURCE_EXISTS,
            Invalid::HrConnector => &r::INVALID_HR_CONNECTOR,
            Invalid::HrConnectorExists => &r::HR_CONNECTOR_EXISTS,
            Invalid::HrRecords => &r::INVALID_HR_RECORDS,
            Invalid::McpPins => &r::INVALID_MCP_PINS,
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
            | Invalid::NoTrustAnchor
            | Invalid::NoSamlSp
            | Invalid::NoSshHostGroup
            | Invalid::NoSignalSource
            | Invalid::NoProxy
            | Invalid::NoExportSink
            | Invalid::NoLinuxHost
            | Invalid::NoHrSource
            | Invalid::NoHrConnector
            | Invalid::NoCrossAppConnection
            | Invalid::NoScimClient
            | Invalid::NoGateway
            | Invalid::NoDomain
            | Invalid::NoRelayMessage => &codes::NOT_FOUND,
            // OP-156 m.3 (c)
            Invalid::RelayShredded => &r::CONTENT_SHREDDED,
            Invalid::RelayExpired => &r::MESSAGE_EXPIRED,
            // OP-157 m.4 (a)
            Invalid::NotYetServed => &codes::NOT_YET_SERVED,
            Invalid::CaseSystemUnknown => &r::CASE_SYSTEM_UNKNOWN,
            Invalid::DelegatedAdminOff => &r::DELEGATED_ADMIN_OFF,
            Invalid::OffboardingDispositionMissing => &r::OFFBOARDING_DISPOSITION_MISSING,
            // OP-158 m.3 (aa)
            Invalid::AuditTierTooShort => &codes::durability::AUDIT_TIER_TOO_SHORT,
            Invalid::HashProfileDowngrade => &codes::durability::HASH_PROFILE_DOWNGRADE,
            Invalid::RehomeIncomplete => &codes::durability::REHOME_INCOMPLETE,
            Invalid::PlacementMismatch => &codes::durability::PLACEMENT_MISMATCH,
            // OP-159 m.3 (nn)
            Invalid::FipsPqExclusive => &codes::assurance::FIPS_PQ_EXCLUSIVE,
            Invalid::PqKeyUnavailable => &codes::assurance::PQ_KEY_UNAVAILABLE,
            Invalid::AlgorithmProfileConflict => &codes::assurance::ALGORITHM_PROFILE_CONFLICT,
        },
        AdminError::Issuer(_) | AdminError::NoEnvironment => &codes::NOT_FOUND,
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
