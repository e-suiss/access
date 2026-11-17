//! The `idp.*` write path between the planes (MD-14, E34, EI-25, OP-146 I10): the actions the
//! identity plane publishes, the Exercise it sends as PEP, the committed decision it binds its
//! configuration to, and the Genesis a new environment's governing domain is opened with (TN-111).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::{BlockerClass, Capacity, Decision, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{ExerciseBasis, Root};
use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};

/// The resource namespace every `idp.*` action addresses: `[slug, kind, …]` paths.
pub const RESOURCE_NAMESPACE: &str = "idp";

/// Version of every `idp.*` catalog (OP-153 m.3 (a), m.25 (b), OP-154 m.3 (a), OP-155 m.3 (a),
/// OP-156 m.3 (a), OP-157 m.3 (a), OP-158 m.3 (a), OP-159 m.3 (a), m.48 (b)).
pub const CATALOG_VERSION: u64 = 10;

/// The `idp.*` action namespaces, one SPP each (OP-141 m.35, OP-153 m.3 (a), OP-154 m.3 (a),
/// OP-155 m.3 (a), OP-156 m.3 (a), OP-157 m.3 (a)).
pub const NAMESPACES: [&str; 27] = [
    "idp.account",
    "idp.agent",
    "idp.client",
    "idp.domain",
    "idp.export",
    "idp.federation",
    "idp.gateway",
    "idp.group",
    "idp.hook",
    "idp.hr",
    "idp.linux",
    "idp.mapper",
    "idp.org",
    "idp.proxy",
    "idp.environment",
    "idp.relay",
    "idp.review",
    "idp.saml",
    "idp.scim",
    "idp.signal",
    "idp.social",
    "idp.ssh",
    "idp.support",
    "idp.upstream",
    "idp.vault",
    "idp.vc",
    "idp.webhook",
];

/// Stable code of an `idp.*` write the environment's governing domain refuses because it does not yet
/// accept the catalog that declares the action (OP-153 m.3 (a)): the environment's catalog upgrade
/// must commit first.
pub const CATALOG_UPGRADE_REQUIRED: &str = "catalog-upgrade-required";

/// Whether `decision` is a DENY of an action no live `schema-definition` Acceptance of the
/// domain declares: for an [`IdpAction`] this means only that the environment's catalog upgrade has
/// not committed yet (OP-153 m.3 (a), OP-141 m.35 (e)).
#[must_use]
pub fn catalog_upgrade_required(decision: &Decision) -> bool {
    decision.outcome == Outcome::Deny
        && decision.blockers.iter().any(|b| {
            b.class == BlockerClass::SchemaNotAccepted
                && b.subcode.as_deref() == Some("unknown-action")
        })
}

/// One `idp.*` domain action. Its Consequence Tier follows from its Action Schema (OP-141
/// m.34 (a), m.35 (g)): reserved is CT3, irreversible at least CT2, reversible CT1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdpAction {
    /// Registers a client (TN-15, §12.1.2): CT2.
    ClientRegister,
    /// Replaces a client's name, authentication method and redirect URIs: CT2.
    ClientUpdate,
    /// Retires a client; narrowing, CT1.
    ClientRetire,
    /// Changes the environment's client and CIMD acceptance policy (§11.3, AG-4): CT2.
    CimdPolicy,
    /// Sets a token claim from a profile attribute (TN-117): CT2.
    MapperSet,
    /// Sets the environment's JOSE signing algorithm (OP-146 m.8 (e)): CT2.
    EnvironmentJoseAlg,
    /// Raises the environment's Argon2id parameters (OP-33, §17.5.2); narrowing, CT1.
    EnvironmentArgon2,
    /// Pins or changes the environment's RP ID (IDP-5, IDI-4): reserved, irreversible, CT3.
    EnvironmentRpId,
    /// Moves the environment to another governing domain (§12.1.1 2a): reserved, CT3.
    EnvironmentRehome,
    /// Registers an upstream identity provider (TN-95): reserved, CT3.
    UpstreamRegister,
    /// Maps upstream groups or claims onto environment membership (TN-117, L6): reserved, CT3.
    UpstreamMapping,
    /// Changes the environment's login branding: name, logo, colours and the hosted page's CSP
    /// origins (TN-106, §12.4.2): CT2.
    EnvironmentBranding,
    /// Changes the environment's JOSE key rotation policy (TN-118, §12.1.2): reserved, CT3.
    EnvironmentKeyPolicy,
    /// Rotates the environment's active JOSE key now, outside the schedule (TN-118): reserved, CT3.
    EnvironmentKeyRotate,
    /// Drops an environment JOSE key at once, as on compromise (§13.2): narrowing, CT1 (§13.7.1).
    EnvironmentKeyDrop,
    /// Erases an account for good by crypto-shredding (OP-73, TN-118): reserved, CT3.
    AccountDelete,
    /// Suspends an account: it cannot sign in until reactivated (§12.3.1); narrowing, CT1.
    AccountSuspend,
    /// Reactivates a suspended account (§12.3.1): CT2.
    AccountReactivate,
    /// Replaces a confidential client's secret; the old one stays valid for the overlap window
    /// (CR-38): CT2.
    ClientSecretRotate,
    /// Creates a group with its one membership issuer (TN-117): CT2.
    GroupCreate,
    /// Renames a group: CT2.
    GroupUpdate,
    /// Retires a group and ends its memberships; narrowing, CT1.
    GroupRetire,
    /// Adds members to a group whose membership issuer is the environment's administration (TN-117):
    /// CT2.
    GroupMembersAdd,
    /// Removes members from such a group; narrowing, CT1.
    GroupMembersRemove,
    /// Replaces an upstream identity provider's registration (TN-95): reserved, CT3.
    UpstreamUpdate,
    /// Retires an upstream identity provider; narrowing, CT1.
    UpstreamRetire,
    /// Sets the environment's sign-in requirements: methods, required fields, MFA, registration
    /// domain lists (TN-132): CT2.
    EnvironmentSigninPolicy,
    /// Sets the environment's console session policy (TN-129, OP-151 m.3 (f)): CT2.
    EnvironmentSessionPolicy,
    /// Tightens the environment's protection mode: monitor to enforce, a later SL2 stage, more denied
    /// ASNs (OP-151 m.3 (o), m.14 (f)); narrowing, CT1.
    EnvironmentProtectionMode,
    /// Changes the environment's protection mode so that anything loosens (OP-151 m.14 (f)): CT2.
    EnvironmentProtectionModeLoosen,
    /// Makes an account a canary: a credential the environment plants (§4.4, OP-151 m.14 (f)): CT2.
    AccountCanary,
    /// Sets what the environment's extension points may reach and receive: private targets and hook
    /// disclosures (OP-151 m.10 (e)): CT2 either way.
    EnvironmentExtensionPolicy,
    /// Registers an inline hook at one call point (TN-135, OP-151 m.10 (d)): CT2.
    HookRegister,
    /// Retires an inline hook; narrowing, CT1.
    HookRetire,
    /// Registers a webhook (TN-136): CT2.
    WebhookRegister,
    /// Changes a webhook's URL or events, or rotates its key: CT2.
    WebhookUpdate,
    /// Retires a webhook; narrowing, CT1.
    WebhookRetire,
    /// Links an upstream subject to an account, so the upstream's inbound signals about it
    /// reach the account (§9.16.2 k.4, TN-42, OP-152 m.7 (d) E6): CT2.
    UpstreamLink,
    /// Issues a reset-intent token to the account's registered notification address (TN-61,
    /// OP-153 m.3 (f)): CT2.
    AccountResetIntent,
    /// Issues a temporary access pass (TN-62, OP-153 m.3 (f)): CT2.
    AccountTapIssue,
    /// Narrows the account's recovery policy (TN-52, OP-153 m.3 (d)): CT1.
    AccountRecoveryPolicy,
    /// Loosens the recovery or cooling table, forward only (TN-55, OP-153 m.3 (e)): reserved,
    /// CT3.
    AccountRecoveryPolicyLoosen,
    /// Exports the person's own data under their self-anchor (TN-79, OP-153 m.3 (cc)): CT1.
    AccountExport,
    /// Exports the environment's accounts for migration, encrypted to an environment-bound key (TN-86,
    /// OP-153 m.3 (n)): reserved, CT3.
    AccountMigrationExport,
    /// Creates an organization bound to its registered Party (TN-5, OP-153 m.3 (b)): CT2.
    OrgCreate,
    /// Changes an organization's name and profile: CT2.
    OrgUpdate,
    /// Claims a domain for an organization, pending verification (TN-90, OP-153 m.3 (o)): CT2.
    OrgDomainClaim,
    /// Invites a person into an organization (TN-89, OP-153 m.3 (o)): CT2.
    OrgInvite,
    /// Issues an organization's setup link (OP-153 m.3 (o)): CT2.
    OrgSetupLink,
    /// Releases a claimed domain: CT1.
    OrgDomainRelease,
    /// Revokes a pending invitation: CT1.
    OrgInviteRevoke,
    /// Removes a member from an organization; the last owner is kept (OP-153 m.3 (p)): CT1.
    OrgMemberRemove,
    /// Drafts an enterprise connection; enacting it is `idp.upstream.register` (OP-153 m.3
    /// (p)): CT1.
    OrgSsoDraft,
    /// Enables a social sign-in preset (IDP-31, OP-153 m.3 (l)): CT2.
    SocialEnable,
    /// Changes an enabled social preset's client: CT2.
    SocialUpdate,
    /// Disables a social preset: CT1.
    SocialDisable,
    /// Sets the environment's WebAuthn related origins, verified domains only (OP-153 m.3 (u)): CT2.
    EnvironmentRelatedOrigins,
    /// Overrides the environment's unprotected message keys (TN-108, X35, OP-153 m.3 (s)): CT2.
    EnvironmentLocaleOverrides,
    /// Publishes the environment's consent documents (IDP-37, OP-153 m.3 (ee)): CT2.
    EnvironmentConsentDocuments,
    /// Sets the environment's preference topics (IDP-37, OP-153 m.3 (ee)): CT2.
    EnvironmentPreferenceTopics,
    /// Sets the environment's inactivity policy (TN-51, OP-153 m.3 (dd)): CT2.
    EnvironmentInactivityPolicy,
    /// Extends a retention period (T39, OP-153 m.3 (ff)): CT2.
    EnvironmentRetentionExtend,
    /// Moves the environment's hosted surfaces, issuer and RP ID to a verified customer domain
    /// (OP-153 m.3 (u)): reserved, irreversible, CT3.
    EnvironmentCustomDomain,
    /// Reads the account's own resources under its self-anchor (E34): CT1.
    AccountRead,
    /// Changes the account's own profile fields under its self-anchor (E34): CT1.
    AccountProfileUpdate,
    /// Changes the account's primary e-mail address after step-up and an out-of-band code
    /// (E34, OP-153 m.3 (i)): CT2.
    AccountEmailChange,
    /// Places a legal hold that stops destruction of the held records (T39, OP-153 m.3 (ff)):
    /// CT1.
    EnvironmentRetentionHoldPlace,
    /// Lifts a legal hold, letting destruction run on its schedule again (T39): CT2.
    EnvironmentRetentionHoldLift,
    /// Binds two accounts of two environments of the same tenant as one person, by an administrator
    /// (OP-153 m.18 (e), m.25 (b)): CT2.
    AccountBind,
    /// Imports accounts from another identity provider (§12.3.7, TN-85, OP-153 m.19 (d),
    /// m.25 (b)): CT2.
    AccountImport,
    /// Records a guardianship between two accounts of the environment (E53, OP-153 m.20 (g),
    /// m.25 (b)): CT2.
    AccountGuardianshipRecord,
    /// Tightens the environment's hosted-page CSP mode: report-only to enforce (OP-153 m.22 (g),
    /// m.25 (b)); narrowing, CT1.
    EnvironmentCspMode,
    /// Changes the environment's hosted-page CSP mode so that it loosens: enforce to report-only
    /// (OP-153 m.22 (g), m.25 (b)): CT2.
    EnvironmentCspModeLoosen,
    /// Registers an agent: its record, operator and kind, bound to one self-registered agent
    /// Party (OP-154 m.3 (c)): CT2.
    AgentRegister,
    /// Changes an agent's name and description: CT1.
    AgentUpdate,
    /// Assigns a human sponsor to an agent (AG-41, OP-154 m.3 (e)): CT2.
    AgentSponsorAssign,
    /// Removes a sponsor; the last one leaving suspends the agent (OP-154 m.3 (e)): CT1.
    AgentSponsorRemove,
    /// Retires an agent; narrowing, CT1.
    AgentRetire,
    /// Defines an agent Grant template with its mandatory budget (OP-154 m.3 (g)): CT2.
    AgentTemplateDefine,
    /// Enables an upstream of the catalog as a vault Resource (OP-154 m.3 (t)): CT2.
    VaultResourceEnable,
    /// Disables a vault Resource; narrowing, CT1.
    VaultResourceDisable,
    /// Registers a tenant's own upstream as a vault Resource: reserved, CT3.
    VaultResourceRegister,
    /// Opens release path (b) for CT0–CT1 classes; a loosening (OP-154 m.3 (t)): CT2.
    VaultReleaseModeOpen,
    /// Closes release path (b); narrowing, CT1.
    VaultReleaseModeClose,
    /// Registers a protected resource or MCP server for `resource` validation (OP-154 m.3
    /// (a)): CT2.
    ClientResourceRegister,
    /// Turns on or widens the dynamic client registration profile (OP-154 m.3 (j)): CT2.
    ClientDcrPolicy,
    /// Tightens the dynamic client registration profile; narrowing, CT1.
    ClientDcrPolicyTighten,
    /// Records a cross-app connection for ID-JAG (OP-154 m.3 (n)): CT2.
    ClientCrossAppConnection,
    /// Retires a cross-app connection; narrowing, CT1.
    ClientCrossAppConnectionRetire,
    /// Turns on the device authorization grant (RFC 8628, OP-154 m.3 (p)): CT2.
    EnvironmentDeviceCode,
    /// Turns off the device authorization grant; narrowing, CT1.
    EnvironmentDeviceCodeClose,
    /// Registers a SAML service provider from its metadata or catalog template (OP-155 m.3 (a), (e)): CT2.
    SamlSpRegister,
    /// Registers or changes an SP whose template maps a Claim that selects authority (L6): reserved, CT3.
    SamlSpMapping,
    /// Replaces a SAML service provider's registration: CT2.
    SamlSpUpdate,
    /// Retires a SAML service provider; narrowing, CT1.
    SamlSpRetire,
    /// Sets the SAML signing certificate rotation policy (OP-155 m.3 (e)): CT2.
    SamlCertPolicy,
    /// Replaces the SAML signing certificate at once, outside the policy: reserved, CT3.
    SamlCertEmergency,
    /// Registers an inbound SCIM client; its opaque token is shown once (OP-155 m.3 (g)): CT2.
    ScimClientRegister,
    /// Replaces an inbound SCIM client's token: CT2.
    ScimTokenRotate,
    /// Retires an inbound SCIM client; narrowing, CT1.
    ScimClientRetire,
    /// Registers an outbound SCIM target with its sealed secret: CT2.
    ScimOutboundRegister,
    /// Retires an outbound SCIM target; narrowing, CT1.
    ScimOutboundRetire,
    /// Registers an edge gateway and its internal mTLS identity `urn:suiss:access:gw:<kind>:<name>` (OP-155 m.3 (c)): CT2.
    GatewayRegister,
    /// Retires an edge gateway; its identity is never reused; narrowing, CT1.
    GatewayRetire,
    /// Sets a Kerberos gateway's keytab rotation policy (OP-155 m.3 (o)): CT2.
    GatewayKeytabPolicy,
    /// Replaces a Kerberos gateway's keytab at once: reserved, CT3.
    GatewayKeytabEmergency,
    /// Registers a `RadSec` client of a RADIUS gateway (OP-155 m.3 (f)): CT2.
    GatewayRadiusClientRegister,
    /// Turns on OpenID Federation for the environment's issuer as a leaf (OP-155 m.3 (j)): CT2.
    FederationEnable,
    /// Turns OpenID Federation off; narrowing, CT1.
    FederationDisable,
    /// Trusts a federation's trust anchor: reserved, CT3.
    FederationTrustAnchorAdd,
    /// Stops trusting a trust anchor; narrowing, CT1.
    FederationTrustAnchorRemove,
    /// Turns on the intermediate or trust anchor role, off by default (OP-155 m.3 (j)): CT2.
    FederationTaEnable,
    /// Opens automatic or explicit OIDF client registration: CT2.
    FederationRegistrationOpen,
    /// Closes OIDF client registration; narrowing, CT1.
    FederationRegistrationClose,
    /// Turns on the OID4VP verifier for the environment (OP-155 m.3 (p)): CT2.
    VcVerifierEnable,
    /// Turns the OID4VP verifier off; narrowing, CT1.
    VcVerifierDisable,
    /// Sets the trusted lists (the EU `LoTL` or a TL) whose issuers the verifier accepts: reserved,
    /// CT3.
    VcTrustedList,
    /// Turns on the OID4VCI person-attribute issuer (OP-155 m.3 (p)): CT2.
    VcIssuerEnable,
    /// Turns the person-attribute issuer off; narrowing, CT1.
    VcIssuerDisable,
    /// Puts a client under the FAPI 2.0 profile (OP-155 m.3 (k)); tightening, CT1.
    ClientProfile,
    /// Takes a client out of the FAPI 2.0 profile; a loosening, CT2.
    ClientProfileLoosen,
    /// Allows a client `client_secret_post` or `client_secret_jwt` (OP-155 m.3 (k)): CT2.
    ClientAuthMethodLegacy,
    /// Lets a client take RS256 identity assertions; the environment's `rsa-id` key is made on first use (MD-6): CT2.
    ClientAlgRs256,
    /// Turns on JWE for a client's ID tokens, userinfo or JARM (OP-155 m.3 (k)); tightening, CT1.
    ClientEncryption,
    /// Allows a client the SAML 2.0 bearer grant (RFC 7522) from an accepted SAML upstream: CT2.
    ClientSamlBearer,
    /// Grants a client the legacy bearer exception: identity plane protocol tokens only, never advertised (OP-155 m.3 (k)): CT2.
    ClientLegacyBearer,
    /// Turns on CIBA poll and ping (OP-155 m.3 (l)): CT2.
    EnvironmentCiba,
    /// Turns CIBA off; narrowing, CT1.
    EnvironmentCibaClose,
    /// Turns on certificate, PIV and CAC sign-in (OP-155 m.3 (m)): CT2.
    EnvironmentCertificateLogin,
    /// Publishes `mtls_endpoint_aliases` on the mTLS listener (OP-155 m.3 (m)): CT2.
    EnvironmentMtlsAliases,
    /// Turns on home environment discovery, confirmed on an interstitial (OP-155 m.3 (h)): CT2.
    EnvironmentHrd,
    /// Turns home environment discovery off; narrowing, CT1.
    EnvironmentHrdClose,
    /// Lets the environment's clients opt in to front-channel logout (OP-155 m.3 (k)): CT2.
    EnvironmentFrontchannelLogout,
    /// Enforces SSO on an organization: its members' passwords, API tokens, sign-ins and refresh families end, and pending invitations follow the chosen fate (OP-155 m.3 (i)); narrowing, CT1.
    OrgSsoEnforce,
    /// Lifts an organization's SSO enforcement; a loosening, CT2.
    OrgSsoEnforceLift,
    /// Maps an upstream's `acr`, `amr` or `AuthnContextClassRef` onto assurance (OP-155 m.3 (h)): reserved, CT3.
    UpstreamAssuranceMap,
    /// Registers a custom domain, verified by `_access-challenge` TXT and CNAME (OP-156 m.3 (i)): CT2.
    DomainRegister,
    /// Retires a custom domain; it is no longer served; narrowing, CT1.
    DomainRetire,
    /// Binds the issuer or passkey RP ID to a verified custom domain, irreversibly (§10.2.4, TN-16): reserved, CT3.
    DomainIssuerBind,
    /// Registers a forward-auth proxy or Access Proxy as a PEP (OP-156 m.3 (l), IDP-30): CT2.
    ProxyRegister,
    /// Replaces a proxy's registration: CT2.
    ProxyUpdate,
    /// Retires a proxy; narrowing, CT1.
    ProxyRetire,
    /// Lets a proxy send the plain identity headers to its application (OP-156 m.3 (l)): CT2.
    ProxyPlainHeaders,
    /// Stops the plain identity headers; narrowing, CT1.
    ProxyPlainHeadersClose,
    /// Pins an MCP server's tool list by the SHA-256 of each tool definition (OP-156 m.3 (n)): CT2.
    ProxyMcpPin,
    /// Turns on the environment's SSH user certificate authority (OP-156 m.3 (o), IDP-32): CT2.
    SshCaEnable,
    /// Turns the SSH certificate authority off; narrowing, CT1.
    SshCaDisable,
    /// Rotates the SSH CA key on its schedule: CT2.
    SshCaRotate,
    /// Replaces the SSH CA key at once: reserved, CT3.
    SshCaEmergency,
    /// Registers an SSH server group, the resource of `ssh.login` Grants: CT2.
    SshHostGroupRegister,
    /// Retires an SSH server group; narrowing, CT1.
    SshHostGroupRetire,
    /// Registers a Linux host of the Linux client (OP-156 m.3 (p)): CT2.
    LinuxHostRegister,
    /// Retires a Linux host; narrowing, CT1.
    LinuxHostRetire,
    /// Sets a host's offline cache limits within the `ValidityContract` horizon: CT2.
    LinuxOfflinePolicy,
    /// Sets a host's local break-glass policy over an offline PAP: reserved, CT3.
    LinuxBreakGlassPolicy,
    /// Registers an HR source as a Claim issuer (OP-156 m.3 (q), IDP-35): CT2.
    HrSourceRegister,
    /// Retires an HR source; narrowing, CT1.
    HrSourceRetire,
    /// Imports an HR batch or CSV file into the HR issuer's Claims: CT2.
    HrImport,
    /// Registers an HR connector of `services/hr-connector`: CT2.
    HrConnectorRegister,
    /// Retires an HR connector; narrowing, CT1.
    HrConnectorRetire,
    /// Registers an export sink for the read-only SIEM projection (OP-156 m.3 (s)): CT2.
    ExportSinkRegister,
    /// Replaces an export sink's configuration: CT2.
    ExportSinkUpdate,
    /// Retires an export sink; narrowing, CT1.
    ExportSinkRetire,
    /// Registers a signal source as a Claim issuer; its effect still needs an Acceptance (OP-156 m.3 (r)): CT2.
    SignalSourceRegister,
    /// Retires a signal source; narrowing, CT1.
    SignalSourceRetire,
    /// Turns on push verification with number matching (OP-156 m.3 (d)): CT2.
    EnvironmentPush,
    /// Turns push verification off; narrowing, CT1.
    EnvironmentPushClose,
    /// Turns on the restricted SMS one-time code (OP-156 m.3 (f)): CT2.
    EnvironmentSmsOtp,
    /// Turns the SMS one-time code off; narrowing, CT1.
    EnvironmentSmsOtpClose,
    /// Opens `Permissions-Policy: payment` on the approval surface for Secure Payment Confirmation (OP-156 m.3 (g)): CT2.
    EnvironmentSpc,
    /// Names the coordinator URL the hub links pending approvals to (OP-156 m.3 (t)): CT2.
    EnvironmentCoordinator,
    /// Turns on the IYS consent registry events (OP-156 m.3 (c)): CT2.
    EnvironmentIys,
    /// Turns the IYS consent registry events off; narrowing, CT1.
    EnvironmentIysClose,
    /// Turns the immediate security authority notices back on (OP-156 m.3 (c)): CT2.
    EnvironmentSecurityNotices,
    /// Turns the immediate security authority notices off; it lessens notice, CT1.
    EnvironmentSecurityNoticesClose,
    /// Resends an undelivered Relay message as a new outbox row citing the original; a message
    /// whose sealed content was crypto-shredded cannot be resent (OP-156 m.3 (c)): CT1.
    RelayResend,
    /// Changes the account's sign-in methods; on the support protected list (§8.16 #3, OP-157
    /// m.3 (a)): reserved, CT3.
    AccountSigninMethodChange,
    /// Changes the account's second factors; on the support protected list: reserved, CT3.
    AccountMfaChange,
    /// Changes the account's phone number; on the support protected list: reserved, CT3.
    AccountPhoneChange,
    /// Makes or changes a payment for the account; on the support protected list: reserved, CT3.
    AccountPayment,
    /// Raises the account's role; on the support protected list: reserved, CT3.
    AccountRoleElevate,
    /// Invites another person in the account's name; on the support protected list: reserved, CT3.
    AccountInvite,
    /// Creates an API key for the account; on the support protected list: reserved, CT3.
    AccountApiKeyCreate,
    /// Issues a long-lived token for the account; on the support protected list: reserved, CT3.
    AccountTokenLongLived,
    /// Uploads a redacted support artifact (HAR, JSON or a text log) for a case (TN-74, OP-157 m.3
    /// (g)): CT1.
    AccountArtifactUpload,
    /// Reads a sealed support artifact under its own Grant (TN-74, OP-157 m.3 (g)): CT2.
    AccountArtifactRead,
    /// Registers a support case system as a Claim issuer of `support_case` Claims (OP-157 m.3 (e)):
    /// CT2.
    SupportCaseSystemRegister,
    /// Retires a support case system; narrowing, CT1.
    SupportCaseSystemRetire,
    /// Opens support artifact uploads with their size and retention limits (OP-157 m.3 (g)): CT2.
    SupportArtifactPolicy,
    /// Closes support artifact uploads; narrowing, CT1.
    SupportArtifactPolicyClose,
    /// Names an access review campaign's period and scope, a view and never a queue (IDP-39 (3),
    /// OP-157 m.3 (w)): CT2.
    ReviewSchedule,
    /// Ends an access review campaign; narrowing, CT1.
    ReviewScheduleClose,
    /// Marks an organization member's account as a break-glass account; the mark carries no authority
    /// (INV-28, OP-157 m.3 (h)): CT2.
    OrgMemberBreakglass,
    /// Clears the break-glass mark; narrowing, CT1.
    OrgMemberBreakglassClear,
    /// Opens delegated administration through meta-action role Grants (TN-114, OP-157 m.3 (t)): CT2.
    EnvironmentDelegatedAdmin,
    /// Closes delegated administration for new admin Grants; narrowing, CT1.
    EnvironmentDelegatedAdminClose,
    /// Opens CT1 approval inside the approver notification (OP-157 m.3 (m)): CT2.
    EnvironmentApprovalInline,
    /// Closes in-notification approval; narrowing, CT1.
    EnvironmentApprovalInlineClose,
    /// Opens CT1 batch approval of at most ten requests (OP-157 m.3 (m)): CT2.
    EnvironmentApprovalBatch,
    /// Closes batch approval; narrowing, CT1.
    EnvironmentApprovalBatchClose,
    /// Another Party's review of one break-glass use as a drill, an emergency or a misuse; it
    /// grants nothing (OP-157 m.3 (h), m.4 (b)): CT1.
    OrgBreakglassReview,
    /// Declares the environment's residency; changing it is a cell move (CMP-26, OP-158 m.3 (a), (o)): reserved, CT3.
    EnvironmentResidency,
    /// Declares the async DR profile (RPO > 0), which lowers the guarantee (OP-58, OP-158 m.3 (a), (r)): reserved, CT3.
    EnvironmentDrProfile,
    /// Returns the environment to the synchronous DR class; narrowing, CT1.
    EnvironmentDrProfileClose,
    /// Sets the environment's `rate_limit_rps` (OP-35, OP-158 m.3 (a), (v)): CT2.
    EnvironmentRateLimit,
    /// Sets the environment's crypto profile; the FIPS profile narrows the algorithm set (CR-15, CR-36, OP-158 m.3 (a), (y)): CT2.
    EnvironmentCryptoProfile,
    /// Raises the environment's hash profile; it is never lowered (OP-33, OP-158 m.3 (a)): narrowing, CT1.
    EnvironmentHashProfile,
    /// Sets the environment's cold audit tier target and hot window, at least 30 days (OP-37, OP-158 m.3 (a), (w)): CT2.
    EnvironmentAuditTier,
    /// Closes the environment's cold audit tier target; narrowing, CT1.
    EnvironmentAuditTierClose,
    /// Adds an ML-DSA algorithm (`ml-dsa-65`, `ml-dsa-44` or `ml-dsa-87`) to the environment's accept
    /// and signing set; the classical algorithms stay (CR-41, CR-8, OP-159 m.3 (a)): reserved, CT3.
    EnvironmentSigningProfile,
    /// Takes ML-DSA out of the environment's set (§15.16 m.2); narrowing, CT1.
    EnvironmentSigningProfileClose,
    /// Sets the environment's hybrid key exchange share policy, `optimistic` or `advertise-only`; both
    /// offer the post-quantum group (CR-12 m.3, OP-159 m.3 (a)): CT2.
    EnvironmentKexShare,
    /// Binds an existing standard environment's domain as consuming its tenant's management
    /// environment's Claims (TN-4, OP-159 m.48 (b)): the environment's root signs it, the binding
    /// holds after a 24-hour cool-down; CT2.
    EnvironmentConsumerBind,
}

impl IdpAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 213] = [
        Self::ClientRegister,
        Self::ClientUpdate,
        Self::ClientRetire,
        Self::CimdPolicy,
        Self::MapperSet,
        Self::EnvironmentJoseAlg,
        Self::EnvironmentArgon2,
        Self::EnvironmentRpId,
        Self::EnvironmentRehome,
        Self::UpstreamRegister,
        Self::UpstreamMapping,
        Self::EnvironmentBranding,
        Self::EnvironmentKeyPolicy,
        Self::EnvironmentKeyRotate,
        Self::EnvironmentKeyDrop,
        Self::AccountDelete,
        Self::AccountSuspend,
        Self::AccountReactivate,
        Self::ClientSecretRotate,
        Self::GroupCreate,
        Self::GroupUpdate,
        Self::GroupRetire,
        Self::GroupMembersAdd,
        Self::GroupMembersRemove,
        Self::UpstreamUpdate,
        Self::UpstreamRetire,
        Self::EnvironmentSigninPolicy,
        Self::EnvironmentSessionPolicy,
        Self::EnvironmentProtectionMode,
        Self::EnvironmentProtectionModeLoosen,
        Self::AccountCanary,
        Self::EnvironmentExtensionPolicy,
        Self::HookRegister,
        Self::HookRetire,
        Self::WebhookRegister,
        Self::WebhookUpdate,
        Self::WebhookRetire,
        Self::UpstreamLink,
        Self::AccountResetIntent,
        Self::AccountTapIssue,
        Self::AccountRecoveryPolicy,
        Self::AccountRecoveryPolicyLoosen,
        Self::AccountExport,
        Self::AccountMigrationExport,
        Self::OrgCreate,
        Self::OrgUpdate,
        Self::OrgDomainClaim,
        Self::OrgInvite,
        Self::OrgSetupLink,
        Self::OrgDomainRelease,
        Self::OrgInviteRevoke,
        Self::OrgMemberRemove,
        Self::OrgSsoDraft,
        Self::SocialEnable,
        Self::SocialUpdate,
        Self::SocialDisable,
        Self::EnvironmentRelatedOrigins,
        Self::EnvironmentLocaleOverrides,
        Self::EnvironmentConsentDocuments,
        Self::EnvironmentPreferenceTopics,
        Self::EnvironmentInactivityPolicy,
        Self::EnvironmentRetentionExtend,
        Self::EnvironmentCustomDomain,
        Self::AccountRead,
        Self::AccountProfileUpdate,
        Self::AccountEmailChange,
        Self::EnvironmentRetentionHoldPlace,
        Self::EnvironmentRetentionHoldLift,
        Self::AccountBind,
        Self::AccountImport,
        Self::AccountGuardianshipRecord,
        Self::EnvironmentCspMode,
        Self::EnvironmentCspModeLoosen,
        Self::AgentRegister,
        Self::AgentUpdate,
        Self::AgentSponsorAssign,
        Self::AgentSponsorRemove,
        Self::AgentRetire,
        Self::AgentTemplateDefine,
        Self::VaultResourceEnable,
        Self::VaultResourceDisable,
        Self::VaultResourceRegister,
        Self::VaultReleaseModeOpen,
        Self::VaultReleaseModeClose,
        Self::ClientResourceRegister,
        Self::ClientDcrPolicy,
        Self::ClientDcrPolicyTighten,
        Self::ClientCrossAppConnection,
        Self::ClientCrossAppConnectionRetire,
        Self::EnvironmentDeviceCode,
        Self::EnvironmentDeviceCodeClose,
        Self::SamlSpRegister,
        Self::SamlSpMapping,
        Self::SamlSpUpdate,
        Self::SamlSpRetire,
        Self::SamlCertPolicy,
        Self::SamlCertEmergency,
        Self::ScimClientRegister,
        Self::ScimTokenRotate,
        Self::ScimClientRetire,
        Self::ScimOutboundRegister,
        Self::ScimOutboundRetire,
        Self::GatewayRegister,
        Self::GatewayRetire,
        Self::GatewayKeytabPolicy,
        Self::GatewayKeytabEmergency,
        Self::GatewayRadiusClientRegister,
        Self::FederationEnable,
        Self::FederationDisable,
        Self::FederationTrustAnchorAdd,
        Self::FederationTrustAnchorRemove,
        Self::FederationTaEnable,
        Self::FederationRegistrationOpen,
        Self::FederationRegistrationClose,
        Self::VcVerifierEnable,
        Self::VcVerifierDisable,
        Self::VcTrustedList,
        Self::VcIssuerEnable,
        Self::VcIssuerDisable,
        Self::ClientProfile,
        Self::ClientProfileLoosen,
        Self::ClientAuthMethodLegacy,
        Self::ClientAlgRs256,
        Self::ClientEncryption,
        Self::ClientSamlBearer,
        Self::ClientLegacyBearer,
        Self::EnvironmentCiba,
        Self::EnvironmentCibaClose,
        Self::EnvironmentCertificateLogin,
        Self::EnvironmentMtlsAliases,
        Self::EnvironmentHrd,
        Self::EnvironmentHrdClose,
        Self::EnvironmentFrontchannelLogout,
        Self::OrgSsoEnforce,
        Self::OrgSsoEnforceLift,
        Self::UpstreamAssuranceMap,
        Self::DomainRegister,
        Self::DomainRetire,
        Self::DomainIssuerBind,
        Self::ProxyRegister,
        Self::ProxyUpdate,
        Self::ProxyRetire,
        Self::ProxyPlainHeaders,
        Self::ProxyPlainHeadersClose,
        Self::ProxyMcpPin,
        Self::SshCaEnable,
        Self::SshCaDisable,
        Self::SshCaRotate,
        Self::SshCaEmergency,
        Self::SshHostGroupRegister,
        Self::SshHostGroupRetire,
        Self::LinuxHostRegister,
        Self::LinuxHostRetire,
        Self::LinuxOfflinePolicy,
        Self::LinuxBreakGlassPolicy,
        Self::HrSourceRegister,
        Self::HrSourceRetire,
        Self::HrImport,
        Self::HrConnectorRegister,
        Self::HrConnectorRetire,
        Self::ExportSinkRegister,
        Self::ExportSinkUpdate,
        Self::ExportSinkRetire,
        Self::SignalSourceRegister,
        Self::SignalSourceRetire,
        Self::EnvironmentPush,
        Self::EnvironmentPushClose,
        Self::EnvironmentSmsOtp,
        Self::EnvironmentSmsOtpClose,
        Self::EnvironmentSpc,
        Self::EnvironmentCoordinator,
        Self::EnvironmentIys,
        Self::EnvironmentIysClose,
        Self::EnvironmentSecurityNotices,
        Self::EnvironmentSecurityNoticesClose,
        Self::RelayResend,
        Self::AccountSigninMethodChange,
        Self::AccountMfaChange,
        Self::AccountPhoneChange,
        Self::AccountPayment,
        Self::AccountRoleElevate,
        Self::AccountInvite,
        Self::AccountApiKeyCreate,
        Self::AccountTokenLongLived,
        Self::AccountArtifactUpload,
        Self::AccountArtifactRead,
        Self::SupportCaseSystemRegister,
        Self::SupportCaseSystemRetire,
        Self::SupportArtifactPolicy,
        Self::SupportArtifactPolicyClose,
        Self::ReviewSchedule,
        Self::ReviewScheduleClose,
        Self::OrgMemberBreakglass,
        Self::OrgMemberBreakglassClear,
        Self::EnvironmentDelegatedAdmin,
        Self::EnvironmentDelegatedAdminClose,
        Self::EnvironmentApprovalInline,
        Self::EnvironmentApprovalInlineClose,
        Self::EnvironmentApprovalBatch,
        Self::EnvironmentApprovalBatchClose,
        Self::OrgBreakglassReview,
        Self::EnvironmentResidency,
        Self::EnvironmentDrProfile,
        Self::EnvironmentDrProfileClose,
        Self::EnvironmentRateLimit,
        Self::EnvironmentCryptoProfile,
        Self::EnvironmentHashProfile,
        Self::EnvironmentAuditTier,
        Self::EnvironmentAuditTierClose,
        Self::EnvironmentSigningProfile,
        Self::EnvironmentSigningProfileClose,
        Self::EnvironmentKexShare,
        Self::EnvironmentConsumerBind,
    ];

    /// The catalog version that first declared it (OP-153 m.3 (a), OP-154 m.3 (a), OP-155
    /// m.3 (a), OP-156 m.3 (a), OP-157 m.3 (a), OP-158 m.3 (a), OP-159 m.3 (a), m.48 (b)).
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per catalog version, listing its actions"
    )]
    pub const fn since(self) -> u64 {
        match self {
            Self::EnvironmentConsumerBind => 10,
            Self::EnvironmentSigningProfile
            | Self::EnvironmentSigningProfileClose
            | Self::EnvironmentKexShare => 9,
            Self::EnvironmentResidency
            | Self::EnvironmentDrProfile
            | Self::EnvironmentDrProfileClose
            | Self::EnvironmentRateLimit
            | Self::EnvironmentCryptoProfile
            | Self::EnvironmentHashProfile
            | Self::EnvironmentAuditTier
            | Self::EnvironmentAuditTierClose => 8,
            Self::AccountSigninMethodChange
            | Self::AccountMfaChange
            | Self::AccountPhoneChange
            | Self::AccountPayment
            | Self::AccountRoleElevate
            | Self::AccountInvite
            | Self::AccountApiKeyCreate
            | Self::AccountTokenLongLived
            | Self::AccountArtifactUpload
            | Self::AccountArtifactRead
            | Self::SupportCaseSystemRegister
            | Self::SupportCaseSystemRetire
            | Self::SupportArtifactPolicy
            | Self::SupportArtifactPolicyClose
            | Self::ReviewSchedule
            | Self::ReviewScheduleClose
            | Self::OrgMemberBreakglass
            | Self::OrgMemberBreakglassClear
            | Self::EnvironmentDelegatedAdmin
            | Self::EnvironmentDelegatedAdminClose
            | Self::EnvironmentApprovalInline
            | Self::EnvironmentApprovalInlineClose
            | Self::EnvironmentApprovalBatch
            | Self::EnvironmentApprovalBatchClose
            | Self::OrgBreakglassReview => 7,
            Self::DomainRegister
            | Self::DomainRetire
            | Self::DomainIssuerBind
            | Self::ProxyRegister
            | Self::ProxyUpdate
            | Self::ProxyRetire
            | Self::ProxyPlainHeaders
            | Self::ProxyPlainHeadersClose
            | Self::ProxyMcpPin
            | Self::SshCaEnable
            | Self::SshCaDisable
            | Self::SshCaRotate
            | Self::SshCaEmergency
            | Self::SshHostGroupRegister
            | Self::SshHostGroupRetire
            | Self::LinuxHostRegister
            | Self::LinuxHostRetire
            | Self::LinuxOfflinePolicy
            | Self::LinuxBreakGlassPolicy
            | Self::HrSourceRegister
            | Self::HrSourceRetire
            | Self::HrImport
            | Self::HrConnectorRegister
            | Self::HrConnectorRetire
            | Self::ExportSinkRegister
            | Self::ExportSinkUpdate
            | Self::ExportSinkRetire
            | Self::SignalSourceRegister
            | Self::SignalSourceRetire
            | Self::EnvironmentPush
            | Self::EnvironmentPushClose
            | Self::EnvironmentSmsOtp
            | Self::EnvironmentSmsOtpClose
            | Self::EnvironmentSpc
            | Self::EnvironmentCoordinator
            | Self::EnvironmentIys
            | Self::EnvironmentIysClose
            | Self::EnvironmentSecurityNotices
            | Self::EnvironmentSecurityNoticesClose
            | Self::RelayResend => 6,
            Self::SamlSpRegister
            | Self::SamlSpMapping
            | Self::SamlSpUpdate
            | Self::SamlSpRetire
            | Self::SamlCertPolicy
            | Self::SamlCertEmergency
            | Self::ScimClientRegister
            | Self::ScimTokenRotate
            | Self::ScimClientRetire
            | Self::ScimOutboundRegister
            | Self::ScimOutboundRetire
            | Self::GatewayRegister
            | Self::GatewayRetire
            | Self::GatewayKeytabPolicy
            | Self::GatewayKeytabEmergency
            | Self::GatewayRadiusClientRegister
            | Self::FederationEnable
            | Self::FederationDisable
            | Self::FederationTrustAnchorAdd
            | Self::FederationTrustAnchorRemove
            | Self::FederationTaEnable
            | Self::FederationRegistrationOpen
            | Self::FederationRegistrationClose
            | Self::VcVerifierEnable
            | Self::VcVerifierDisable
            | Self::VcTrustedList
            | Self::VcIssuerEnable
            | Self::VcIssuerDisable
            | Self::ClientProfile
            | Self::ClientProfileLoosen
            | Self::ClientAuthMethodLegacy
            | Self::ClientAlgRs256
            | Self::ClientEncryption
            | Self::ClientSamlBearer
            | Self::ClientLegacyBearer
            | Self::EnvironmentCiba
            | Self::EnvironmentCibaClose
            | Self::EnvironmentCertificateLogin
            | Self::EnvironmentMtlsAliases
            | Self::EnvironmentHrd
            | Self::EnvironmentHrdClose
            | Self::EnvironmentFrontchannelLogout
            | Self::OrgSsoEnforce
            | Self::OrgSsoEnforceLift
            | Self::UpstreamAssuranceMap => 5,
            Self::AgentRegister
            | Self::AgentUpdate
            | Self::AgentSponsorAssign
            | Self::AgentSponsorRemove
            | Self::AgentRetire
            | Self::AgentTemplateDefine
            | Self::VaultResourceEnable
            | Self::VaultResourceDisable
            | Self::VaultResourceRegister
            | Self::VaultReleaseModeOpen
            | Self::VaultReleaseModeClose
            | Self::ClientResourceRegister
            | Self::ClientDcrPolicy
            | Self::ClientDcrPolicyTighten
            | Self::ClientCrossAppConnection
            | Self::ClientCrossAppConnectionRetire
            | Self::EnvironmentDeviceCode
            | Self::EnvironmentDeviceCodeClose => 4,
            Self::AccountBind
            | Self::AccountImport
            | Self::AccountGuardianshipRecord
            | Self::EnvironmentCspMode
            | Self::EnvironmentCspModeLoosen => 3,
            Self::AccountResetIntent
            | Self::AccountTapIssue
            | Self::AccountRecoveryPolicy
            | Self::AccountRecoveryPolicyLoosen
            | Self::AccountExport
            | Self::AccountMigrationExport
            | Self::OrgCreate
            | Self::OrgUpdate
            | Self::OrgDomainClaim
            | Self::OrgInvite
            | Self::OrgSetupLink
            | Self::OrgDomainRelease
            | Self::OrgInviteRevoke
            | Self::OrgMemberRemove
            | Self::OrgSsoDraft
            | Self::SocialEnable
            | Self::SocialUpdate
            | Self::SocialDisable
            | Self::EnvironmentRelatedOrigins
            | Self::EnvironmentLocaleOverrides
            | Self::EnvironmentConsentDocuments
            | Self::EnvironmentPreferenceTopics
            | Self::EnvironmentInactivityPolicy
            | Self::EnvironmentRetentionExtend
            | Self::EnvironmentCustomDomain
            | Self::AccountRead
            | Self::AccountProfileUpdate
            | Self::AccountEmailChange
            | Self::EnvironmentRetentionHoldPlace
            | Self::EnvironmentRetentionHoldLift => 2,
            _ => 1,
        }
    }

    /// Its namespace.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per namespace, listing its actions"
    )]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::ClientRegister
            | Self::ClientUpdate
            | Self::ClientRetire
            | Self::CimdPolicy
            | Self::ClientSecretRotate
            | Self::ClientResourceRegister
            | Self::ClientDcrPolicy
            | Self::ClientDcrPolicyTighten
            | Self::ClientCrossAppConnection
            | Self::ClientCrossAppConnectionRetire
            | Self::ClientProfile
            | Self::ClientProfileLoosen
            | Self::ClientAuthMethodLegacy
            | Self::ClientAlgRs256
            | Self::ClientEncryption
            | Self::ClientSamlBearer
            | Self::ClientLegacyBearer => "idp.client",
            Self::AgentRegister
            | Self::AgentUpdate
            | Self::AgentSponsorAssign
            | Self::AgentSponsorRemove
            | Self::AgentRetire
            | Self::AgentTemplateDefine => "idp.agent",
            Self::VaultResourceEnable
            | Self::VaultResourceDisable
            | Self::VaultResourceRegister
            | Self::VaultReleaseModeOpen
            | Self::VaultReleaseModeClose => "idp.vault",
            Self::GroupCreate
            | Self::GroupUpdate
            | Self::GroupRetire
            | Self::GroupMembersAdd
            | Self::GroupMembersRemove => "idp.group",
            Self::MapperSet => "idp.mapper",
            Self::EnvironmentJoseAlg
            | Self::EnvironmentArgon2
            | Self::EnvironmentRpId
            | Self::EnvironmentRehome
            | Self::EnvironmentResidency
            | Self::EnvironmentDrProfile
            | Self::EnvironmentDrProfileClose
            | Self::EnvironmentRateLimit
            | Self::EnvironmentCryptoProfile
            | Self::EnvironmentHashProfile
            | Self::EnvironmentAuditTier
            | Self::EnvironmentAuditTierClose
            | Self::EnvironmentSigningProfile
            | Self::EnvironmentSigningProfileClose
            | Self::EnvironmentKexShare
            | Self::EnvironmentConsumerBind
            | Self::EnvironmentBranding
            | Self::EnvironmentKeyPolicy
            | Self::EnvironmentKeyRotate
            | Self::EnvironmentKeyDrop
            | Self::EnvironmentSigninPolicy
            | Self::EnvironmentSessionPolicy
            | Self::EnvironmentProtectionMode
            | Self::EnvironmentProtectionModeLoosen
            | Self::EnvironmentExtensionPolicy
            | Self::EnvironmentRelatedOrigins
            | Self::EnvironmentLocaleOverrides
            | Self::EnvironmentConsentDocuments
            | Self::EnvironmentPreferenceTopics
            | Self::EnvironmentInactivityPolicy
            | Self::EnvironmentRetentionExtend
            | Self::EnvironmentCustomDomain
            | Self::EnvironmentRetentionHoldPlace
            | Self::EnvironmentRetentionHoldLift
            | Self::EnvironmentCspMode
            | Self::EnvironmentCspModeLoosen
            | Self::EnvironmentDeviceCode
            | Self::EnvironmentDeviceCodeClose
            | Self::EnvironmentCiba
            | Self::EnvironmentCibaClose
            | Self::EnvironmentCertificateLogin
            | Self::EnvironmentMtlsAliases
            | Self::EnvironmentHrd
            | Self::EnvironmentHrdClose
            | Self::EnvironmentFrontchannelLogout
            | Self::EnvironmentPush
            | Self::EnvironmentPushClose
            | Self::EnvironmentSmsOtp
            | Self::EnvironmentSmsOtpClose
            | Self::EnvironmentSpc
            | Self::EnvironmentCoordinator
            | Self::EnvironmentIys
            | Self::EnvironmentIysClose
            | Self::EnvironmentSecurityNotices
            | Self::EnvironmentSecurityNoticesClose
            | Self::EnvironmentDelegatedAdmin
            | Self::EnvironmentDelegatedAdminClose
            | Self::EnvironmentApprovalInline
            | Self::EnvironmentApprovalInlineClose
            | Self::EnvironmentApprovalBatch
            | Self::EnvironmentApprovalBatchClose => "idp.environment",
            Self::OrgCreate
            | Self::OrgUpdate
            | Self::OrgDomainClaim
            | Self::OrgInvite
            | Self::OrgSetupLink
            | Self::OrgDomainRelease
            | Self::OrgInviteRevoke
            | Self::OrgMemberRemove
            | Self::OrgSsoDraft
            | Self::OrgSsoEnforce
            | Self::OrgSsoEnforceLift
            | Self::OrgMemberBreakglass
            | Self::OrgMemberBreakglassClear
            | Self::OrgBreakglassReview => "idp.org",
            Self::SamlSpRegister
            | Self::SamlSpMapping
            | Self::SamlSpUpdate
            | Self::SamlSpRetire
            | Self::SamlCertPolicy
            | Self::SamlCertEmergency => "idp.saml",
            Self::ScimClientRegister
            | Self::ScimTokenRotate
            | Self::ScimClientRetire
            | Self::ScimOutboundRegister
            | Self::ScimOutboundRetire => "idp.scim",
            Self::GatewayRegister
            | Self::GatewayRetire
            | Self::GatewayKeytabPolicy
            | Self::GatewayKeytabEmergency
            | Self::GatewayRadiusClientRegister => "idp.gateway",
            Self::FederationEnable
            | Self::FederationDisable
            | Self::FederationTrustAnchorAdd
            | Self::FederationTrustAnchorRemove
            | Self::FederationTaEnable
            | Self::FederationRegistrationOpen
            | Self::FederationRegistrationClose => "idp.federation",
            Self::VcVerifierEnable
            | Self::VcVerifierDisable
            | Self::VcTrustedList
            | Self::VcIssuerEnable
            | Self::VcIssuerDisable => "idp.vc",
            Self::DomainRegister | Self::DomainRetire | Self::DomainIssuerBind => "idp.domain",
            Self::ProxyRegister
            | Self::ProxyUpdate
            | Self::ProxyRetire
            | Self::ProxyPlainHeaders
            | Self::ProxyPlainHeadersClose
            | Self::ProxyMcpPin => "idp.proxy",
            Self::SshCaEnable
            | Self::SshCaDisable
            | Self::SshCaRotate
            | Self::SshCaEmergency
            | Self::SshHostGroupRegister
            | Self::SshHostGroupRetire => "idp.ssh",
            Self::LinuxHostRegister
            | Self::LinuxHostRetire
            | Self::LinuxOfflinePolicy
            | Self::LinuxBreakGlassPolicy => "idp.linux",
            Self::HrSourceRegister
            | Self::HrSourceRetire
            | Self::HrImport
            | Self::HrConnectorRegister
            | Self::HrConnectorRetire => "idp.hr",
            Self::ExportSinkRegister | Self::ExportSinkUpdate | Self::ExportSinkRetire => {
                "idp.export"
            }
            Self::SignalSourceRegister | Self::SignalSourceRetire => "idp.signal",
            Self::RelayResend => "idp.relay",
            Self::SocialEnable | Self::SocialUpdate | Self::SocialDisable => "idp.social",
            Self::HookRegister | Self::HookRetire => "idp.hook",
            Self::WebhookRegister | Self::WebhookUpdate | Self::WebhookRetire => "idp.webhook",
            Self::UpstreamRegister
            | Self::UpstreamMapping
            | Self::UpstreamUpdate
            | Self::UpstreamRetire
            | Self::UpstreamLink
            | Self::UpstreamAssuranceMap => "idp.upstream",
            Self::AccountDelete
            | Self::AccountSuspend
            | Self::AccountReactivate
            | Self::AccountCanary
            | Self::AccountResetIntent
            | Self::AccountTapIssue
            | Self::AccountRecoveryPolicy
            | Self::AccountRecoveryPolicyLoosen
            | Self::AccountExport
            | Self::AccountMigrationExport
            | Self::AccountRead
            | Self::AccountProfileUpdate
            | Self::AccountEmailChange
            | Self::AccountBind
            | Self::AccountImport
            | Self::AccountGuardianshipRecord
            | Self::AccountSigninMethodChange
            | Self::AccountMfaChange
            | Self::AccountPhoneChange
            | Self::AccountPayment
            | Self::AccountRoleElevate
            | Self::AccountInvite
            | Self::AccountApiKeyCreate
            | Self::AccountTokenLongLived
            | Self::AccountArtifactUpload
            | Self::AccountArtifactRead => "idp.account",
            Self::SupportCaseSystemRegister
            | Self::SupportCaseSystemRetire
            | Self::SupportArtifactPolicy
            | Self::SupportArtifactPolicyClose => "idp.support",
            Self::ReviewSchedule | Self::ReviewScheduleClose => "idp.review",
        }
    }

    /// Its name within the namespace.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one arm per action name")]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClientRegister
            | Self::UpstreamRegister
            | Self::HookRegister
            | Self::WebhookRegister
            | Self::AgentRegister
            | Self::GatewayRegister
            | Self::DomainRegister
            | Self::ProxyRegister => "register",
            Self::ClientUpdate
            | Self::GroupUpdate
            | Self::UpstreamUpdate
            | Self::WebhookUpdate
            | Self::OrgUpdate
            | Self::SocialUpdate
            | Self::AgentUpdate
            | Self::ProxyUpdate => "update",
            Self::ClientRetire
            | Self::GroupRetire
            | Self::UpstreamRetire
            | Self::HookRetire
            | Self::WebhookRetire
            | Self::AgentRetire
            | Self::GatewayRetire
            | Self::DomainRetire
            | Self::ProxyRetire => "retire",
            Self::AgentSponsorAssign => "sponsor_assign",
            Self::AgentSponsorRemove => "sponsor_remove",
            Self::AgentTemplateDefine => "template_define",
            Self::VaultResourceEnable => "resource_enable",
            Self::VaultResourceDisable => "resource_disable",
            Self::VaultResourceRegister | Self::ClientResourceRegister => "resource_register",
            Self::VaultReleaseModeOpen => "release_mode_open",
            Self::VaultReleaseModeClose => "release_mode_close",
            Self::ClientDcrPolicy => "dcr_policy",
            Self::ClientDcrPolicyTighten => "dcr_policy_tighten",
            Self::ClientCrossAppConnection => "cross_app_connection",
            Self::ClientCrossAppConnectionRetire => "cross_app_connection_retire",
            Self::EnvironmentDeviceCode => "device_code",
            Self::EnvironmentDeviceCodeClose => "device_code_close",
            Self::EnvironmentExtensionPolicy => "extension_policy",
            Self::ClientSecretRotate => "secret_rotate",
            Self::GroupCreate | Self::OrgCreate => "create",
            Self::GroupMembersAdd => "members_add",
            Self::GroupMembersRemove => "members_remove",
            Self::AccountSuspend => "suspend",
            Self::AccountReactivate => "reactivate",
            Self::EnvironmentSigninPolicy => "signin_policy",
            Self::EnvironmentSessionPolicy => "session_policy",
            Self::CimdPolicy => "cimd_policy",
            Self::MapperSet => "set",
            Self::EnvironmentJoseAlg => "jose_alg",
            Self::EnvironmentArgon2 => "argon2",
            Self::EnvironmentRpId => "rp_id",
            Self::EnvironmentRehome => "rehome",
            Self::UpstreamMapping => "mapping",
            Self::EnvironmentBranding => "branding",
            Self::EnvironmentKeyPolicy => "key_policy",
            Self::EnvironmentKeyRotate => "key_rotate",
            Self::EnvironmentKeyDrop => "key_drop",
            Self::AccountDelete => "delete",
            Self::EnvironmentProtectionMode => "protection_mode",
            Self::EnvironmentProtectionModeLoosen => "protection_mode_loosen",
            Self::AccountCanary => "canary",
            Self::UpstreamLink => "link",
            Self::AccountResetIntent => "reset_intent",
            Self::AccountTapIssue => "tap_issue",
            Self::AccountRecoveryPolicy => "recovery_policy",
            Self::AccountRecoveryPolicyLoosen => "recovery_policy_loosen",
            Self::AccountExport => "export",
            Self::AccountMigrationExport => "migration_export",
            Self::OrgDomainClaim => "domain_claim",
            Self::OrgInvite | Self::AccountInvite => "invite",
            Self::OrgSetupLink => "setup_link",
            Self::OrgDomainRelease => "domain_release",
            Self::OrgInviteRevoke => "invite_revoke",
            Self::OrgMemberRemove => "member_remove",
            Self::OrgSsoDraft => "sso_draft",
            Self::SocialEnable | Self::FederationEnable => "enable",
            Self::SocialDisable | Self::FederationDisable => "disable",
            Self::EnvironmentRelatedOrigins => "related_origins",
            Self::EnvironmentLocaleOverrides => "locale_overrides",
            Self::EnvironmentConsentDocuments => "consent_documents",
            Self::EnvironmentPreferenceTopics => "preference_topics",
            Self::EnvironmentInactivityPolicy => "inactivity_policy",
            Self::EnvironmentRetentionExtend => "retention_extend",
            Self::EnvironmentCustomDomain => "custom_domain",
            Self::AccountRead => "read",
            Self::AccountProfileUpdate => "profile_update",
            Self::AccountEmailChange => "email_change",
            Self::EnvironmentRetentionHoldPlace => "retention_hold_place",
            Self::EnvironmentRetentionHoldLift => "retention_hold_lift",
            Self::AccountBind => "bind",
            Self::AccountImport | Self::HrImport => "import",
            Self::AccountGuardianshipRecord => "guardianship_record",
            Self::EnvironmentCspMode => "csp_mode",
            Self::EnvironmentCspModeLoosen => "csp_mode_loosen",
            Self::SamlSpRegister => "sp_register",
            Self::SamlSpMapping => "sp_mapping",
            Self::SamlSpUpdate => "sp_update",
            Self::SamlSpRetire => "sp_retire",
            Self::SamlCertPolicy => "cert_policy",
            Self::SamlCertEmergency => "cert_emergency",
            Self::ScimClientRegister => "client_register",
            Self::ScimTokenRotate => "token_rotate",
            Self::ScimClientRetire => "client_retire",
            Self::ScimOutboundRegister => "outbound_register",
            Self::ScimOutboundRetire => "outbound_retire",
            Self::GatewayKeytabPolicy => "keytab_policy",
            Self::GatewayKeytabEmergency => "keytab_emergency",
            Self::GatewayRadiusClientRegister => "radius_client_register",
            Self::FederationTrustAnchorAdd => "trust_anchor_add",
            Self::FederationTrustAnchorRemove => "trust_anchor_remove",
            Self::FederationTaEnable => "ta_enable",
            Self::FederationRegistrationOpen => "registration_open",
            Self::FederationRegistrationClose => "registration_close",
            Self::VcVerifierEnable => "verifier_enable",
            Self::VcVerifierDisable => "verifier_disable",
            Self::VcTrustedList => "trusted_list",
            Self::VcIssuerEnable => "issuer_enable",
            Self::VcIssuerDisable => "issuer_disable",
            Self::ClientProfile => "profile",
            Self::ClientProfileLoosen => "profile_loosen",
            Self::ClientAuthMethodLegacy => "auth_method_legacy",
            Self::ClientAlgRs256 => "alg_rs256",
            Self::ClientEncryption => "encryption",
            Self::ClientSamlBearer => "saml_bearer",
            Self::ClientLegacyBearer => "legacy_bearer",
            Self::EnvironmentCiba => "ciba",
            Self::EnvironmentCibaClose => "ciba_close",
            Self::EnvironmentCertificateLogin => "certificate_login",
            Self::EnvironmentMtlsAliases => "mtls_aliases",
            Self::EnvironmentHrd => "hrd",
            Self::EnvironmentHrdClose => "hrd_close",
            Self::EnvironmentFrontchannelLogout => "frontchannel_logout",
            Self::OrgSsoEnforce => "sso_enforce",
            Self::OrgSsoEnforceLift => "sso_enforce_lift",
            Self::UpstreamAssuranceMap => "assurance_map",
            Self::DomainIssuerBind => "issuer_bind",
            Self::ProxyPlainHeaders => "plain_headers",
            Self::ProxyPlainHeadersClose => "plain_headers_close",
            Self::ProxyMcpPin => "mcp_pin",
            Self::SshCaEnable => "ca_enable",
            Self::SshCaDisable => "ca_disable",
            Self::SshCaRotate => "ca_rotate",
            Self::SshCaEmergency => "ca_emergency",
            Self::SshHostGroupRegister => "host_group_register",
            Self::SshHostGroupRetire => "host_group_retire",
            Self::LinuxHostRegister => "host_register",
            Self::LinuxHostRetire => "host_retire",
            Self::LinuxOfflinePolicy => "offline_policy",
            Self::LinuxBreakGlassPolicy => "break_glass_policy",
            Self::HrSourceRegister | Self::SignalSourceRegister => "source_register",
            Self::HrSourceRetire | Self::SignalSourceRetire => "source_retire",
            Self::HrConnectorRegister => "connector_register",
            Self::HrConnectorRetire => "connector_retire",
            Self::ExportSinkRegister => "sink_register",
            Self::ExportSinkUpdate => "sink_update",
            Self::ExportSinkRetire => "sink_retire",
            Self::EnvironmentPush => "push",
            Self::EnvironmentPushClose => "push_close",
            Self::EnvironmentSmsOtp => "sms_otp",
            Self::EnvironmentSmsOtpClose => "sms_otp_close",
            Self::EnvironmentSpc => "spc",
            Self::EnvironmentCoordinator => "coordinator",
            Self::EnvironmentIys => "iys",
            Self::EnvironmentIysClose => "iys_close",
            Self::EnvironmentSecurityNotices => "security_notices",
            Self::EnvironmentSecurityNoticesClose => "security_notices_close",
            Self::RelayResend => "resend",
            Self::AccountSigninMethodChange => "signin_method_change",
            Self::AccountMfaChange => "mfa_change",
            Self::AccountPhoneChange => "phone_change",
            Self::AccountPayment => "payment",
            Self::AccountRoleElevate => "role_elevate",
            Self::AccountApiKeyCreate => "api_key_create",
            Self::AccountTokenLongLived => "token_long_lived",
            Self::AccountArtifactUpload => "artifact_upload",
            Self::AccountArtifactRead => "artifact_read",
            Self::SupportCaseSystemRegister => "case_system_register",
            Self::SupportCaseSystemRetire => "case_system_retire",
            Self::SupportArtifactPolicy => "artifact_policy",
            Self::SupportArtifactPolicyClose => "artifact_policy_close",
            Self::ReviewSchedule => "schedule",
            Self::ReviewScheduleClose => "schedule_close",
            Self::OrgMemberBreakglass => "member_breakglass",
            Self::OrgMemberBreakglassClear => "member_breakglass_clear",
            Self::EnvironmentDelegatedAdmin => "delegated_admin",
            Self::EnvironmentDelegatedAdminClose => "delegated_admin_close",
            Self::EnvironmentApprovalInline => "approval_inline",
            Self::EnvironmentApprovalInlineClose => "approval_inline_close",
            Self::EnvironmentApprovalBatch => "approval_batch",
            Self::EnvironmentApprovalBatchClose => "approval_batch_close",
            Self::OrgBreakglassReview => "breakglass_review",
            Self::EnvironmentResidency => "residency",
            Self::EnvironmentDrProfile => "dr_profile",
            Self::EnvironmentDrProfileClose => "dr_profile_close",
            Self::EnvironmentRateLimit => "rate_limit",
            Self::EnvironmentCryptoProfile => "crypto_profile",
            Self::EnvironmentHashProfile => "hash_profile",
            Self::EnvironmentAuditTier => "audit_tier",
            Self::EnvironmentAuditTierClose => "audit_tier_close",
            Self::EnvironmentSigningProfile => "signing_profile",
            Self::EnvironmentSigningProfileClose => "signing_profile_close",
            Self::EnvironmentKexShare => "kex_share",
            Self::EnvironmentConsumerBind => "consumer_bind",
        }
    }

    /// `namespace.name`, the label the identity plane records with its configuration.
    #[must_use]
    pub fn label(self) -> String {
        format!("{}.{}", self.namespace(), self.name())
    }

    /// The action with this label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.label() == label)
    }

    /// What it does to the world (§9.13.3).
    #[must_use]
    pub const fn effect(self) -> EffectClass {
        match self {
            Self::ClientRetire
            | Self::EnvironmentArgon2
            | Self::EnvironmentKeyDrop
            | Self::GroupRetire
            | Self::GroupMembersRemove
            | Self::AccountSuspend
            | Self::UpstreamRetire
            | Self::EnvironmentProtectionMode
            | Self::HookRetire
            | Self::WebhookRetire
            | Self::AccountRecoveryPolicy
            | Self::AccountExport
            | Self::OrgDomainRelease
            | Self::OrgInviteRevoke
            | Self::OrgMemberRemove
            | Self::OrgSsoDraft
            | Self::SocialDisable
            | Self::AccountRead
            | Self::AccountProfileUpdate
            | Self::EnvironmentRetentionHoldPlace
            | Self::EnvironmentCspMode
            | Self::AgentUpdate
            | Self::AgentSponsorRemove
            | Self::AgentRetire
            | Self::VaultResourceDisable
            | Self::VaultReleaseModeClose
            | Self::ClientDcrPolicyTighten
            | Self::ClientCrossAppConnectionRetire
            | Self::EnvironmentDeviceCodeClose
            | Self::SamlSpRetire
            | Self::ScimClientRetire
            | Self::ScimOutboundRetire
            | Self::GatewayRetire
            | Self::FederationDisable
            | Self::FederationTrustAnchorRemove
            | Self::FederationRegistrationClose
            | Self::VcVerifierDisable
            | Self::VcIssuerDisable
            | Self::ClientProfile
            | Self::ClientEncryption
            | Self::EnvironmentCibaClose
            | Self::EnvironmentHrdClose
            | Self::OrgSsoEnforce
            | Self::DomainRetire
            | Self::ProxyRetire
            | Self::ProxyPlainHeadersClose
            | Self::SshCaDisable
            | Self::SshHostGroupRetire
            | Self::LinuxHostRetire
            | Self::HrSourceRetire
            | Self::HrConnectorRetire
            | Self::ExportSinkRetire
            | Self::SignalSourceRetire
            | Self::EnvironmentPushClose
            | Self::EnvironmentSmsOtpClose
            | Self::EnvironmentIysClose
            | Self::EnvironmentSecurityNoticesClose
            | Self::RelayResend
            | Self::AccountArtifactUpload
            | Self::SupportCaseSystemRetire
            | Self::SupportArtifactPolicyClose
            | Self::ReviewScheduleClose
            | Self::OrgMemberBreakglassClear
            | Self::EnvironmentDelegatedAdminClose
            | Self::EnvironmentApprovalInlineClose
            | Self::EnvironmentApprovalBatchClose
            | Self::OrgBreakglassReview
            | Self::EnvironmentDrProfileClose
            | Self::EnvironmentHashProfile
            | Self::EnvironmentAuditTierClose
            | Self::EnvironmentSigningProfileClose => EffectClass::Reversible,
            _ => EffectClass::Irreversible,
        }
    }

    /// Reserved: only an express Grant covers it, and it is CT3 (§13.7.1).
    #[must_use]
    pub const fn reserved(self) -> bool {
        matches!(
            self,
            Self::EnvironmentRpId
                | Self::EnvironmentRehome
                | Self::UpstreamRegister
                | Self::UpstreamMapping
                | Self::UpstreamUpdate
                | Self::MapperSet
                | Self::EnvironmentKeyPolicy
                | Self::EnvironmentKeyRotate
                | Self::AccountDelete
                | Self::AccountRecoveryPolicyLoosen
                | Self::AccountMigrationExport
                | Self::EnvironmentCustomDomain
                | Self::VaultResourceRegister
                | Self::SamlSpMapping
                | Self::SamlCertEmergency
                | Self::GatewayKeytabEmergency
                | Self::FederationTrustAnchorAdd
                | Self::VcTrustedList
                | Self::UpstreamAssuranceMap
                | Self::DomainIssuerBind
                | Self::SshCaEmergency
                | Self::LinuxBreakGlassPolicy
                | Self::AccountSigninMethodChange
                | Self::AccountMfaChange
                | Self::AccountPhoneChange
                | Self::AccountPayment
                | Self::AccountRoleElevate
                | Self::AccountInvite
                | Self::AccountApiKeyCreate
                | Self::AccountTokenLongLived
                | Self::EnvironmentResidency
                | Self::EnvironmentDrProfile
                | Self::EnvironmentSigningProfile
        )
    }

    /// Its typed parameters (OP-156 m.3 (c)).
    #[must_use]
    pub fn params(self) -> BTreeMap<String, String> {
        match self {
            Self::RelayResend => BTreeMap::from([(String::from("event_id"), String::from("text"))]),
            // OP-157 m.3 (c), (g)
            Self::AccountArtifactUpload | Self::AccountArtifactRead => {
                BTreeMap::from([(String::from("case"), String::from("text"))])
            }
            _ => BTreeMap::new(),
        }
    }

    /// Its Action Schema.
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        ActionSchema {
            reversibility: None,
            name: String::from(self.name()),
            major: 1,
            effect: self.effect(),
            reserved: self.reserved(),
            consumption_bearing: false,
            params: self.params(),
            resource_types: BTreeSet::new(),
            render: None,
        }
    }

    /// The reference an intent names it by.
    #[must_use]
    pub fn action_ref(self) -> ActionRef {
        ActionRef {
            namespace: String::from(self.namespace()),
            name: String::from(self.name()),
            major: 1,
            schema: action_digest(&self.schema()),
        }
    }
}

/// The SPP of one `idp.*` namespace in the current catalog, published by `publisher` (OP-141
/// m.35 (a)).
#[must_use]
pub fn spp(namespace: &str, publisher: Id) -> Spp {
    spp_at(namespace, publisher, CATALOG_VERSION)
}

/// The SPP of one `idp.*` namespace as catalog `version` declared it: what an environment opened with
/// that catalog accepts (OP-153 m.3 (a)).
#[must_use]
pub fn spp_at(namespace: &str, publisher: Id, version: u64) -> Spp {
    Spp {
        publisher,
        namespace: String::from(namespace),
        catalog_version: version,
        actions: IdpAction::ALL
            .into_iter()
            .filter(|a| a.namespace() == namespace && a.since() <= version)
            .map(IdpAction::schema)
            .collect(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// An `idp.*` Exercise the identity plane sends as PEP (MD-14): the intent it built from the
/// change and the actor's statement over it.
#[derive(Clone, Debug)]
pub struct Submission {
    /// The environment's governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent; its `opaque["change"]` is the change digest (EI-25), or for a meta-action
    /// its `opaque["payload"]` the payload digest.
    pub intent: IntentEnvelope,
    /// The meta payload of a core meta-action write, such as one Grant revoke or amend of a
    /// bulk job (E17, TN-125); `None` for an `idp.*` change.
    pub payload: Option<Box<access_kernel::meta::Payload>>,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// The actor's AIS over the intent.
    pub ais: Vec<u8>,
    /// The `ExerciseID`s of allowed contributions the Exercise presents as proofs (L1-ADP-12),
    /// such as a recipient's `accept_root` to an ownership handover (TN-91).
    pub contributions: Vec<Digest>,
    /// The identity plane as PEP.
    pub pep: String,
    /// The Party the identity plane bound the requesting session's subject to (§13.4 G54,
    /// OP-149 m.16 (a)): the Exercise is refused with [`ACTOR_BINDING`] unless a live Instance
    /// of that Party signed its AIS. `None` only for the operator's own root key, which has no
    /// session.
    pub actor: Option<Id>,
}

/// Stable code of an `idp.*` Exercise whose AIS no live Instance of the session's Party signed.
pub const ACTOR_BINDING: &str = "actor-binding";

/// A committed ALLOW of an `idp.*` action: what the identity plane binds its row to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The governing domain.
    pub domain: Digest,
    /// The nonce.
    pub nonce: Vec<u8>,
    /// Position of the decision record.
    pub position: u64,
    /// The intent digest the decision is about.
    pub intent: Digest,
    /// The `ExerciseID`.
    pub exercise: Digest,
    /// Whether the decision was already recorded before this request.
    pub replayed: bool,
}

/// The authority plane's answer to a [`Submission`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed and committed.
    Committed(Committed),
    /// Denied or waiting on an action; nothing may be written.
    NotAllowed {
        /// The decision.
        decision: Decision,
        /// Position of its record, when recorded.
        position: Option<u64>,
    },
    /// No decision: the request is malformed, rejected or cannot be decided now.
    Refused {
        /// Stable reason code.
        code: String,
        /// Stable codes of what the refusal expected and did not find (RFC 9457 `errors[].code`,
        /// OP-149 m.24 (b), m.30 (b)); empty unless the plane can tell.
        errors: Vec<&'static str>,
    },
}

/// The environment issuer's Acceptance of `org_member` for subject selection (C13, E18, OP-153
/// m.17 (c), m.25 (i) (3)): an organization's rule-shaped Grants, such as its autojoin role,
/// select the Parties whose live `org_member` Claim names it. The identity plane names it
/// explicitly in each environment's Genesis order; a domain opened before it establishes it once its
/// root signs it.
#[must_use]
pub fn org_member_selection(issuer: access_kernel::model::Id) -> suiss_crypto::dcbor::Value {
    use access_kernel::codec::Canonical as _;
    use suiss_crypto::dcbor::Value;
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::SUBJECT_SELECTION),
        ),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(
                &access_kernel::claim::body::Class::OrgMember.name(),
            )]),
        ),
        (
            Value::text("subject"),
            access_kernel::model::SubjectSelector::Public.to_value(),
        ),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// What a new environment's governing domain is opened with (TN-111, §12.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisOrder {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The environment's immutable slug: the domain's `idp` Anchor covers `idp:[slug, …]` only, so
    /// no other domain governs the environment (MD-5a, TN-1).
    pub slug: String,
    /// The founding root of the domain and of its `idp` Anchor.
    pub root: Root,
    /// The CT3 time-lock in seconds; `None` keeps the default (OP-141 m.34 (d)).
    pub ct3_delay_s: Option<u64>,
    /// Whether the domain declares causal-bound allowances: an upstream `ExerciseID` then backs
    /// at most one downstream Exercise (§7.9.7.4, E17, OP-152 m.7 (d) E11).
    pub causal_binding: bool,
    /// Further catalogs the founder publishes in the Genesis besides the `idp.*` ones (OP-141
    /// m.35 (c)); each one's publisher is the founder.
    pub schemas: Vec<Spp>,
    /// The environment's identity Claim issuer Party, when it has one: the domain is born accepting
    /// it for `actor-binding` only (§10.1.4 rule 3, OP-142).
    pub issuer: Option<access_kernel::model::Id>,
    /// Further Acceptances the founder establishes at Genesis, each an `acceptance-content`
    /// (L0-META-5, L2-CLM-3); a local deployment's declarant is accepted this way (OP-149
    /// m.26 (c)).
    pub acceptances: Vec<suiss_crypto::dcbor::Value>,
    /// Classes of the environment issuer's Claims the domain is born accepting as predicate input
    /// too (§10.1.4 rule 3, L2-CLM-3): what a hosted approval's `authentication` Claim proves
    /// with (SI-5, OP-149 m.29 (b)). Empty keeps `actor-binding` alone.
    pub issuer_predicate_input: Vec<String>,
    /// The meta-anchor's rootTerms recovery entry, when the template could build one (§13.6,
    /// SEC20, OP-158 m.3 (m)).
    pub recovery: Option<access_kernel::recovery::RecoveryEntry>,
    /// The tenant administrator rule the domain is born with (OP-159 m.47 (d), (h), (k) (4)).
    pub admin_rule: Option<AdminRule>,
}

/// The tenant administrator rule of a new governing domain (OP-159 m.47 (d), (k) (4)): a set of
/// rule-shaped Grants whose holder is `Pred{tenant_administration = true}` from the management
/// environment's issuer, covering the console's meta-actions and reads and `actions` on the
/// environment's own `idp` resources; never `idp.platform.*` unless the domain is the platform
/// environment's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminRule {
    /// The primary environment's Claim issuer Party.
    pub issuer: Id,
    /// Whether the issuer is another environment's: the domain is then born accepting it for
    /// `actor-binding` and, as predicate input, `authentication` too (TN-4 consuming binding).
    pub foreign: bool,
    /// The `idp` actions the rule covers on the environment's `idp` resources.
    pub actions: Vec<ActionRef>,
}

/// The class a tenant administrator rule selects by (OP-159 m.47 (d)).
pub const TENANT_ADMINISTRATION: &str = "tenant_administration";

/// The classes a consuming domain accepts from the primary environment's issuer for
/// `actor-binding` (OP-159 m.47 (d)): who the administrator's Party is and that its account
/// stands.
pub const PRIMARY_BINDING_CLASSES: [&str; 3] = [
    "account_status",
    "authentication",
    "identity_binding_person",
];

/// The domain a Genesis opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisOpened {
    /// The `DomainID`.
    pub domain: Digest,
    /// The Acceptance through which the domain selects the tenant's administrators, when its
    /// Genesis carried an administrator rule (OP-159 m.47 (d)): what the consuming binding names.
    pub admin_acceptance: Option<Id>,
}

/// The other plane could not be reached or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unavailable(pub String);
