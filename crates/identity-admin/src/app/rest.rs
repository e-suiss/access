//! The realm-admin REST resources over the `idp.*` write path (OP-151 m.2 M1, TN-110, TN-112):
//! each write operation compiles its JSON body into exactly one [`Change`], and each resource
//! reads back as a JSON view with no credential field (TN-61). The view's `ETag` is the
//! position of the decision that last changed it.

use std::collections::BTreeSet;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_account::domain::recovery_policy;

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Window;
use access_store::federation::SocialRow;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::realm::{self as resources, AccountRow, GroupRow, UpstreamRow};
use access_store::idp::{self, ClientRow};
use serde_json::{Map, Value as Json, json};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::Admin;
use crate::AdminError;
use crate::domain::realm::{AssuranceProfile, Binding, EnumerationMode};
use crate::domain::{
    Attribute, AuthMethod, Branding, Change, CimdPolicy, ClaimName, Client, ClientId, Color,
    Disclosure, ExtensionPolicy, Group, HOOK_PREFIX, HookChange, HookPoint, HookSpec, Invalid,
    JoseAlg, Members, MembershipIssuer, Name, OnNoAnswer, OrgCreate, OrgInvite, OrgMember,
    OrgUpdate, ProtectionMode, RedirectUri, RpId, SessionPolicy, SigninMethod, SigninPolicy,
    Signing, Social, SocialClient, Subject, Upstream, UpstreamLink, WEBHOOK_PREFIX, WebhookChange,
    WebhookSpec,
};
use crate::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_events::domain::webhook::event_names;
use access_store::extensions::{HookListing, WebhookListing};

/// The longest validity a write's intent may ask for.
pub const MAX_VALIDITY_MS: u64 = 15 * 60_000;

/// The validity a prepared write gets when its body names none.
pub const DEFAULT_VALIDITY_MS: u64 = 10 * 60_000;

/// The body member that carries a write's intent validity.
pub const VALIDITY: &str = "validity";

/// A management write operation (the manifest's operation ids).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `createClient`.
    CreateClient,
    /// `putClient`.
    PutClient,
    /// `retireClient`.
    RetireClient,
    /// `rotateClientSecret`.
    RotateClientSecret,
    /// `putGroup`: create or update.
    PutGroup,
    /// `retireGroup`.
    RetireGroup,
    /// `addGroupMembers`.
    AddGroupMembers,
    /// `removeGroupMembers`.
    RemoveGroupMembers,
    /// `suspendAccount`.
    SuspendAccount,
    /// `reactivateAccount`.
    ReactivateAccount,
    /// `putUpstreamIdp`: register or update.
    PutUpstream,
    /// `retireUpstreamIdp`.
    RetireUpstream,
    /// `linkUpstreamSubject` (OP-152 m.7 (d) E6).
    LinkUpstreamSubject,
    /// `putSigninPolicy`.
    PutSigninPolicy,
    /// `putSessionPolicy`.
    PutSessionPolicy,
    /// `putBranding`.
    PutBranding,
    /// `putRpId`.
    PutRpId,
    /// `putMapper`: set or remove.
    PutMapper,
    /// `putJoseAlg` (MD-3, OP-146 m.8 (e)).
    PutJoseAlg,
    /// `putCimdPolicy`/`patchCimdPolicy` (§11.3, AG-4).
    PutCimdPolicy,
    /// `putProtectionMode`/`patchProtectionMode` (OP-151 m.3 (o), m.14 (f)).
    PutProtectionMode,
    /// `markCanaryAccount` (§4.4).
    MarkCanary,
    /// `resendRelayMessage`: `idp.relay.resend` (OP-156 m.3 (c)).
    ResendRelay,
    /// `putSecurityNotices`: `idp.realm.security_notices`, or `security_notices_close`.
    PutSecurityNotices,
    /// `deleteAccount`: `idp.account.delete`, reserved (OP-153 m.3 (bb)).
    DeleteAccount,
    /// `rehomeRealm`: `idp.realm.rehome`, reserved and declaration only (OP-150 m.11 (b)).
    RehomeRealm,
    /// `createResetIntent`: `idp.account.reset_intent` (TN-61).
    ResetIntent,
    /// `createTemporaryAccessPass`: `idp.account.tap_issue` (TN-62).
    IssueTap,
    /// `putRecoveryPolicy`: `idp.account.recovery_policy`, or its loosening (TN-55).
    PutRecoveryPolicy,
    /// `registerHook` (TN-135).
    RegisterHook,
    /// `retireHook`.
    RetireHook,
    /// `registerWebhook` (TN-136).
    RegisterWebhook,
    /// `putWebhook`: a new URL and events.
    PutWebhook,
    /// `rotateWebhookKey`: a new key, the old one overlapping.
    RotateWebhookKey,
    /// `retireWebhook`.
    RetireWebhook,
    /// `putExtensionPolicy` (OP-151 m.10 (e)).
    PutExtensionPolicy,
    /// `createOrganization`: `idp.org.create` (TN-5, OP-153 m.3 (b)).
    CreateOrganization,
    /// `removeOrganizationMember`: `idp.org.member_remove` (OP-153 m.3 (p)).
    RemoveOrganizationMember,
    /// `createInvitation`: `idp.org.invite` (TN-89, OP-153 m.3 (o)).
    CreateInvitation,
    /// `revokeInvitation`: `idp.org.invite_revoke` (OP-153 m.3 (o)).
    RevokeInvitation,
    /// `patchOrganization`: `idp.org.update` (TN-98).
    PatchOrganization,
    /// `putSocialProvider`: `idp.social.enable` or `update` (OP-153 m.3 (l)).
    PutSocial,
    /// `disableSocialProvider`: `idp.social.disable`.
    DisableSocial,
    /// `claimOrganizationDomain`: `idp.org.domain_claim` (TN-90).
    ClaimOrganizationDomain,
    /// `releaseOrganizationDomain`: `idp.org.domain_release` (TN-90).
    ReleaseOrganizationDomain,
    /// `draftOrganizationConnection`: `idp.org.sso_draft` (TN-120).
    DraftOrganizationConnection,
    /// `enforceOrganizationSso`: `idp.org.sso_enforce` (TN-94, OP-155 m.3 (i)).
    EnforceOrganizationSso,
    /// `liftOrganizationSso`: `idp.org.sso_enforce_lift` (TN-94).
    LiftOrganizationSso,
    /// `createOrganizationSetupLink`: `idp.org.setup_link` (TN-134).
    CreateOrganizationSetupLink,
    /// `putCspMode`: `idp.realm.csp_mode`, or `csp_mode_loosen` when it loosens (OP-153 m.22 (g)).
    PutCspMode,
    /// `putRelatedOrigins`: `idp.realm.related_origins` (TN-18, OP-153 m.22 (k)).
    PutRelatedOrigins,
    /// `putLocaleOverrides`: `idp.realm.locale_overrides` (X35, OP-153 m.22 (k)).
    PutLocaleOverrides,
    /// `importAccounts`: `idp.account.import` over a file the body carries (TN-85, OP-153 m.19 (d)).
    ImportAccounts,
    /// `exportAccounts`: `idp.account.migration_export`, reserved (TN-86, OP-153 m.19 (d)).
    ExportAccounts,
    /// `bindAccount`: `idp.account.bind` (OP-153 m.18 (e)).
    BindAccount,
    /// `recordGuardianship`: `idp.account.guardianship_record` (E53, OP-153 m.20 (g)).
    RecordGuardianship,
    /// `registerAgent`: `idp.agent.register` (OP-154 m.3 (c)).
    RegisterAgent,
    /// `patchAgent`: `idp.agent.update`.
    PatchAgent,
    /// `retireAgent`: `idp.agent.retire`.
    RetireAgent,
    /// `assignAgentSponsor`: `idp.agent.sponsor_assign` (OP-154 m.3 (e)).
    AssignAgentSponsor,
    /// `removeAgentSponsor`: `idp.agent.sponsor_remove`, keyed `agent:sponsor`.
    RemoveAgentSponsor,
    /// `defineAgentTemplate`: `idp.agent.template_define` (OP-154 m.3 (g)).
    DefineAgentTemplate,
    /// `putVaultResource`: `idp.vault.resource_enable` for a catalog upstream, else
    /// `resource_register` (OP-154 m.3 (t)).
    PutVaultResource,
    /// `disableVaultResource`: `idp.vault.resource_disable`.
    DisableVaultResource,
    /// `putVaultReleaseMode`: `idp.vault.release_mode_open` or `release_mode_close`.
    PutVaultReleaseMode,
    /// `registerProtectedResource`: `idp.client.resource_register` (AG-8).
    RegisterProtectedResource,
    /// `registerSamlSp`: `idp.saml.sp_register` (OP-155 m.3 (a), (e)).
    RegisterSamlSp,
    /// `putSamlSp`: `idp.saml.sp_update`.
    PutSamlSp,
    /// `retireSamlSp`: `idp.saml.sp_retire`.
    RetireSamlSp,
    /// `putSamlCertificatePolicy`: `idp.saml.cert_policy`.
    PutSamlCertificatePolicy,
    /// `replaceSamlCertificate`: `idp.saml.cert_emergency` (reserved).
    ReplaceSamlCertificate,
    /// `registerGateway`: `idp.gateway.register` (OP-155 m.3 (c), m.6 (h)).
    RegisterGateway,
    /// `retireGateway`: `idp.gateway.retire`.
    RetireGateway,
    /// `registerDomain`: `idp.domain.register` (OP-156 m.3 (i)).
    RegisterDomain,
    /// `retireDomain`: `idp.domain.retire`.
    RetireDomain,
    /// `bindDomainIssuer`: `idp.domain.issuer_bind` (reserved).
    BindDomainIssuer,
    /// `putSshCa`: `idp.ssh.ca_enable` or `ca_disable` (OP-156 m.3 (o)).
    PutSshCa,
    /// `rotateSshCa`: `idp.ssh.ca_rotate`.
    RotateSshCa,
    /// `replaceSshCa`: `idp.ssh.ca_emergency` (reserved).
    ReplaceSshCa,
    /// `registerSshHostGroup`: `idp.ssh.host_group_register`.
    RegisterSshHostGroup,
    /// `retireSshHostGroup`: `idp.ssh.host_group_retire`, keyed by the group's name.
    RetireSshHostGroup,
    /// `registerSignalSource`: `idp.signal.source_register` (OP-156 m.3 (r)).
    RegisterSignalSource,
    /// `retireSignalSource`: `idp.signal.source_retire`, keyed by the source's name.
    RetireSignalSource,
    /// `registerProxy`: `idp.proxy.register` (OP-156 m.3 (l)).
    RegisterProxy,
    /// `putProxy`: `idp.proxy.update`.
    PutProxy,
    /// `retireProxy`: `idp.proxy.retire`.
    RetireProxy,
    /// `putProxyPlainHeaders`: `idp.proxy.plain_headers` or `plain_headers_close`.
    PutProxyPlainHeaders,
    /// `registerExportSink`: `idp.export.sink_register` (OP-156 m.3 (s)).
    RegisterExportSink,
    /// `putExportSink`: `idp.export.sink_update`, keyed by the sink's name.
    PutExportSink,
    /// `retireExportSink`: `idp.export.sink_retire`, keyed by the sink's name.
    RetireExportSink,
    /// `registerLinuxHost`: `idp.linux.host_register` (OP-156 m.3 (p)).
    RegisterLinuxHost,
    /// `retireLinuxHost`: `idp.linux.host_retire`, keyed by the host's name.
    RetireLinuxHost,
    /// `putLinuxOfflinePolicy`: `idp.linux.offline_policy`.
    PutLinuxOfflinePolicy,
    /// `putLinuxBreakGlassPolicy`: `idp.linux.break_glass_policy` (reserved).
    PutLinuxBreakGlassPolicy,
    /// `registerHrSource`: `idp.hr.source_register` (OP-156 m.3 (q)).
    RegisterHrSource,
    /// `retireHrSource`: `idp.hr.source_retire`, keyed by the source's name.
    RetireHrSource,
    /// `importHrBatch`: `idp.hr.import` of a JSONL batch, keyed by the source's name.
    ImportHrBatch,
    /// `importHrCsv`: `idp.hr.import` of an RFC 4180 CSV file, keyed by the source's name.
    ImportHrCsv,
    /// `registerHrConnector`: `idp.hr.connector_register`.
    RegisterHrConnector,
    /// `retireHrConnector`: `idp.hr.connector_retire`, keyed by the connector's name.
    RetireHrConnector,
    /// `pinMcpTools`: `idp.proxy.mcp_pin` (OP-156 m.3 (n)).
    PinMcpTools,
    /// `putDcrPolicy`: `idp.client.dcr_policy`, or `dcr_policy_tighten` (OP-154 m.3 (j)).
    PutDcrPolicy,
    /// `putFederation`: `idp.federation.enable` or `disable` (OP-155 m.3 (j)).
    PutFederation,
    /// `addTrustAnchor`: `idp.federation.trust_anchor_add` (reserved).
    AddTrustAnchor,
    /// `removeTrustAnchor`: `idp.federation.trust_anchor_remove`, keyed by the anchor's id.
    RemoveTrustAnchor,
    /// `putFederationAuthority`: `idp.federation.ta_enable`.
    PutFederationAuthority,
    /// `putFederationRegistration`: `idp.federation.registration_open` or `registration_close`.
    PutFederationRegistration,
    /// `putDeviceCode`: `idp.realm.device_code`, or `device_code_close` (OP-154 m.3 (p)).
    PutDeviceCode,
    /// `putPush`: `idp.realm.push`, or `push_close` (OP-156 m.3 (d)).
    PutPush,
    /// `putSmsOtp`: `idp.realm.sms_otp`, or `sms_otp_close` (OP-156 m.3 (f)).
    PutSmsOtp,
    /// `putSpc`: `idp.realm.spc` (OP-156 m.3 (g)).
    PutSpc,
    /// `putCiba`: `idp.realm.ciba`, or `ciba_close` (OP-155 m.3 (l)).
    PutCiba,
    /// `putCoordinator`: `idp.realm.coordinator` (OP-156 m.3 (t)).
    PutCoordinator,
    /// `createCrossAppConnection`: `idp.client.cross_app_connection` (OP-154 m.3 (n)).
    CreateCrossAppConnection,
    /// `retireCrossAppConnection`: `idp.client.cross_app_connection_retire`.
    RetireCrossAppConnection,
    /// `putCertificateLogin`: `idp.realm.certificate_login` (OP-155 m.3 (m)).
    PutCertificateLogin,
    /// `putMtlsAliases`: `idp.realm.mtls_aliases` (OP-155 m.3 (m)).
    PutMtlsAliases,
    /// `putHrd`: `idp.realm.hrd` or `hrd_close` (TN-98, OP-155 m.3 (h)).
    PutHrd,
    /// `putIys`: `idp.realm.iys` or `iys_close` (OP-156 m.3 (c)).
    PutIys,
    /// `putPreferenceTopics`: `idp.realm.preference_topics` (OP-153 m.3 (ee)).
    PutPreferenceTopics,
    /// `putUpstreamAssuranceMap`: `idp.upstream.assurance_map` (IDP-27, OP-155 m.3 (h)).
    PutUpstreamAssuranceMap,
    /// `registerScimClient`: `idp.scim.client_register` (OP-155 m.3 (g)).
    RegisterScimClient,
    /// `rotateScimSecret`: `idp.scim.token_rotate`.
    RotateScimSecret,
    /// `retireScimClient`: `idp.scim.client_retire`.
    RetireScimClient,
    /// `registerScimTarget`: `idp.scim.outbound_register`.
    RegisterScimTarget,
    /// `retireScimTarget`: `idp.scim.outbound_retire`.
    RetireScimTarget,
    /// `putClientProfile`: `idp.client.profile`, or `profile_loosen` (OP-155 m.3 (k)).
    PutClientProfile,
    /// `putClientLegacyAuthentication`: `idp.client.auth_method_legacy`.
    PutClientLegacyAuthentication,
    /// `putClientSigningAlg`: `idp.client.alg_rs256`.
    PutClientSigningAlg,
    /// `putClientEncryption`: `idp.client.encryption`.
    PutClientEncryption,
    /// `putClientSamlBearer`: `idp.client.saml_bearer`.
    PutClientSamlBearer,
    /// `putClientLegacyBearer`: `idp.client.legacy_bearer`.
    PutClientLegacyBearer,
    /// `putFrontchannelLogout`: `idp.realm.frontchannel_logout`.
    PutFrontchannelLogout,
    /// `registerRadiusClient`: `idp.gateway.radius_client_register` (OP-155 m.3 (f)).
    RegisterRadiusClient,
    /// `putKeytabPolicy`: `idp.gateway.keytab_policy` (OP-155 m.3 (o)).
    PutKeytabPolicy,
    /// `replaceKeytab`: `idp.gateway.keytab_emergency`, reserved (OP-155 m.3 (o)).
    ReplaceKeytab,
}

impl Op {
    /// The operation with this manifest id.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one match over the manifest's write operations"
    )]
    pub fn from_operation(id: &str) -> Option<Self> {
        Some(match id {
            "createClient" => Self::CreateClient,
            "putClient" | "patchClient" => Self::PutClient,
            "retireClient" => Self::RetireClient,
            "rotateClientSecret" => Self::RotateClientSecret,
            "putGroup" | "patchGroup" => Self::PutGroup,
            "retireGroup" => Self::RetireGroup,
            "addGroupMembers" => Self::AddGroupMembers,
            "removeGroupMembers" => Self::RemoveGroupMembers,
            "suspendAccount" => Self::SuspendAccount,
            "reactivateAccount" => Self::ReactivateAccount,
            "putUpstreamIdp" | "patchUpstreamIdp" => Self::PutUpstream,
            "retireUpstreamIdp" => Self::RetireUpstream,
            "linkUpstreamSubject" => Self::LinkUpstreamSubject,
            "putSigninPolicy" | "patchSigninPolicy" => Self::PutSigninPolicy,
            "putSessionPolicy" | "patchSessionPolicy" => Self::PutSessionPolicy,
            "putBranding" | "patchBranding" => Self::PutBranding,
            "putRpId" => Self::PutRpId,
            "putMapper" => Self::PutMapper,
            "putJoseAlg" => Self::PutJoseAlg,
            "putCimdPolicy" | "patchCimdPolicy" => Self::PutCimdPolicy,
            "putProtectionMode" | "patchProtectionMode" => Self::PutProtectionMode,
            "markCanaryAccount" => Self::MarkCanary,
            "resendRelayMessage" => Self::ResendRelay,
            "putSecurityNotices" => Self::PutSecurityNotices,
            "deleteAccount" => Self::DeleteAccount,
            "rehomeRealm" => Self::RehomeRealm,
            "createResetIntent" => Self::ResetIntent,
            "createTemporaryAccessPass" => Self::IssueTap,
            "putRecoveryPolicy" => Self::PutRecoveryPolicy,
            "registerHook" => Self::RegisterHook,
            "retireHook" => Self::RetireHook,
            "registerWebhook" => Self::RegisterWebhook,
            "putWebhook" | "patchWebhook" => Self::PutWebhook,
            "rotateWebhookKey" => Self::RotateWebhookKey,
            "retireWebhook" => Self::RetireWebhook,
            "putExtensionPolicy" | "patchExtensionPolicy" => Self::PutExtensionPolicy,
            "createOrganization" => Self::CreateOrganization,
            "removeOrganizationMember" => Self::RemoveOrganizationMember,
            "createInvitation" => Self::CreateInvitation,
            "revokeInvitation" => Self::RevokeInvitation,
            "patchOrganization" => Self::PatchOrganization,
            "putSocialProvider" | "patchSocialProvider" => Self::PutSocial,
            "disableSocialProvider" => Self::DisableSocial,
            "claimOrganizationDomain" => Self::ClaimOrganizationDomain,
            "releaseOrganizationDomain" => Self::ReleaseOrganizationDomain,
            "draftOrganizationConnection" => Self::DraftOrganizationConnection,
            "enforceOrganizationSso" => Self::EnforceOrganizationSso,
            "liftOrganizationSso" => Self::LiftOrganizationSso,
            "createOrganizationSetupLink" => Self::CreateOrganizationSetupLink,
            "putCspMode" => Self::PutCspMode,
            "putRelatedOrigins" => Self::PutRelatedOrigins,
            "putLocaleOverrides" => Self::PutLocaleOverrides,
            "importAccounts" => Self::ImportAccounts,
            "exportAccounts" => Self::ExportAccounts,
            "bindAccount" => Self::BindAccount,
            "recordGuardianship" => Self::RecordGuardianship,
            "registerAgent" => Self::RegisterAgent,
            "patchAgent" => Self::PatchAgent,
            "retireAgent" => Self::RetireAgent,
            "assignAgentSponsor" => Self::AssignAgentSponsor,
            "removeAgentSponsor" => Self::RemoveAgentSponsor,
            "defineAgentTemplate" => Self::DefineAgentTemplate,
            "putVaultResource" => Self::PutVaultResource,
            "disableVaultResource" => Self::DisableVaultResource,
            "putVaultReleaseMode" => Self::PutVaultReleaseMode,
            "registerProtectedResource" => Self::RegisterProtectedResource,
            "registerSamlSp" => Self::RegisterSamlSp,
            "putSamlSp" => Self::PutSamlSp,
            "retireSamlSp" => Self::RetireSamlSp,
            "putSamlCertificatePolicy" => Self::PutSamlCertificatePolicy,
            "replaceSamlCertificate" => Self::ReplaceSamlCertificate,
            "registerGateway" => Self::RegisterGateway,
            "retireGateway" => Self::RetireGateway,
            "registerDomain" => Self::RegisterDomain,
            "retireDomain" => Self::RetireDomain,
            "bindDomainIssuer" => Self::BindDomainIssuer,
            "putSshCa" => Self::PutSshCa,
            "rotateSshCa" => Self::RotateSshCa,
            "replaceSshCa" => Self::ReplaceSshCa,
            "registerSshHostGroup" => Self::RegisterSshHostGroup,
            "retireSshHostGroup" => Self::RetireSshHostGroup,
            "registerSignalSource" => Self::RegisterSignalSource,
            "retireSignalSource" => Self::RetireSignalSource,
            "registerProxy" => Self::RegisterProxy,
            "putProxy" => Self::PutProxy,
            "retireProxy" => Self::RetireProxy,
            "putProxyPlainHeaders" => Self::PutProxyPlainHeaders,
            "registerExportSink" => Self::RegisterExportSink,
            "putExportSink" => Self::PutExportSink,
            "retireExportSink" => Self::RetireExportSink,
            "registerLinuxHost" => Self::RegisterLinuxHost,
            "retireLinuxHost" => Self::RetireLinuxHost,
            "putLinuxOfflinePolicy" => Self::PutLinuxOfflinePolicy,
            "putLinuxBreakGlassPolicy" => Self::PutLinuxBreakGlassPolicy,
            "registerHrSource" => Self::RegisterHrSource,
            "retireHrSource" => Self::RetireHrSource,
            "importHrBatch" => Self::ImportHrBatch,
            "importHrCsv" => Self::ImportHrCsv,
            "registerHrConnector" => Self::RegisterHrConnector,
            "retireHrConnector" => Self::RetireHrConnector,
            "pinMcpTools" => Self::PinMcpTools,
            "putDcrPolicy" => Self::PutDcrPolicy,
            "putFederation" => Self::PutFederation,
            "addTrustAnchor" => Self::AddTrustAnchor,
            "removeTrustAnchor" => Self::RemoveTrustAnchor,
            "putFederationAuthority" => Self::PutFederationAuthority,
            "putFederationRegistration" => Self::PutFederationRegistration,
            "putDeviceCode" => Self::PutDeviceCode,
            "putPush" => Self::PutPush,
            "putSmsOtp" => Self::PutSmsOtp,
            "putSpc" => Self::PutSpc,
            "putCiba" => Self::PutCiba,
            "putCoordinator" => Self::PutCoordinator,
            "createCrossAppConnection" => Self::CreateCrossAppConnection,
            "retireCrossAppConnection" => Self::RetireCrossAppConnection,
            "putCertificateLogin" => Self::PutCertificateLogin,
            "putMtlsAliases" => Self::PutMtlsAliases,
            "putHrd" => Self::PutHrd,
            "putIys" => Self::PutIys,
            "putPreferenceTopics" => Self::PutPreferenceTopics,
            "putUpstreamAssuranceMap" => Self::PutUpstreamAssuranceMap,
            "registerScimClient" => Self::RegisterScimClient,
            "rotateScimSecret" => Self::RotateScimSecret,
            "retireScimClient" => Self::RetireScimClient,
            "registerScimTarget" => Self::RegisterScimTarget,
            "retireScimTarget" => Self::RetireScimTarget,
            "putClientProfile" => Self::PutClientProfile,
            "putClientLegacyAuthentication" => Self::PutClientLegacyAuthentication,
            "putClientSigningAlg" => Self::PutClientSigningAlg,
            "putClientEncryption" => Self::PutClientEncryption,
            "putClientSamlBearer" => Self::PutClientSamlBearer,
            "putClientLegacyBearer" => Self::PutClientLegacyBearer,
            "putFrontchannelLogout" => Self::PutFrontchannelLogout,
            "registerRadiusClient" => Self::RegisterRadiusClient,
            "putKeytabPolicy" => Self::PutKeytabPolicy,
            "replaceKeytab" => Self::ReplaceKeytab,
            _ => return None,
        })
    }
}

fn obj(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<&'a str, Invalid> {
    m.get(k).and_then(Json::as_str).ok_or(Invalid::Body)
}

fn opt_text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<Option<&'a str>, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s)),
        Some(_) => Err(Invalid::Body),
    }
}

fn flag(m: &Map<String, Json>, k: &str) -> Result<bool, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(Invalid::Body),
    }
}

fn texts<'a>(m: &'a Map<String, Json>, k: &str) -> Result<Vec<&'a str>, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(a)) => a.iter().map(|v| v.as_str().ok_or(Invalid::Body)).collect(),
        Some(_) => Err(Invalid::Body),
    }
}

/// Only `allowed` members (and the validity and AIS) may appear.
fn only(m: &Map<String, Json>, allowed: &[&str]) -> Result<(), Invalid> {
    if m.keys()
        .all(|k| allowed.contains(&k.as_str()) || k == VALIDITY || k == "ais")
    {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

fn uris(list: &[&str]) -> Result<Vec<RedirectUri>, Invalid> {
    list.iter().map(|u| RedirectUri::parse(u)).collect()
}

fn ms_text(v: &Json) -> Result<u64, Invalid> {
    match v {
        Json::String(s) => s.parse().map_err(|_| Invalid::Body),
        Json::Number(n) => n.as_u64().ok_or(Invalid::Body),
        _ => Err(Invalid::Body),
    }
}

/// RFC 3339 in UTC with milliseconds (OP-65).
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    let nanos = i128::from(ms).saturating_mul(1_000_000);
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn parse_rfc3339(s: &str) -> Result<u64, Invalid> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Invalid::Validity)?;
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(ms).map_err(|_| Invalid::Validity)
}

/// The intent validity a write's body names: `{"not_before", "not_after"}` in RFC 3339, at
/// most [`MAX_VALIDITY_MS`] long.
///
/// # Errors
/// [`Invalid::Validity`].
pub fn validity(body: &Json) -> Result<Window, Invalid> {
    let v = body
        .get(VALIDITY)
        .and_then(Json::as_object)
        .ok_or(Invalid::Validity)?;
    let from = parse_rfc3339(
        v.get("not_before")
            .and_then(Json::as_str)
            .ok_or(Invalid::Validity)?,
    )?;
    let until = parse_rfc3339(
        v.get("not_after")
            .and_then(Json::as_str)
            .ok_or(Invalid::Validity)?,
    )?;
    if until <= from || until.saturating_sub(from) > MAX_VALIDITY_MS {
        return Err(Invalid::Validity);
    }
    Ok(Window { from, until })
}

/// The validity member for `now`: from one minute before to [`DEFAULT_VALIDITY_MS`] after.
#[must_use]
pub fn default_validity(now_ms: u64) -> Json {
    json!({
        "not_before": rfc3339(now_ms.saturating_sub(60_000)),
        "not_after": rfc3339(now_ms.saturating_add(DEFAULT_VALIDITY_MS)),
    })
}

fn client(id: ClientId, m: &Map<String, Json>) -> Result<Client, Invalid> {
    only(
        m,
        &[
            "client_id",
            "display_name",
            "token_endpoint_auth_method",
            "jwks_uri",
            "redirect_uris",
            "post_logout_redirect_uris",
            "backchannel_logout_uri",
            "require_pushed_authorization_requests",
            "status",
            "platform_product",
            "subject_type",
            "public_sub_opt_in",
            "sector_identifier_uri",
            "third_party",
            "spiffe_id",
            "spiffe_bundle_endpoint",
            "agent",
        ],
    )?;
    // OP-149 m.4
    if m.get("platform_product").is_some_and(|v| !v.is_null()) {
        return Err(Invalid::PlatformTenant);
    }
    let method = opt_text(m, "token_endpoint_auth_method")?.unwrap_or("none");
    let auth = match method {
        // OP-154 m.3 (r)
        "spiffe_jwt" | "spiffe_x509" => AuthMethod::Spiffe(Box::new(crate::domain::SpiffeAuth {
            x509: method == "spiffe_x509",
            spiffe_id: String::from(opt_text(m, "spiffe_id")?.ok_or(Invalid::Workload)?),
            bundle_endpoint: String::from(
                opt_text(m, "spiffe_bundle_endpoint")?.ok_or(Invalid::Workload)?,
            ),
            agent: party_of(
                opt_text(m, "agent")?.ok_or(Invalid::Workload)?,
                Invalid::Workload,
            )?,
        })),
        _ => {
            let spiffe = ["spiffe_id", "spiffe_bundle_endpoint", "agent"];
            if spiffe
                .iter()
                .any(|k| m.get(*k).is_some_and(|v| !v.is_null()))
            {
                return Err(Invalid::Workload);
            }
            AuthMethod::from_parts(method, opt_text(m, "jwks_uri")?)?
        }
    };
    Ok(Client {
        id,
        display_name: String::from(text(m, "display_name")?),
        auth,
        redirect_uris: uris(&texts(m, "redirect_uris")?)?,
        post_logout_redirect_uris: uris(&texts(m, "post_logout_redirect_uris")?)?,
        backchannel_logout_uri: opt_text(m, "backchannel_logout_uri")?.map(String::from),
        require_par: flag(m, "require_pushed_authorization_requests")?,
        platform: None,
        subject: subject_of(m)?,
        third_party: flag(m, "third_party")?,
    })
}

/// MD-10: `subject_type` is `pairwise` unless the body says `public` and opts in with
/// `public_sub_opt_in: true`; a client's view carries both, so a merge patch keeps them.
fn subject_of(m: &Map<String, Json>) -> Result<Subject, Invalid> {
    let public = match opt_text(m, "subject_type")? {
        None | Some("pairwise") => false,
        Some("public") => true,
        Some(_) => return Err(Invalid::PublicSub),
    };
    let opted = flag(m, "public_sub_opt_in")?;
    if public != opted && (public || opted) {
        return Err(Invalid::PublicSub);
    }
    Ok(Subject {
        public,
        sector_identifier_uri: opt_text(m, "sector_identifier_uri")?.map(String::from),
    })
}

fn subject(ids: &IdKey, s: &str) -> Result<[u8; 16], Invalid> {
    ids.decode(SUBJECT_PREFIX, s)
        .map_err(|_| Invalid::NoAccount)
}

/// The `idp.agent.*` change of an agent operation (OP-154 m.3 (c), (e), (g)), `None` for any
/// other operation.
fn agent_change(
    op: Op,
    key: Option<&str>,
    m: &Map<String, Json>,
    ids: &IdKey,
) -> Result<Option<crate::domain::agent::AgentChange>, Invalid> {
    use crate::domain::agent::{AgentChange, AgentKind, AgentRegister, AgentUpdate, Sponsor};
    let agent = |k: Option<&str>| party_of(key_of(k)?, Invalid::NoAgent);
    Ok(Some(match op {
        Op::RegisterAgent => {
            only(
                m,
                &[
                    "agent",
                    "operator",
                    "agent_kind",
                    "display_name",
                    "description",
                    "sponsors",
                ],
            )?;
            AgentChange::Register(AgentRegister {
                party: party_of(text(m, "agent")?, Invalid::Agent)?,
                operator: party_of(text(m, "operator")?, Invalid::Agent)?,
                kind: AgentKind::parse(text(m, "agent_kind")?)?,
                display_name: String::from(text(m, "display_name")?),
                description: opt_text(m, "description")?.map(String::from),
                sponsors: texts(m, "sponsors")?
                    .into_iter()
                    .map(|s| subject(ids, s))
                    .collect::<Result<_, _>>()?,
            })
        }
        Op::PatchAgent => {
            only(m, &["display_name", "description"])?;
            AgentChange::Update(AgentUpdate {
                agent: agent(key)?,
                display_name: String::from(text(m, "display_name")?),
                description: opt_text(m, "description")?.map(String::from),
            })
        }
        Op::RetireAgent => {
            only(m, &[])?;
            AgentChange::Retire(agent(key)?)
        }
        Op::AssignAgentSponsor => {
            only(m, &["account_id"])?;
            AgentChange::SponsorAssign(Sponsor {
                agent: agent(key)?,
                subject: subject(ids, text(m, "account_id")?)?,
            })
        }
        Op::RemoveAgentSponsor => {
            only(m, &[])?;
            let (a, s) = key_of(key)?.split_once(':').ok_or(Invalid::Body)?;
            AgentChange::SponsorRemove(Sponsor {
                agent: party_of(a, Invalid::NoAgent)?,
                subject: subject(ids, s)?,
            })
        }
        Op::DefineAgentTemplate => AgentChange::TemplateDefine(template(m)?),
        _ => return Ok(None),
    }))
}

/// An agent Grant template from its body (OP-154 m.3 (g)).
fn template(m: &Map<String, Json>) -> Result<crate::domain::agent::AgentTemplate, Invalid> {
    use crate::domain::agent::{AgentTemplate, Spend};
    only(
        m,
        &[
            "name",
            "actions",
            "resource",
            "consumption",
            "spend",
            "count",
            "delegation_depth",
            "ttl_s",
        ],
    )?;
    let bad = Invalid::AgentTemplate;
    let resource = m.get("resource").and_then(Json::as_object).ok_or(bad)?;
    let count = m.get("count").and_then(Json::as_object).ok_or(bad)?;
    let spend = match m.get("spend") {
        None | Some(Json::Null) => None,
        Some(Json::Object(s)) => Some(Spend {
            param: String::from(text(s, "param")?),
            unit: String::from(text(s, "unit")?),
            per_intent: s.get("per_intent").and_then(Json::as_i64).ok_or(bad)?,
            daily: s.get("daily").and_then(Json::as_u64).ok_or(bad)?,
        }),
        Some(_) => return Err(bad),
    };
    let actions = match m.get("actions") {
        Some(Json::Array(a)) => a
            .iter()
            .map(|x| template_action(x).ok_or(bad))
            .collect::<Result<_, _>>()?,
        _ => return Err(bad),
    };
    Ok(AgentTemplate {
        name: Name::parse(text(m, "name")?)?,
        actions,
        namespace: String::from(text(resource, "namespace")?),
        prefix: texts(resource, "prefix")?
            .into_iter()
            .map(String::from)
            .collect(),
        consumption: flag(m, "consumption")?,
        spend,
        count: count.get("capacity").and_then(Json::as_u64).ok_or(bad)?,
        window_s: count.get("window_s").and_then(Json::as_u64).ok_or(bad)?,
        depth: m
            .get("delegation_depth")
            .map_or(Some(0), Json::as_u64)
            .ok_or(bad)?,
        ttl_ms: m
            .get("ttl_s")
            .and_then(Json::as_u64)
            .and_then(|s| s.checked_mul(1000))
            .ok_or(bad)?,
    })
}

/// An action of a template: `{namespace, name, major, schema}` with the schema digest in
/// base64url; an `idp.*` action may leave the digest out, the catalog's is used.
fn template_action(v: &Json) -> Option<access_kernel::model::ActionRef> {
    let o = v.as_object()?;
    let namespace = o.get("namespace")?.as_str()?;
    let name = o.get("name")?.as_str()?;
    let major = o.get("major")?.as_u64()?;
    let schema = if let Some(s) = o.get("schema").and_then(Json::as_str) {
        access_kernel::digest::Digest(<[u8; 32]>::try_from(b64url_decode(s).ok()?.as_slice()).ok()?)
    } else {
        let label = format!("{namespace}.{name}");
        access_internal_api::idp::IdpAction::from_label(&label)?
            .action_ref()
            .schema
    };
    Some(access_kernel::model::ActionRef {
        namespace: String::from(namespace),
        name: String::from(name),
        major,
        schema,
    })
}

/// Prefix of an invitation's external id (OP-137).
pub const INVITATION_PREFIX: &str = "inv";

/// Prefix of a domain claim's external id (OP-137).
pub const DOMAIN_CLAIM_PREFIX: &str = "dom";

/// An organization's Party from its external id, the base64url of its 16 bytes (TN-3).
fn party_of(s: &str, missing: Invalid) -> Result<[u8; 16], Invalid> {
    b64url_decode(s)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .ok_or(missing)
}

/// A lifetime given in whole seconds, or `default_ms` when absent.
fn seconds(m: &Map<String, Json>, k: &str, default_ms: u64) -> Result<u64, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(default_ms),
        Some(v) => v
            .as_u64()
            .and_then(|s| s.checked_mul(1000))
            .ok_or(Invalid::Body),
    }
}

/// The profile change a client profile operation asks for (OP-155 m.3 (k)). `client_secret_jwt`
/// needs the realm KEK to seal its secret and is refused here until a write path holds one.
fn profile_delta(op: Op, m: &Map<String, Json>) -> Result<crate::domain::ProfileDelta, Invalid> {
    use crate::domain::ProfileDelta;
    use access_identity_oauth::domain::fapi::{Encryption, IdAlg};
    let bad = |_| Invalid::ClientProfile;
    Ok(match op {
        Op::PutClientProfile => {
            only(m, &["profile"])?;
            match text(m, "profile")? {
                "fapi2" => ProfileDelta::Fapi2(true),
                "baseline" => ProfileDelta::Fapi2(false),
                _ => return Err(Invalid::ClientProfile),
            }
        }
        Op::PutClientLegacyAuthentication => {
            only(m, &["token_endpoint_auth_method"])?;
            match text(m, "token_endpoint_auth_method")? {
                access_identity_oauth::domain::fapi::CLIENT_SECRET_POST => ProfileDelta::SecretPost,
                _ => return Err(Invalid::ClientProfile),
            }
        }
        Op::PutClientSigningAlg => {
            only(m, &["id_token_signed_response_alg"])?;
            match opt_text(m, "id_token_signed_response_alg")? {
                None => ProfileDelta::SigningAlg(None),
                Some(a) => ProfileDelta::SigningAlg(Some(
                    IdAlg::from_name(a).ok_or(Invalid::ClientProfile)?,
                )),
            }
        }
        Op::PutClientEncryption => {
            only(m, &["alg", "jwks", "id_token", "userinfo", "jarm"])?;
            let alg = access_crypto::jwe::KeyAlg::from_name(text(m, "alg")?)
                .ok_or(Invalid::ClientProfile)?;
            let jwks = m.get("jwks").ok_or(Invalid::ClientProfile)?;
            ProfileDelta::Encryption(Encryption {
                alg,
                jwks: serde_json::to_string(jwks).map_err(bad)?,
                id_token: flag(m, "id_token")?,
                userinfo: flag(m, "userinfo")?,
                jarm: flag(m, "jarm")?,
            })
        }
        Op::PutClientSamlBearer => {
            only(m, &["upstream"])?;
            ProfileDelta::SamlBearer(String::from(text(m, "upstream")?))
        }
        Op::PutClientLegacyBearer => {
            only(m, &["enabled"])?;
            if !flag(m, "enabled")? {
                return Err(Invalid::ClientProfile);
            }
            ProfileDelta::LegacyBearer
        }
        _ => return Err(Invalid::Body),
    })
}

fn key_of(key: Option<&str>) -> Result<&str, Invalid> {
    key.ok_or(Invalid::Body)
}

/// The `idp.vault.*` change of a vault operation (OP-154 m.3 (t)), `None` for any other.
fn vault_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<access_identity_vault::domain::resource::VaultChange>, Invalid> {
    use access_identity_vault::domain::catalog::Catalog;
    use access_identity_vault::domain::resource::{Invalid as Bad, VaultChange};
    let bad = |e: Bad| match e {
        Bad::Resource | Bad::Upstream => Invalid::VaultResource,
    };
    if !matches!(
        op,
        Op::PutVaultResource | Op::DisableVaultResource | Op::PutVaultReleaseMode
    ) {
        return Ok(None);
    }
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    Ok(Some(match op {
        Op::PutVaultResource => {
            let catalog = Catalog::get_shipped().ok_or(Invalid::VaultResource)?;
            VaultChange::put(key_of(key)?, &body, catalog).map_err(bad)?
        }
        Op::DisableVaultResource => {
            if obj(&body)?.is_empty() {
                VaultChange::Disable(String::from(key_of(key)?))
            } else {
                return Err(Invalid::Body);
            }
        }
        Op::PutVaultReleaseMode => VaultChange::release_mode(&body).map_err(bad)?,
        _ => return Ok(None),
    }))
}

/// The `idp.federation.*` change of a federation operation (OP-155 m.3 (j)), `None` for any
/// other.
fn federation_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<crate::domain::federation::FederationChange>, Invalid> {
    use crate::domain::federation::FederationChange as F;
    if !matches!(
        op,
        Op::PutFederation
            | Op::AddTrustAnchor
            | Op::RemoveTrustAnchor
            | Op::PutFederationAuthority
            | Op::PutFederationRegistration
    ) {
        return Ok(None);
    }
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let bad = |_| Invalid::Federation;
    Ok(Some(match op {
        Op::PutFederation => F::put_federation(&own).map_err(bad)?,
        Op::AddTrustAnchor => F::add_anchor(&own).map_err(bad)?,
        Op::RemoveTrustAnchor => {
            if !own.is_empty() {
                return Err(Invalid::Body);
            }
            F::TrustAnchorRemove(super::federation::anchor_of(key_of(key)?)?)
        }
        Op::PutFederationAuthority => F::put_authority(&own).map_err(bad)?,
        Op::PutFederationRegistration => F::put_registration(&own).map_err(bad)?,
        _ => return Ok(None),
    }))
}

/// The `idp.saml.*` or `idp.gateway.*` change of a SAML or gateway operation (OP-155 m.3 (a)),
/// `None` for any other.
fn saml_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<crate::domain::saml::SamlChange>, Invalid> {
    use crate::domain::saml::SamlChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    Ok(Some(match op {
        Op::RegisterSamlSp => SamlChange::register(&body)?,
        Op::PutSamlSp => SamlChange::update(key_of(key)?, &body)?,
        Op::RetireSamlSp => SamlChange::retire(key_of(key)?, &body)?,
        Op::PutSamlCertificatePolicy => SamlChange::cert_policy(&body)?,
        Op::ReplaceSamlCertificate => SamlChange::cert_emergency(&body)?,
        Op::RegisterGateway => SamlChange::gateway_register(&body)?,
        Op::RetireGateway => SamlChange::gateway_retire(key_of(key)?, &body)?,
        _ => return Ok(None),
    }))
}

/// The `idp.ssh.*` change of an SSH CA or server group operation (OP-156 m.3 (o)), `None` for
/// any other.
fn ssh_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<access_identity_ssh::domain::change::SshChange>, Invalid> {
    use access_identity_ssh::domain::change::SshChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    let ca = |_| Invalid::SshCa;
    let group = |_| Invalid::SshHostGroup;
    Ok(Some(match op {
        Op::PutSshCa => SshChange::put_ca(&body).map_err(ca)?,
        Op::RotateSshCa => SshChange::rotate_ca(&body, false).map_err(ca)?,
        Op::ReplaceSshCa => SshChange::rotate_ca(&body, true).map_err(ca)?,
        Op::RegisterSshHostGroup => SshChange::register_group(&body).map_err(group)?,
        Op::RetireSshHostGroup => SshChange::retire_group(key_of(key)?, &body).map_err(group)?,
        _ => return Ok(None),
    }))
}

/// The `idp.hr.*` change of an HR source, import or connector operation (OP-156 m.3 (q)),
/// `None` for any other.
fn hr_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<crate::domain::hr::HrChange>, Invalid> {
    use crate::domain::hr::HrChange;
    use access_identity_account::app::hr::Format;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    Ok(Some(match op {
        Op::RegisterHrSource => HrChange::register_source(&body)?,
        Op::RetireHrSource => HrChange::retire_source(key_of(key)?, &body)?,
        Op::ImportHrBatch => HrChange::import(key_of(key)?, Format::Jsonl, &body)?,
        Op::ImportHrCsv => HrChange::import(key_of(key)?, Format::Csv, &body)?,
        Op::RegisterHrConnector => HrChange::register_connector(&body)?,
        Op::RetireHrConnector => HrChange::retire_connector(key_of(key)?, &body)?,
        _ => return Ok(None),
    }))
}

/// The `idp.export.*` change of an export sink operation (OP-156 m.3 (s)), `None` for any other.
fn export_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<access_identity_export::domain::sink::ExportChange>, Invalid> {
    use access_identity_export::domain::sink::ExportChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    let sink = |_| Invalid::ExportSink;
    Ok(Some(match op {
        Op::RegisterExportSink => ExportChange::register(&body).map_err(sink)?,
        Op::PutExportSink => ExportChange::update(key_of(key)?, &body).map_err(sink)?,
        Op::RetireExportSink => ExportChange::retire(key_of(key)?, &body).map_err(sink)?,
        _ => return Ok(None),
    }))
}

/// The `idp.signal.*` change of a signal source operation (OP-156 m.3 (r)), `None` for any
/// other.
fn signal_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<access_identity_signals::domain::source::SourceChange>, Invalid> {
    use access_identity_signals::domain::source::SourceChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    let bad = |_| Invalid::SignalSource;
    Ok(Some(match op {
        Op::RegisterSignalSource => SourceChange::register(&body).map_err(bad)?,
        Op::RetireSignalSource => SourceChange::retire(key_of(key)?, &body).map_err(bad)?,
        _ => return Ok(None),
    }))
}

/// The `idp.proxy.*` change of a proxy operation (OP-156 m.3 (l)), `None` for any other.
fn proxy_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<access_identity_proxy::domain::registration::ProxyChange>, Invalid> {
    use access_identity_proxy::domain::registration::ProxyChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    let bad = |_| Invalid::Proxy;
    Ok(Some(match op {
        Op::RegisterProxy => ProxyChange::register(&body).map_err(bad)?,
        Op::PutProxy => ProxyChange::update(key_of(key)?, &body).map_err(bad)?,
        Op::RetireProxy => ProxyChange::retire(key_of(key)?, &body).map_err(bad)?,
        Op::PutProxyPlainHeaders => ProxyChange::plain_headers(key_of(key)?, &body).map_err(bad)?,
        _ => return Ok(None),
    }))
}

/// The `idp.linux.*` change of a Linux host operation (OP-156 m.3 (p)), `None` for any other.
fn linux_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<crate::domain::linux::LinuxChange>, Invalid> {
    use crate::domain::linux::LinuxChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    Ok(Some(match op {
        Op::RegisterLinuxHost => LinuxChange::register(&body)?,
        Op::RetireLinuxHost => LinuxChange::retire(key_of(key)?, &body)?,
        Op::PutLinuxOfflinePolicy => LinuxChange::offline_policy(key_of(key)?, &body)?,
        Op::PutLinuxBreakGlassPolicy => LinuxChange::break_glass(key_of(key)?, &body)?,
        _ => return Ok(None),
    }))
}

/// A hook's or webhook's id from its external id; anything else is `missing`.
fn extension_id(ids: &IdKey, prefix: &str, s: &str, missing: Invalid) -> Result<[u8; 16], Invalid> {
    ids.decode(prefix, s).map_err(|_| missing)
}

/// Disclosures, sorted and unique.
fn disclosures(list: &[&str], invalid: Invalid) -> Result<Vec<Disclosure>, Invalid> {
    let set = list
        .iter()
        .map(|d| Disclosure::from_name(d).ok_or(invalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(set.into_iter().collect())
}

fn events(m: &Map<String, Json>) -> Result<Vec<String>, Invalid> {
    let list: Vec<String> = texts(m, "events")?.into_iter().map(String::from).collect();
    event_names(&list).map_err(|_| Invalid::WebhookEvents)
}

/// The `idp.scim.*` change of a SCIM operation (OP-155 m.3 (g)), `None` for any other.
fn scim_change(
    op: Op,
    key: Option<&str>,
    m: &Map<String, Json>,
) -> Result<Option<crate::domain::scim::ScimChange>, Invalid> {
    use crate::domain::scim::{ScimChange, TargetSecret};
    let name = |k: Option<&str>| key_of(k).map(String::from);
    Ok(Some(match op {
        Op::RegisterScimClient => {
            only(m, &["name", "profile", "organization"])?;
            ScimChange::ClientRegister {
                name: String::from(text(m, "name")?),
                profile: opt_text(m, "profile")?.map(String::from),
                // TN-95
                org: opt_text(m, "organization")?
                    .map(|o| party_of(o, Invalid::NoOrg))
                    .transpose()?,
            }
        }
        Op::RotateScimSecret => {
            only(m, &[])?;
            ScimChange::TokenRotate(name(key)?)
        }
        Op::RetireScimClient => {
            only(m, &[])?;
            ScimChange::ClientRetire(name(key)?)
        }
        Op::RegisterScimTarget => {
            only(m, &["name", "base_url", "bearer"])?;
            ScimChange::OutboundRegister {
                name: String::from(text(m, "name")?),
                base_url: String::from(text(m, "base_url")?),
                secret: TargetSecret::parse(text(m, "bearer")?)?,
            }
        }
        Op::RetireScimTarget => {
            only(m, &[])?;
            ScimChange::OutboundRetire(name(key)?)
        }
        _ => return Ok(None),
    }))
}

/// The `idp.domain.*` change of a custom domain operation (OP-156 m.3 (i)), `None` for any other.
fn domain_change(
    op: Op,
    key: Option<&str>,
    body: &Json,
) -> Result<Option<crate::domain::custom_domain::DomainChange>, Invalid> {
    use crate::domain::custom_domain::DomainChange;
    let mut own = obj(body)?.clone();
    own.remove(VALIDITY);
    own.remove("ais");
    let body = Json::Object(own);
    Ok(Some(match op {
        Op::RegisterDomain => DomainChange::register(&body)?,
        Op::RetireDomain => DomainChange::retire(key_of(key)?, &body)?,
        Op::BindDomainIssuer => DomainChange::issuer_bind(key_of(key)?, &body)?,
        _ => return Ok(None),
    }))
}

/// Compiles one write operation's body into its one [`Change`] (TN-110). `key` is the path's
/// natural key; a create carries the `client_id` its prepare step assigned.
///
/// # Errors
/// [`Invalid`].
#[expect(
    clippy::too_many_lines,
    reason = "one match over the operations; each arm is the operation's body contract"
)]
pub fn compile(op: Op, key: Option<&str>, body: &Json, ids: &IdKey) -> Result<Change, Invalid> {
    let m = obj(body)?;
    if let Some(a) = agent_change(op, key, m, ids)? {
        return Ok(Change::Agent(a));
    }
    if let Some(v) = vault_change(op, key, body)? {
        return Ok(Change::Vault(v));
    }
    if let Some(s) = scim_change(op, key, m)? {
        return Ok(Change::Scim(s));
    }
    if let Some(f) = federation_change(op, key, body)? {
        return Ok(Change::Federation(f));
    }
    if let Some(s) = saml_change(op, key, body)? {
        return Ok(Change::Saml(s));
    }
    if let Some(d) = domain_change(op, key, body)? {
        return Ok(Change::Domain(d));
    }
    if let Some(s) = ssh_change(op, key, body)? {
        return Ok(Change::Ssh(s));
    }
    if let Some(s) = signal_change(op, key, body)? {
        return Ok(Change::Signal(Box::new(s)));
    }
    if let Some(p) = proxy_change(op, key, body)? {
        return Ok(Change::Proxy(p));
    }
    if let Some(e) = export_change(op, key, body)? {
        return Ok(Change::Export(e));
    }
    if let Some(l) = linux_change(op, key, body)? {
        return Ok(Change::Linux(l));
    }
    if let Some(h) = hr_change(op, key, body)? {
        return Ok(Change::Hr(h));
    }
    // OP-156 m.3 (n)
    if op == Op::PinMcpTools {
        let mut own = m.clone();
        own.remove(VALIDITY);
        own.remove("ais");
        return access_identity_proxy::domain::mcp::McpPinChange::parse(
            key_of(key)?,
            &Json::Object(own),
        )
        .map(Change::McpPin)
        .map_err(|_| Invalid::McpPins);
    }
    Ok(match op {
        Op::CreateOrganization => {
            only(m, &["party", "display_name"])?;
            Change::OrgCreate(OrgCreate {
                party: party_of(text(m, "party")?, Invalid::Body)?,
                display_name: String::from(text(m, "display_name")?),
            })
        }
        Op::PutSocial => {
            only(m, &["preset", "client_id", "client_secret_ref", "status"])?;
            let preset = Name::parse(key_of(key)?)?;
            if opt_text(m, "preset")?.is_some_and(|n| n != preset.as_str()) {
                return Err(Invalid::Name);
            }
            let client = match (opt_text(m, "client_id")?, opt_text(m, "client_secret_ref")?) {
                (None, None) => None,
                (Some(id), Some(r)) => Some(SocialClient {
                    client_id: String::from(id),
                    secret_ref: String::from(r),
                }),
                _ => return Err(Invalid::Social),
            };
            Change::SocialEnable(Social { preset, client })
        }
        Op::DisableSocial => {
            only(m, &[])?;
            Change::SocialDisable(Name::parse(key_of(key)?)?)
        }
        Op::RemoveOrganizationMember => {
            only(m, &["account_id"])?;
            Change::OrgMemberRemove(OrgMember {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                subject: subject(ids, text(m, "account_id")?)?,
            })
        }
        Op::CreateInvitation => {
            only(
                m,
                &["email", "inviter_name", "role", "role_version", "days"],
            )?;
            let version = m
                .get("role_version")
                .and_then(Json::as_u64)
                .ok_or(Invalid::Invitation)?;
            let days = match m.get("days") {
                None | Some(Json::Null) => crate::domain::INVITATION_DEFAULT_DAYS,
                Some(d) => d
                    .as_u64()
                    .and_then(|d| u32::try_from(d).ok())
                    .ok_or(Invalid::Invitation)?,
            };
            Change::OrgInvite(OrgInvite {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                email: access_identity_account::app::vault::folded(text(m, "email")?),
                inviter_name: String::from(text(m, "inviter_name")?),
                role: (Name::parse(text(m, "role")?)?, version),
                days,
            })
        }
        Op::PatchOrganization => {
            only(m, &["display_name", "hrd", "autojoin"])?;
            Change::OrgUpdate(OrgUpdate {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                display_name: opt_text(m, "display_name")?.map(String::from),
                hrd: match m.get("hrd") {
                    None | Some(Json::Null) => None,
                    Some(Json::Bool(b)) => Some(*b),
                    Some(_) => return Err(Invalid::Body),
                },
                autojoin: match m.get("autojoin") {
                    None | Some(Json::Null) => None,
                    Some(Json::Object(a)) => {
                        only(a, &["domain", "on"])?;
                        let on = a.get("on").and_then(Json::as_bool).ok_or(Invalid::Body)?;
                        Some((text(a, "domain")?.to_ascii_lowercase(), on))
                    }
                    Some(_) => return Err(Invalid::Body),
                },
            })
        }
        Op::ClaimOrganizationDomain => {
            only(m, &["domain", "method"])?;
            Change::OrgDomainClaim(crate::domain::org::DomainClaim {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                domain: text(m, "domain")?
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                method: crate::domain::org::Method::parse(text(m, "method")?)
                    .ok_or(Invalid::DomainClaim)?,
            })
        }
        Op::ReleaseOrganizationDomain => {
            only(m, &["claim_id"])?;
            Change::OrgDomainRelease {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                claim: ids
                    .decode(DOMAIN_CLAIM_PREFIX, text(m, "claim_id")?)
                    .map_err(|_| Invalid::NoDomain)?,
            }
        }
        // TN-120, OP-153 m.3 (p), OP-155 m.3 (i)
        Op::DraftOrganizationConnection => {
            only(
                m,
                &[
                    "protocol",
                    "issuer",
                    "client_id",
                    "entity_id",
                    "metadata_url",
                ],
            )?;
            let connection = match opt_text(m, "protocol")? {
                None | Some("oidc") => {
                    only(m, &["protocol", "issuer", "client_id"])?;
                    crate::domain::org::DraftConnection::Oidc {
                        issuer: String::from(text(m, "issuer")?),
                        client_id: String::from(text(m, "client_id")?),
                    }
                }
                Some("saml") => {
                    only(m, &["protocol", "entity_id", "metadata_url"])?;
                    crate::domain::org::DraftConnection::Saml {
                        entity_id: String::from(text(m, "entity_id")?),
                        metadata_url: String::from(text(m, "metadata_url")?),
                    }
                }
                Some(_) => return Err(Invalid::SsoDraft),
            };
            Change::OrgSsoDraft(crate::domain::org::SsoDraft {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                connection,
            })
        }
        // TN-94, C10, OP-155 m.3 (i)
        Op::EnforceOrganizationSso => {
            only(m, &["invitations"])?;
            Change::OrgSsoEnforce(crate::domain::sso::SsoEnforcement {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                invites: Some(
                    crate::domain::sso::InviteFate::parse(text(m, "invitations")?)
                        .ok_or(Invalid::Body)?,
                ),
            })
        }
        Op::LiftOrganizationSso => {
            only(m, &[])?;
            Change::OrgSsoEnforce(crate::domain::sso::SsoEnforcement {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                invites: None,
            })
        }
        // TN-134
        Op::CreateOrganizationSetupLink => {
            only(m, &["email"])?;
            Change::OrgSetupLink(crate::domain::sso::SetupLinkOrder {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                email: opt_text(m, "email")?.map(access_identity_account::app::vault::folded),
            })
        }
        Op::RevokeInvitation => {
            only(m, &["invitation_id"])?;
            Change::OrgInviteRevoke {
                org: party_of(key_of(key)?, Invalid::NoOrg)?,
                invitation: ids
                    .decode(INVITATION_PREFIX, text(m, "invitation_id")?)
                    .map_err(|_| Invalid::NoInvitation)?,
            }
        }
        Op::CreateClient => {
            let id = ClientId::parse(text(m, "client_id")?)?;
            Change::ClientRegister(client(id, m)?)
        }
        Op::PutClient => {
            let id = ClientId::parse(key_of(key)?)?;
            if opt_text(m, "client_id")?.is_some_and(|c| c != id.as_str()) {
                return Err(Invalid::ClientId);
            }
            Change::ClientUpdate(client(id, m)?)
        }
        Op::RetireClient => {
            only(m, &[])?;
            Change::ClientRetire(ClientId::parse(key_of(key)?)?)
        }
        Op::RotateClientSecret => {
            only(m, &[])?;
            Change::ClientSecretRotate(ClientId::parse(key_of(key)?)?)
        }
        // OP-155 m.3 (k)
        Op::PutClientProfile
        | Op::PutClientLegacyAuthentication
        | Op::PutClientSigningAlg
        | Op::PutClientEncryption
        | Op::PutClientSamlBearer
        | Op::PutClientLegacyBearer => Change::ClientProfile {
            client: ClientId::parse(key_of(key)?)?,
            delta: profile_delta(op, m)?,
        },
        Op::PutFrontchannelLogout => {
            only(m, &["enabled"])?;
            if !flag(m, "enabled")? {
                return Err(Invalid::ClientProfile);
            }
            Change::FrontchannelLogout
        }
        Op::PutGroup => {
            only(m, &["name", "display_name", "membership_issuer", "status"])?;
            let name = Name::parse(key_of(key)?)?;
            if opt_text(m, "name")?.is_some_and(|n| n != name.as_str()) {
                return Err(Invalid::Name);
            }
            let issuer = opt_text(m, "membership_issuer")?
                .map_or(Ok(MembershipIssuer::Admin), MembershipIssuer::parse)?;
            Change::GroupCreate(Group {
                name,
                display_name: String::from(text(m, "display_name")?),
                issuer,
            })
        }
        Op::RetireGroup => {
            only(m, &[])?;
            Change::GroupRetire(Name::parse(key_of(key)?)?)
        }
        Op::AddGroupMembers | Op::RemoveGroupMembers => {
            only(m, &["account_ids"])?;
            let subjects = texts(m, "account_ids")?
                .iter()
                .map(|s| subject(ids, s))
                .collect::<Result<BTreeSet<_>, _>>()?;
            let members = Members {
                group: Name::parse(key_of(key)?)?,
                subjects,
            };
            if op == Op::AddGroupMembers {
                Change::GroupMembersAdd(members)
            } else {
                Change::GroupMembersRemove(members)
            }
        }
        Op::SuspendAccount | Op::ReactivateAccount => {
            only(m, &[])?;
            let s = subject(ids, key_of(key)?)?;
            if op == Op::SuspendAccount {
                Change::AccountSuspend(s)
            } else {
                Change::AccountReactivate(s)
            }
        }
        Op::PutUpstream => {
            only(
                m,
                &[
                    "name",
                    "issuer",
                    "client_id",
                    "client_secret_ref",
                    "jwks_uri",
                    "ssf",
                    "status",
                    "display_name",
                    "protocol",
                    "subject_key",
                    "client_auth",
                    "preset",
                    "organization",
                    "allow_unsolicited",
                    "saml",
                ],
            )?;
            let name = Name::parse(key_of(key)?)?;
            if opt_text(m, "name")?.is_some_and(|n| n != name.as_str()) {
                return Err(Invalid::Name);
            }
            Change::UpstreamRegister(Upstream {
                name,
                issuer: String::from(text(m, "issuer")?),
                client_id: String::from(text(m, "client_id")?),
                client_secret_ref: opt_text(m, "client_secret_ref")?.map(String::from),
                jwks_uri: String::from(text(m, "jwks_uri")?),
                ssf: match m.get("ssf") {
                    None | Some(Json::Null) => None,
                    Some(v) => Some(
                        crate::domain::realm::TransmitterConfig::parse(v)
                            .map_err(|_| Invalid::Upstream)?,
                    ),
                },
                profile: Box::new(upstream_profile(m)?),
            })
        }
        Op::RetireUpstream => {
            only(m, &[])?;
            Change::UpstreamRetire(Name::parse(key_of(key)?)?)
        }
        Op::LinkUpstreamSubject => {
            only(m, &["sub", "account_id"])?;
            Change::UpstreamLink(UpstreamLink {
                upstream: Name::parse(key_of(key)?)?,
                sub: String::from(text(m, "sub")?),
                account: subject(ids, text(m, "account_id")?)?,
            })
        }
        Op::PutSigninPolicy => {
            only(
                m,
                &[
                    "methods",
                    "required_fields",
                    "mfa_required",
                    "domain_allow",
                    "domain_deny",
                    "enumeration",
                    "email_keep_days",
                    "dbsc",
                    "profile",
                ],
            )?;
            let set = |k| -> Result<BTreeSet<String>, Invalid> {
                Ok(texts(m, k)?.into_iter().map(String::from).collect())
            };
            Change::SigninPolicy(SigninPolicy {
                methods: texts(m, "methods")?
                    .into_iter()
                    .map(SigninMethod::parse)
                    .collect::<Result<_, _>>()?,
                required_fields: set("required_fields")?,
                mfa_required: flag(m, "mfa_required")?,
                domain_allow: set("domain_allow")?,
                domain_deny: set("domain_deny")?,
                // OP-153 m.3 (i), (j)
                enumeration: match m.get("enumeration") {
                    None => EnumerationMode::Uniform,
                    Some(Json::String(s)) => {
                        EnumerationMode::parse(s).ok_or(Invalid::SigninPolicy)?
                    }
                    Some(_) => return Err(Invalid::SigninPolicy),
                },
                email_keep_days: match m.get("email_keep_days") {
                    None | Some(Json::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .and_then(|d| u32::try_from(d).ok())
                            .ok_or(Invalid::SigninPolicy)?,
                    ),
                },
                // OP-153 m.22 (c), m.25 (b)
                dbsc: match m.get("dbsc") {
                    None => true,
                    Some(Json::Bool(b)) => *b,
                    Some(_) => return Err(Invalid::SigninPolicy),
                },
                // OP-156 m.3 (e)
                profile: match m.get("profile") {
                    None => AssuranceProfile::Standard,
                    Some(Json::String(s)) => {
                        AssuranceProfile::parse(s).ok_or(Invalid::SigninPolicy)?
                    }
                    Some(_) => return Err(Invalid::SigninPolicy),
                },
            })
        }
        Op::PutSessionPolicy => {
            only(m, &["absolute_ms", "idle_ms", "binding"])?;
            Change::SessionPolicy(SessionPolicy {
                absolute_ms: ms_text(m.get("absolute_ms").ok_or(Invalid::Body)?)?,
                idle_ms: ms_text(m.get("idle_ms").ok_or(Invalid::Body)?)?,
                binding: Binding::parse(text(m, "binding")?).ok_or(Invalid::SessionPolicy)?,
            })
        }
        Op::PutBranding => {
            only(
                m,
                &[
                    "display_name",
                    "logo_uri",
                    "primary_color",
                    "background_color",
                    "csp_origins",
                ],
            )?;
            Change::Branding(Branding {
                display_name: opt_text(m, "display_name")?.map(String::from),
                logo_uri: opt_text(m, "logo_uri")?.map(String::from),
                primary_color: opt_text(m, "primary_color")?
                    .map(Color::parse)
                    .transpose()?,
                background_color: opt_text(m, "background_color")?
                    .map(Color::parse)
                    .transpose()?,
                csp_origins: texts(m, "csp_origins")?
                    .into_iter()
                    .map(String::from)
                    .collect(),
            })
        }
        // TN-85, OP-153 m.19 (d), m.25 (b)
        Op::ImportAccounts => {
            only(m, &["file", "accounts", "content"])?;
            Change::AccountImport(crate::domain::accounts::AccountImport {
                file: b64url_decode(text(m, "file")?)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .ok_or(Invalid::Body)?,
                accounts: m
                    .get("accounts")
                    .and_then(Json::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(Invalid::Body)?,
            })
        }
        // E53, OP-153 m.20 (g), m.25 (b), (c)
        Op::RecordGuardianship => {
            use access_identity_account::domain::claim_classes::GuardianshipBasis;
            only(m, &["guardian_account_id", "basis", "country"])?;
            Change::GuardianshipRecord(crate::domain::accounts::GuardianshipRecord {
                guardian: subject(ids, text(m, "guardian_account_id")?)?,
                ward: subject(ids, key_of(key)?)?,
                basis: match text(m, "basis")? {
                    "parent" => GuardianshipBasis::Parent,
                    "legal_guardian" => GuardianshipBasis::LegalGuardian,
                    _ => return Err(Invalid::Body),
                },
                country: String::from(text(m, "country")?),
            })
        }
        Op::RegisterAgent
        | Op::PatchAgent
        | Op::RetireAgent
        | Op::AssignAgentSponsor
        | Op::RemoveAgentSponsor
        | Op::DefineAgentTemplate
        | Op::PutVaultResource
        | Op::DisableVaultResource
        | Op::PutVaultReleaseMode
        | Op::RegisterScimClient
        | Op::RotateScimSecret
        | Op::RetireScimClient
        | Op::RegisterScimTarget
        | Op::RetireScimTarget
        | Op::PutFederation
        | Op::AddTrustAnchor
        | Op::RemoveTrustAnchor
        | Op::PutFederationAuthority
        | Op::PutFederationRegistration
        | Op::RegisterSamlSp
        | Op::PutSamlSp
        | Op::RetireSamlSp
        | Op::PutSamlCertificatePolicy
        | Op::ReplaceSamlCertificate
        | Op::RegisterGateway
        | Op::RetireGateway
        | Op::RegisterDomain
        | Op::RetireDomain
        | Op::BindDomainIssuer
        | Op::PutSshCa
        | Op::RotateSshCa
        | Op::ReplaceSshCa
        | Op::RegisterSshHostGroup
        | Op::RetireSshHostGroup
        | Op::RegisterSignalSource
        | Op::RetireSignalSource
        | Op::RegisterProxy
        | Op::PutProxy
        | Op::RetireProxy
        | Op::PutProxyPlainHeaders
        | Op::RegisterExportSink
        | Op::PutExportSink
        | Op::RetireExportSink
        | Op::RegisterLinuxHost
        | Op::RetireLinuxHost
        | Op::PutLinuxOfflinePolicy
        | Op::PutLinuxBreakGlassPolicy
        | Op::RegisterHrSource
        | Op::RetireHrSource
        | Op::ImportHrBatch
        | Op::ImportHrCsv
        | Op::RegisterHrConnector
        | Op::RetireHrConnector
        | Op::PinMcpTools => return Err(Invalid::Body),
        // OP-153 m.18 (e), m.25 (b)
        Op::BindAccount => {
            only(
                m,
                &["peer_realm", "peer_realm_id", "peer_account_id", "offer"],
            )?;
            Change::AccountBind(crate::domain::accounts::AccountBind {
                subject: subject(ids, key_of(key)?)?,
                peer_realm: party_of(text(m, "peer_realm_id")?, Invalid::NoAccount)?,
                peer_subject: subject(ids, text(m, "peer_account_id")?)?,
                offer: opt_text(m, "offer")?.map(|o| suiss_crypto::digest::sha256(o.as_bytes())),
            })
        }
        // TN-86, OP-153 m.19 (d), m.25 (b)
        Op::ExportAccounts => {
            only(m, &["recipient"])?;
            Change::MigrationExport(crate::domain::accounts::MigrationExport {
                recipient: b64url_decode(text(m, "recipient")?).map_err(|_| Invalid::Body)?,
            })
        }
        // OP-153 m.22 (g), m.25 (b)
        Op::PutCspMode => {
            only(m, &["csp_mode"])?;
            Change::CspMode {
                mode: crate::domain::accounts::CspMode::parse(text(m, "csp_mode")?)
                    .ok_or(Invalid::Branding)?,
                loosens: false,
            }
        }
        // TN-18, OP-153 m.22 (k), m.25 (b)
        Op::PutRelatedOrigins => {
            only(m, &["origins"])?;
            Change::RelatedOrigins(crate::domain::RelatedOrigins {
                origins: texts(m, "origins")?.into_iter().map(String::from).collect(),
            })
        }
        // X35, OP-153 m.22 (k), m.25 (b)
        Op::PutLocaleOverrides => {
            only(m, &["overrides"])?;
            let mut by_locale = std::collections::BTreeMap::new();
            match m.get("overrides") {
                None | Some(Json::Null) => {}
                Some(Json::Object(locales)) => {
                    for (locale, keys) in locales {
                        let keys = keys.as_object().ok_or(Invalid::LocaleOverrides)?;
                        let mut by_key = std::collections::BTreeMap::new();
                        for (k, v) in keys {
                            let v = v.as_str().ok_or(Invalid::LocaleOverrides)?;
                            by_key.insert(k.clone(), String::from(v));
                        }
                        by_locale.insert(locale.to_ascii_lowercase(), by_key);
                    }
                }
                Some(_) => return Err(Invalid::LocaleOverrides),
            }
            Change::LocaleOverrides(crate::domain::LocaleOverrides { texts: by_locale })
        }
        Op::PutRpId => {
            only(m, &["rp_id", "acknowledge_passkey_loss"])?;
            Change::RpId(RpId::parse(text(m, "rp_id")?)?)
        }
        // OP-150 m.11 (b), TN-61
        Op::DeleteAccount => {
            only(m, &[])?;
            Change::AccountDelete(subject(ids, key_of(key)?)?)
        }
        Op::RehomeRealm => return Err(Invalid::Reserved),
        // TN-61
        Op::ResetIntent => {
            only(m, &["ttl_s"])?;
            Change::AccountResetIntent {
                subject: subject(ids, key_of(key)?)?,
                ttl_ms: seconds(m, "ttl_s", recovery_policy::INTENT_TTL_MS)?,
            }
        }
        // TN-62
        Op::IssueTap => {
            only(m, &["ttl_s", "length", "one_time"])?;
            let length = match m.get("length") {
                None | Some(Json::Null) => recovery_policy::TAP_LENGTH,
                Some(v) => v
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or(Invalid::Body)?,
            };
            Change::AccountTapIssue(crate::domain::TapIssue {
                subject: subject(ids, key_of(key)?)?,
                ttl_ms: seconds(m, "ttl_s", recovery_policy::TAP_TTL_MS)?,
                length: u8::try_from(length).map_err(|_| Invalid::Body)?,
                one_time: match m.get("one_time") {
                    None | Some(Json::Null) => true,
                    Some(Json::Bool(b)) => *b,
                    Some(_) => return Err(Invalid::Body),
                },
            })
        }
        // TN-55, OP-153 m.3 (e)
        Op::PutRecoveryPolicy => {
            let mut body = m.clone();
            body.remove(VALIDITY);
            body.remove("ais");
            let policy: recovery_policy::RecoveryPolicy =
                serde_json::from_value(Json::Object(body)).map_err(|_| Invalid::RecoveryPolicy)?;
            Change::RecoveryPolicy {
                policy,
                loosens: false,
            }
        }
        Op::PutJoseAlg => {
            only(m, &["alg"])?;
            Change::JoseAlg(JoseAlg::from_name(text(m, "alg")?).ok_or(Invalid::JoseAlg)?)
        }
        // OP-154 m.3 (p)
        Op::PutDeviceCode => {
            only(m, &["enabled"])?;
            Change::DeviceCode(flag(m, "enabled")?)
        }
        // OP-156 m.3 (d)
        Op::PutPush => {
            only(m, &["enabled"])?;
            Change::Push(flag(m, "enabled")?)
        }
        // OP-156 m.3 (f)
        Op::PutSmsOtp => {
            only(m, &["enabled"])?;
            Change::SmsOtp(flag(m, "enabled")?)
        }
        // OP-156 m.3 (g)
        Op::PutSpc => {
            only(m, &["enabled"])?;
            Change::Spc(flag(m, "enabled")?)
        }
        // OP-155 m.3 (l)
        Op::PutCiba => {
            only(m, &["enabled", "login_hint", "ping"])?;
            let ping = match m.get("ping") {
                None | Some(Json::Null) => Vec::new(),
                Some(Json::Array(a)) => a
                    .iter()
                    .map(|p| {
                        let p = p.as_object().ok_or(Invalid::Body)?;
                        only(p, &["client_id", "endpoint"])?;
                        Ok((
                            ClientId::parse(text(p, "client_id")?)?,
                            String::from(text(p, "endpoint")?),
                        ))
                    })
                    .collect::<Result<Vec<_>, Invalid>>()?,
                Some(_) => return Err(Invalid::Body),
            };
            Change::Ciba(crate::domain::CibaSetting {
                enabled: flag(m, "enabled")?,
                login_hint: flag(m, "login_hint")?,
                ping,
            })
        }
        // OP-156 m.3 (t)
        Op::PutCoordinator => {
            only(m, &["attention_url"])?;
            Change::Coordinator(match m.get("attention_url") {
                None | Some(Json::Null) => None,
                Some(Json::String(u)) => Some(u.clone()),
                Some(_) => return Err(Invalid::Body),
            })
        }
        // OP-155 m.3 (m)
        Op::PutCertificateLogin => {
            only(m, &["enabled", "rule", "anchors", "piv_policies"])?;
            let rule = access_identity_x509::domain::login::Rule::parse(text(m, "rule")?)
                .ok_or(Invalid::CertificateLogin)?;
            let anchors = texts(m, "anchors")?
                .into_iter()
                .map(|a| {
                    access_kernel::json::b64url_decode(a).map_err(|_| Invalid::CertificateLogin)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Change::CertificateLogin(crate::domain::certificate::CertificateLogin {
                enabled: flag(m, "enabled")?,
                rule,
                anchors,
                piv_policies: texts(m, "piv_policies")?
                    .into_iter()
                    .map(String::from)
                    .collect(),
            })
        }
        Op::PutMtlsAliases => {
            only(m, &["published"])?;
            Change::MtlsAliases(flag(m, "published")?)
        }
        // OP-155 m.3 (f)
        Op::RegisterRadiusClient => {
            only(m, &["client", "certificate"])?;
            let gateway = crate::domain::gateway::key_of_kind(
                key_of(key)?,
                access_internal_api::edge::GatewayKind::Radius,
            )?;
            let der = b64url_decode(text(m, "certificate")?).map_err(|_| Invalid::Gateway)?;
            Change::GatewayRadiusClientRegister(crate::domain::gateway::RadiusClient::new(
                gateway,
                text(m, "client")?,
                &der,
            )?)
        }
        // OP-155 m.3 (o)
        Op::PutKeytabPolicy => {
            only(m, &["spn", "rotate_days"])?;
            let gateway = crate::domain::gateway::key_of_kind(
                key_of(key)?,
                access_internal_api::edge::GatewayKind::Kerberos,
            )?;
            let rotate_days = m
                .get("rotate_days")
                .and_then(Json::as_u64)
                .and_then(|d| u16::try_from(d).ok())
                .ok_or(Invalid::Gateway)?;
            Change::GatewayKeytabPolicy(crate::domain::gateway::KeytabPolicy {
                gateway,
                spn: String::from(text(m, "spn")?),
                rotate_days,
            })
        }
        Op::ReplaceKeytab => {
            only(m, &["kvno"])?;
            let gateway = crate::domain::gateway::key_of_kind(
                key_of(key)?,
                access_internal_api::edge::GatewayKind::Kerberos,
            )?;
            let kvno = m
                .get("kvno")
                .and_then(Json::as_u64)
                .and_then(|k| u32::try_from(k).ok())
                .ok_or(Invalid::Gateway)?;
            Change::GatewayKeytabEmergency { gateway, kvno }
        }
        // TN-98, OP-155 m.3 (h)
        Op::PutHrd => {
            only(m, &["enabled"])?;
            Change::Hrd(flag(m, "enabled")?)
        }
        // OP-156 m.3 (c), IDP-37 (4)
        Op::PutIys => {
            only(m, &["enabled", "recipient_type"])?;
            Change::Iys {
                enabled: flag(m, "enabled")?,
                recipient_type: match m.get("recipient_type") {
                    None => String::from("individual"),
                    Some(Json::String(t)) => t.clone(),
                    Some(_) => return Err(Invalid::Body),
                },
            }
        }
        // OP-153 m.3 (ee)
        Op::PutPreferenceTopics => {
            only(m, &["topics"])?;
            let Some(Json::Array(list)) = m.get("topics") else {
                return Err(Invalid::Body);
            };
            Change::PreferenceTopics(
                list.iter()
                    .map(|t| t.as_str().map(String::from).ok_or(Invalid::Body))
                    .collect::<Result<_, _>>()?,
            )
        }
        // IDP-27, OP-155 m.3 (h)
        Op::PutUpstreamAssuranceMap => {
            only(m, &["entries"])?;
            Change::UpstreamAssuranceMap {
                name: Name::parse(key_of(key)?)?,
                map: Box::new(
                    serde_json::from_value(Json::Object(m.clone()))
                        .map_err(|_| Invalid::Upstream)?,
                ),
            }
        }
        // OP-154 m.3 (j)
        Op::PutDcrPolicy => {
            only(m, &["enabled", "domains", "initial_access_tokens"])?;
            let mut tokens = std::collections::BTreeSet::new();
            for t in texts(m, "initial_access_tokens")? {
                let d = access_kernel::json::b64url_decode(t)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(Invalid::DcrPolicy)?;
                tokens.insert(d);
            }
            Change::DcrPolicy {
                policy: access_identity_oauth::domain::dcr::DcrPolicy {
                    enabled: flag(m, "enabled")?,
                    domains: texts(m, "domains")?.into_iter().map(String::from).collect(),
                    tokens,
                },
                loosens: true,
            }
        }
        // AG-8, OP-154 m.3 (a)
        // OP-154 m.3 (n), AG-28
        Op::CreateCrossAppConnection => {
            only(
                m,
                &[
                    "connection",
                    "client_id",
                    "audience",
                    "resource",
                    "scopes",
                    "subject_policy",
                ],
            )?;
            if opt_text(m, "subject_policy")?.is_some_and(|p| p != "pairwise") {
                return Err(Invalid::CrossAppConnection);
            }
            Change::CrossAppConnection(crate::domain::CrossAppConnection {
                name: String::from(text(m, "connection")?),
                client_id: String::from(text(m, "client_id")?),
                audience: String::from(text(m, "audience")?),
                resource: String::from(text(m, "resource")?),
                scopes: texts(m, "scopes")?.into_iter().map(String::from).collect(),
            })
        }
        Op::RetireCrossAppConnection => {
            only(m, &[])?;
            Change::CrossAppConnectionRetire(String::from(key_of(key)?))
        }
        Op::RegisterProtectedResource => {
            only(m, &["resource", "display_name"])?;
            Change::ResourceRegister(crate::domain::ProtectedResource {
                resource: String::from(text(m, "resource")?),
                display_name: String::from(text(m, "display_name")?),
            })
        }
        Op::PutCimdPolicy => {
            only(m, &["enabled", "domains"])?;
            Change::CimdPolicy(CimdPolicy {
                enabled: flag(m, "enabled")?,
                domains: texts(m, "domains")?.into_iter().map(String::from).collect(),
            })
        }
        Op::PutProtectionMode => {
            const PROTECTIONS: [&str; 4] =
                ["bot", "suspicious_ip", "breached_password", "brute_force"];
            only(
                m,
                &[
                    "bot",
                    "suspicious_ip",
                    "breached_password",
                    "brute_force",
                    "sl2",
                    "denied_asns",
                ],
            )?;
            let mut values = Vec::new();
            for p in PROTECTIONS {
                if let Some(v) = opt_text(m, p)? {
                    values.push((p, v));
                }
            }
            let asns = match m.get("denied_asns") {
                None | Some(Json::Null) => Vec::new(),
                Some(Json::Array(a)) => a
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or(Invalid::ProtectionMode)
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(Invalid::ProtectionMode),
            };
            let mode = ProtectionMode::parse(&values, text(m, "sl2")?, &asns)
                .map_err(|_| Invalid::ProtectionMode)?;
            Change::ProtectionMode {
                mode,
                loosens: false,
            }
        }
        Op::MarkCanary => {
            only(m, &[])?;
            Change::AccountCanary(subject(ids, key_of(key)?)?)
        }
        // OP-156 m.3 (c)
        Op::PutSecurityNotices => {
            only(m, &["enabled"])?;
            Change::SecurityNotices(flag(m, "enabled")?)
        }
        Op::ResendRelay => {
            only(m, &[])?;
            Change::RelayResend(super::relay::event_id(key_of(key)?)?)
        }
        Op::PutMapper => {
            only(m, &["claim", "source"])?;
            let claim = ClaimName::parse(key_of(key)?)?;
            Change::MapperSet {
                claim,
                source: opt_text(m, "source")?.map(Attribute::parse).transpose()?,
            }
        }
        Op::RegisterHook => {
            only(
                m,
                &[
                    "hook_id",
                    "point",
                    "url",
                    "on_no_answer",
                    "disclose",
                    "signing",
                ],
            )?;
            let id = extension_id(ids, HOOK_PREFIX, text(m, "hook_id")?, Invalid::Body)?;
            let spec = HookSpec {
                point: HookPoint::from_name(text(m, "point")?).ok_or(Invalid::Hook)?,
                url: String::from(text(m, "url")?),
                on_no_answer: OnNoAnswer::from_name(
                    opt_text(m, "on_no_answer")?.unwrap_or("refuse"),
                )
                .ok_or(Invalid::Hook)?,
                disclose: disclosures(&texts(m, "disclose")?, Invalid::Hook)?,
                signing: Signing::from_name(opt_text(m, "signing")?.unwrap_or("ed25519"))
                    .ok_or(Invalid::Hook)?,
            };
            Change::Hook(HookChange::Register { id, spec })
        }
        Op::RetireHook => {
            only(m, &[])?;
            let id = extension_id(ids, HOOK_PREFIX, key_of(key)?, Invalid::NoHook)?;
            Change::Hook(HookChange::Retire { id })
        }
        Op::RegisterWebhook => {
            only(m, &["webhook_id", "url", "events", "signing"])?;
            let id = extension_id(ids, WEBHOOK_PREFIX, text(m, "webhook_id")?, Invalid::Body)?;
            let spec = WebhookSpec {
                url: String::from(text(m, "url")?),
                events: events(m)?,
                signing: Signing::from_name(opt_text(m, "signing")?.unwrap_or("ed25519"))
                    .ok_or(Invalid::Hook)?,
            };
            Change::Webhook(WebhookChange::Register { id, spec })
        }
        Op::PutWebhook => {
            only(m, &["webhook_id", "url", "events", "status"])?;
            let k = key_of(key)?;
            let id = extension_id(ids, WEBHOOK_PREFIX, k, Invalid::NoWebhook)?;
            if opt_text(m, "webhook_id")?.is_some_and(|w| w != k) {
                return Err(Invalid::Body);
            }
            Change::Webhook(WebhookChange::Update {
                id,
                url: String::from(text(m, "url")?),
                events: events(m)?,
                rotate: false,
            })
        }
        Op::RotateWebhookKey => {
            only(m, &[])?;
            let id = extension_id(ids, WEBHOOK_PREFIX, key_of(key)?, Invalid::NoWebhook)?;
            Change::Webhook(WebhookChange::Update {
                id,
                url: String::new(),
                events: Vec::new(),
                rotate: true,
            })
        }
        Op::RetireWebhook => {
            only(m, &[])?;
            let id = extension_id(ids, WEBHOOK_PREFIX, key_of(key)?, Invalid::NoWebhook)?;
            Change::Webhook(WebhookChange::Retire { id })
        }
        Op::PutExtensionPolicy => {
            only(m, &["allow_private_targets", "hook_disclosure"])?;
            Change::ExtensionPolicy(ExtensionPolicy {
                allow_private_targets: flag(m, "allow_private_targets")?,
                hook_disclosure: disclosures(
                    &texts(m, "hook_disclosure")?,
                    Invalid::ExtensionPolicy,
                )?,
            })
        }
    })
}

/// The passkey loss an RP ID change acknowledges: `acknowledge_passkey_loss` as the decimal
/// count (IDI-4).
#[must_use]
pub fn acknowledged_passkeys(body: &Json) -> Option<u64> {
    body.get("acknowledge_passkey_loss")
        .and_then(|v| ms_text(v).ok())
}

/// A workload client's view: its registration beside the client's (OP-154 m.3 (r)).
#[must_use]
pub fn workload_client_view(
    c: &ClientRow,
    w: Option<&access_store::workloads::ClientWorkload>,
) -> Json {
    let mut v = client_view(c);
    if let (Some(w), Some(o)) = (w, v.as_object_mut()) {
        o.insert(String::from("spiffe_id"), json!(w.spiffe_id));
        o.insert(
            String::from("spiffe_bundle_endpoint"),
            json!(w.bundle_endpoint),
        );
        o.insert(String::from("agent"), json!(b64url_encode(&w.agent)));
    }
    v
}

/// A client's view: no secret, ever (CR-38).
#[must_use]
pub fn client_view(c: &ClientRow) -> Json {
    json!({
        "client_id": c.client_id,
        "display_name": c.display_name,
        "token_endpoint_auth_method": c.auth_method,
        "jwks_uri": c.jwks_uri,
        "redirect_uris": c.redirect_uris,
        "post_logout_redirect_uris": c.post_logout_redirect_uris,
        "backchannel_logout_uri": c.backchannel_logout_uri,
        "require_pushed_authorization_requests": c.require_par,
        "platform_product": c.platform_product,
        "subject_type": if c.public_sub { "public" } else { "pairwise" },
        "public_sub_opt_in": c.public_sub,
        "third_party": c.third_party,
        "sector_identifier_uri": c.sector_identifier_uri,
        "status": if c.active { "active" } else { "retired" },
    })
}

/// A group's view.
#[must_use]
pub fn group_view(g: &GroupRow) -> Json {
    json!({
        "name": g.name,
        "display_name": g.display_name,
        "membership_issuer": g.membership_issuer,
        "status": if g.active { "active" } else { "retired" },
    })
}

/// An upstream registration's profile fields (OP-155 m.3 (h)); omitted ones take the
/// profile's defaults: OIDC, `sub`, `private_key_jwt` (or `client_secret_post` when a secret
/// reference is given), no preset, no organization, unsolicited SAML refused.
fn upstream_profile(
    m: &Map<String, Json>,
) -> Result<access_identity_federation::domain::connection::Profile, Invalid> {
    use access_identity_federation::domain::connection::Profile;
    let has_secret = opt_text(m, "client_secret_ref")?.is_some();
    let mut fields = Map::new();
    for k in [
        "display_name",
        "protocol",
        "subject_key",
        "client_auth",
        "preset",
        "organization",
        "allow_unsolicited",
        "saml",
    ] {
        if let Some(v) = m.get(k).filter(|v| !v.is_null()) {
            fields.insert(String::from(k), v.clone());
        }
    }
    if !fields.contains_key("client_auth") {
        fields.insert(
            String::from("client_auth"),
            json!(Profile::legacy(has_secret).client_auth.name()),
        );
    }
    serde_json::from_value(Json::Object(fields)).map_err(|_| Invalid::Upstream)
}

/// An upstream provider's view: the secret only by its reference.
#[must_use]
pub fn upstream_view(u: &UpstreamRow) -> Json {
    let profile = access_identity_federation::domain::connection::Profile::stored(
        u.profile.as_deref(),
        u.client_secret_ref.is_some(),
    )
    .ok();
    let mut v = json!({
        "name": u.name,
        "issuer": u.issuer,
        "client_id": u.client_id,
        "client_secret_ref": u.client_secret_ref,
        "jwks_uri": u.jwks_uri,
        "ssf": u.ssf.as_deref().and_then(|s| serde_json::from_str::<Json>(s).ok()),
        "status": if u.active { "active" } else { "retired" },
    });
    if let (Some(o), Some(Json::Object(p))) = (
        v.as_object_mut(),
        profile.map(|p| serde_json::to_value(p).unwrap_or_default()),
    ) {
        o.extend(p);
    }
    v
}

/// Whether a client is a native app: a redirect URI with a private-use scheme or a loopback
/// address (RFC 8252).
fn native(c: &ClientRow) -> bool {
    c.active
        && c.redirect_uris.iter().any(|u| {
            !u.starts_with("https://")
                && (!u.starts_with("http://")
                    || u.starts_with("http://127.0.0.1")
                    || u.starts_with("http://[::1]"))
        })
}

/// A social preset's view: the secret only by its reference, and its warnings (TN-87,
/// IDP-31 (5)); a warning never refuses anything.
#[must_use]
pub fn social_view(s: &SocialRow, apple_recommended: bool) -> Json {
    use access_identity_federation::domain::rules::{APPLE_TRANSFER_MS, Warning};
    let mut warnings = Vec::new();
    if let Some(at) = s.client_changed_ms {
        warnings.push(json!({ "code": Warning::ClientIdChanged.code(), "at": rfc3339(at) }));
        if s.preset == access_identity_federation::domain::rules::APPLE {
            let until = at.saturating_add(APPLE_TRANSFER_MS);
            warnings.push(json!({ "code": Warning::AppleTransferUntil(until).code(), "until": rfc3339(until) }));
        }
    }
    if apple_recommended && s.active {
        warnings.push(json!({ "code": Warning::AppleRecommended.code() }));
    }
    json!({
        "preset": s.preset,
        "client_id": s.client_id,
        "client_secret_ref": s.client_secret_ref,
        "shared_development_client": s.client_id.is_none(),
        "status": if s.active { "active" } else { "disabled" },
        "warnings": warnings,
    })
}

/// An account's view: its state, never a credential (TN-61, §12.3.1).
#[must_use]
pub fn account_view(a: &AccountRow, ids: &IdKey) -> Json {
    json!({
        "account_id": ids.encode(SUBJECT_PREFIX, a.subject).unwrap_or_default(),
        "status": a.status,
        "status_at": rfc3339(a.status_at_ms),
        "created_at": rfc3339(a.created_at_ms),
    })
}

/// The realm's protection mode as the settings view shows it (OP-151 m.3 (o)); brute-force
/// protection is always `enforce`.
#[must_use]
pub fn protection_view(m: &ProtectionMode) -> Json {
    json!({
        "bot": m.bot.name(),
        "suspicious_ip": m.suspicious_ip.name(),
        "breached_password": m.breached_password.name(),
        "brute_force": "enforce",
        "sl2": m.sl2.name(),
        "denied_asns": m.denied_asns.iter().collect::<Vec<_>>(),
    })
}

/// A hook's view: the Ed25519 public key it signs with, never the key itself (TN-61).
#[must_use]
pub fn hook_view(h: &HookListing, ids: &IdKey) -> Json {
    json!({
        "hook_id": ids.encode(HOOK_PREFIX, h.id).unwrap_or_default(),
        "point": h.point,
        "url": h.url,
        "on_no_answer": h.on_no_answer,
        "disclose": h.disclose,
        "signing": h.signing,
        "public_key": h.public_key.map(|k| access_crypto::webhook::WebhookPublicKey::from_bytes(k).text()),
        "status": if h.active { "active" } else { "retired" },
    })
}

/// A webhook's view, without key material (TN-61).
#[must_use]
pub fn webhook_view(w: &WebhookListing, ids: &IdKey) -> Json {
    json!({
        "webhook_id": ids.encode(WEBHOOK_PREFIX, w.webhook.id).unwrap_or_default(),
        "url": w.webhook.url,
        "events": w.webhook.events,
        "signing": w.webhook.signing,
        "status": if w.webhook.active { "active" } else { "retired" },
    })
}

/// Deterministic CBOR of a stored policy as JSON: maps, text, booleans, arrays; integers up to
/// 2^53 as numbers.
#[must_use]
pub fn cbor_json(v: &Value) -> Json {
    match v {
        Value::Unsigned(n) if *n <= (1 << 53) => json!(n),
        Value::Unsigned(n) => json!(n.to_string()),
        Value::Text(s) => json!(s),
        Value::Bool(b) => json!(b),
        Value::Bytes(b) => json!(b64url_encode(b)),
        Value::Array(a) => Json::Array(a.iter().map(cbor_json).collect()),
        Value::Map(m) => Json::Object(
            m.iter()
                .filter_map(|(k, v)| match k {
                    Value::Text(k) => Some((k.clone(), cbor_json(v))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Negative(_) | Value::Tag(..) => Json::Null,
    }
}

fn stored(bytes: Option<&[u8]>, default: &Value) -> Json {
    bytes
        .and_then(|b| dcbor::decode(b, Limits::CEILING).ok())
        .map_or_else(|| cbor_json(default), |v| cbor_json(&v))
}

/// The default sign-in requirements (TN-132): email, no MFA requirement, open registration.
#[must_use]
pub fn default_signin() -> SigninPolicy {
    SigninPolicy {
        methods: BTreeSet::from([SigninMethod::Email, SigninMethod::Passkey]),
        required_fields: BTreeSet::from([String::from("email")]),
        mfa_required: false,
        domain_allow: BTreeSet::new(),
        domain_deny: BTreeSet::new(),
        enumeration: EnumerationMode::Uniform,
        email_keep_days: None,
        dbsc: true,
        profile: AssuranceProfile::Standard,
    }
}

/// What one read returned: views with their `ETag` positions, and the natural key the next page
/// starts after.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Read {
    /// The views and their positions.
    pub items: Vec<(Json, u64)>,
    /// The last item's natural key, when the page is full.
    pub last: Option<String>,
}

/// A readable collection or singleton.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Clients.
    Clients,
    /// Groups.
    Groups,
    /// Accounts.
    Accounts,
    /// Upstream identity providers.
    Upstreams,
    /// The realm settings singleton.
    Settings,
    /// Inline hooks (TN-135).
    Hooks,
    /// Webhooks (TN-136).
    Webhooks,
    /// The realm's signal sources (§8.13, OP-151 m.19 (e)): inbound transmitters and verifier
    /// reports; the process adds its `GeoIP` source's state.
    Signals,
    /// The realm's daily sign-in analytics of the last [`ANALYTICS_DAYS`] days (IDP-36).
    Analytics,
    /// One webhook's delivery log, by its `webhook_id` (TN-136): no event body.
    Deliveries,
    /// The social presets the realm enabled, with their warnings (IDP-31, TN-87).
    Socials,
    /// Organizations by their Party's base64url, each with its members and roots, domain
    /// claims, ownership handovers and connection drafts (§8.5 S7, §12.3.8, OP-153 m.10 (c)).
    Organizations,
    /// Agents by their Party's base64url: the registry (OP-154 m.3 (e), AG-41).
    Agents,
    /// One agent's sponsorship episodes, by the agent's Party (AG-41, SI-21).
    AgentSponsors,
    /// The vault Resources by name (OP-154 m.3 (t)): never a client secret.
    VaultResources,
    /// The SAML service providers and WS-Federation relying parties by name (OP-155 m.3 (e)).
    SamlSps,
    /// The SSH server groups by name (OP-156 m.3 (o)).
    SshHostGroups,
    /// The signal sources by name (OP-156 m.3 (r)).
    SignalSources,
    /// The forward-auth proxies by name (OP-156 m.3 (l)).
    Proxies,
    /// The export sinks by name, with their delivery state (OP-156 m.3 (s)).
    ExportSinks,
    /// The Linux client hosts by name (OP-156 m.3 (p)).
    LinuxHosts,
    /// The HR sources by name (OP-156 m.3 (q)).
    HrSources,
    /// The HR connectors by name (OP-156 m.3 (q)).
    HrConnectors,
    /// The protected resources by canonical URI (AG-8).
    ProtectedResources,
    /// The trust anchors by the base64url of their entity identifier (OP-155 m.3 (j)).
    TrustAnchors,
    /// What enforcing SSO on one organization would end (TN-94, X20, OP-155 m.3 (i)).
    SsoPreview,
    /// The realm's custom domains by host (OP-156 m.3 (i)).
    CustomDomains,
    /// The undelivered Relay messages by event id, without their content (OP-156 m.3 (c)).
    RelayUndelivered,
}

/// How many days the analytics read covers, today included (PD).
pub const ANALYTICS_DAYS: u32 = 30;

/// One day, `YYYY-MM-DD`, of days since the Unix epoch.
fn day_text(day: u32) -> String {
    rfc3339(u64::from(day).saturating_mul(86_400_000))
        .get(..10)
        .map(String::from)
        .unwrap_or_default()
}

/// The analytics view: per day the funnel's ends, adoption and methods; surge alerts (IDP-36).
fn analytics_view(r: &access_identity_risk::app::analytics::Report) -> Json {
    json!({
        "days": r.days.iter().map(|d| json!({
            "day": day_text(d.day),
            "started": d.flows_started,
            "completed": d.sessions_created,
            "failed": d.failed_logins,
            "active_accounts": d.accounts_active,
            "passkey_accounts": d.accounts_with_passkey,
            "mfa_accounts": d.accounts_with_mfa,
            "legacy_password_accounts": d.legacy_password_accounts,
            "mfa_setup": d.mfa_setup_completed,
            "methods": {
                "password": d.method_password,
                "passkey": d.method_passkey,
                "email_code": d.method_email_code,
                "magic_link": d.method_magic_link,
            },
        })).collect::<Vec<_>>(),
        "surges": r.surges.iter().map(|a| json!({
            "day": day_text(a.day),
            "failed": a.observed,
            "baseline": a.baseline,
        })).collect::<Vec<_>>(),
    })
}

/// The delivery log view of one row: no event body (TN-136).
fn delivery_view(d: &access_store::extensions::DeliveryLogRow) -> Json {
    json!({
        "event_id": d.event_id,
        "event": d.event_type.strip_prefix("urn:suiss:access:event:").unwrap_or(&d.event_type),
        "state": d.state,
        "attempts": d.attempts,
        "last_status": d.last_status,
        "last_latency_ms": d.last_latency_ms,
        "last_reason": d.last_reason,
        "occurred_at": rfc3339(d.occurred_ms),
        "queued_at": rfc3339(d.queued_ms),
    })
}

/// A stored signed Unix-ms time as RFC 3339.
fn at_ms(ms: i64) -> String {
    rfc3339(u64::try_from(ms).unwrap_or(0))
}

/// An organization in a list (OP-153 m.10 (c)): its external id is its Party's base64url.
fn organization_summary(o: &access_store::orgs::OrgRow) -> Json {
    json!({
        "organization": b64url_encode(&o.party),
        "display_name": o.display_name,
        "hrd": o.hrd,
    })
}

/// A delivery log cursor: the queue time as stored and the event id.
fn delivery_cursor(after: &str) -> Option<(&str, &str)> {
    after.split_once('|')
}

#[cfg(test)]
mod tests;

/// The id a page starts after: the cursor's 16 bytes, past every id when it is not one.
fn cursor(after: Option<&str>) -> [u8; 16] {
    match after {
        Some(a) => b64url_decode(a)
            .ok()
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .unwrap_or([0xff; 16]),
        None => [0; 16],
    }
}

fn full<T>(rows: &[T], limit: u32, key: impl Fn(&T) -> String) -> Option<String> {
    (u32::try_from(rows.len()).ok() == Some(limit))
        .then(|| rows.last().map(key))
        .flatten()
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// One organization as S7 reads it (§8.5 S7, §8.17.7.6, TN-91, TN-90, TN-120): its roots
    /// and members with how each joined (the membership source, apart from any sign-in source),
    /// its role's versioned Grant and any autojoin cooling, its domain claims with their watch
    /// state, its ownership handovers and its connection drafts. Ownership is root standing,
    /// never billing.
    async fn organization_view(
        &self,
        t: &mut TenantTx,
        org: &access_store::orgs::OrgRow,
    ) -> Result<Json, AdminError> {
        let account = |s: [u8; 16]| self.ids.encode(SUBJECT_PREFIX, s).unwrap_or_default();
        let members = t.members(org.id).await?;
        let domains = t.open_domain_claims(Some(org.id)).await?;
        let handovers = t.transfers(org.id).await?;
        let drafts = t.sso_drafts(org.id).await?;
        Ok(json!({
            "organization": b64url_encode(&org.party),
            "display_name": org.display_name,
            "hrd": org.hrd,
            "roots": members.iter().filter(|m| m.owner).count(),
            "members": members.iter().map(|m| json!({
                "account_id": account(m.subject),
                "owner": m.owner,
                "membership_source": m.source.word(),
                "role": m.role.as_ref().map(|(n, v)| json!({ "name": n, "version": v })),
                "role_grant": m.grant_state,
                "grant": m.grant.map(|g| b64url_encode(&g)),
                "cooling_until": m.cooling_until_ms.map(at_ms),
                "joined_at": at_ms(m.joined_ms),
            })).collect::<Vec<_>>(),
            "domains": domains.iter().map(|d| json!({
                "domain": d.domain,
                "method": d.method,
                "verified_at": d.verified_ms.map(at_ms),
                "reverify_by": d.reverify_ms.map(at_ms),
                "changed_at": d.changed_ms.map(at_ms),
                "contested_at": d.contested_ms.map(at_ms),
                "autojoin": d.autojoin,
                "claimed": d.claimed,
            })).collect::<Vec<_>>(),
            "handovers": handovers.iter().map(|h| json!({
                "handover": b64url_encode(&h.id),
                "from": account(h.from),
                "to": account(h.to),
                "state": h.state.word(),
                "effective_at": at_ms(h.effective_ms),
                "dns_recovery": h.dns_recovery,
            })).collect::<Vec<_>>(),
            "connection_drafts": drafts.iter().filter(|d| !d.withdrawn).map(|d| json!({
                "protocol": d.protocol,
                "issuer": d.issuer,
                "client_id": d.client_id,
                "entity_id": d.entity_id,
                "metadata_url": d.metadata_url,
                "provider": d.provider,
                "drafted_by": b64url_encode(&d.drafted_by),
                "through_setup_link": d.setup_link.is_some(),
            })).collect::<Vec<_>>(),
        }))
    }

    /// What enforcing SSO on `org` would end (TN-94, X20, OP-155 m.3 (i)): each active member's
    /// local sign-in methods, directory app passwords, open sign-ins and refresh families; the
    /// service accounts, members holding API keys the sweep revokes; and the pending invitations.
    /// It changes nothing.
    async fn sso_preview(
        &self,
        t: &mut TenantTx,
        org: &access_store::orgs::OrgRow,
    ) -> Result<Json, AdminError> {
        let account = |s: [u8; 16]| self.ids.encode(SUBJECT_PREFIX, s).unwrap_or_default();
        let impact = t.sso_impact(org.id).await?;
        let state = t.sso_enforcement(org.id).await?;
        let pending = t.open_invitations(org.id).await?.len();
        let sum = |f: fn(&access_store::org_sso::MemberImpact) -> u64| {
            impact.iter().map(f).fold(0_u64, u64::saturating_add)
        };
        Ok(json!({
            "organization": b64url_encode(&org.party),
            "enforced": state.as_ref().is_some_and(|s| s.enforced),
            "invitations": state.and_then(|s| s.invites),
            "members": impact.iter().map(|m| json!({
                "account_id": account(m.subject),
                "owner": m.owner,
                "local_sign_in_methods": m.local_methods,
                "password": m.password,
                "api_keys": m.api_keys,
                "sign_ins": m.sessions,
                "refresh_families": m.refresh_families,
                "linked_sign_ins": m.linked_sign_ins,
                "service_account": m.api_keys > 0,
            })).collect::<Vec<_>>(),
            "service_accounts": impact
                .iter()
                .filter(|m| m.api_keys > 0)
                .map(|m| account(m.subject))
                .collect::<Vec<_>>(),
            "pending_invitations": pending,
            "totals": {
                "members": impact.len(),
                "local_sign_in_methods": sum(|m| m.local_methods),
                "api_keys": sum(|m| m.api_keys),
                "sign_ins": sum(|m| m.sessions),
                "refresh_families": sum(|m| m.refresh_families),
            },
        }))
    }

    /// A `PUT` upsert by natural key (OP-65): a group or upstream provider that exists is
    /// updated, otherwise created. Prepare and commit resolve alike; a state change between
    /// them changes the intent, and the commit is refused.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn resolve(
        &self,
        tenant: TenantId,
        realm: RealmId,
        change: Change,
    ) -> Result<Change, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let resolved = match change {
            Change::GroupCreate(g)
                if resources::group(&mut t, g.name.as_str()).await?.is_some() =>
            {
                Change::GroupUpdate(g)
            }
            Change::UpstreamRegister(u)
                if resources::upstream(&mut t, u.name.as_str())
                    .await?
                    .is_some() =>
            {
                Change::UpstreamUpdate(u)
            }
            // TN-55
            Change::RecoveryPolicy { policy, .. } => {
                let current = match t.recovery_realm_policy().await? {
                    Some(b) => recovery_policy::RecoveryPolicy::from_bytes(&b)
                        .map_err(|_| AdminError::Encode)?,
                    None => recovery_policy::RecoveryPolicy::DEFAULT,
                };
                Change::RecoveryPolicy {
                    loosens: policy.loosens(&current),
                    policy,
                }
            }
            Change::SocialEnable(s)
                if t.social_provider(s.preset.as_str())
                    .await?
                    .is_some_and(|r| r.active) =>
            {
                Change::SocialUpdate(s)
            }
            // OP-151 m.14 (f)
            Change::ProtectionMode { mode, .. } => {
                let tier = access_identity_risk::app::settings::change_tier(&mut t, &mode)
                    .await
                    .map_err(|e| match e {
                        access_identity_risk::RiskError::Store(s) => AdminError::Store(s),
                        _ => AdminError::Unavailable(String::from("risk")),
                    })?;
                Change::ProtectionMode {
                    mode,
                    loosens: tier == access_identity_risk::domain::mode::Tier::Ct2,
                }
            }
            // OP-154 m.3 (j)
            Change::DcrPolicy { policy, .. } => {
                let current =
                    access_identity_oauth::app::oauth::dcr::policy_of(&t.dcr_policy().await?);
                Change::DcrPolicy {
                    loosens: !policy.narrows(&current),
                    policy,
                }
            }
            // OP-153 m.22 (g), m.25 (b)
            Change::CspMode { mode, .. } => {
                let stored = access_store::idp::branding(&mut t)
                    .await?
                    .and_then(|b| dcbor::decode(&b, Limits::CEILING).ok());
                Change::CspMode {
                    mode,
                    loosens: mode.loosens(crate::domain::accounts::CspMode::of(stored.as_ref())),
                }
            }
            // TN-136
            Change::Webhook(WebhookChange::Update {
                id, rotate: true, ..
            }) => match access_store::extensions::webhook(&mut t, &id).await? {
                Some(w) if w.active => Change::Webhook(WebhookChange::Update {
                    id,
                    url: w.url,
                    events: w.events,
                    rotate: true,
                }),
                _ => return Err(Invalid::NoWebhook.into()),
            },
            other => other,
        };
        t.commit().await?;
        Ok(resolved)
    }

    /// Reads one resource (`key`) or one page of a collection after `after` (TN-113: the
    /// transaction's realm scope is the filter; nothing outside it is visible).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn read(
        &self,
        tenant: TenantId,
        realm: RealmId,
        kind: Kind,
        key: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Read, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let read = self.read_in(&mut t, kind, key, after, limit).await;
        t.commit().await?;
        read
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match over the readable kinds, each arm its read"
    )]
    async fn read_in(
        &self,
        t: &mut TenantTx,
        kind: Kind,
        key: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Read, AdminError> {
        let after_text = after.unwrap_or("");
        Ok(match (kind, key) {
            (Kind::Clients, Some(k)) => {
                let c = idp::client(t, k).await?;
                let at = resources::client_position(t, k).await?;
                let w = match &c {
                    Some(c) => access_store::workloads::client_workload(t, c.client_uuid).await?,
                    None => None,
                };
                Read {
                    items: c
                        .zip(at)
                        .map(|(c, p)| (workload_client_view(&c, w.as_ref()), p))
                        .into_iter()
                        .collect(),
                    last: None,
                }
            }
            (Kind::Clients, None) => {
                let rows = resources::clients(t, after_text, limit).await?;
                let mut items = Vec::with_capacity(rows.len());
                for (c, p) in &rows {
                    let w = access_store::workloads::client_workload(t, c.client_uuid).await?;
                    items.push((workload_client_view(c, w.as_ref()), *p));
                }
                Read {
                    last: full(&rows, limit, |(c, _)| c.client_id.clone()),
                    items,
                }
            }
            (Kind::Groups, Some(k)) => Read {
                items: resources::group(t, k)
                    .await?
                    .map(|g| (group_view(&g), g.position))
                    .into_iter()
                    .collect(),
                last: None,
            },
            (Kind::Groups, None) => {
                let rows = resources::groups(t, after_text, limit).await?;
                Read {
                    last: full(&rows, limit, |g| g.name.clone()),
                    items: rows.iter().map(|g| (group_view(g), g.position)).collect(),
                }
            }
            (Kind::Upstreams, Some(k)) => Read {
                items: resources::upstream(t, k)
                    .await?
                    .map(|u| (upstream_view(&u), u.position))
                    .into_iter()
                    .collect(),
                last: None,
            },
            (Kind::Upstreams, None) => {
                let rows = resources::upstreams(t, after_text, limit).await?;
                Read {
                    last: full(&rows, limit, |u| u.name.clone()),
                    items: rows
                        .iter()
                        .map(|u| (upstream_view(u), u.position))
                        .collect(),
                }
            }
            // AG-8
            (Kind::ProtectedResources, _) => Read {
                items: t
                    .protected_resources()
                    .await?
                    .into_iter()
                    .filter(|r| key.is_none_or(|k| k == r.resource))
                    .map(|r| {
                        (
                            serde_json::json!({
                                "resource": r.resource,
                                "display_name": r.display_name,
                            }),
                            0,
                        )
                    })
                    .collect(),
                last: None,
            },
            // OP-155 m.3 (j)
            // OP-156 m.3 (c)
            (Kind::RelayUndelivered, _) => Read {
                items: super::relay::list(t, key, limit).await?,
                last: None,
            },
            (Kind::TrustAnchors, _) => Read {
                items: super::federation::anchors(t, key).await?,
                last: None,
            },
            // OP-154 m.3 (t)
            (Kind::VaultResources, _) => Read {
                items: super::vault::list(t, key).await?,
                last: None,
            },
            // OP-155 m.3 (e)
            (Kind::SamlSps, _) => Read {
                items: super::saml::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (i)
            (Kind::CustomDomains, _) => Read {
                items: super::custom_domains::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (o)
            (Kind::SshHostGroups, _) => Read {
                items: super::ssh::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (r)
            (Kind::SignalSources, _) => Read {
                items: super::signal_sources::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (l)
            (Kind::Proxies, _) => Read {
                items: super::proxy::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (s)
            (Kind::ExportSinks, _) => Read {
                items: super::export_sinks::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (p)
            (Kind::LinuxHosts, _) => Read {
                items: super::linux::list(t, key).await?,
                last: None,
            },
            // OP-156 m.3 (q)
            (Kind::HrSources, _) => Read {
                items: super::hr::sources(t, key).await?,
                last: None,
            },
            (Kind::HrConnectors, _) => Read {
                items: super::hr::connectors(t, key).await?,
                last: None,
            },
            (Kind::Socials, _) => {
                let rows = t.social_providers().await?;
                let clients = resources::clients(t, "", 1000).await?;
                let enabled: Vec<&str> = rows
                    .iter()
                    .filter(|r| r.active)
                    .map(|r| r.preset.as_str())
                    .collect();
                // IDP-31 (5)
                let apple = access_identity_federation::domain::rules::apple_recommended(
                    clients.iter().any(|(c, _)| native(c)),
                    enabled,
                );
                Read {
                    items: rows
                        .iter()
                        .filter(|r| key.is_none_or(|k| k == r.preset))
                        .map(|r| (social_view(r, apple), r.position))
                        .collect(),
                    last: None,
                }
            }
            (Kind::Agents, Some(k)) => {
                let Some(party) = agent_key(k) else {
                    return Ok(Read::default());
                };
                let Some(a) = t.agent(party).await? else {
                    return Ok(Read::default());
                };
                let g = idp::governance(t).await?.ok_or(AdminError::NoRealm)?;
                // AG-21, OP-154 m.3 (f)
                let instances = self
                    .governance
                    .instances(
                        access_kernel::digest::Digest(*g.domain.as_bytes()),
                        access_kernel::model::Id(a.party),
                    )
                    .await
                    .map_err(|e| AdminError::Unavailable(e.0))?;
                Read {
                    items: vec![(
                        super::agents::view(t, self.ids, &a, Some(&instances)).await?,
                        0,
                    )],
                    last: None,
                }
            }
            (Kind::Agents, None) => {
                let rows = t.agents(after.and_then(agent_key), limit).await?;
                let mut items = Vec::with_capacity(rows.len());
                for a in &rows {
                    items.push((super::agents::view(t, self.ids, a, None).await?, 0));
                }
                Read {
                    last: full(&rows, limit, |a| b64url_encode(&a.party)),
                    items,
                }
            }
            (Kind::AgentSponsors, k) => {
                let Some(a) = k.and_then(agent_key) else {
                    return Ok(Read::default());
                };
                let Some(row) = t.agent(a).await? else {
                    return Ok(Read::default());
                };
                let view = super::agents::view(t, self.ids, &row, None).await?;
                Read {
                    items: view
                        .get("sponsorships")
                        .and_then(Json::as_array)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|s| (s, 0))
                        .collect(),
                    last: None,
                }
            }
            // TN-94, X20, OP-155 m.3 (i)
            (Kind::SsoPreview, Some(k)) => {
                let Some(party) = b64url_decode(k)
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                else {
                    return Ok(Read::default());
                };
                let Some(org) = t.org_by_party(party).await?.filter(|o| !o.ended) else {
                    return Ok(Read::default());
                };
                Read {
                    items: vec![(self.sso_preview(t, &org).await?, 0)],
                    last: None,
                }
            }
            (Kind::Organizations, Some(k)) => {
                let Some(party) = b64url_decode(k)
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                else {
                    return Ok(Read::default());
                };
                let Some(org) = t.org_by_party(party).await?.filter(|o| !o.ended) else {
                    return Ok(Read::default());
                };
                Read {
                    items: vec![(self.organization_view(t, &org).await?, 0)],
                    last: None,
                }
            }
            (Kind::Organizations, None) => {
                let start = after
                    .and_then(|a| b64url_decode(a).ok())
                    .and_then(|b| <[u8; 16]>::try_from(b).ok());
                let rows = t.orgs_page(start, i64::from(limit)).await?;
                let mut items = Vec::with_capacity(rows.len());
                for o in &rows {
                    items.push((organization_summary(o), 0));
                }
                Read {
                    last: full(&rows, limit, |o| b64url_encode(&o.id)),
                    items,
                }
            }
            (Kind::Accounts, Some(k)) => {
                let Ok(s) = self.ids.decode(SUBJECT_PREFIX, k) else {
                    return Ok(Read::default());
                };
                Read {
                    items: resources::account(t, s)
                        .await?
                        .map(|a| (account_view(&a, self.ids), 0))
                        .into_iter()
                        .collect(),
                    last: None,
                }
            }
            (Kind::Accounts, None) => {
                let start = match after {
                    Some(a) => b64url_decode(a)
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        .unwrap_or([0xff; 16]),
                    None => [0; 16],
                };
                let rows = resources::accounts(t, start, limit).await?;
                Read {
                    last: full(&rows, limit, |a| b64url_encode(&a.subject)),
                    items: rows
                        .iter()
                        .map(|a| (account_view(a, self.ids), 0))
                        .collect(),
                }
            }
            (Kind::Hooks, _) => {
                let only = match key {
                    Some(k) => match self.ids.decode(HOOK_PREFIX, k) {
                        Ok(id) => Some(id),
                        Err(_) => return Ok(Read::default()),
                    },
                    None => None,
                };
                let rows = access_store::extensions::hooks(t, only.as_ref(), &cursor(after), limit)
                    .await?;
                Read {
                    last: full(&rows, limit, |h| b64url_encode(&h.id)).filter(|_| key.is_none()),
                    items: rows
                        .iter()
                        .map(|h| (hook_view(h, self.ids), h.position))
                        .collect(),
                }
            }
            (Kind::Webhooks, _) => {
                let only = match key {
                    Some(k) => match self.ids.decode(WEBHOOK_PREFIX, k) {
                        Ok(id) => Some(id),
                        Err(_) => return Ok(Read::default()),
                    },
                    None => None,
                };
                let rows =
                    access_store::extensions::webhooks(t, only.as_ref(), &cursor(after), limit)
                        .await?;
                Read {
                    last: full(&rows, limit, |w| b64url_encode(&w.webhook.id))
                        .filter(|_| key.is_none()),
                    items: rows
                        .iter()
                        .map(|w| (webhook_view(w, self.ids), w.position))
                        .collect(),
                }
            }
            // §8.13, OP-151 m.7 (g), m.19 (e)
            (Kind::Signals, _) => {
                let now = t.server_time().await?;
                let rows = t.transmitters().await?;
                let transmitters: Vec<Json> = rows
                    .iter()
                    .filter(|r| !r.disabled)
                    .map(|r| {
                        json!({
                            "name": r.issuer,
                            "delayed_since": access_identity_events::domain::inbound::delayed_since(
                                r.last_seen_ms,
                                r.created_ms,
                                r.expected_interval_s,
                                now,
                            ),
                        })
                    })
                    .collect();
                Read {
                    items: vec![(json!({ "transmitters": transmitters, "verifiers": [] }), 0)],
                    last: None,
                }
            }
            // IDP-36, OP-151 m.14 (i)
            (Kind::Analytics, _) => {
                let today = u32::try_from(t.server_time().await? / 86_400_000)
                    .map_err(|_| AdminError::Unavailable(String::from("time")))?;
                let from = today.saturating_sub(ANALYTICS_DAYS.saturating_sub(1));
                let report = access_identity_risk::app::analytics::read(t, from, today)
                    .await
                    .map_err(|_| AdminError::Unavailable(String::from("analytics")))?;
                Read {
                    items: vec![(analytics_view(&report), 0)],
                    last: None,
                }
            }
            // TN-136, OP-151 m.19 (e)
            (Kind::Deliveries, Some(k)) => {
                let Ok(id) = self.ids.decode(WEBHOOK_PREFIX, k) else {
                    return Err(Invalid::NoWebhook.into());
                };
                if access_store::extensions::webhook(t, &id).await?.is_none() {
                    return Err(Invalid::NoWebhook.into());
                }
                let rows = t
                    .webhook_deliveries(&id, after.and_then(delivery_cursor), limit)
                    .await?;
                Read {
                    last: full(&rows, limit, |d| format!("{}|{}", d.queued_at, d.event_id)),
                    items: rows.iter().map(|d| (delivery_view(d), 0)).collect(),
                }
            }
            (Kind::Deliveries | Kind::SsoPreview, None) => Read::default(),
            (Kind::Settings, _) => {
                let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                let p = resources::policies(t).await?;
                let branding = idp::branding(t).await?;
                let mappers = idp::mappers(t).await?;
                // OP-153 m.22 (g), (k), m.25 (b)
                let csp_mode = crate::domain::accounts::CspMode::of(
                    branding
                        .as_deref()
                        .and_then(|b| dcbor::decode(b, Limits::CEILING).ok())
                        .as_ref(),
                );
                let related = idp::related_origins(t).await?;
                let overrides = idp::locale_overrides(t).await?;
                let protection = access_identity_risk::app::settings::mode(t)
                    .await
                    .map_err(|_| AdminError::Unavailable(String::from("risk")))?;
                let view = json!({
                    "jose_alg": s.jose_alg,
                    "argon2": {
                        "m_kib": s.argon2_m_kib, "t": s.argon2_t, "p": s.argon2_p
                    },
                    "rp_id": s.rp_id,
                    "cimd": { "enabled": s.cimd_enabled, "domains": s.cimd_domains },
                    "signin_policy": stored(p.signin.as_deref(), &default_signin().to_value()),
                    "session_policy":
                        stored(p.session.as_deref(), &SessionPolicy::DEFAULT.to_value()),
                    "branding": stored(branding.as_deref(), &Branding::default().to_value()),
                    "extension_policy":
                        stored(p.extension.as_deref(), &ExtensionPolicy::default().to_value()),
                    "mappers": mappers.iter().map(|(c, s)| json!({"claim": c, "source": s}))
                        .collect::<Vec<_>>(),
                    "protection_mode": protection_view(&protection),
                    "csp_mode": csp_mode.name(),
                    "related_origins": related,
                    "locale_overrides": stored(overrides.as_deref(), &Value::Map(Vec::new())),
                    // TN-124, OP-151 m.17 (d)
                    "managed": [],
                });
                Read {
                    items: vec![(view, p.position.unwrap_or(0))],
                    last: None,
                }
            }
        })
    }
}

fn agent_key(k: &str) -> Option<[u8; 16]> {
    b64url_decode(k)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
}
