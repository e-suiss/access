//! The management API as the command line knows it: `sdks/openapi/admin-v1.json`, compiled in
//! (TN-112 item 8: the client follows the contract the server generates). Resource names,
//! operations and the members a client may not write (`readOnly`) come from it; a resource the
//! contract does not name is refused before anything is sent.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::OnceLock;

use access_identity_risk::domain::mode::{ProtectionMode, Tier, tier};
use access_internal_api::idp::IdpAction;
use serde_json::Value;

const CONTRACT: &str = include_str!("../../../sdks/openapi/admin-v1.json");

/// The realm surface's path prefix.
pub(crate) const REALM_PREFIX: &str = "/admin/v1/realms/{slug}";

/// The operation that drafts a write (OP-151 m.11 (a)).
pub(crate) const DRAFT: &str = "draftIntent";

/// An HTTP method of the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Put,
    Patch,
}

impl Method {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
        }
    }

    fn parse(m: &str) -> Option<Self> {
        match m {
            "get" => Some(Self::Get),
            "post" => Some(Self::Post),
            "put" => Some(Self::Put),
            "patch" => Some(Self::Patch),
            _ => None,
        }
    }
}

/// One operation of the realm surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Operation {
    pub(crate) id: String,
    pub(crate) method: Method,
    /// The path after the realm prefix, with at most one `{key}` parameter.
    pub(crate) path: String,
    /// The read scope; `None` for a write (the caller's AIS).
    pub(crate) scope: Option<String>,
}

impl Operation {
    /// A write: it carries an AIS and compiles to one Exercise (TN-110).
    pub(crate) fn writes(&self) -> bool {
        self.scope.is_none()
    }

    /// The resource name: the first path segment after the realm prefix.
    pub(crate) fn resource(&self) -> &str {
        self.path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("")
    }

    /// Whether the path names one resource by key.
    pub(crate) fn keyed(&self) -> bool {
        self.path.contains('{')
    }

    /// The trailing action segment (`retire`, `secret/rotate`, …) after the key, if any.
    pub(crate) fn action(&self) -> &str {
        self.path.split_once('}').map_or("", |(_, rest)| rest)
    }

    /// The concrete path for `slug` and `key`, each percent-encoded as one segment.
    pub(crate) fn url_path(&self, slug: &str, key: Option<&str>) -> String {
        let mut out = String::from("/admin/v1/realms/");
        out.push_str(&segment(slug));
        let mut rest = self.path.as_str();
        while let Some(open) = rest.find('{') {
            out.push_str(rest.get(..open).unwrap_or(""));
            out.push_str(&segment(key.unwrap_or("")));
            rest = rest
                .get(open..)
                .and_then(|r| r.find('}').and_then(|c| r.get(c.saturating_add(1)..)))
                .unwrap_or("");
        }
        out.push_str(rest);
        out
    }
}

/// One path segment, percent-encoded (RFC 3986 unreserved kept).
pub(crate) fn segment(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The contract, parsed once.
pub(crate) struct Contract {
    pub(crate) operations: Vec<Operation>,
    read_only: BTreeSet<(String, String)>,
    declared: BTreeSet<(String, String)>,
}

fn parse(doc: &Value) -> Contract {
    let mut operations = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (path, item) in paths {
            let Some(rest) = path.strip_prefix(REALM_PREFIX) else {
                continue;
            };
            let Some(item) = item.as_object() else {
                continue;
            };
            for (m, op) in item {
                let (Some(method), Some(id)) = (
                    Method::parse(m),
                    op.get("operationId").and_then(Value::as_str),
                ) else {
                    continue;
                };
                operations.push(Operation {
                    id: id.to_owned(),
                    method,
                    path: rest.to_owned(),
                    scope: op
                        .get("x-access-scope")
                        .and_then(Value::as_str)
                        .map(String::from),
                });
            }
        }
    }
    let mut read_only = BTreeSet::new();
    let mut declared = BTreeSet::new();
    if let Some(schemas) = doc
        .pointer("/components/schemas")
        .and_then(Value::as_object)
    {
        for (name, schema) in schemas {
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (field, p) in props {
                    declared.insert((name.clone(), field.clone()));
                    if p.get("readOnly").and_then(Value::as_bool) == Some(true) {
                        read_only.insert((name.clone(), field.clone()));
                    }
                }
            }
        }
    }
    Contract {
        operations,
        read_only,
        declared,
    }
}

/// The compiled-in contract.
pub(crate) fn contract() -> &'static Contract {
    static C: OnceLock<Contract> = OnceLock::new();
    C.get_or_init(|| {
        serde_json::from_str::<Value>(CONTRACT).map_or_else(
            |_| Contract {
                operations: Vec::new(),
                read_only: BTreeSet::new(),
                declared: BTreeSet::new(),
            },
            |doc| parse(&doc),
        )
    })
}

impl Contract {
    /// The operation with this id.
    pub(crate) fn operation(&self, id: &str) -> Option<&Operation> {
        self.operations.iter().find(|o| o.id == id)
    }

    /// Every resource name of the realm surface, sorted.
    pub(crate) fn resources(&self) -> BTreeSet<&str> {
        self.operations
            .iter()
            .map(Operation::resource)
            .filter(|r| !r.is_empty() && *r != "intents")
            .collect()
    }

    /// The operation with `method` on `resource`: for a keyed one, the first path segment and
    /// the action suffix after the key (`/retire`); otherwise the whole path
    /// (`settings/branding`).
    pub(crate) fn find(
        &self,
        resource: &str,
        method: Method,
        keyed: bool,
        action: &str,
    ) -> Option<&Operation> {
        self.operations.iter().find(|o| {
            o.method == method
                && o.keyed() == keyed
                && if keyed {
                    o.resource() == resource && o.action() == action
                } else {
                    o.path.trim_start_matches('/') == resource && action.is_empty()
                }
        })
    }

    /// Whether `field` of schema `schema` is server-generated (`readOnly`).
    pub(crate) fn read_only(&self, schema: &str, field: &str) -> bool {
        self.read_only
            .contains(&(schema.to_owned(), field.to_owned()))
    }

    /// Whether schema `schema` declares `field`.
    pub(crate) fn declares(&self, schema: &str, field: &str) -> bool {
        self.declared
            .contains(&(schema.to_owned(), field.to_owned()))
    }
}

/// Writes the contract declares but no server applies yet (answered `501`): reserved (CT3)
/// and never sent by the command line (OP-150 m.11 (b), TN-118).
pub(crate) const DECLARED_RESERVED: [&str; 0] = [];

/// Writes `access admin` refuses: a bulk job is a set of Exercises the command line already
/// makes one at a time (TN-125, X20); `apply` sends one write per change. An offboarding commit
/// is such a set too, and a review keep records an identity audit row, no `idp.*` action
/// (OP-157 m.3 (v), (w)).
pub(crate) const UNSUPPORTED: [&str; 4] = [
    "createJob",
    "revokeAllAgentInstances",
    "commitOffboarding",
    "keepReviewItem",
];

/// The `idp.*` action a write operation compiles to; `None` for an operation the command line
/// does not know, which it treats as reserved (fail closed, TN-122). A protection mode change
/// without its two sides is taken as loosening ([`protection_action`] decides with them).
#[expect(clippy::too_many_lines, reason = "one arm per contract write")]
pub(crate) fn action_of(operation: &str, exists: bool) -> Option<IdpAction> {
    Some(match operation {
        "putClient" if exists => IdpAction::ClientUpdate,
        "createClient" | "putClient" => IdpAction::ClientRegister,
        "patchClient" => IdpAction::ClientUpdate,
        "retireClient" => IdpAction::ClientRetire,
        "rotateClientSecret" => IdpAction::ClientSecretRotate,
        "putGroup" if exists => IdpAction::GroupUpdate,
        "putGroup" => IdpAction::GroupCreate,
        "patchGroup" => IdpAction::GroupUpdate,
        "retireGroup" => IdpAction::GroupRetire,
        "addGroupMembers" => IdpAction::GroupMembersAdd,
        "removeGroupMembers" => IdpAction::GroupMembersRemove,
        "suspendAccount" => IdpAction::AccountSuspend,
        "reactivateAccount" => IdpAction::AccountReactivate,
        "putUpstreamIdp" if exists => IdpAction::UpstreamUpdate,
        "putUpstreamIdp" => IdpAction::UpstreamRegister,
        "patchUpstreamIdp" => IdpAction::UpstreamUpdate,
        "retireUpstreamIdp" => IdpAction::UpstreamRetire,
        "linkUpstreamSubject" => IdpAction::UpstreamLink,
        "putSocialProvider" if exists => IdpAction::SocialUpdate,
        "putSocialProvider" => IdpAction::SocialEnable,
        "patchSocialProvider" => IdpAction::SocialUpdate,
        "disableSocialProvider" => IdpAction::SocialDisable,
        "createOrganization" => IdpAction::OrgCreate,
        "removeOrganizationMember" => IdpAction::OrgMemberRemove,
        "createInvitation" => IdpAction::OrgInvite,
        "revokeInvitation" => IdpAction::OrgInviteRevoke,
        "patchOrganization" => IdpAction::OrgUpdate,
        "claimOrganizationDomain" => IdpAction::OrgDomainClaim,
        "releaseOrganizationDomain" => IdpAction::OrgDomainRelease,
        "draftOrganizationConnection" => IdpAction::OrgSsoDraft,
        "putSigninPolicy" | "patchSigninPolicy" => IdpAction::RealmSigninPolicy,
        "putSessionPolicy" | "patchSessionPolicy" => IdpAction::RealmSessionPolicy,
        "putBranding" | "patchBranding" => IdpAction::RealmBranding,
        "putRpId" => IdpAction::RealmRpId,
        "putMapper" => IdpAction::MapperSet,
        "putJoseAlg" => IdpAction::RealmJoseAlg,
        "putCimdPolicy" | "patchCimdPolicy" => IdpAction::CimdPolicy,
        "putProtectionMode" | "patchProtectionMode" => IdpAction::RealmProtectionModeLoosen,
        "markCanaryAccount" => IdpAction::AccountCanary,
        "putExtensionPolicy" | "patchExtensionPolicy" => IdpAction::RealmExtensionPolicy,
        "registerHook" => IdpAction::HookRegister,
        "retireHook" => IdpAction::HookRetire,
        "registerWebhook" => IdpAction::WebhookRegister,
        "putWebhook" | "patchWebhook" | "rotateWebhookKey" => IdpAction::WebhookUpdate,
        "retireWebhook" => IdpAction::WebhookRetire,
        "deleteAccount" => IdpAction::AccountDelete,
        "rehomeRealm" => IdpAction::RealmRehome,
        "createResetIntent" => IdpAction::AccountResetIntent,
        "createTemporaryAccessPass" => IdpAction::AccountTapIssue,
        "putRecoveryPolicy" => IdpAction::AccountRecoveryPolicyLoosen,
        // OP-153 m.22 (g), (k), m.25 (b)
        "putCspMode" => IdpAction::RealmCspModeLoosen,
        "putRelatedOrigins" => IdpAction::RealmRelatedOrigins,
        "putLocaleOverrides" => IdpAction::RealmLocaleOverrides,
        "importAccounts" => IdpAction::AccountImport,
        "exportAccounts" => IdpAction::AccountMigrationExport,
        "bindAccount" => IdpAction::AccountBind,
        "recordGuardianship" => IdpAction::AccountGuardianshipRecord,
        // OP-154 m.3 (a)
        "registerAgent" => IdpAction::AgentRegister,
        "patchAgent" => IdpAction::AgentUpdate,
        "retireAgent" => IdpAction::AgentRetire,
        "assignAgentSponsor" => IdpAction::AgentSponsorAssign,
        "removeAgentSponsor" => IdpAction::AgentSponsorRemove,
        "defineAgentTemplate" => IdpAction::AgentTemplateDefine,
        "registerProtectedResource" => IdpAction::ClientResourceRegister,
        "putDcrPolicy" => IdpAction::ClientDcrPolicy,
        "createCrossAppConnection" => IdpAction::ClientCrossAppConnection,
        "retireCrossAppConnection" => IdpAction::ClientCrossAppConnectionRetire,
        "putDeviceCode" => IdpAction::RealmDeviceCode,
        "putVaultResource" => IdpAction::VaultResourceRegister,
        "disableVaultResource" => IdpAction::VaultResourceDisable,
        "putVaultReleaseMode" => IdpAction::VaultReleaseModeOpen,
        // OP-155 m.3 (a)
        "registerSamlSp" => IdpAction::SamlSpMapping,
        "putSamlSp" => IdpAction::SamlSpUpdate,
        "retireSamlSp" => IdpAction::SamlSpRetire,
        "putSamlCertificatePolicy" => IdpAction::SamlCertPolicy,
        "replaceSamlCertificate" => IdpAction::SamlCertEmergency,
        "registerScimClient" => IdpAction::ScimClientRegister,
        "rotateScimSecret" => IdpAction::ScimTokenRotate,
        "retireScimClient" => IdpAction::ScimClientRetire,
        "registerScimTarget" => IdpAction::ScimOutboundRegister,
        "retireScimTarget" => IdpAction::ScimOutboundRetire,
        "registerGateway" => IdpAction::GatewayRegister,
        "retireGateway" => IdpAction::GatewayRetire,
        "putKeytabPolicy" => IdpAction::GatewayKeytabPolicy,
        "replaceKeytab" => IdpAction::GatewayKeytabEmergency,
        "registerRadiusClient" => IdpAction::GatewayRadiusClientRegister,
        "putFederation" => IdpAction::FederationEnable,
        "addTrustAnchor" => IdpAction::FederationTrustAnchorAdd,
        "removeTrustAnchor" => IdpAction::FederationTrustAnchorRemove,
        "putFederationAuthority" => IdpAction::FederationTaEnable,
        "putFederationRegistration" => IdpAction::FederationRegistrationOpen,
        "putVcVerifier" => IdpAction::VcVerifierEnable,
        "putVcTrustedLists" => IdpAction::VcTrustedList,
        "putVcIssuer" => IdpAction::VcIssuerEnable,
        "putClientProfile" => IdpAction::ClientProfileLoosen,
        "putClientLegacyAuthentication" => IdpAction::ClientAuthMethodLegacy,
        "putClientSigningAlg" => IdpAction::ClientAlgRs256,
        "putClientEncryption" => IdpAction::ClientEncryption,
        "putClientSamlBearer" => IdpAction::ClientSamlBearer,
        "putClientLegacyBearer" => IdpAction::ClientLegacyBearer,
        "putCiba" => IdpAction::RealmCiba,
        "putCertificateLogin" => IdpAction::RealmCertificateLogin,
        "putMtlsAliases" => IdpAction::RealmMtlsAliases,
        "putHrd" => IdpAction::RealmHrd,
        "putFrontchannelLogout" => IdpAction::RealmFrontchannelLogout,
        "enforceOrganizationSso" => IdpAction::OrgSsoEnforce,
        "liftOrganizationSso" => IdpAction::OrgSsoEnforceLift,
        "createOrganizationSetupLink" => IdpAction::OrgSetupLink,
        "putUpstreamAssuranceMap" => IdpAction::UpstreamAssuranceMap,
        // OP-156 m.3 (a)
        "registerDomain" => IdpAction::DomainRegister,
        "retireDomain" => IdpAction::DomainRetire,
        "bindDomainIssuer" => IdpAction::DomainIssuerBind,
        "registerProxy" => IdpAction::ProxyRegister,
        "putProxy" => IdpAction::ProxyUpdate,
        "retireProxy" => IdpAction::ProxyRetire,
        "putProxyPlainHeaders" => IdpAction::ProxyPlainHeaders,
        "pinMcpTools" => IdpAction::ProxyMcpPin,
        "putSshCa" => IdpAction::SshCaEnable,
        "rotateSshCa" => IdpAction::SshCaRotate,
        "replaceSshCa" => IdpAction::SshCaEmergency,
        "registerSshHostGroup" => IdpAction::SshHostGroupRegister,
        "retireSshHostGroup" => IdpAction::SshHostGroupRetire,
        "registerLinuxHost" => IdpAction::LinuxHostRegister,
        "retireLinuxHost" => IdpAction::LinuxHostRetire,
        "putLinuxOfflinePolicy" => IdpAction::LinuxOfflinePolicy,
        "putLinuxBreakGlassPolicy" => IdpAction::LinuxBreakGlassPolicy,
        "registerHrSource" => IdpAction::HrSourceRegister,
        "retireHrSource" => IdpAction::HrSourceRetire,
        "importHrBatch" | "importHrCsv" => IdpAction::HrImport,
        "registerHrConnector" => IdpAction::HrConnectorRegister,
        "retireHrConnector" => IdpAction::HrConnectorRetire,
        "registerExportSink" => IdpAction::ExportSinkRegister,
        "putExportSink" => IdpAction::ExportSinkUpdate,
        "retireExportSink" => IdpAction::ExportSinkRetire,
        "registerSignalSource" => IdpAction::SignalSourceRegister,
        "retireSignalSource" => IdpAction::SignalSourceRetire,
        "putPush" => IdpAction::RealmPush,
        "putSmsOtp" => IdpAction::RealmSmsOtp,
        "putSpc" => IdpAction::RealmSpc,
        "putCoordinator" => IdpAction::RealmCoordinator,
        "putIys" => IdpAction::RealmIys,
        "putPreferenceTopics" => IdpAction::RealmPreferenceTopics,
        "putSecurityNotices" => IdpAction::RealmSecurityNotices,
        "resendRelayMessage" => IdpAction::RelayResend,
        "registerCaseSystem" => IdpAction::SupportCaseSystemRegister,
        "retireCaseSystem" => IdpAction::SupportCaseSystemRetire,
        "putSupportArtifactPolicy" => IdpAction::SupportArtifactPolicy,
        "markBreakglassAccount" => IdpAction::OrgMemberBreakglass,
        "clearBreakglassAccount" => IdpAction::OrgMemberBreakglassClear,
        "scheduleReview" => IdpAction::ReviewSchedule,
        "closeReview" => IdpAction::ReviewScheduleClose,
        "putDelegatedAdmin" => IdpAction::RealmDelegatedAdmin,
        "putApprovalInline" => IdpAction::RealmApprovalInline,
        "putApprovalBatch" => IdpAction::RealmApprovalBatch,
        _ => return None,
    })
}

fn protection_mode(v: &Value) -> Option<ProtectionMode> {
    let mut values = Vec::new();
    for p in ["bot", "suspicious_ip", "breached_password", "brute_force"] {
        if let Some(e) = v.get(p) {
            values.push((p, e.as_str()?));
        }
    }
    let asns = match v.get("denied_asns") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|n| n.as_u64().and_then(|n| u32::try_from(n).ok()))
            .collect::<Option<Vec<u32>>>()?,
        Some(_) => return None,
    };
    ProtectionMode::parse(&values, v.get("sl2")?.as_str()?, &asns).ok()
}

/// The action of a protection mode change from `current` to `desired` (the settings view's
/// `protection_mode`), as the server's tier rule decides it: loosening anything is
/// `protection_mode_loosen` (CT2), tightening `protection_mode` (CT1); a side that does not
/// parse is loosening (OP-151 m.3 (o)).
pub(crate) fn protection_action(current: &Value, desired: &Value) -> IdpAction {
    match (protection_mode(current), protection_mode(desired)) {
        (Some(from), Some(to)) if tier(&from, &to) == Tier::Ct1 => IdpAction::RealmProtectionMode,
        _ => IdpAction::RealmProtectionModeLoosen,
    }
}

/// Whether a write is reserved (CT3): the reconciler's Grant has no reserved action, so it only
/// proposes it (TN-122, E11). An operation the command line cannot place is reserved.
pub(crate) fn reserved(operation: &str, exists: bool) -> bool {
    DECLARED_RESERVED.contains(&operation)
        || action_of(operation, exists).is_none_or(IdpAction::reserved)
}

#[cfg(test)]
mod tests;
