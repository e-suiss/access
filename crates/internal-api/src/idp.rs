//! The `idp.*` write path between the planes (MD-14, E34, EI-25, OP-146 I10): the actions the
//! identity plane publishes, the Exercise it sends as PEP, the committed decision it binds its
//! configuration to, and the Genesis a new realm's governing domain is opened with (TN-111).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::{BlockerClass, Capacity, Decision, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{ExerciseBasis, Root};
use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};

/// The resource namespace every `idp.*` action addresses: `[slug, kind, …]` paths.
pub const RESOURCE_NAMESPACE: &str = "idp";

/// Version of every `idp.*` catalog (OP-153 m.3 (a), m.25 (b)).
pub const CATALOG_VERSION: u64 = 3;

/// The `idp.*` action namespaces, one SPP each (OP-141 m.35, OP-153 m.3 (a)).
pub const NAMESPACES: [&str; 10] = [
    "idp.account",
    "idp.client",
    "idp.group",
    "idp.hook",
    "idp.mapper",
    "idp.org",
    "idp.realm",
    "idp.social",
    "idp.upstream",
    "idp.webhook",
];

/// Stable code of an `idp.*` write the realm's governing domain refuses because it does not yet
/// accept the catalog that declares the action (OP-153 m.3 (a)): the realm's catalog upgrade
/// must commit first.
pub const CATALOG_UPGRADE_REQUIRED: &str = "catalog-upgrade-required";

/// Whether `decision` is a DENY of an action no live `schema-definition` Acceptance of the
/// domain declares: for an [`IdpAction`] this means only that the realm's catalog upgrade has
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
    /// Changes the realm's client and CIMD acceptance policy (§11.3, AG-4): CT2.
    CimdPolicy,
    /// Sets a token claim from a profile attribute (TN-117): CT2.
    MapperSet,
    /// Sets the realm's JOSE signing algorithm (OP-146 m.8 (e)): CT2.
    RealmJoseAlg,
    /// Raises the realm's Argon2id parameters (OP-33, §17.5.2); narrowing, CT1.
    RealmArgon2,
    /// Pins or changes the realm's RP ID (IDP-5, IDI-4): reserved, irreversible, CT3.
    RealmRpId,
    /// Moves the realm to another governing domain (§12.1.1 2a): reserved, CT3.
    RealmRehome,
    /// Registers an upstream identity provider (TN-95): reserved, CT3.
    UpstreamRegister,
    /// Maps upstream groups or claims onto realm membership (TN-117, L6): reserved, CT3.
    UpstreamMapping,
    /// Changes the realm's login branding: name, logo, colours and the hosted page's CSP
    /// origins (TN-106, §12.4.2): CT2.
    RealmBranding,
    /// Changes the realm's JOSE key rotation policy (TN-118, §12.1.2): reserved, CT3.
    RealmKeyPolicy,
    /// Rotates the realm's active JOSE key now, outside the schedule (TN-118): reserved, CT3.
    RealmKeyRotate,
    /// Drops a realm JOSE key at once, as on compromise (§13.2): narrowing, CT1 (§13.7.1).
    RealmKeyDrop,
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
    /// Adds members to a group whose membership issuer is the realm's administration (TN-117):
    /// CT2.
    GroupMembersAdd,
    /// Removes members from such a group; narrowing, CT1.
    GroupMembersRemove,
    /// Replaces an upstream identity provider's registration (TN-95): reserved, CT3.
    UpstreamUpdate,
    /// Retires an upstream identity provider; narrowing, CT1.
    UpstreamRetire,
    /// Sets the realm's sign-in requirements: methods, required fields, MFA, registration
    /// domain lists (TN-132): CT2.
    RealmSigninPolicy,
    /// Sets the realm's console session policy (TN-129, OP-151 m.3 (f)): CT2.
    RealmSessionPolicy,
    /// Tightens the realm's protection mode: monitor to enforce, a later SL2 stage, more denied
    /// ASNs (OP-151 m.3 (o), m.14 (f)); narrowing, CT1.
    RealmProtectionMode,
    /// Changes the realm's protection mode so that anything loosens (OP-151 m.14 (f)): CT2.
    RealmProtectionModeLoosen,
    /// Makes an account a canary: a credential the realm plants (§4.4, OP-151 m.14 (f)): CT2.
    AccountCanary,
    /// Sets what the realm's extension points may reach and receive: private targets and hook
    /// disclosures (OP-151 m.10 (e)): CT2 either way.
    RealmExtensionPolicy,
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
    /// Exports the realm's accounts for migration, encrypted to a realm-bound key (TN-86,
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
    /// Sets the realm's WebAuthn related origins, verified domains only (OP-153 m.3 (u)): CT2.
    RealmRelatedOrigins,
    /// Overrides the realm's unprotected message keys (TN-108, X35, OP-153 m.3 (s)): CT2.
    RealmLocaleOverrides,
    /// Publishes the realm's consent documents (IDP-37, OP-153 m.3 (ee)): CT2.
    RealmConsentDocuments,
    /// Sets the realm's preference topics (IDP-37, OP-153 m.3 (ee)): CT2.
    RealmPreferenceTopics,
    /// Sets the realm's inactivity policy (TN-51, OP-153 m.3 (dd)): CT2.
    RealmInactivityPolicy,
    /// Extends a retention period (T39, OP-153 m.3 (ff)): CT2.
    RealmRetentionExtend,
    /// Moves the realm's hosted surfaces, issuer and RP ID to a verified customer domain
    /// (OP-153 m.3 (u)): reserved, irreversible, CT3.
    RealmCustomDomain,
    /// Reads the account's own resources under its self-anchor (E34): CT1.
    AccountRead,
    /// Changes the account's own profile fields under its self-anchor (E34): CT1.
    AccountProfileUpdate,
    /// Changes the account's primary e-mail address after step-up and an out-of-band code
    /// (E34, OP-153 m.3 (i)): CT2.
    AccountEmailChange,
    /// Places a legal hold that stops destruction of the held records (T39, OP-153 m.3 (ff)):
    /// CT1.
    RealmRetentionHoldPlace,
    /// Lifts a legal hold, letting destruction run on its schedule again (T39): CT2.
    RealmRetentionHoldLift,
    /// Binds two accounts of two realms of the same tenant as one person, by an administrator
    /// (OP-153 m.18 (e), m.25 (b)): CT2.
    AccountBind,
    /// Imports accounts from another identity provider (§12.3.7, TN-85, OP-153 m.19 (d),
    /// m.25 (b)): CT2.
    AccountImport,
    /// Records a guardianship between two accounts of the realm (E53, OP-153 m.20 (g),
    /// m.25 (b)): CT2.
    AccountGuardianshipRecord,
    /// Tightens the realm's hosted-page CSP mode: report-only to enforce (OP-153 m.22 (g),
    /// m.25 (b)); narrowing, CT1.
    RealmCspMode,
    /// Changes the realm's hosted-page CSP mode so that it loosens: enforce to report-only
    /// (OP-153 m.22 (g), m.25 (b)): CT2.
    RealmCspModeLoosen,
}

impl IdpAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 73] = [
        Self::ClientRegister,
        Self::ClientUpdate,
        Self::ClientRetire,
        Self::CimdPolicy,
        Self::MapperSet,
        Self::RealmJoseAlg,
        Self::RealmArgon2,
        Self::RealmRpId,
        Self::RealmRehome,
        Self::UpstreamRegister,
        Self::UpstreamMapping,
        Self::RealmBranding,
        Self::RealmKeyPolicy,
        Self::RealmKeyRotate,
        Self::RealmKeyDrop,
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
        Self::RealmSigninPolicy,
        Self::RealmSessionPolicy,
        Self::RealmProtectionMode,
        Self::RealmProtectionModeLoosen,
        Self::AccountCanary,
        Self::RealmExtensionPolicy,
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
        Self::RealmRelatedOrigins,
        Self::RealmLocaleOverrides,
        Self::RealmConsentDocuments,
        Self::RealmPreferenceTopics,
        Self::RealmInactivityPolicy,
        Self::RealmRetentionExtend,
        Self::RealmCustomDomain,
        Self::AccountRead,
        Self::AccountProfileUpdate,
        Self::AccountEmailChange,
        Self::RealmRetentionHoldPlace,
        Self::RealmRetentionHoldLift,
        Self::AccountBind,
        Self::AccountImport,
        Self::AccountGuardianshipRecord,
        Self::RealmCspMode,
        Self::RealmCspModeLoosen,
    ];

    /// The catalog version that first declared it (OP-153 m.3 (a)).
    #[must_use]
    pub const fn since(self) -> u64 {
        match self {
            Self::AccountBind
            | Self::AccountImport
            | Self::AccountGuardianshipRecord
            | Self::RealmCspMode
            | Self::RealmCspModeLoosen => 3,
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
            | Self::RealmRelatedOrigins
            | Self::RealmLocaleOverrides
            | Self::RealmConsentDocuments
            | Self::RealmPreferenceTopics
            | Self::RealmInactivityPolicy
            | Self::RealmRetentionExtend
            | Self::RealmCustomDomain
            | Self::AccountRead
            | Self::AccountProfileUpdate
            | Self::AccountEmailChange
            | Self::RealmRetentionHoldPlace
            | Self::RealmRetentionHoldLift => 2,
            _ => 1,
        }
    }

    /// Its namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::ClientRegister
            | Self::ClientUpdate
            | Self::ClientRetire
            | Self::CimdPolicy
            | Self::ClientSecretRotate => "idp.client",
            Self::GroupCreate
            | Self::GroupUpdate
            | Self::GroupRetire
            | Self::GroupMembersAdd
            | Self::GroupMembersRemove => "idp.group",
            Self::MapperSet => "idp.mapper",
            Self::RealmJoseAlg
            | Self::RealmArgon2
            | Self::RealmRpId
            | Self::RealmRehome
            | Self::RealmBranding
            | Self::RealmKeyPolicy
            | Self::RealmKeyRotate
            | Self::RealmKeyDrop
            | Self::RealmSigninPolicy
            | Self::RealmSessionPolicy
            | Self::RealmProtectionMode
            | Self::RealmProtectionModeLoosen
            | Self::RealmExtensionPolicy
            | Self::RealmRelatedOrigins
            | Self::RealmLocaleOverrides
            | Self::RealmConsentDocuments
            | Self::RealmPreferenceTopics
            | Self::RealmInactivityPolicy
            | Self::RealmRetentionExtend
            | Self::RealmCustomDomain
            | Self::RealmRetentionHoldPlace
            | Self::RealmRetentionHoldLift
            | Self::RealmCspMode
            | Self::RealmCspModeLoosen => "idp.realm",
            Self::OrgCreate
            | Self::OrgUpdate
            | Self::OrgDomainClaim
            | Self::OrgInvite
            | Self::OrgSetupLink
            | Self::OrgDomainRelease
            | Self::OrgInviteRevoke
            | Self::OrgMemberRemove
            | Self::OrgSsoDraft => "idp.org",
            Self::SocialEnable | Self::SocialUpdate | Self::SocialDisable => "idp.social",
            Self::HookRegister | Self::HookRetire => "idp.hook",
            Self::WebhookRegister | Self::WebhookUpdate | Self::WebhookRetire => "idp.webhook",
            Self::UpstreamRegister
            | Self::UpstreamMapping
            | Self::UpstreamUpdate
            | Self::UpstreamRetire
            | Self::UpstreamLink => "idp.upstream",
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
            | Self::AccountGuardianshipRecord => "idp.account",
        }
    }

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClientRegister
            | Self::UpstreamRegister
            | Self::HookRegister
            | Self::WebhookRegister => "register",
            Self::ClientUpdate
            | Self::GroupUpdate
            | Self::UpstreamUpdate
            | Self::WebhookUpdate
            | Self::OrgUpdate
            | Self::SocialUpdate => "update",
            Self::ClientRetire
            | Self::GroupRetire
            | Self::UpstreamRetire
            | Self::HookRetire
            | Self::WebhookRetire => "retire",
            Self::RealmExtensionPolicy => "extension_policy",
            Self::ClientSecretRotate => "secret_rotate",
            Self::GroupCreate | Self::OrgCreate => "create",
            Self::GroupMembersAdd => "members_add",
            Self::GroupMembersRemove => "members_remove",
            Self::AccountSuspend => "suspend",
            Self::AccountReactivate => "reactivate",
            Self::RealmSigninPolicy => "signin_policy",
            Self::RealmSessionPolicy => "session_policy",
            Self::CimdPolicy => "cimd_policy",
            Self::MapperSet => "set",
            Self::RealmJoseAlg => "jose_alg",
            Self::RealmArgon2 => "argon2",
            Self::RealmRpId => "rp_id",
            Self::RealmRehome => "rehome",
            Self::UpstreamMapping => "mapping",
            Self::RealmBranding => "branding",
            Self::RealmKeyPolicy => "key_policy",
            Self::RealmKeyRotate => "key_rotate",
            Self::RealmKeyDrop => "key_drop",
            Self::AccountDelete => "delete",
            Self::RealmProtectionMode => "protection_mode",
            Self::RealmProtectionModeLoosen => "protection_mode_loosen",
            Self::AccountCanary => "canary",
            Self::UpstreamLink => "link",
            Self::AccountResetIntent => "reset_intent",
            Self::AccountTapIssue => "tap_issue",
            Self::AccountRecoveryPolicy => "recovery_policy",
            Self::AccountRecoveryPolicyLoosen => "recovery_policy_loosen",
            Self::AccountExport => "export",
            Self::AccountMigrationExport => "migration_export",
            Self::OrgDomainClaim => "domain_claim",
            Self::OrgInvite => "invite",
            Self::OrgSetupLink => "setup_link",
            Self::OrgDomainRelease => "domain_release",
            Self::OrgInviteRevoke => "invite_revoke",
            Self::OrgMemberRemove => "member_remove",
            Self::OrgSsoDraft => "sso_draft",
            Self::SocialEnable => "enable",
            Self::SocialDisable => "disable",
            Self::RealmRelatedOrigins => "related_origins",
            Self::RealmLocaleOverrides => "locale_overrides",
            Self::RealmConsentDocuments => "consent_documents",
            Self::RealmPreferenceTopics => "preference_topics",
            Self::RealmInactivityPolicy => "inactivity_policy",
            Self::RealmRetentionExtend => "retention_extend",
            Self::RealmCustomDomain => "custom_domain",
            Self::AccountRead => "read",
            Self::AccountProfileUpdate => "profile_update",
            Self::AccountEmailChange => "email_change",
            Self::RealmRetentionHoldPlace => "retention_hold_place",
            Self::RealmRetentionHoldLift => "retention_hold_lift",
            Self::AccountBind => "bind",
            Self::AccountImport => "import",
            Self::AccountGuardianshipRecord => "guardianship_record",
            Self::RealmCspMode => "csp_mode",
            Self::RealmCspModeLoosen => "csp_mode_loosen",
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
            | Self::RealmArgon2
            | Self::RealmKeyDrop
            | Self::GroupRetire
            | Self::GroupMembersRemove
            | Self::AccountSuspend
            | Self::UpstreamRetire
            | Self::RealmProtectionMode
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
            | Self::RealmRetentionHoldPlace
            | Self::RealmCspMode => EffectClass::Reversible,
            _ => EffectClass::Irreversible,
        }
    }

    /// Reserved: only an express Grant covers it, and it is CT3 (§13.7.1).
    #[must_use]
    pub const fn reserved(self) -> bool {
        matches!(
            self,
            Self::RealmRpId
                | Self::RealmRehome
                | Self::UpstreamRegister
                | Self::UpstreamMapping
                | Self::UpstreamUpdate
                | Self::RealmKeyPolicy
                | Self::RealmKeyRotate
                | Self::AccountDelete
                | Self::AccountRecoveryPolicyLoosen
                | Self::AccountMigrationExport
                | Self::RealmCustomDomain
        )
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
            params: BTreeMap::new(),
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

/// The SPP of one `idp.*` namespace as catalog `version` declared it: what a realm opened with
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
    /// The realm's governing domain.
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

/// The realm issuer's Acceptance of `org_member` for subject selection (C13, E18, OP-153
/// m.17 (c), m.25 (i) (3)): an organization's rule-shaped Grants, such as its autojoin role,
/// select the Parties whose live `org_member` Claim names it. The identity plane names it
/// explicitly in each realm's Genesis order; a domain opened before it establishes it once its
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

/// What a new realm's governing domain is opened with (TN-111, §12.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisOrder {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The realm's immutable slug: the domain's `idp` Anchor covers `idp:[slug, …]` only, so
    /// no other domain governs the realm (MD-5a, TN-1).
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
    /// The realm's identity Claim issuer Party, when it has one: the domain is born accepting
    /// it for `actor-binding` only (§10.1.4 rule 3, OP-142).
    pub issuer: Option<access_kernel::model::Id>,
    /// Further Acceptances the founder establishes at Genesis, each an `acceptance-content`
    /// (L0-META-5, L2-CLM-3); a local deployment's declarant is accepted this way (OP-149
    /// m.26 (c)).
    pub acceptances: Vec<suiss_crypto::dcbor::Value>,
    /// Classes of the realm issuer's Claims the domain is born accepting as predicate input
    /// too (§10.1.4 rule 3, L2-CLM-3): what a hosted approval's `authentication` Claim proves
    /// with (SI-5, OP-149 m.29 (b)). Empty keeps `actor-binding` alone.
    pub issuer_predicate_input: Vec<String>,
}

/// The domain a Genesis opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisOpened {
    /// The `DomainID`.
    pub domain: Digest,
}

/// The other plane could not be reached or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unavailable(pub String);
