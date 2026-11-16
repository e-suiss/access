//! The local platform administrator (OP-159 m.41 (a)): an account in the platform realm with a
//! password and an authenticator app, signed in to the console like any realm's user, and a
//! Party the platform realm's root grants the `idp.platform.*` actions by a `grant_issue`
//! Exercise. Nobody holds them by default (INV-29); this Grant is the only reason the account
//! may create tenants, realms and sandbox domains. Every step looks for its result first, so a
//! second run changes nothing.
//!
//! In each realm the plan names (OP-159 m.43 (c)) the same person also has an account, with the
//! same identifier, password and authenticator app, and that realm's root grants its Party every
//! realm administration action the console asks about: the `idp.*` actions and the core
//! meta-actions and reads of the Admin, Developer and Audit screens, never `idp.platform.*`.
//! The platform realm gives it nothing there (TN-119, INV-29).

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_authority_core::genesis::IDP_ANCHOR;
use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_admin::app::Admin;
use access_identity_admin::domain::Change;
use access_identity_admin::domain::provision::PlatformAction;
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_internal_api::idp::{IdpAction, RESOURCE_NAMESPACE};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, ExerciseBasis, GrantBasis, GrantContent};
use access_kernel::model::Id;
use access_store::authority::realm_delegated_admin_open;
use access_store::identity::{RealmId, TenantId};
use access_store::scope::DomainId;
use serde::{Deserialize, Serialize};
use suiss_crypto::pkcs11::HsmSigner;

use super::local::Seed;
use super::{
    Bootstrap, BootstrapError, MetaExercises, TotpOut, TotpSeedFile, authority, grant_of,
    holding_json, named_password, sample_tenant,
};

/// The token label of the platform administrator's device key.
pub(crate) const DEVICE_LABEL: &str = "access/bootstrap/platform-admin-device";

/// What the root signs to derive the nonce of the platform Grant; its bounds are part of it, so
/// a Grant of another shape is another Grant.
const GRANT_LABEL: &[u8] = b"access-bootstrap/platform-grant:1";

/// What a realm's root signs to derive the nonce of one of its Grants to the platform
/// administrator's Party there; its bounds are part of it.
const REALM_GRANT_LABEL: &[u8] = b"access-bootstrap/realm-admin-grant:1";

/// The core meta-actions and reads the console's Admin, Developer and Audit screens ask about
/// and write, by the resource namespace their intents name (OP-159 m.43 (c), OP-152 m.7 (d),
/// OP-151 m.8 (h)).
pub(crate) const META_GRANTS: [(&str, &[&str]); 8] = [
    (
        "access.domain",
        &[
            "authority_set_define",
            "grant_issue",
            "grant_amend",
            "grant_revoke",
            "acceptance_establish",
            "acceptance_amend",
            "policy_set",
            "instance_terminate",
            "party_depart",
            "anchor_amend",
        ],
    ),
    ("access.role", &["authority_set_define"]),
    ("access.grant", &["grant_amend", "grant_revoke"]),
    ("access.acceptance", &["acceptance_amend"]),
    ("access.instance", &["instance_terminate"]),
    ("access.party", &["party_depart"]),
    ("access.policy", &["policy_set", "policy_retire"]),
    ("access.audit", &["read", "audit_export"]),
];

/// The token label of the platform administrator's device key in the realm `slug`.
pub(crate) fn realm_device_label(slug: &str) -> String {
    format!("{DEVICE_LABEL}/{slug}")
}

/// `[platform_admin]` as written: the password comes from the variable `password_env` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlatformAdminFile {
    identifier: String,
    password: Option<String>,
    password_env: Option<String>,
    totp_seed_file: Option<PathBuf>,
    #[serde(default)]
    realms: Vec<String>,
}

impl core::fmt::Debug for PlatformAdminFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAdminFile")
            .field("identifier", &self.identifier)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_env", &self.password_env)
            .field("totp_seed_file", &self.totp_seed_file)
            .field("realms", &self.realms)
            .finish()
    }
}

/// The platform administrator as checked.
#[derive(Clone)]
pub(crate) struct PlatformAdminPlan {
    /// The login identifier.
    pub(crate) identifier: String,
    /// The password, from the plan or the variable it named.
    pub(crate) password: Secret<String>,
    /// Where the seed of the administrator's authenticator app is kept.
    pub(crate) totp: Option<TotpSeedFile>,
    /// The plan's tenant realms the same person also administers (OP-159 m.43 (c)).
    pub(crate) realms: Vec<String>,
}

impl core::fmt::Debug for PlatformAdminPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAdminPlan")
            .field("identifier", &self.identifier)
            .field("totp", &self.totp.as_ref().map(|t| &t.path))
            .field("realms", &self.realms)
            .finish_non_exhaustive()
    }
}

/// The platform administrator in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PlatformAdminOut {
    /// The platform realm's slug: what the console's sign-in asks for.
    pub(crate) realm: String,
    /// The platform realm's issuer.
    pub(crate) issuer: String,
    /// The login identifier.
    pub(crate) identifier: String,
    /// The account (`usr_…`).
    pub(crate) subject: String,
    /// Its Party, base64url.
    pub(crate) party: String,
    /// Its device Instance in the platform realm's governing domain, base64url.
    pub(crate) instance: String,
    /// The granted actions, `idp.platform.<name>`.
    pub(crate) actions: Vec<String>,
    /// The Party's holding of the platform Grant: the `basis` its writes are signed on.
    pub(crate) basis: serde_json::Value,
    /// The administrator's authenticator app, when the plan asks for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) totp: Option<TotpOut>,
    /// Whether this run made the account.
    pub(crate) created: bool,
    /// The realms the same person also administers, each by that realm's root's Grants.
    pub(crate) realms: Vec<RealmAdminOut>,
}

/// One root Grant to the administrator's Party in a realm it administers.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RealmGrantOut {
    /// The resource namespace the Grant covers (`idp` is the realm's own resources).
    pub(crate) resource: String,
    /// The granted actions, `<namespace>.<name>`.
    pub(crate) actions: Vec<String>,
    /// The Party's holding: the `basis` its writes are signed on.
    pub(crate) basis: serde_json::Value,
}

/// The platform administrator in a realm it also administers (OP-159 m.43 (c)).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RealmAdminOut {
    /// The realm's slug: the console address is `/console/<realm>`.
    pub(crate) realm: String,
    /// The realm's issuer.
    pub(crate) issuer: String,
    /// The account (`usr_…`) in this realm.
    pub(crate) subject: String,
    /// Its Party in the realm's governing domain, base64url.
    pub(crate) party: String,
    /// Its device Instance there, base64url.
    pub(crate) instance: String,
    /// The root's Grants to the Party.
    pub(crate) grants: Vec<RealmGrantOut>,
    /// Whether this run opened the realm's delegated administration (TN-114), without which
    /// no meta-action Grant is issued.
    pub(crate) delegated_admin_opened: bool,
    /// The authenticator app: the platform realm's seed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) totp: Option<TotpOut>,
    /// Whether this run made the account.
    pub(crate) created: bool,
}

/// Checks the plan's `[platform_admin]` section when it is present: each realm it names is one
/// of `tenants`, once.
pub(super) fn check(
    file: Option<PlatformAdminFile>,
    tenants: &[String],
) -> Result<Option<PlatformAdminPlan>, BootstrapError> {
    let Some(p) = file else {
        return Ok(None);
    };
    if p.identifier.trim().is_empty() {
        return Err(BootstrapError::Plan(String::from(
            "platform_admin: identifier is required",
        )));
    }
    let password = named_password("platform_admin", p.password, p.password_env.as_deref())?;
    let mut seen = BTreeSet::new();
    for r in &p.realms {
        sample_tenant(tenants, "platform_admin", r)?;
        if !seen.insert(r.as_str()) {
            return Err(BootstrapError::Plan(format!(
                "platform_admin: realm {r} is named twice"
            )));
        }
    }
    Ok(Some(PlatformAdminPlan {
        identifier: p.identifier,
        password,
        totp: p
            .totp_seed_file
            .as_deref()
            .map(TotpSeedFile::open)
            .transpose()?,
        realms: p.realms,
    }))
}

/// The Grant of every `idp.platform.*` action to `holder` over the platform realm's `idp`
/// resources, on its `idp` Anchor (OP-159 m.41 (a), OP-151 m.2 M2).
pub(super) fn platform_grant(domain: &Digest, slug: &str, holder: Id) -> GrantContent {
    let mut content = grant_of(
        domain,
        holder,
        authority(
            PlatformAction::ALL
                .into_iter()
                .map(PlatformAction::action_ref)
                .collect(),
            RESOURCE_NAMESPACE,
            BTreeSet::new(),
        ),
    );
    content.basis = GrantBasis::Anchor(meta::object_id(domain, meta::kind::ANCHOR, IDP_ANCHOR));
    content.authority.authority.resource = super::governance::realm_resources(slug);
    content
}

/// The Grant of every `idp.*` realm action to `holder` over the realm `slug`'s `idp`
/// resources, on its `idp` Anchor (OP-159 m.43 (c)); the platform actions are not among them.
pub(super) fn realm_idp_grant(domain: &Digest, slug: &str, holder: Id) -> GrantContent {
    let mut content = grant_of(
        domain,
        holder,
        authority(
            IdpAction::ALL
                .into_iter()
                .map(IdpAction::action_ref)
                .collect(),
            RESOURCE_NAMESPACE,
            BTreeSet::new(),
        ),
    );
    content.basis = GrantBasis::Anchor(meta::object_id(domain, meta::kind::ANCHOR, IDP_ANCHOR));
    content.authority.authority.resource = super::governance::realm_resources(slug);
    content
}

/// The Grant of the core `names` over the objects of `namespace` to `holder`, on the
/// meta-anchor (OP-159 m.43 (c), TN-114).
pub(super) fn realm_meta_grant(
    domain: &Digest,
    namespace: &str,
    names: &[&str],
    holder: Id,
) -> GrantContent {
    grant_of(
        domain,
        holder,
        authority(
            names.iter().map(|n| meta::core_action(n)).collect(),
            namespace,
            BTreeSet::new(),
        ),
    )
}

/// The nonce label of the Grant `content` to `party` in `domain`.
fn realm_grant_label(domain: &Digest, party: Id, content: &GrantContent) -> Vec<u8> {
    let mut label = REALM_GRANT_LABEL.to_vec();
    label.extend_from_slice(&domain.0);
    label.extend_from_slice(&party.0);
    label.extend_from_slice(&meta::bounds_digest(&content.authority).0);
    label
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// The platform administrator of `p` in the platform realm (OP-159 m.41 (a)): an active
    /// account with the plan's password and, when the plan names a seed file, an authenticator
    /// app; its Party and device Instance; and the root's Grant of the `idp.platform.*`
    /// actions to that Party (INV-29: given explicitly, never held by default).
    pub(super) async fn platform_admin(
        &self,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug, issuer): (Digest, &HsmSigner, &str, &str),
        p: &PlatformAdminPlan,
    ) -> Result<PlatformAdminOut, BootstrapError> {
        let (subject, external, created) = self
            .account(ids, (tenant, realm), &p.identifier, Some(&p.password))
            .await?;
        let (party, instance) = self
            .device_party((tenant, realm), domain, subject, (DEVICE_LABEL, None))
            .await?;
        let (_, totp) = self
            .authenticators(
                slug,
                subject,
                &p.identifier,
                (false, p.totp.as_ref().map(|f| (f, Seed::Drawn))),
            )
            .await?;
        let grant = platform_grant(&domain, slug, party);
        let mut label = GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&party.0);
        label.extend_from_slice(&meta::bounds_digest(&grant.authority).0);
        let idp = meta::object_id(&domain, meta::kind::ANCHOR, IDP_ANCHOR);
        let holding = self
            .granted_on(
                domain,
                root,
                &label,
                (grant, ExerciseBasis::Anchor(idp)),
                party,
            )
            .await?;
        Ok(PlatformAdminOut {
            realm: String::from(slug),
            issuer: String::from(issuer),
            identifier: p.identifier.clone(),
            subject: external,
            party: b64url_encode(&party.0),
            instance: b64url_encode(&instance.0),
            actions: PlatformAction::ALL
                .into_iter()
                .map(PlatformAction::label)
                .collect(),
            basis: holding_json(&holding),
            totp,
            created,
            realms: Vec::new(),
        })
    }

    /// The platform administrator of `p` in the tenant realm `slug` (OP-159 m.43 (c), TN-119,
    /// INV-29): an active account with the same identifier and password and, when the plan
    /// names a seed file, the same authenticator app (`redrawn` when the platform realm drew its
    /// seed in this run); its Party and device Instance; the realm's delegated administration
    /// opened by the root's own `idp.realm.delegated_admin` (TN-114); and the root's
    /// `grant_issue`s to that Party of every `idp.*` action and of the console's core
    /// meta-actions and reads.
    pub(super) async fn realm_admin(
        &self,
        admin: &Admin<'_, P, P, K>,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug, issuer): (Digest, &HsmSigner, &str, &str),
        (p, redrawn): (&PlatformAdminPlan, bool),
    ) -> Result<RealmAdminOut, BootstrapError> {
        let (subject, external, created) = self
            .account(ids, (tenant, realm), &p.identifier, Some(&p.password))
            .await?;
        let label = realm_device_label(slug);
        let (party, instance) = self
            .device_party((tenant, realm), domain, subject, (&label, None))
            .await?;
        let (_, totp) = self
            .authenticators(
                slug,
                subject,
                &p.identifier,
                (
                    false,
                    p.totp.as_ref().map(|f| (f, Seed::Shared { redrawn })),
                ),
            )
            .await?;
        let mut grants = Vec::new();
        let content = realm_idp_grant(&domain, slug, party);
        let idp = meta::object_id(&domain, meta::kind::ANCHOR, IDP_ANCHOR);
        let holding = self
            .granted_on(
                domain,
                root,
                &realm_grant_label(&domain, party, &content),
                (content, ExerciseBasis::Anchor(idp)),
                party,
            )
            .await?;
        grants.push(RealmGrantOut {
            resource: String::from(RESOURCE_NAMESPACE),
            actions: IdpAction::ALL.into_iter().map(IdpAction::label).collect(),
            basis: holding_json(&holding),
        });
        // TN-114, OP-157 m.3 (t)
        let opened = !realm_delegated_admin_open(self.app, &DomainId::from_bytes(domain.0)).await?;
        if opened {
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::DelegatedAdmin(true),
            )
            .await?;
        }
        for (namespace, names) in META_GRANTS {
            let content = realm_meta_grant(&domain, namespace, names, party);
            let holding = self
                .granted(
                    domain,
                    root,
                    &realm_grant_label(&domain, party, &content),
                    content,
                    party,
                )
                .await?;
            grants.push(RealmGrantOut {
                resource: String::from(namespace),
                actions: names
                    .iter()
                    .map(|n| format!("{}.{n}", meta::NAMESPACE))
                    .collect(),
                basis: holding_json(&holding),
            });
        }
        Ok(RealmAdminOut {
            realm: String::from(slug),
            issuer: String::from(issuer),
            subject: external,
            party: b64url_encode(&party.0),
            instance: b64url_encode(&instance.0),
            grants,
            delegated_admin_opened: opened,
            totp,
            created,
        })
    }
}
