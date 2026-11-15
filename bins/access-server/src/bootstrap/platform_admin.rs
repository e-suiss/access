//! The local platform administrator (OP-159 m.41 (a)): an account in the platform realm with a
//! password and an authenticator app, signed in to the console like any realm's user, and a
//! Party the platform realm's root grants the `idp.platform.*` actions by a `grant_issue`
//! Exercise. Nobody holds them by default (INV-29); this Grant is the only reason the account
//! may create tenants, realms and sandbox domains. Every step looks for its result first, so a
//! second run changes nothing.

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_authority_core::genesis::IDP_ANCHOR;
use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_admin::domain::provision::PlatformAction;
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_internal_api::idp::RESOURCE_NAMESPACE;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, ExerciseBasis, GrantBasis, GrantContent};
use access_kernel::model::Id;
use access_store::identity::{RealmId, TenantId};
use serde::{Deserialize, Serialize};
use suiss_crypto::pkcs11::HsmSigner;

use super::{
    Bootstrap, BootstrapError, MetaExercises, TotpOut, TotpSeedFile, authority, grant_of,
    holding_json, named_password,
};

/// The token label of the platform administrator's device key.
pub(crate) const DEVICE_LABEL: &str = "access/bootstrap/platform-admin-device";

/// What the root signs to derive the nonce of the platform Grant; its bounds are part of it, so
/// a Grant of another shape is another Grant.
const GRANT_LABEL: &[u8] = b"access-bootstrap/platform-grant:1";

/// `[platform_admin]` as written: the password comes from the variable `password_env` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlatformAdminFile {
    identifier: String,
    password: Option<String>,
    password_env: Option<String>,
    totp_seed_file: Option<PathBuf>,
}

impl core::fmt::Debug for PlatformAdminFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAdminFile")
            .field("identifier", &self.identifier)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_env", &self.password_env)
            .field("totp_seed_file", &self.totp_seed_file)
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
}

impl core::fmt::Debug for PlatformAdminPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlatformAdminPlan")
            .field("identifier", &self.identifier)
            .field("totp", &self.totp.as_ref().map(|t| &t.path))
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
}

/// Checks the plan's `[platform_admin]` section when it is present.
pub(super) fn check(
    file: Option<PlatformAdminFile>,
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
    Ok(Some(PlatformAdminPlan {
        identifier: p.identifier,
        password,
        totp: p
            .totp_seed_file
            .as_deref()
            .map(TotpSeedFile::open)
            .transpose()?,
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
            .authenticators(slug, subject, &p.identifier, (false, p.totp.as_ref()))
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
        })
    }
}
