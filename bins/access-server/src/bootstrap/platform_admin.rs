//! The local platform administrator (OP-159 m.41 (a), m.47 (i)): an account in the platform environment,
//! the platform tenant's management environment, with a password and an authenticator app, signed in
//! to the console like any administrator. It administers the platform tenant by the administrator
//! rule of the platform environment's Genesis, which covers the `idp.platform.*` actions there and
//! nowhere else: the bootstrap adds it as a tenant administrator and opens its
//! `tenant_administration` line, which the restate job states (OP-159 m.47 (d), (f)). Nobody holds
//! the platform actions by default (INV-29). The platform administrator holds nothing in any other
//! tenant (TN-119, TNI-15). Every step looks for its result first, so a second run changes nothing.

use std::path::PathBuf;

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_admin::domain::provision::PlatformAction;
use access_identity_admin::ports::{Decider, EnvironmentKeys, Governance, Instances};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenant_admin::{self as tenants, NewAdmin};
use serde::{Deserialize, Serialize};

use super::{Bootstrap, BootstrapError, MetaExercises, TotpOut, TotpSeedFile, named_password};

/// The token label of the platform administrator's device key.
pub(crate) const DEVICE_LABEL: &str = "access/bootstrap/platform-admin-device";

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
    /// The platform environment's slug: the console address is `/console/<environment>`.
    pub(crate) environment: String,
    /// The platform environment's issuer.
    pub(crate) issuer: String,
    /// The login identifier.
    pub(crate) identifier: String,
    /// The account (`usr_…`).
    pub(crate) subject: String,
    /// Its Party, base64url.
    pub(crate) party: String,
    /// Its device Instance in the platform environment's governing domain, base64url.
    pub(crate) instance: String,
    /// The actions the platform environment's administrator rule covers, `idp.platform.<name>`
    /// among them.
    pub(crate) actions: Vec<String>,
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

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: EnvironmentKeys,
{
    /// The platform administrator of `p` in the platform environment (OP-159 m.41 (a), m.47 (i)): an
    /// active account with the plan's password and, when the plan names a seed file, an
    /// authenticator app; its Party and device Instance; and its place among the platform tenant's
    /// administrators with its `tenant_administration` line in the platform environment's domain.
    pub(super) async fn platform_admin(
        &self,
        ids: &IdKey,
        (tenant, environment): (TenantId, EnvironmentId),
        (domain, slug, issuer): (Digest, &str, &str),
        p: &PlatformAdminPlan,
    ) -> Result<PlatformAdminOut, BootstrapError> {
        let (subject, external, created) = self
            .account(ids, (tenant, environment), &p.identifier, Some(&p.password))
            .await?;
        let (party, instance) = self
            .device_party((tenant, environment), domain, subject, (DEVICE_LABEL, None))
            .await?;
        let (_, totp) = self
            .authenticators(slug, subject, &p.identifier, (false, p.totp.as_ref()))
            .await?;
        // OP-159 m.47 (d), (i)
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        tenants::add_admin(
            &mut t,
            &subject,
            &NewAdmin {
                party: Some(&party.0),
                owner: false,
                exercise: None,
                cooling_s: None,
            },
        )
        .await?;
        tenants::open_line(&mut t, &subject, &DomainId::from_bytes(domain.0), &party.0).await?;
        t.commit().await?;
        Ok(PlatformAdminOut {
            environment: String::from(slug),
            issuer: String::from(issuer),
            identifier: p.identifier.clone(),
            subject: external,
            party: b64url_encode(&party.0),
            instance: b64url_encode(&instance.0),
            actions: PlatformAction::ALL
                .into_iter()
                .map(PlatformAction::label)
                .collect(),
            totp,
            created,
        })
    }
}
