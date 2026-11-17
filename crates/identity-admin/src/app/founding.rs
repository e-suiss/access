//! A tenant's founding (OP-159 m.47 (c), TN-141): the invited founder proves the address with the
//! magic code, then the primary environment's governing domain is opened with the founder's
//! device Party as its root (`provisioned_by` the tenant creation). The platform signs nothing in
//! the new domain (INV-29, TNI-15). The founder's account, credentials and Instance are the hosted
//! login's; this module opens the environment and closes the founding.

use access_identity_oauth::domain::issuer::IssuerStyle;
use access_internal_api::idp::IdpAction;
use access_kernel::digest::Digest;
use access_kernel::meta::Root;
use access_kernel::model::{ActionRef, Id};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::tenant_admin::{self as tenants, FoundingRoute};

use super::{Admin, Administered, CreatedEnvironment, NewEnvironment};
use crate::AdminError;
use crate::domain::tenant::{self, TenantAction};
use crate::ports::{Decider, EnvironmentKeys, Governance, Instances};

/// Why a founding step was refused.
#[derive(Debug, thiserror::Error)]
pub enum FoundingError {
    /// No founding has this link, or the slug is not its.
    #[error("no such founding")]
    NotFound,
    /// The link expired; the platform can reinvite (TN-141).
    #[error("founding expired")]
    Expired,
    /// The address or the code does not match (TN-89 (5)).
    #[error("founding code")]
    Code,
    /// A step out of order: completed already, or not yet verified.
    #[error("founding state")]
    State,
    /// The identity plane or the authority plane failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
}

impl From<access_store::StoreError> for FoundingError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Admin(e.into())
    }
}

impl FoundingError {
    /// HTTP status and stable problem code.
    #[must_use]
    pub const fn problem(&self) -> (u16, &'static str) {
        match self {
            Self::NotFound => (404, "not-found"),
            Self::Expired => (410, "founding-expired"),
            Self::Code => (400, "invalid-code"),
            Self::State => (409, "founding-state"),
            Self::Admin(a) => a.problem(),
        }
    }
}

/// A founding as its route shows it: no secret, no identifier.
#[derive(Clone)]
pub struct FoundingView {
    /// The route.
    pub route: FoundingRoute,
    /// The tenant's display name.
    pub display_name: String,
}

/// A founder's device Party: the first half of its key's RFC 7638 thumbprint (OP-159 m.47 (c),
/// `P = root_party(K)`), so every step names the same Party.
#[must_use]
pub fn device_party(key: &PublicKey) -> Id {
    let t = thumbprint(key);
    let mut id = [0; 16];
    id.copy_from_slice(t.get(..16).unwrap_or(&[0; 16]));
    Id(id)
}

/// The actions the primary environment's administrator rule covers on its own `idp`
/// The further catalogs, Acceptances and issuer predicate classes a primary environment's Genesis
/// carries: none from a founder's link; the local plan's fixtures from the bootstrap (OP-159 m.49
/// (h)).
pub type GenesisExtras = (
    Vec<access_kernel::schema::Spp>,
    Vec<suiss_crypto::dcbor::Value>,
    Vec<String>,
);

/// resources: every `idp.*` action and the administered `idp.tenant.*` ones (OP-159 m.47 (d), (e)).
#[must_use]
pub fn primary_actions() -> Vec<ActionRef> {
    IdpAction::ALL
        .into_iter()
        .map(IdpAction::action_ref)
        .chain(
            TenantAction::ADMINISTERED
                .into_iter()
                .map(TenantAction::action_ref),
        )
        .collect()
}

impl<D: Decider, G: Governance + Instances, K: EnvironmentKeys> Admin<'_, D, G, K> {
    /// The founding the link token `token` names, when it is the one of `slug` (TN-141).
    ///
    /// # Errors
    /// [`FoundingError::NotFound`]; [`FoundingError::Admin`].
    pub async fn founding(&self, slug: &str, token: &str) -> Result<FoundingView, FoundingError> {
        let hash = access_identity_account::domain::invitation::token_hash(token);
        let route = tenants::founding_by_token(self.app, &hash)
            .await?
            .filter(|r| r.slug == slug)
            .ok_or(FoundingError::NotFound)?;
        let mut t = TenantTx::begin_tenant(self.app, route.tenant).await?;
        let name = tenants::tenant_profile(&mut t)
            .await?
            .and_then(|(n, _)| n)
            .unwrap_or_default();
        t.commit().await?;
        Ok(FoundingView {
            route,
            display_name: name,
        })
    }

    async fn live(&self, slug: &str, token: &str) -> Result<FoundingView, FoundingError> {
        let v = self.founding(slug, token).await?;
        if v.route.completed {
            return Err(FoundingError::State);
        }
        let now = access_store::authority::server_time(self.app).await?;
        if now >= v.route.expires_ms {
            return Err(FoundingError::Expired);
        }
        Ok(v)
    }

    /// Proves the founder's address with the magic code (TN-89 (5), (7)): the address's blind
    /// index and the code must be the founding's. Repeating it after it succeeded is a no-op.
    ///
    /// # Errors
    /// [`FoundingError`].
    pub async fn verify_founding(
        &self,
        slug: &str,
        token: &str,
        (email, code): (&str, &str),
    ) -> Result<FoundingView, FoundingError> {
        let v = self.live(slug, token).await?;
        let tenant = *v.route.tenant.as_bytes();
        let index = self
            .keys
            .blind_index(v.route.environment)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?
            .index(
                &tenant,
                v.route.environment.as_bytes(),
                &access_identity_account::app::vault::folded(email),
            )
            .map_err(|_| AdminError::Unavailable(String::from("vault")))?;
        let mut t = TenantTx::begin_tenant(self.app, v.route.tenant).await?;
        let f = tenants::founding(&mut t)
            .await?
            .ok_or(FoundingError::NotFound)?;
        let code_hash = access_identity_account::domain::invitation::code_hash(code);
        if f.founder_index != index || f.code_hash != code_hash {
            t.rollback().await?;
            return Err(FoundingError::Code);
        }
        if !f.verified {
            tenants::verify_founding(&mut t).await?;
        }
        t.commit().await?;
        Ok(v)
    }

    /// Opens the primary environment of a verified founding with `founder` as its sole root
    /// (TN-111 with `acknowledge_no_recovery`, TN-138, TN-141): its Genesis publishes the tenant
    /// catalog, carries the administrator rule over its own issuer and records the tenant creation
    /// as `provisioned_by`. Repeating it finds what it opened.
    ///
    /// # Errors
    /// [`FoundingError`].
    pub async fn open_primary(
        &self,
        slug: &str,
        token: &str,
        founder: Id,
        (schemas, acceptances, issuer_predicate_input): GenesisExtras,
    ) -> Result<CreatedEnvironment, FoundingError> {
        let v = self.live(slug, token).await?;
        if !v.route.verified {
            return Err(FoundingError::State);
        }
        let tenant = v.route.tenant;
        let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
        let f = tenants::founding(&mut t)
            .await?
            .ok_or(FoundingError::NotFound)?;
        let opened = tenants::primary_environment(&mut t).await?;
        let placement = tenants::tenant_placement(&mut t).await?;
        t.commit().await?;
        if let Some((environment, _)) = opened {
            return Ok(self.created(tenant, environment).await?);
        }
        Ok(self
            .create_environment(&NewEnvironment {
                tenant,
                slug,
                style: IssuerStyle::Path,
                placement: &placement,
                root: Root::Sole(founder),
                ct3_delay_s: None,
                causal_binding: false,
                schemas: std::iter::once(tenant::catalog(founder))
                    .chain(schemas)
                    .collect(),
                acceptances,
                issuer_predicate_input,
                provisioned_by: Some(Digest(f.exercise)),
                administered: Some(Administered::Own(primary_actions())),
                primary: Some(f.environment),
            })
            .await?)
    }

    /// The environment `environment` of `tenant` as it was created.
    async fn created(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
    ) -> Result<CreatedEnvironment, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let g = access_store::idp::governance(&mut t)
            .await?
            .ok_or(AdminError::NoEnvironment)?;
        t.commit().await?;
        let issuer = g.issuer.ok_or(AdminError::NoEnvironment)?;
        Ok(CreatedEnvironment {
            environment,
            domain: Digest(*g.domain.as_bytes()),
            issuer: access_identity_oauth::domain::issuer::Issuer::parse(&issuer)?,
            admin_acceptance: None,
        })
    }

    /// Closes a founding: binds the founder's account to its device Party, makes it the tenant's
    /// first owner, completes the founding and makes the tenant active (TN-141, OP-159 m.47 (e)).
    ///
    /// # Errors
    /// [`FoundingError`].
    pub async fn finish_founding(
        &self,
        slug: &str,
        token: &str,
        (subject, party): ([u8; 16], Id),
    ) -> Result<(), FoundingError> {
        let v = self.founding(slug, token).await?;
        let mut t = TenantTx::begin(self.app, v.route.tenant, v.route.environment).await?;
        access_store::idp::bind_subject_party(&mut t, &subject, &party.0).await?;
        tenants::add_admin(
            &mut t,
            &subject,
            &tenants::NewAdmin {
                party: Some(&party.0),
                owner: true,
                exercise: None,
                cooling_s: None,
                scope: None,
            },
        )
        .await?;
        tenants::complete_founding(&mut t, &subject).await?;
        tenants::set_tenant_status(&mut t, "provisioning", "active").await?;
        t.commit().await?;
        Ok(())
    }
}
