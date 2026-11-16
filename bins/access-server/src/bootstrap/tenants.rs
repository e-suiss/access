//! The plan's tenants with administrators (OP-159 m.47 (c), (d), (i), TN-141): the platform creates
//! each with a founder invitation, the bootstrap plays the founder headless (the address proven
//! with the code, the management environment opened with the founder's device key as its root, the
//! founder's account with the plan's password and authenticator app, the founding closed), then
//! the founder's key opens each of the tenant's environments by `idp.tenant.environment_create`.
//! Each environment's root is the founder, never the operator. A second run finds every step done.

use std::path::PathBuf;

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_admin::app::provision::{Order, Platform, Provisioned};
use access_identity_admin::app::tenant::TenantOrder as TenantWrite;
use access_identity_admin::app::{Admin, Applied};
use access_identity_admin::domain::provision::{PlatformChange, TenantOrder};
use access_identity_admin::domain::tenant::{NewTenantEnvironment, TenantChange};
use access_identity_admin::ports::{Decider, EnvironmentKeys, Governance, Instances};
use access_identity_oauth::domain::issuer::IssuerStyle;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, ExerciseBasis, kind};
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::tenancy::route_by_slug;
use access_store::tenant_admin as tenants;
use serde::{Deserialize, Serialize};
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::Signer as _;

use super::{
    Bootstrap, BootstrapError, IDP_ANCHOR, MetaExercises, Moment, PLACEMENT, TotpOut, TotpSeedFile,
    named_password, root_party, server_time, sign, token_key,
};

/// The token label prefix of a tenant founder's device key: `<prefix>/<management slug>`.
pub(crate) const FOUNDER_LABEL: &str = "access/bootstrap/founder";

/// The token label of the founder of the management environment `slug`.
pub(crate) fn founder_label(slug: &str) -> String {
    format!("{FOUNDER_LABEL}/{slug}")
}

/// `[[tenant]]` as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TenantFile {
    name: String,
    management: String,
    #[serde(default)]
    environments: Vec<String>,
    founder: FounderFile,
}

/// `[tenant.founder]` as written: the password comes from the variable `password_env` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FounderFile {
    identifier: String,
    password: Option<String>,
    password_env: Option<String>,
    totp_seed_file: Option<PathBuf>,
}

impl core::fmt::Debug for TenantFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TenantFile")
            .field("name", &self.name)
            .field("management", &self.management)
            .field("environments", &self.environments)
            .finish_non_exhaustive()
    }
}

/// A tenant with administrators as checked.
#[derive(Clone)]
pub(crate) struct TenantPlan {
    /// Its display name.
    pub(crate) name: String,
    /// Its management environment's slug.
    pub(crate) management: String,
    /// Its other environments' slugs.
    pub(crate) environments: Vec<String>,
    /// The founder's identifier.
    pub(crate) identifier: String,
    /// The founder's password.
    pub(crate) password: Secret<String>,
    /// Where the founder's authenticator app seed is kept.
    pub(crate) totp: Option<TotpSeedFile>,
}

impl core::fmt::Debug for TenantPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TenantPlan")
            .field("name", &self.name)
            .field("management", &self.management)
            .field("environments", &self.environments)
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}

/// Checks the plan's `[[tenant]]` sections: every slug once across them and `taken`.
pub(super) fn check(
    files: Vec<TenantFile>,
    taken: &[String],
) -> Result<Vec<TenantPlan>, BootstrapError> {
    let mut seen: std::collections::BTreeSet<String> = taken.iter().cloned().collect();
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        for slug in std::iter::once(&f.management).chain(&f.environments) {
            if !seen.insert(slug.clone()) {
                return Err(BootstrapError::Plan(format!(
                    "tenant {}: environment {slug} is named twice",
                    f.name
                )));
            }
        }
        let password = named_password(
            &format!("tenant {} founder", f.name),
            f.founder.password,
            f.founder.password_env.as_deref(),
        )?;
        out.push(TenantPlan {
            name: f.name,
            management: f.management,
            environments: f.environments,
            identifier: f.founder.identifier,
            password,
            totp: f
                .founder
                .totp_seed_file
                .as_deref()
                .map(TotpSeedFile::open)
                .transpose()?,
        });
    }
    Ok(out)
}

/// A tenant with administrators in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TenantOut {
    /// Its display name.
    pub(crate) name: String,
    /// Its management environment: the console address is `/console/<management>`.
    pub(crate) management: String,
    /// Its other environments.
    pub(crate) environments: Vec<String>,
    /// The founder, the tenant's first owner.
    pub(crate) founder: FounderOut,
}

/// A tenant's founder in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct FounderOut {
    /// The login identifier.
    pub(crate) identifier: String,
    /// The account (`usr_…`) in the management environment.
    pub(crate) subject: String,
    /// Its device Party, the root of the tenant's environments, base64url.
    pub(crate) party: String,
    /// The founder's authenticator app, when the plan asks for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) totp: Option<TotpOut>,
    /// Whether this run founded the tenant.
    pub(crate) created: bool,
}

/// One environment a managed tenant opened, for the environment loop.
pub(crate) struct Opened {
    pub(crate) slug: String,
    pub(crate) tenant: TenantId,
    pub(crate) environment: EnvironmentId,
    pub(crate) domain: Digest,
    pub(crate) created: bool,
}

/// The further catalogs, Acceptances and issuer predicate classes an environment's Genesis
/// carries for the plan's local fixtures.
pub(crate) type Genesis = (
    Vec<access_kernel::schema::Spp>,
    Vec<suiss_crypto::dcbor::Value>,
    Vec<String>,
);

/// What gives an environment's Genesis facts by its slug and the founder's Party.
pub(crate) type GenesisOf<'a> = &'a dyn Fn(&str, access_kernel::model::Id) -> Genesis;

/// The platform environment the tenants are created in, and the operator's key that roots it.
pub(super) struct PlatformRoot<'a> {
    pub(super) tenant: TenantId,
    pub(super) environment: EnvironmentId,
    pub(super) root: &'a HsmSigner,
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: EnvironmentKeys,
{
    /// The founded tenant of `t` and its environments, founding it headless when the platform
    /// has not created it yet (OP-159 m.47 (c), (i)); returns the opened environments with the
    /// management environment first, the founder's key and the summary.
    pub(super) async fn managed_tenant(
        &self,
        admin: &Admin<'_, P, P, K>,
        ids: &IdKey,
        platform: &PlatformRoot<'_>,
        (t, genesis): (&TenantPlan, GenesisOf<'_>),
    ) -> Result<(Vec<Opened>, HsmSigner, TenantOut), BootstrapError> {
        let founder_key = token_key(self.hsm, &founder_label(&t.management))?;
        let founder = root_party(&founder_key.public_key());
        let created = route_by_slug(self.router, &t.management).await?.is_none();
        let (tenant, management, domain) = if created {
            self.found(admin, platform, t, founder).await?
        } else {
            let route = route_by_slug(self.router, &t.management)
                .await?
                .ok_or(BootstrapError::Plan(format!("{}: no route", t.management)))?;
            let mut tx = TenantTx::begin(self.app, route.tenant, route.environment).await?;
            let g = access_store::idp::governance(&mut tx)
                .await?
                .ok_or(access_identity_admin::AdminError::NoEnvironment)?;
            tx.commit().await?;
            (
                route.tenant,
                route.environment,
                Digest(*g.domain.as_bytes()),
            )
        };
        admin.open_keys(tenant, management).await?;
        self.onboard(tenant, management, domain, &founder_key, founder)
            .await?;
        let (subject, external, _) = self
            .account(ids, (tenant, management), &t.identifier, Some(&t.password))
            .await?;
        let (_, totp) = self
            .authenticators(
                &t.management,
                subject,
                &t.identifier,
                (false, t.totp.as_ref()),
            )
            .await?;
        if created {
            let token = Self::founding_token(admin, tenant)?;
            admin
                .finish_founding(&t.management, &token, (subject, founder))
                .await
                .map_err(|e| BootstrapError::Refused(e.to_string()))?;
        }
        let mut opened = vec![Opened {
            slug: t.management.clone(),
            tenant,
            environment: management,
            domain,
            created,
        }];
        for slug in &t.environments {
            opened.push(
                self.tenant_environment(
                    admin,
                    (tenant, management, domain),
                    (&founder_key, subject),
                    (slug, genesis(slug, founder)),
                )
                .await?,
            );
        }
        let out = TenantOut {
            name: t.name.clone(),
            management: t.management.clone(),
            environments: t.environments.clone(),
            founder: FounderOut {
                identifier: t.identifier.clone(),
                subject: external,
                party: b64url_encode(&founder.0),
                totp,
                created,
            },
        };
        Ok((opened, founder_key, out))
    }

    /// The founder's link token of `tenant`: the first round's, which the bootstrap derives as the
    /// platform did (TN-141).
    fn founding_token(
        admin: &Admin<'_, P, P, K>,
        tenant: TenantId,
    ) -> Result<String, BootstrapError> {
        let (_, secrets) = admin.founder_commitment(*tenant.as_bytes(), "", 0)?;
        Ok(secrets.token.expose().clone())
    }

    /// Creates the tenant by the platform root's `idp.platform.tenant_create` and plays its
    /// founder: the address proven with the code and the management environment opened with
    /// `founder` as its root.
    async fn found(
        &self,
        admin: &Admin<'_, P, P, K>,
        platform: &PlatformRoot<'_>,
        t: &TenantPlan,
        founder: access_kernel::model::Id,
    ) -> Result<(TenantId, EnvironmentId, Digest), BootstrapError> {
        let email = access_identity_admin::domain::tenant::folded_email(&t.identifier)
            .ok_or_else(|| BootstrapError::Plan(format!("{}: founder identifier", t.name)))?;
        let tenant = if let Some(tenant) =
            tenants::founding_by_slug(self.router, &t.management).await?
        {
            tenant
        } else {
            {
                let tenant = TenantId::from_bytes(access_store::idp::new_uuid(self.app).await?);
                let (commitment, _) = admin.founder_commitment(*tenant.as_bytes(), &email, 0)?;
                let change = PlatformChange::Tenant(TenantOrder {
                    tenant: *tenant.as_bytes(),
                    display_name: t.name.clone(),
                    management_slug: t.management.clone(),
                    placement: String::from(PLACEMENT),
                    founder: commitment,
                });
                let p = Platform {
                    tenant: platform.tenant,
                    environment: platform.environment,
                    router: self.router,
                };
                let m = Moment::at(server_time(self.app).await?);
                let prepared = admin
                    .prepare_provision(&p, &change, m.validity)
                    .await
                    .map_err(|e| BootstrapError::Refused(e.to_string()))?;
                self.lead(prepared.domain).await?;
                let basis = ExerciseBasis::Anchor(meta::object_id(
                    &prepared.domain,
                    kind::ANCHOR,
                    IDP_ANCHOR,
                ));
                let nonce = access_crypto::random::bytes::<16>()
                    .map_err(|_| BootstrapError::Unavailable(String::from("rng")))?;
                let ais = sign(
                    platform.root,
                    &m.statement(prepared.domain, &nonce, prepared.digest, basis),
                )?;
                let done = Box::pin(admin.provision(
                    &p,
                    Order {
                        change: &change,
                        nonce: nonce.to_vec(),
                        validity: m.validity,
                        basis,
                        capacity: Capacity::Own,
                        mail: None,
                    },
                    ais,
                ))
                .await
                .map_err(|e| BootstrapError::Refused(e.to_string()))?;
                if !matches!(done, Provisioned::Done { .. }) {
                    return Err(BootstrapError::Refused(String::from("tenant_create")));
                }
                tenant
            }
        };
        let (_, secrets) = admin.founder_commitment(*tenant.as_bytes(), &email, 0)?;
        let token = secrets.token.expose().clone();
        admin
            .verify_founding(&t.management, &token, (&email, secrets.code.expose()))
            .await
            .map_err(|e| BootstrapError::Refused(e.to_string()))?;
        let created = admin
            .open_management(&t.management, &token, founder)
            .await
            .map_err(|e| BootstrapError::Refused(e.to_string()))?;
        Ok((tenant, created.environment, created.domain))
    }

    /// The tenant environment `slug`, opened by the founder's `idp.tenant.environment_create` when
    /// there is none (OP-159 m.47 (d), (h)), and the founder's Instance in its domain.
    async fn tenant_environment(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, management, domain): (TenantId, EnvironmentId, Digest),
        (founder_key, subject): (&HsmSigner, [u8; 16]),
        (slug, genesis): (&str, Genesis),
    ) -> Result<Opened, BootstrapError> {
        let founder = root_party(&founder_key.public_key());
        let (environment, env_domain, created) = if let Some(route) =
            route_by_slug(self.router, slug).await?
        {
            let mut tx = TenantTx::begin(self.app, route.tenant, route.environment).await?;
            let g = access_store::idp::governance(&mut tx)
                .await?
                .ok_or(access_identity_admin::AdminError::NoEnvironment)?;
            tx.commit().await?;
            (route.environment, Digest(*g.domain.as_bytes()), false)
        } else {
            let change = TenantChange::EnvironmentCreate(NewTenantEnvironment {
                slug: String::from(slug),
                style: IssuerStyle::Path,
                sandbox: false,
                schemas: genesis.0,
                acceptances: genesis.1,
                issuer_predicate_input: genesis.2,
            });
            let m = Moment::at(server_time(self.app).await?);
            let prepared = admin
                .prepare_tenant((tenant, management), &change, m.validity)
                .await
                .map_err(|e| BootstrapError::Refused(e.to_string()))?;
            self.lead(prepared.domain).await?;
            let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
            let nonce = access_crypto::random::bytes::<16>()
                .map_err(|_| BootstrapError::Unavailable(String::from("rng")))?;
            let ais = sign(
                founder_key,
                &m.statement(prepared.domain, &nonce, prepared.digest, basis),
            )?;
            let (applied, opened) = Box::pin(admin.apply_tenant(
                TenantWrite {
                    tenant,
                    environment: management,
                    change: &change,
                    subject: Some(subject),
                    nonce: nonce.to_vec(),
                    validity: m.validity,
                    basis,
                    capacity: Capacity::Own,
                    console: None,
                },
                ais,
            ))
            .await
            .map_err(|e| BootstrapError::Refused(e.to_string()))?;
            if let Applied::NotAllowed { decision, .. } = applied {
                return Err(BootstrapError::Refused(format!(
                    "environment_create: {:?}",
                    decision.outcome
                )));
            }
            let opened = opened.ok_or_else(|| {
                BootstrapError::Refused(String::from("environment_create opened nothing"))
            })?;
            (opened.environment, opened.domain, true)
        };
        admin.open_keys(tenant, environment).await?;
        self.onboard(tenant, environment, env_domain, founder_key, founder)
            .await?;
        // OP-159 m.47 (d), (f)
        let mut tx = TenantTx::begin(self.app, tenant, management).await?;
        tenants::open_line(
            &mut tx,
            &subject,
            &access_store::scope::DomainId::from_bytes(env_domain.0),
            &founder.0,
        )
        .await?;
        tx.commit().await?;
        Ok(Opened {
            slug: String::from(slug),
            tenant,
            environment,
            domain: env_domain,
            created,
        })
    }
}
