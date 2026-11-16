//! A tenant's administration from its management environment (OP-159 m.47 (d), (e), (f), (h)):
//! each `idp.tenant.*` change is an Exercise in the management environment's governing domain,
//! committed before anything is written (TN-110, PI-4). An environment opens in the tenant whose
//! management domain recorded the order (PI-7), rooted in the tenant's owners, with the
//! administrator rule over the management environment's issuer in its Genesis, and is bound as
//! a domain consuming that issuer's Claims (TN-4).

use access_identity_oauth::domain::issuer::Issuer;
use access_internal_api::idp::{IdpAction, Submission, Verdict};
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};
use access_store::environment_binding::{self, Role};
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::idp::{self, Decision as Bind};
use access_store::scope::DomainId;
use access_store::tenant_admin as tenants;

use super::{Admin, Administered, Applied, NewEnvironment, Prepared};
use crate::AdminError;
use crate::domain::provision::SANDBOX_BUDGET;
use crate::domain::tenant::{MANAGEMENT, TenantChange, TenantInvalid, owners_root};
use crate::ports::{Decider, EnvironmentKeys, Governance, Instances};

/// Why a tenant write did not happen.
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    /// Refused before a decision.
    #[error(transparent)]
    Invalid(#[from] TenantInvalid),
    /// The identity plane or the authority plane failed or refused.
    #[error(transparent)]
    Admin(#[from] AdminError),
}

impl From<access_store::StoreError> for TenantError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Admin(e.into())
    }
}

/// A tenant write as its caller signs it.
pub struct TenantOrder<'a> {
    /// The tenant.
    pub tenant: TenantId,
    /// Its management environment.
    pub environment: EnvironmentId,
    /// The change.
    pub change: &'a TenantChange,
    /// The session subject, when a session asks.
    pub subject: Option<[u8; 16]>,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent's validity.
    pub validity: Window,
    /// The actor's declared basis.
    pub basis: ExerciseBasis,
    /// The actor's declared capacity.
    pub capacity: Capacity,
}

/// What a committed environment creation opened.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedEnvironment {
    /// The environment.
    pub environment: EnvironmentId,
    /// Its governing domain.
    pub domain: Digest,
    /// Its issuer.
    pub issuer: String,
}

/// The `idp` actions a standard environment's administrator rule covers (OP-159 m.47 (d)).
#[must_use]
pub fn environment_actions() -> Vec<access_kernel::model::ActionRef> {
    IdpAction::ALL
        .into_iter()
        .map(IdpAction::action_ref)
        .collect()
}

impl<D: Decider, G: Governance + Instances, K: EnvironmentKeys> Admin<'_, D, G, K> {
    /// The governing domain and slug of `environment` when it is `tenant`'s management environment
    /// (TN-138).
    async fn management(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
    ) -> Result<(Digest, String), TenantError> {
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let kind = tenants::environment_kind(&mut t).await?;
        let g = idp::governance(&mut t).await?;
        t.commit().await?;
        let g = g.ok_or(AdminError::NoEnvironment)?;
        if kind.as_deref() != Some(MANAGEMENT) {
            return Err(TenantInvalid::NotManagement.into());
        }
        Ok((Digest(*g.domain.as_bytes()), g.slug))
    }

    /// Whether `change` fits the tenant's current state: a new environment's slug is free
    /// (TN-16); a removed or promoted administrator is a live one; the last owner stays.
    async fn tenant_fits(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
        change: &TenantChange,
    ) -> Result<(), TenantError> {
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let admins = tenants::admins(&mut t).await?;
        t.commit().await?;
        let live = |s: &[u8; 16]| {
            admins
                .iter()
                .find(|a| a.subject == *s && a.ended_ms.is_none())
        };
        match change {
            TenantChange::EnvironmentCreate(e) => {
                if !tenants::slug_free(self.app, &e.slug).await? {
                    return Err(TenantInvalid::Provision(
                        crate::domain::provision::ProvisionInvalid::SlugTaken,
                    )
                    .into());
                }
            }
            TenantChange::AdminRemove { subject } => {
                let a = live(subject).ok_or(TenantInvalid::NoAdmin)?;
                let owners = admins
                    .iter()
                    .filter(|a| a.owner && a.ended_ms.is_none())
                    .count();
                if a.owner && owners <= 1 {
                    return Err(TenantInvalid::LastOwner.into());
                }
            }
            TenantChange::OwnerAdd { subject } => {
                let a = live(subject).ok_or(TenantInvalid::NoAdmin)?;
                if a.owner || a.party.is_none() {
                    return Err(TenantInvalid::NoAdmin.into());
                }
            }
            TenantChange::AdminInvite(_) => {}
        }
        Ok(())
    }

    /// The intent the caller signs for `change` in the management environment (TN-110, EI-25).
    ///
    /// # Errors
    /// [`TenantError`].
    pub async fn prepare_tenant(
        &self,
        (tenant, environment): (TenantId, EnvironmentId),
        change: &TenantChange,
        validity: Window,
    ) -> Result<Prepared, TenantError> {
        change.check()?;
        let (domain, slug) = self.management(tenant, environment).await?;
        self.tenant_fits(tenant, environment, change).await?;
        let intent = change
            .intent(&slug, validity)
            .map_err(|_| AdminError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| AdminError::Encode)?;
        Ok(Prepared {
            domain,
            intent,
            digest,
        })
    }

    /// Has the management environment's governing domain commit `order`, binds the ALLOW and
    /// writes what it names (TN-110, EI-25, PI-7).
    ///
    /// # Errors
    /// [`TenantError`]; a DENY is [`Applied::NotAllowed`].
    #[expect(
        clippy::too_many_lines,
        reason = "the decision, its binding and the change's writes in one place, as provisioning"
    )]
    pub async fn apply_tenant(
        &self,
        order: TenantOrder<'_>,
        ais: Vec<u8>,
    ) -> Result<(Applied, Option<OpenedEnvironment>), TenantError> {
        order.change.check()?;
        let (domain, slug) = self.management(order.tenant, order.environment).await?;
        let intent = order
            .change
            .intent(&slug, order.validity)
            .map_err(|_| AdminError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| AdminError::Encode)?;
        let actor = match order.subject {
            Some(s) => {
                let mut t = TenantTx::begin(self.app, order.tenant, order.environment).await?;
                let p = idp::subject_party(&mut t, &s).await?;
                t.commit().await?;
                Some(p.map(Id).ok_or_else(|| {
                    AdminError::Refused(String::from(access_internal_api::idp::ACTOR_BINDING))
                })?)
            }
            None => None,
        };
        // §13.4 G54, TN-49
        self.standing((order.tenant, order.environment), domain, &ais, actor)
            .await?;
        let verdict = self
            .decider
            .decide(Submission {
                actor,
                domain,
                nonce: order.nonce.clone(),
                payload: None,
                intent,
                basis: order.basis,
                capacity: order.capacity,
                ais,
                contributions: Vec::new(),
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let committed = match verdict {
            Verdict::Committed(c) => c,
            Verdict::NotAllowed { decision, position } => {
                return Ok((Applied::NotAllowed { decision, position }, None));
            }
            Verdict::Refused { code, .. } if code == "unavailable" => {
                return Err(AdminError::Unavailable(code).into());
            }
            Verdict::Refused { code, .. } => return Err(AdminError::Refused(code).into()),
        };
        // EI-25
        if committed.intent != digest
            || committed.domain != domain
            || committed.nonce != order.nonce
        {
            return Err(AdminError::Unbound.into());
        }
        let change = order.change.digest().map_err(|_| AdminError::Encode)?;
        let label = order.change.action().label();
        let mut t = TenantTx::begin(self.app, order.tenant, order.environment).await?;
        let bound = idp::bind(
            &mut t,
            &Bind {
                domain: &DomainId::from_bytes(domain.0),
                position: committed.position,
                nonce: &committed.nonce,
                intent: committed.intent.0,
                change: change.0,
                action: &label,
            },
        )
        .await?;
        let first = bound.is_some();
        if first
            && let Err(e) = self
                .tenant_fits(order.tenant, order.environment, order.change)
                .await
        {
            t.rollback().await?;
            return Err(e);
        }
        let exercise = committed.exercise;
        match order.change {
            TenantChange::AdminRemove { subject } if first => {
                tenants::end_admin(&mut t, subject, Some(&exercise.0)).await?;
            }
            TenantChange::OwnerAdd { subject } if first => {
                tenants::make_owner(&mut t, subject).await?;
            }
            _ => {}
        }
        t.commit().await?;
        let opened = match order.change {
            TenantChange::EnvironmentCreate(e) => Some(
                Box::pin(self.open_tenant_environment(
                    (order.tenant, order.environment),
                    e,
                    &exercise,
                ))
                .await?,
            ),
            _ => None,
        };
        let applied = if first {
            Applied::Written {
                exercise,
                position: committed.position,
                secret: None,
            }
        } else {
            Applied::AlreadyWritten {
                exercise,
                position: committed.position,
            }
        };
        Ok((applied, opened))
    }

    /// Opens the environment of a bound `idp.tenant.environment_create` (OP-159 m.47 (d), (e), (h)):
    /// rooted in the tenant's owners, with the administrator rule over the management environment's
    /// issuer, placed where the tenant is, bound as consuming that issuer's Claims, and the
    /// issuer's key opened there. Repeating it finds what it opened.
    ///
    /// # Errors
    /// [`TenantError`].
    pub async fn open_tenant_environment(
        &self,
        (tenant, management): (TenantId, EnvironmentId),
        e: &crate::domain::tenant::NewTenantEnvironment,
        exercise: &Digest,
    ) -> Result<OpenedEnvironment, TenantError> {
        let mut t = TenantTx::begin(self.app, tenant, management).await?;
        let owners: std::collections::BTreeSet<Id> = tenants::admins(&mut t)
            .await?
            .into_iter()
            .filter(|a| a.owner && a.ended_ms.is_none())
            .filter_map(|a| a.party.map(Id))
            .collect();
        let issuer = access_store::issuer::environment_issuer(&mut t)
            .await?
            .ok_or(AdminError::NoEnvironment)?;
        let placement = tenants::tenant_placement(&mut t).await?;
        t.commit().await?;
        let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
        let existing = tenants::tenant_environments(&mut t)
            .await?
            .into_iter()
            .find(|x| x.slug == e.slug);
        t.commit().await?;
        let root = owners_root(&owners).ok_or(TenantInvalid::NoAdmin)?;
        let (environment, domain, issuer_url, acceptance) = if let Some(found) = existing {
            let mut tx = TenantTx::begin(self.app, tenant, found.environment).await?;
            let opener = access_store::tenancy::provisioned_by(&mut tx).await?;
            tx.commit().await?;
            // TN-16, INV-32
            if opener != Some(exercise.0) {
                return Err(TenantInvalid::Provision(
                    crate::domain::provision::ProvisionInvalid::SlugTaken,
                )
                .into());
            }
            (
                found.environment,
                Digest(*found.domain.as_bytes()),
                found.issuer.unwrap_or_default(),
                None,
            )
        } else {
            let created = self
                .create_environment(&NewEnvironment {
                    tenant,
                    slug: &e.slug,
                    style: e.style,
                    placement: &placement,
                    root,
                    ct3_delay_s: None,
                    causal_binding: false,
                    schemas: e.schemas.clone(),
                    acceptances: e.acceptances.clone(),
                    issuer_predicate_input: e.issuer_predicate_input.clone(),
                    provisioned_by: Some(*exercise),
                    administered: Some(Administered::By {
                        issuer,
                        actions: environment_actions(),
                    }),
                    management: None,
                })
                .await?;
            (
                created.environment,
                created.domain,
                String::from(Issuer::as_str(&created.issuer)),
                created.admin_acceptance,
            )
        };
        let d = DomainId::from_bytes(domain.0);
        let mut t = TenantTx::begin(self.app, tenant, management).await?;
        // TN-4, OP-159 m.47 (d)
        if let Some(a) = acceptance {
            environment_binding::bind(&mut t, management, &d, Role::Consuming { acceptance: a.0 })
                .await?;
        }
        t.commit().await?;
        // OP-151 m.3 (m)
        if e.sandbox {
            let mut tx = TenantTx::begin(self.app, tenant, environment).await?;
            access_store::sandbox::mark(
                &mut tx,
                &d,
                access_store::sandbox::Budget {
                    exercises_per_day: SANDBOX_BUDGET.exercises_per_day,
                    projections_per_day: SANDBOX_BUDGET.projections_per_day,
                },
            )
            .await?;
            tx.commit().await?;
        }
        // OP-159 m.47 (d), OP-150 L2
        Box::pin(self.register_issuer_in(tenant, management, domain)).await?;
        Ok(OpenedEnvironment {
            environment,
            domain,
            issuer: issuer_url,
        })
    }
}
