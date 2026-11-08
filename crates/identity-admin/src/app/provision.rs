//! The platform-admin surface's writes (OP-151 m.2 M2): each provisioning change is an
//! `idp.platform.*` Exercise in the platform realm's governing domain, committed by the authority
//! plane before anything is created (TN-110, PI-4, INV-2). A realm or a sandbox is then opened by
//! a Genesis of its own governing domain with the caller's founding root (TN-111, §5.16); the
//! operator holds nothing in it (INV-29). Every effect is idempotent: a retry of a committed
//! Exercise finishes what the first attempt left.

use access_identity_oauth::domain::issuer::{Issuer, IssuerStyle};
use access_internal_api::idp::{Submission, Verdict};
use access_kernel::claim::body::Class;
use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Window;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{self, Decision as Bind};
use access_store::sandbox::{self, Budget};
use access_store::scope::DomainId;
use access_store::tenancy;

use super::{Admin, NewRealm, Prepared};
use crate::AdminError;
use crate::domain::provision::{
    PlatformChange, ProvisionInvalid, RealmOrder, Recovery, SANDBOX_BUDGET, recovery,
};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// The platform realm whose governing domain decides provisioning, and the router pool that
/// reads across tenants.
pub struct Platform<'a> {
    /// The platform tenant.
    pub tenant: TenantId,
    /// The platform realm.
    pub realm: RealmId,
    /// The router pool (OP-132 m.3).
    pub router: &'a Pool,
}

/// Why a provisioning write did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The change is refused before a decision.
    #[error(transparent)]
    Invalid(#[from] ProvisionInvalid),
    /// The identity plane or the authority plane failed or refused.
    #[error(transparent)]
    Admin(#[from] AdminError),
}

impl From<access_store::StoreError> for ProvisionError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Admin(e.into())
    }
}

/// What a committed provisioning change created.
#[derive(Clone, PartialEq, Eq)]
pub enum Created {
    /// The tenant.
    Tenant(TenantId),
    /// The realm and its governing domain, the Genesis digest (TN-111).
    Realm {
        /// The tenant.
        tenant: TenantId,
        /// The realm.
        realm: RealmId,
        /// Its governing domain: the digest of its Genesis record.
        domain: Digest,
        /// Its issuer.
        issuer: String,
        /// What recovery its Genesis declares (§13.7.7).
        recovery: Recovery,
        /// Its sandbox budget, for a sandbox (OP-151 m.3 (m)).
        sandbox: Option<Budget>,
    },
}

/// The answer to a provisioning write; a refusal is a decision, not an error.
#[derive(Clone, PartialEq, Eq)]
pub enum Provisioned {
    /// Committed, and what it created.
    Done {
        /// The `ExerciseID`.
        exercise: Digest,
        /// Position of the decision record.
        position: u64,
        /// What was created.
        created: Created,
    },
    /// Denied or waiting on an action; nothing was created.
    NotAllowed {
        /// The decision.
        decision: Decision,
        /// Position of its record, when recorded.
        position: Option<u64>,
    },
}

/// A provisioning write as its caller signs it.
pub struct Order<'a> {
    /// The change.
    pub change: &'a PlatformChange,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent's validity.
    pub validity: Window,
    /// The actor's declared basis.
    pub basis: ExerciseBasis,
    /// The actor's declared capacity.
    pub capacity: Capacity,
}

fn budget_of(change: &PlatformChange) -> Option<Budget> {
    matches!(change, PlatformChange::Sandbox(_)).then_some(Budget {
        exercises_per_day: SANDBOX_BUDGET.exercises_per_day,
        projections_per_day: SANDBOX_BUDGET.projections_per_day,
    })
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    async fn platform_governing(&self, p: &Platform<'_>) -> Result<(DomainId, String), AdminError> {
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        t.commit().await?;
        Ok((g.domain, g.slug))
    }

    /// Whether `tenant` exists and is active, read by the router role.
    async fn tenant_active(p: &Platform<'_>, tenant: TenantId) -> Result<bool, AdminError> {
        Ok(tenancy::tenant(p.router, tenant)
            .await?
            .is_some_and(|t| t.status == "active"))
    }

    /// The live realm `slug`, read by the router role, with its tenant.
    async fn slug_owner(p: &Platform<'_>, slug: &str) -> Result<Option<TenantId>, AdminError> {
        Ok(tenancy::route_by_slug(p.router, slug)
            .await?
            .map(|r| r.tenant))
    }

    /// Whether `change` fits the platform's current state: a realm's tenant is active and its
    /// slug is free (TN-16, INV-32).
    async fn fits(p: &Platform<'_>, change: &PlatformChange) -> Result<(), ProvisionError> {
        if let PlatformChange::Realm(o) | PlatformChange::Sandbox(o) = change {
            if !Self::tenant_active(p, TenantId::from_bytes(o.tenant)).await? {
                return Err(ProvisionInvalid::NoTenant.into());
            }
            if Self::slug_owner(p, &o.slug).await?.is_some() {
                return Err(ProvisionInvalid::SlugTaken.into());
            }
        }
        Ok(())
    }

    /// The intent the caller signs for `change`, once it fits the platform's current state
    /// (TN-110, EI-25).
    ///
    /// # Errors
    /// [`ProvisionError`].
    pub async fn prepare_provision(
        &self,
        p: &Platform<'_>,
        change: &PlatformChange,
        validity: Window,
    ) -> Result<Prepared, ProvisionError> {
        change.check()?;
        Self::fits(p, change).await?;
        let (domain, slug) = self.platform_governing(p).await?;
        let intent = change
            .intent(&slug, validity)
            .map_err(|_| AdminError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| AdminError::Encode)?;
        Ok(Prepared {
            domain: Digest(*domain.as_bytes()),
            intent,
            digest,
        })
    }

    /// Has the platform realm's governing domain commit `order` with the caller's `ais`, binds
    /// the committed ALLOW, then creates what it names (TN-110, EI-25, TN-111). The caller is
    /// an Instance of that domain with no realm session: the authority plane decides by its
    /// Grants or its root alone (OP-150 m.11 (f)).
    ///
    /// # Errors
    /// [`ProvisionError`]; a DENY or a pending decision is [`Provisioned::NotAllowed`].
    pub async fn provision(
        &self,
        p: &Platform<'_>,
        order: Order<'_>,
        ais: Vec<u8>,
    ) -> Result<Provisioned, ProvisionError> {
        order.change.check()?;
        let (domain, slug) = self.platform_governing(p).await?;
        let intent = order
            .change
            .intent(&slug, order.validity)
            .map_err(|_| AdminError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| AdminError::Encode)?;
        // §13.4 G54, TN-49
        self.standing((p.tenant, p.realm), Digest(*domain.as_bytes()), &ais, None)
            .await?;
        let verdict = self
            .decider
            .decide(Submission {
                actor: None,
                domain: Digest(*domain.as_bytes()),
                nonce: order.nonce.clone(),
                intent,
                basis: order.basis,
                capacity: order.capacity,
                ais,
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let committed = match verdict {
            Verdict::Committed(c) => c,
            Verdict::NotAllowed { decision, position } => {
                return Ok(Provisioned::NotAllowed { decision, position });
            }
            Verdict::Refused { code, .. } if code == "unavailable" => {
                return Err(AdminError::Unavailable(code).into());
            }
            Verdict::Refused { code, .. } => return Err(AdminError::Refused(code).into()),
        };
        // EI-25
        if committed.intent != digest
            || committed.domain.0 != *domain.as_bytes()
            || committed.nonce != order.nonce
        {
            return Err(AdminError::Unbound.into());
        }
        let change = order.change.digest().map_err(|_| AdminError::Encode)?;
        let label = order.change.action().label();
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let bound = idp::bind(
            &mut t,
            &Bind {
                domain: &domain,
                position: committed.position,
                nonce: &committed.nonce,
                intent: committed.intent.0,
                change: change.0,
                action: &label,
            },
        )
        .await?;
        // TN-110, TN-16: the first application of a decision fits the state it changes; only a
        // retry of a bound one finds its own realm
        if bound.is_some()
            && let Err(e) = Self::fits(p, order.change).await
        {
            t.rollback().await?;
            return Err(e);
        }
        t.commit().await?;
        let created = Box::pin(self.create(p, order.change, &committed.exercise)).await?;
        Ok(Provisioned::Done {
            exercise: committed.exercise,
            position: committed.position,
            created,
        })
    }

    /// What a bound provisioning change creates; repeating it finds what it created before.
    async fn create(
        &self,
        p: &Platform<'_>,
        change: &PlatformChange,
        exercise: &Digest,
    ) -> Result<Created, ProvisionError> {
        match change {
            PlatformChange::Tenant { tenant, placement } => {
                let id = TenantId::from_bytes(*tenant);
                sandbox::create_tenant(self.app, id, placement).await?;
                Ok(Created::Tenant(id))
            }
            PlatformChange::Realm(o) | PlatformChange::Sandbox(o) => {
                Box::pin(self.open_realm(p, o, budget_of(change), exercise)).await
            }
        }
    }

    async fn open_realm(
        &self,
        p: &Platform<'_>,
        o: &RealmOrder,
        budget: Option<Budget>,
        exercise: &Digest,
    ) -> Result<Created, ProvisionError> {
        let tenant = TenantId::from_bytes(o.tenant);
        let (realm, domain, issuer) = match tenancy::route_by_slug(p.router, &o.slug).await? {
            Some(route) if route.tenant == tenant => {
                let mut tx = TenantTx::begin(self.app, tenant, route.realm).await?;
                let gov = idp::governance(&mut tx).await?.ok_or(AdminError::NoRealm)?;
                let opener = tenancy::provisioned_by(&mut tx).await?;
                tx.commit().await?;
                // TN-16, INV-32: a retry finishes only the realm its own Exercise opened
                if opener != Some(exercise.0) {
                    return Err(ProvisionInvalid::SlugTaken.into());
                }
                self.open_keys(tenant, route.realm).await?;
                (route.realm, Digest(*gov.domain.as_bytes()), route.issuer)
            }
            Some(_) => return Err(ProvisionInvalid::SlugTaken.into()),
            None => {
                if !Self::tenant_active(p, tenant).await? {
                    return Err(ProvisionInvalid::NoTenant.into());
                }
                let created = self
                    .create_realm(&NewRealm {
                        tenant,
                        slug: &o.slug,
                        style: o.style,
                        placement: &o.placement,
                        root: o.root.clone(),
                        ct3_delay_s: o.ct3_delay_s,
                        schemas: Vec::new(),
                        acceptances: Vec::new(),
                        // OP-149 m.29 (b), SI-5
                        issuer_predicate_input: vec![Class::Authentication.name()],
                        provisioned_by: Some(*exercise),
                    })
                    .await?;
                (
                    created.realm,
                    created.domain,
                    String::from(Issuer::as_str(&created.issuer)),
                )
            }
        };
        // OP-151 m.3 (m)
        if let Some(fixed) = budget {
            let mut tx = TenantTx::begin(self.app, tenant, realm).await?;
            sandbox::mark(&mut tx, &DomainId::from_bytes(domain.0), fixed).await?;
            tx.commit().await?;
        }
        Ok(Created::Realm {
            tenant,
            realm,
            domain,
            issuer,
            recovery: recovery(&o.root),
            sandbox: budget,
        })
    }
}

/// The issuer style a request names: `subdomain` (the default) or `path` (TN-10).
#[must_use]
pub fn style(name: Option<&str>) -> Option<IssuerStyle> {
    match name {
        None | Some("subdomain") => Some(IssuerStyle::Subdomain),
        Some("path") => Some(IssuerStyle::Path),
        Some(_) => None,
    }
}
