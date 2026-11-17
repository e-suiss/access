//! The upgrade path of an existing standard environment into its tenant's administration (TN-4,
//! TN-139, OP-159 m.48 (b)): `idp.environment.consumer_bind` in the environment's own governing
//! domain, signed by its root and never by the operator or the platform (INV-29). The domain must
//! already accept the management environment's `tenant_administration` Claims for subject
//! selection, which its root establishes first; the binding then holds after the 24-hour TN-4
//! cool-down.

use access_kernel::codec::Canonical as _;
use access_kernel::meta::{self, ExerciseBasis};
use access_kernel::model::Id;
use access_store::environment_binding;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::idp;
use access_store::scope::DomainId;
use access_store::tenant_admin;
use suiss_crypto::dcbor::{self, Limits};

use super::{Admin, Proposal};
use crate::AdminError;
use crate::domain::tenant::MANAGEMENT;
use crate::domain::{Change, Invalid};
use crate::ports::{Decider, EnvironmentKeys, Governance, Instances};

/// How long a consumer binding cools before it holds (TN-4, OP-159 m.48 (b), PD): 24 hours.
pub const CONSUMER_COOLING_S: i64 = 86_400;

/// What a consumer binding binds.
pub(crate) struct ConsumerBinding {
    /// The tenant's management environment.
    pub(crate) management: EnvironmentId,
    /// The bound environment's governing domain.
    pub(crate) domain: DomainId,
    /// The Acceptance through which that domain selects the tenant's administrators.
    pub(crate) acceptance: [u8; 16],
}

impl<D: Decider, G: Governance + Instances, K: EnvironmentKeys> Admin<'_, D, G, K> {
    /// What `idp.environment.consumer_bind` of `management` binds for the proposal's environment
    /// (OP-159 m.48 (b)): it is a standard environment, `management` is its tenant's management
    /// environment, the two are not bound yet, and the environment's domain accepts the management
    /// issuer's `tenant_administration` Claims for subject selection.
    ///
    /// # Errors
    /// [`Invalid::ManagementBinding`], [`Invalid::ManagementAcceptanceRequired`];
    /// [`AdminError`].
    pub(crate) async fn consumer_binding(
        &self,
        (tenant, environment): (TenantId, EnvironmentId),
        management: &str,
    ) -> Result<ConsumerBinding, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let kind = tenant_admin::environment_kind(&mut t).await?;
        let g = idp::governance(&mut t)
            .await?
            .ok_or(AdminError::NoEnvironment)?;
        t.commit().await?;
        if kind.as_deref() == Some(MANAGEMENT) {
            return Err(Invalid::ManagementBinding.into());
        }
        let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
        let found = tenant_admin::management_environment(&mut t).await?;
        t.commit().await?;
        let Some((m, _)) = found.filter(|(m, slug)| slug == management && *m != environment) else {
            return Err(Invalid::ManagementBinding.into());
        };
        let mut t = TenantTx::begin(self.app, tenant, m).await?;
        let issuer = access_store::issuer::environment_issuer(&mut t).await?;
        let bound = environment_binding::bound(&mut t, m, &g.domain).await?;
        t.commit().await?;
        let Some(issuer) = issuer.filter(|_| !bound) else {
            return Err(Invalid::ManagementBinding.into());
        };
        let acceptance = self
            .administration_acceptance(&g.domain, Id(issuer))
            .await?
            .ok_or(Invalid::ManagementAcceptanceRequired)?;
        Ok(ConsumerBinding {
            management: m,
            domain: g.domain,
            acceptance,
        })
    }

    /// The live Acceptance of `domain` through which it selects Parties by `issuer`'s
    /// `tenant_administration` Claims (TN-139), if any.
    async fn administration_acceptance(
        &self,
        domain: &DomainId,
        issuer: Id,
    ) -> Result<Option<[u8; 16]>, AdminError> {
        let index = access_store::authority::state_of(
            self.app,
            domain,
            &[meta::key(meta::kind::ACCEPTANCES, &issuer)],
        )
        .await?;
        let Some(dcbor::Value::Array(ids)) = index
            .first()
            .and_then(|r| r.value.as_deref())
            .and_then(|v| dcbor::decode(v, Limits::CEILING).ok())
        else {
            return Ok(None);
        };
        for id in ids.iter().filter_map(|v| Id::from_value(v).ok()) {
            let rows = access_store::authority::state_of(
                self.app,
                domain,
                &[meta::key(meta::kind::ACCEPTANCE, &id)],
            )
            .await?;
            let selects = rows
                .first()
                .and_then(|r| r.value.as_deref())
                .and_then(|v| dcbor::decode(v, Limits::CEILING).ok())
                .and_then(|v| meta::ContentState::from_value(&v).ok())
                .filter(|a| a.ended.is_none())
                .and_then(|a| access_kernel::claim::Gate::of(&a.content).ok())
                .is_some_and(|g| {
                    g.use_ == access_kernel::claim::SUBJECT_SELECTION
                        && g.classes
                            .iter()
                            .any(|c| c == access_internal_api::idp::TENANT_ADMINISTRATION)
                });
            if selects {
                return Ok(Some(id.0));
            }
        }
        Ok(None)
    }
}

/// Whether `p` may be sent as the environment's root (INV-29, OP-159 m.48 (b)): a consumer binding
/// comes from a session on an Anchor basis, so only the root of the Anchor that covers the
/// environment's `idp` resources can be eligible; never the operator's sessionless root key and
/// never a delegated holding.
///
/// # Errors
/// [`Invalid::RootRequired`].
pub(crate) fn root_signed(p: &Proposal) -> Result<(), Invalid> {
    if !matches!(p.change, Change::ConsumerBind { .. }) {
        return Ok(());
    }
    if p.subject.is_some() && matches!(p.basis, ExerciseBasis::Anchor(_)) {
        Ok(())
    } else {
        Err(Invalid::RootRequired)
    }
}
