//! The platform-admin surface's writes (OP-151 m.2 M2, OP-159 m.47 (c), (h)): each provisioning
//! change is an `idp.platform.*` Exercise in the platform environment's governing domain,
//! committed by the authority plane before anything is written (TN-110, PI-4, INV-2). A tenant
//! opens `provisioning` with its founding and the founder's mail in one transaction; the founder
//! opens its management environment (TN-141). The operator holds nothing in it (INV-29, TNI-15).
//! Every effect is idempotent: a retry of a committed Exercise finishes what the first attempt
//! left.

use access_identity_oauth::domain::issuer::IssuerStyle;
use access_internal_api::idp::{Submission, Verdict};
use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Window;
use access_store::Pool;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::idp::{self, Decision as Bind};
use access_store::tenancy;
use access_store::tenant_admin::{self as tenants, NewFounding};

use super::{Admin, Prepared};
use crate::AdminError;
use crate::domain::provision::{
    FOUNDING_TTL_S, FounderCommitment, PlatformChange, ProvisionInvalid,
};
use crate::ports::{Decider, EnvironmentKeys, Governance, Instances};

/// The platform environment whose governing domain decides provisioning, and the router pool that
/// reads across tenants.
pub struct Platform<'a> {
    /// The platform tenant.
    pub tenant: TenantId,
    /// The platform environment.
    pub environment: EnvironmentId,
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

/// What a committed provisioning change wrote.
#[derive(Clone, PartialEq, Eq)]
pub enum Created {
    /// The tenant it created or changed.
    Tenant(TenantId),
}

/// The answer to a provisioning write; a refusal is a decision, not an error.
#[derive(Clone, PartialEq, Eq)]
pub enum Provisioned {
    /// Committed, and what it wrote.
    Done {
        /// The `ExerciseID`.
        exercise: Digest,
        /// Position of the decision record.
        position: u64,
        /// What was written.
        created: Created,
    },
    /// Denied or waiting on an action; nothing was written.
    NotAllowed {
        /// The decision.
        decision: Decision,
        /// Position of its record, when recorded.
        position: Option<u64>,
    },
}

/// A founder's link and code: they exist only in the mail (TN-89 (1), (8)).
pub struct FoundingSecrets {
    /// The link token.
    pub token: access_crypto::Secret<String>,
    /// The magic code.
    pub code: access_crypto::Secret<String>,
}

/// Where a tenant creation's founder mail goes (TN-141).
pub struct FounderMail<'a> {
    /// The founder's folded address.
    pub email: &'a str,
    /// The link and the code the commitment hashes.
    pub secrets: &'a FoundingSecrets,
    /// The console's origin, `https://host[:port]`: the mail names the tenant's console under it
    /// (OP-159 m.47 (c)).
    pub console: Option<&'a str>,
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
    /// For a tenant creation or a reinvitation, the founder's mail.
    pub mail: Option<FounderMail<'a>>,
}

/// The magic code of `bytes`: eight base32 characters of the first five (OP-153 m.3 (o)).
fn magic_code(bytes: &[u8]) -> String {
    let mut bits = [0; 5];
    for (b, x) in bits.iter_mut().zip(bytes) {
        *b = *x;
    }
    super::orgs::magic_code(bits)
}

impl<D: Decider, G: Governance + Instances, K: EnvironmentKeys> Admin<'_, D, G, K> {
    async fn platform_governing(&self, p: &Platform<'_>) -> Result<(Digest, String), AdminError> {
        let mut t = TenantTx::begin(self.app, p.tenant, p.environment).await?;
        let g = idp::governance(&mut t)
            .await?
            .ok_or(AdminError::NoEnvironment)?;
        t.commit().await?;
        Ok((Digest(*g.domain.as_bytes()), g.slug))
    }

    /// The founder commitment of `tenant` to `email` and its secrets (TN-89, TN-141): the
    /// management environment's blind index of the address, and a link and a code the token's
    /// index key derives from the tenant and its `round` of invitations, so the draft and the
    /// write name the same and only the token knows them.
    ///
    /// # Errors
    /// [`AdminError::Unavailable`] when the token refuses the vault keys.
    pub fn founder_commitment(
        &self,
        tenant: [u8; 16],
        email: &str,
        round: u32,
    ) -> Result<(FounderCommitment, FoundingSecrets), AdminError> {
        let key = self
            .keys
            .blind_index(EnvironmentId::from_bytes(tenant))
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let index_of = |value: &str| {
            key.index(
                &tenant,
                &tenant,
                &access_identity_account::app::vault::folded(value),
            )
            .map_err(|_| AdminError::Unavailable(String::from("vault")))
        };
        let index = index_of(email)?;
        let derive = |what: &str| index_of(&format!("access/founding/{what}/{round}"));
        let token = access_kernel::json::b64url_encode(&derive("token")?);
        let code = magic_code(&derive("code")?);
        let commitment = FounderCommitment {
            index,
            token: access_identity_account::domain::invitation::token_hash(&token),
            code: access_identity_account::domain::invitation::code_hash(&code),
        };
        Ok((
            commitment,
            FoundingSecrets {
                token: access_crypto::Secret::new(token),
                code: access_crypto::Secret::new(code),
            },
        ))
    }

    /// The round of invitations the founding of `tenant` is in: 0 for a new tenant.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn founding_round(&self, tenant: TenantId) -> Result<Option<u32>, AdminError> {
        let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
        let f = tenants::founding(&mut t).await?;
        t.commit().await?;
        Ok(f.map(|f| f.reinvites))
    }

    /// Whether `change` fits the platform's current state: a new tenant's management slug is
    /// free (TN-16), a changed tenant exists and is in the state its change needs.
    async fn fits(&self, p: &Platform<'_>, change: &PlatformChange) -> Result<(), ProvisionError> {
        let tenant = TenantId::from_bytes(change.tenant());
        let row = tenancy::tenant(p.router, tenant).await?;
        match change {
            PlatformChange::Tenant(t) => {
                if row.is_some() {
                    return Err(ProvisionInvalid::TenantState.into());
                }
                if !tenants::slug_free(p.router, &t.management_slug).await? {
                    return Err(ProvisionInvalid::SlugTaken.into());
                }
            }
            PlatformChange::Reinvite { .. } => {
                if row.as_ref().map(|r| r.status.as_str()) != Some("provisioning") {
                    return Err(ProvisionInvalid::TenantState.into());
                }
            }
            PlatformChange::Suspend { .. } | PlatformChange::Placement { .. } => {
                match row.as_ref().map(|r| r.status.as_str()) {
                    None => return Err(ProvisionInvalid::NoTenant.into()),
                    Some("active") => {}
                    Some(_) => return Err(ProvisionInvalid::TenantState.into()),
                }
            }
            PlatformChange::Reactivate { .. } => match row.as_ref().map(|r| r.status.as_str()) {
                None => return Err(ProvisionInvalid::NoTenant.into()),
                Some("suspended") => {}
                Some(_) => return Err(ProvisionInvalid::TenantState.into()),
            },
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
        self.fits(p, change).await?;
        let (domain, slug) = self.platform_governing(p).await?;
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

    /// Has the platform environment's governing domain commit `order` with the caller's `ais`, binds
    /// the committed ALLOW, then writes what it names (TN-110, EI-25). The caller is an Instance
    /// of that domain with no environment session: the authority plane decides by its Grants or
    /// its root alone (OP-150 m.11 (f)).
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
        self.standing((p.tenant, p.environment), domain, &ais, None)
            .await?;
        let inviter = self.signer_subject(p, domain, &ais).await?;
        let verdict = self
            .decider
            .decide(Submission {
                actor: None,
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
                return Ok(Provisioned::NotAllowed { decision, position });
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
        let mut t = TenantTx::begin(self.app, p.tenant, p.environment).await?;
        let bound = idp::bind(
            &mut t,
            &Bind {
                domain: &access_store::scope::DomainId::from_bytes(domain.0),
                position: committed.position,
                nonce: &committed.nonce,
                intent: committed.intent.0,
                change: change.0,
                action: &label,
            },
        )
        .await?;
        // TN-110, TN-16
        if bound.is_some()
            && let Err(e) = self.fits(p, order.change).await
        {
            t.rollback().await?;
            return Err(e);
        }
        if bound.is_some()
            && let (Some(mail), Some(subject)) = (&order.mail, inviter)
        {
            self.founder_mail(&mut t, p, order.change, mail, subject)
                .await?;
        }
        t.commit().await?;
        let created = self.write_tenant(order.change, &committed.exercise).await?;
        Ok(Provisioned::Done {
            exercise: committed.exercise,
            position: committed.position,
            created,
        })
    }

    /// The platform subject whose Instance signed `ais`, whose key the founder mail is sealed
    /// under, as an organization invitation is under its inviter's (TN-89).
    async fn signer_subject(
        &self,
        p: &Platform<'_>,
        domain: Digest,
        ais: &[u8],
    ) -> Result<Option<[u8; 16]>, AdminError> {
        let Some(party) = self
            .decider
            .signer(domain, ais)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?
        else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(self.app, p.tenant, p.environment).await?;
        let s = idp::party_subject(&mut t, &party.0).await?;
        t.commit().await?;
        Ok(s)
    }

    /// Queues the founder's mail in the platform environment's outbox, in the transaction that
    /// binds the decision (TN-89, TN-141): the link goes to the management environment's founding
    /// route.
    async fn founder_mail(
        &self,
        t: &mut TenantTx,
        p: &Platform<'_>,
        change: &PlatformChange,
        mail: &FounderMail<'_>,
        inviter: [u8; 16],
    ) -> Result<(), AdminError> {
        use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
        use access_identity_account::notify::message::{Address, Body, Message};
        use access_identity_account::notify::notifier::OutboxNotifier;
        use access_identity_account::notify::ports::Notifier as _;

        let (slug, name) = match change {
            PlatformChange::Tenant(o) => (o.management_slug.clone(), o.display_name.clone()),
            PlatformChange::Reinvite { tenant, .. } => {
                let mut tx =
                    TenantTx::begin_tenant(self.app, TenantId::from_bytes(*tenant)).await?;
                let f = tenants::founding(&mut tx)
                    .await?
                    .ok_or(ProvisionInvalid::NoTenant)
                    .map_err(|_| AdminError::NoEnvironment)?;
                let profile = tenants::tenant_profile(&mut tx).await?;
                tx.commit().await?;
                (f.slug, profile.and_then(|(n, _)| n).unwrap_or_default())
            }
            _ => return Ok(()),
        };
        let issuer = self.base.issuer(&slug, IssuerStyle::Path)?;
        let vault = self
            .keys
            .vault(p.environment)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let named = access_identity_account::app::Environment {
            tenant: p.tenant,
            environment: p.environment,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let at = access_store::authority::server_time(self.app).await?;
        let ttl_ms = u64::try_from(FOUNDING_TTL_S)
            .unwrap_or(0)
            .saturating_mul(1000);
        let (token, code) = (mail.secrets.token.expose(), mail.secrets.code.expose());
        let message = Message {
            subject: inviter,
            to: Address::Email(String::from(mail.email)),
            locale: None,
            valid_since_ms: Some(at),
            body: Body::Invitation {
                link: access_crypto::Secret::new(format!(
                    "{}/login/founding/{token}#code={code}",
                    issuer.as_str().trim_end_matches('/')
                )),
                organization: name,
                inviter: String::from("Platform"),
                expires_at_ms: at.saturating_add(ttl_ms),
                console_link: mail.console.map(|o| {
                    access_crypto::Secret::new(format!(
                        "{}/console/{slug}",
                        o.trim_end_matches('/')
                    ))
                }),
            },
        };
        OutboxNotifier::new(&named, &SystemEntropy, &SystemClock)
            .notify(t, &message)
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        Ok(())
    }

    /// What a bound provisioning change writes; repeating it finds what it wrote before.
    async fn write_tenant(
        &self,
        change: &PlatformChange,
        exercise: &Digest,
    ) -> Result<Created, ProvisionError> {
        let tenant = TenantId::from_bytes(change.tenant());
        match change {
            PlatformChange::Tenant(o) => {
                access_store::sandbox::create_tenant_provisioning(self.app, tenant, &o.placement)
                    .await?;
                let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
                tenants::set_display_name(&mut t, &o.display_name).await?;
                tenants::insert_founding(
                    &mut t,
                    &NewFounding {
                        slug: &o.management_slug,
                        environment: EnvironmentId::from_bytes(o.tenant),
                        founder_index: &o.founder.index,
                        token_hash: &o.founder.token,
                        code_hash: &o.founder.code,
                        exercise: &exercise.0,
                        ttl_s: FOUNDING_TTL_S,
                    },
                )
                .await?;
                t.commit().await?;
            }
            PlatformChange::Reinvite { founder, .. } => {
                let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
                let f = tenants::founding(&mut t).await?;
                if f.is_some_and(|f| f.founder_index == founder.index) {
                    tenants::reinvite_founding(
                        &mut t,
                        &founder.token,
                        &founder.code,
                        FOUNDING_TTL_S,
                    )
                    .await?;
                }
                t.commit().await?;
            }
            PlatformChange::Suspend { .. } => {
                let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
                tenants::set_tenant_status(&mut t, "active", "suspended").await?;
                t.commit().await?;
            }
            PlatformChange::Reactivate { .. } => {
                let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
                tenants::set_tenant_status(&mut t, "suspended", "active").await?;
                t.commit().await?;
            }
            PlatformChange::Placement { placement, .. } => {
                let mut t = TenantTx::begin_tenant(self.app, tenant).await?;
                tenants::set_tenant_placement(&mut t, placement).await?;
                t.commit().await?;
            }
        }
        Ok(Created::Tenant(tenant))
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

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.3 (o), TN-141
    #[test]
    fn a_founding_code_is_eight_base32_characters() {
        assert_eq!(magic_code(&[0; 32]), "AAAAAAAA");
        assert_eq!(magic_code(&[0xff; 32]), "77777777");
    }
}
