//! Tenant administrator invitations (OP-159 m.47 (f), TN-89 (1)–(9), (11), TN-109): a committed
//! `idp.tenant.admin_invite` keeps the invitation as hashes of its link token and magic code and the
//! primary environment's blind index of the invitee, and queues its mail in the same
//! transaction; the secrets exist only in the mail. The invitee proves the address with the code,
//! and its acceptance makes it an administrator of the tenant, never an owner; one from another
//! domain than the inviter's holds nothing for [`ADMIN_COOLING_S`] (the TN-89 (10) exception), and
//! every administrator is told. The inviter must still be an administrator when it is accepted
//! (TN-89 (3)).

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::vault::Vault;
use access_identity_account::domain::invitation::{code_hash, token_hash};
use access_identity_account::domain::status::AccountStatus;
use access_store::identity::{EnvironmentId, TenantId, TenantTx};
use access_store::tenant_admin::{self as tenants, AdminInvitation};

use super::Admin;
use super::orgs::{INVITES_PER_DAY, INVITES_PER_HOUR, REPUTATION_WINDOW_S, magic_code, reputable};
use crate::AdminError;
use crate::domain::tenant::{ADMIN_COOLING_S, AdminInvite, PRIMARY, TenantInvalid, email_domain};
use crate::ports::{Decider, EnvironmentKeys, Governance, Instances};

const HOUR_S: i64 = 3_600;
const DAY_S: i64 = 86_400;

/// The hosted login path an invitation's link opens, under the primary environment's issuer.
pub const ACCEPT_PATH: &str = "/login/admin-invite/";

/// Why an invitation step was refused.
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    /// No invitation has this link in this environment.
    #[error("no such invitation")]
    NotFound,
    /// The link expired; an administrator can invite again.
    #[error("invitation expired")]
    Expired,
    /// The address or the code does not match (TN-89 (5)).
    #[error("invitation code")]
    Code,
    /// A step out of order: accepted or replaced already, not proven yet, the address has an
    /// account, or the inviter is no administrator any more (TN-89 (3)).
    #[error("invitation state")]
    State,
    /// The identity plane failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
}

impl From<access_store::StoreError> for InviteError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Admin(e.into())
    }
}

impl InviteError {
    /// HTTP status and stable problem code.
    #[must_use]
    pub const fn problem(&self) -> (u16, &'static str) {
        match self {
            Self::NotFound => (404, "not-found"),
            Self::Expired => (410, "invite-expired"),
            Self::Code => (400, "invalid-code"),
            Self::State => (409, "invite-state"),
            Self::Admin(a) => a.problem(),
        }
    }
}

/// An invitation as its route shows it: no secret, no address.
#[derive(Clone)]
pub struct InvitationView {
    /// The tenant's display name.
    pub tenant: String,
    /// The primary environment's slug.
    pub environment: String,
    /// `pending`, `proven`, `accepted`, `superseded` or `expired`.
    pub state: &'static str,
    /// The invitation.
    pub invitation: AdminInvitation,
}

/// The state an invitation is in at `now_ms`.
#[must_use]
pub fn state_of(i: &AdminInvitation, now_ms: u64) -> &'static str {
    if i.accepted_subject.is_some() {
        "accepted"
    } else if i.superseded {
        "superseded"
    } else if now_ms >= i.expires_ms {
        "expired"
    } else if i.verified {
        "proven"
    } else {
        "pending"
    }
}

/// TN-89 (11), TN-95: the primary environment sent fewer than [`INVITES_PER_HOUR`]
/// invitations this hour and [`INVITES_PER_DAY`] today, and enough of its recent ones were
/// accepted.
pub(crate) async fn invite_current(
    t: &mut TenantTx,
) -> Result<(), crate::app::tenant::TenantError> {
    if tenants::invitation_counts(t, HOUR_S).await?.0 >= INVITES_PER_HOUR
        || tenants::invitation_counts(t, DAY_S).await?.0 >= INVITES_PER_DAY
    {
        return Err(TenantInvalid::InviteLimit.into());
    }
    let (sent, accepted) = tenants::invitation_counts(t, REPUTATION_WINDOW_S).await?;
    if !reputable(sent, accepted) {
        return Err(TenantInvalid::InviteLimit.into());
    }
    Ok(())
}

/// What a committed `idp.tenant.admin_invite` writes with.
pub(crate) struct InviteWrite<'a> {
    /// The environments the invitee administers; `None` is the whole tenant (OP-159 m.49 (d)).
    pub scope: Option<&'a [EnvironmentId]>,
    /// The primary environment's vault keys.
    pub vault: &'a Vault,
    /// The cell's id key.
    pub ids: &'a IdKey,
    /// The inviter's subject and address.
    pub inviter: ([u8; 16], &'a str),
    /// The primary environment's issuer, which the link lives under.
    pub issuer: &'a str,
    /// The tenant's console, `{origin}/console/{primary slug}`.
    pub console: Option<&'a str>,
    /// The tenant's display name: its text, untrusted (TN-131).
    pub tenant: &'a str,
    /// The Exercise that allowed it.
    pub exercise: &'a [u8; 32],
    /// Now, Unix ms.
    pub at: u64,
}

/// Records the invitation and queues its mail through Relay in `t`; the mail is sealed under the
/// inviter's subject key, as the invitee has no account yet (TN-89, OP-153 m.3 (o)).
pub(crate) async fn invite(
    t: &mut TenantTx,
    w: &InviteWrite<'_>,
    i: &AdminInvite,
) -> Result<[u8; 16], AdminError> {
    use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
    use access_identity_account::notify::message::{Address, Body, Message};
    use access_identity_account::notify::notifier::OutboxNotifier;
    use access_identity_account::notify::ports::Notifier as _;

    let environment = t.environment().ok_or(AdminError::NoEnvironment)?;
    let tenant = t.tenant();
    let token = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
    );
    let code = magic_code(access_crypto::random::bytes::<5>().map_err(|_| AdminError::Encode)?);
    let invitee = w
        .vault
        .index
        .index(tenant.as_bytes(), environment.as_bytes(), &i.email)
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
    let domain = email_domain(&i.email);
    let ttl_s = i64::from(i.days).saturating_mul(DAY_S);
    let id = tenants::insert_invitation(
        t,
        &tenants::NewInvitation {
            token_hash: &token_hash(&token),
            code_hash: &code_hash(&code),
            invitee_index: &invitee,
            invitee_domain: domain,
            inviter: &w.inviter.0,
            cross_domain: domain != email_domain(w.inviter.1),
            exercise: w.exercise,
            ttl_s,
            scope: w.scope,
        },
    )
    .await?;
    let named = access_identity_account::app::Environment {
        tenant,
        environment,
        kek: &*w.vault.kek,
        ids: w.ids,
    };
    let message = Message {
        subject: w.inviter.0,
        to: Address::Email(i.email.clone()),
        locale: None,
        valid_since_ms: Some(w.at),
        body: Body::Invitation {
            link: access_crypto::Secret::new(format!(
                "{}{ACCEPT_PATH}{token}#code={code}",
                w.issuer.trim_end_matches('/')
            )),
            organization: w.tenant.chars().take(200).collect(),
            inviter: w.inviter.1.chars().take(200).collect(),
            expires_at_ms: w
                .at
                .saturating_add(u64::try_from(ttl_s).unwrap_or(0).saturating_mul(1000)),
            console_link: w
                .console
                .map(|c| access_crypto::Secret::new(String::from(c))),
        },
    };
    OutboxNotifier::new(&named, &SystemEntropy, &SystemClock)
        .notify(t, &message)
        .await
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
    Ok(id)
}

/// The address `subject` signs in with in `t`'s environment, revealed under `vault`.
pub(crate) async fn address_of(
    t: &mut TenantTx,
    vault: &Vault,
    subject: [u8; 16],
) -> Result<Option<String>, AdminError> {
    let Some((_, stored)) = t.contact(subject).await? else {
        return Ok(None);
    };
    access_identity_account::app::vault::reveal_with_kek(t, &*vault.kek, subject, &stored)
        .await
        .map_err(|e| AdminError::Unavailable(e.to_string()))
}

impl<D: Decider, G: Governance + Instances, K: EnvironmentKeys> Admin<'_, D, G, K> {
    /// The invitation the link token `token` names in the primary environment `place`.
    ///
    /// # Errors
    /// [`InviteError::NotFound`]; [`InviteError::Admin`].
    pub async fn admin_invitation(
        &self,
        (tenant, environment): (TenantId, EnvironmentId),
        token: &str,
    ) -> Result<InvitationView, InviteError> {
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let kind = tenants::environment_kind(&mut t).await?;
        let found = tenants::invitations(&mut t, Some(&token_hash(token)))
            .await?
            .into_iter()
            .next();
        let g = access_store::idp::governance(&mut t).await?;
        let name = tenants::tenant_profile(&mut t)
            .await?
            .and_then(|(n, _)| n)
            .unwrap_or_default();
        t.commit().await?;
        let (Some(invitation), Some(g)) = (found, g) else {
            return Err(InviteError::NotFound);
        };
        if kind.as_deref() != Some(PRIMARY) {
            return Err(InviteError::NotFound);
        }
        let now = access_store::authority::server_time(self.app).await?;
        Ok(InvitationView {
            tenant: name,
            environment: g.slug,
            state: state_of(&invitation, now),
            invitation,
        })
    }

    async fn open_invitation(
        &self,
        place: (TenantId, EnvironmentId),
        token: &str,
    ) -> Result<InvitationView, InviteError> {
        let v = self.admin_invitation(place, token).await?;
        match v.state {
            "pending" | "proven" => Ok(v),
            "expired" => Err(InviteError::Expired),
            _ => Err(InviteError::State),
        }
    }

    /// Proves the invitee's address with the magic code (TN-89 (5), (7)): the address's blind
    /// index and the code must be the invitation's. Repeating it is a no-op.
    ///
    /// # Errors
    /// [`InviteError`].
    pub async fn verify_admin_invitation(
        &self,
        place: (TenantId, EnvironmentId),
        token: &str,
        (email, code): (&str, &str),
    ) -> Result<InvitationView, InviteError> {
        let v = self.open_invitation(place, token).await?;
        let (tenant, environment) = place;
        let index = self
            .keys
            .blind_index(environment)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?
            .index(
                tenant.as_bytes(),
                environment.as_bytes(),
                &access_identity_account::app::vault::folded(email),
            )
            .map_err(|_| AdminError::Unavailable(String::from("vault")))?;
        if v.invitation.invitee_index != index || v.invitation.code_hash != code_hash(code) {
            return Err(InviteError::Code);
        }
        if !v.invitation.verified {
            let mut t = TenantTx::begin(self.app, tenant, environment).await?;
            tenants::verify_invitation(&mut t, &v.invitation.id).await?;
            t.commit().await?;
        }
        Ok(v)
    }

    /// Whether a proven invitation can be accepted now (TN-89 (3)): the inviter is still a live
    /// administrator whose account can sign in.
    ///
    /// # Errors
    /// [`InviteError::State`]; [`InviteError`].
    pub async fn acceptable_admin_invitation(
        &self,
        place: (TenantId, EnvironmentId),
        token: &str,
        proof: (&str, &str),
    ) -> Result<InvitationView, InviteError> {
        let v = self.verify_admin_invitation(place, token, proof).await?;
        let mut t = TenantTx::begin(self.app, place.0, place.1).await?;
        let inviter = tenants::admin(&mut t, &v.invitation.inviter).await?;
        let status = access_store::idp::environment::account(&mut t, v.invitation.inviter)
            .await?
            .map(|a| a.status);
        t.commit().await?;
        let signs_in = status
            .as_deref()
            .and_then(AccountStatus::parse)
            .is_some_and(AccountStatus::can_authenticate);
        if !signs_in || inviter.is_none_or(|a| a.ended_ms.is_some()) {
            return Err(InviteError::State);
        }
        Ok(v)
    }

    /// Closes an accepted invitation with the account `subject` its acceptance made: an
    /// administrator, never an owner, cooling for [`ADMIN_COOLING_S`] when its domain is not the
    /// inviter's (TN-109), and every live administrator told (OP-159 m.47 (f)).
    ///
    /// # Errors
    /// [`InviteError`].
    pub async fn finish_admin_invitation(
        &self,
        place: (TenantId, EnvironmentId),
        token: &str,
        (subject, address): ([u8; 16], &str),
    ) -> Result<(), InviteError> {
        use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
        use access_identity_account::notify::message::{Body, Notice, SecurityEvent};
        use access_identity_account::notify::notices;

        let v = self.admin_invitation(place, token).await?;
        if v.state != "proven" {
            return Err(InviteError::State);
        }
        let (tenant, environment) = place;
        let vault = self
            .keys
            .vault(environment)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let mut t = TenantTx::begin(self.app, tenant, environment).await?;
        let issuer = access_store::idp::governance(&mut t)
            .await?
            .and_then(|g| g.issuer)
            .unwrap_or_default();
        if !tenants::accept_invitation(&mut t, &v.invitation.id, &subject).await? {
            t.rollback().await?;
            return Err(InviteError::State);
        }
        let cooling = v.invitation.cross_domain.then_some(ADMIN_COOLING_S);
        // OP-159 m.47 (f)
        tenants::add_admin(
            &mut t,
            &subject,
            &tenants::NewAdmin {
                party: None,
                owner: false,
                exercise: None,
                cooling_s: cooling,
                scope: v.invitation.scope.as_deref(),
            },
        )
        .await?;
        let now = access_store::authority::server_time(self.app).await?;
        let others: Vec<[u8; 16]> = tenants::admins(&mut t)
            .await?
            .into_iter()
            .filter(|a| a.ended_ms.is_none() && a.subject != subject)
            .map(|a| a.subject)
            .collect();
        let keys = (&*vault.kek, self.ids);
        // SI-21, TN-109
        for admin in others {
            notices::queue(
                &mut t,
                keys,
                &SystemEntropy,
                &SystemClock,
                admin,
                SecurityEvent::AdministratorAdded,
                (address, &issuer),
                now,
            )
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        }
        if let Some(s) = cooling {
            let until = now.saturating_add(u64::try_from(s).unwrap_or(0).saturating_mul(1000));
            notices::queue_body(
                &mut t,
                keys,
                &SystemEntropy,
                &SystemClock,
                subject,
                Body::Notice {
                    notice: Notice::MembershipCooling,
                    at_ms: now,
                    until_ms: Some(until),
                },
            )
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        }
        t.commit().await?;
        Ok(())
    }
}
