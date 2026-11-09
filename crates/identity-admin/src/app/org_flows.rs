//! What committed organization Exercises write besides their decision (TN-90, TN-120,
//! OP-153 m.3 (o), (p)): a domain claim and its one-time challenge, a release that retracts the
//! domain's Claim, and an enterprise connection draft.

use access_store::identity::TenantTx;

use super::ClientSecret;
use super::orgs::live_org;
use crate::AdminError;
use crate::domain::org::{DomainClaim, SsoDraft};
use crate::domain::{Change, Invalid};

/// Records a committed `idp.org.domain_claim` and answers its challenge once: 256 random bits
/// as base64url, kept only as SHA-256 (TN-90, OP-153 m.3 (o)). A second organization's claim of
/// the same domain raises the contested alarm on the watch's next pass and at once here.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn claim_domain(
    t: &mut TenantTx,
    d: &DomainClaim,
    exercise: &[u8; 32],
) -> Result<ClientSecret, AdminError> {
    let org = live_org(t, d.org).await?;
    let token = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
    );
    let hash = suiss_crypto::digest::sha256(token.as_bytes());
    t.claim_domain(org.id, (&d.domain, d.method.word()), &hash, exercise)
        .await?;
    if !t.contest_domain(&d.domain).await?.is_empty() {
        super::domains::CONTESTED.add(1, []);
        tracing::warn!(
            event = "org.domain.contested",
            "a second organization claimed a domain; no autojoin for any of them (TN-90)"
        );
    }
    Ok(ClientSecret(token))
}

/// Releases a claim; a live `domain_verification` Claim of it is retracted (TN-90).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn release_domain(
    t: &mut TenantTx,
    org: [u8; 16],
    claim: [u8; 16],
) -> Result<bool, AdminError> {
    let org = live_org(t, org).await?;
    let c = t
        .open_domain_claims(Some(org.id))
        .await?
        .into_iter()
        .find(|c| c.id == claim)
        .ok_or(Invalid::NoDomain)?;
    let done = t.release_domain(claim).await?;
    if done && c.claimed {
        let now = t.server_time().await?;
        t.domain_claim_issued(claim, false).await?;
        super::domains::queue(t, &super::domains::verification_order(&c, now, true)).await?;
    }
    Ok(done)
}

/// Records a committed `idp.org.sso_draft` by the Party of `subject` (TN-120): a draft only.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn sso_draft(
    t: &mut TenantTx,
    d: &SsoDraft,
    subject: Option<[u8; 16]>,
    exercise: &[u8; 32],
) -> Result<(), AdminError> {
    let org = live_org(t, d.org).await?;
    let by = match subject {
        Some(s) => access_store::idp::subject_party(t, &s)
            .await?
            .unwrap_or([0; 16]),
        None => [0; 16],
    };
    t.insert_sso_draft(org.id, (&d.issuer, &d.client_id), by, exercise)
        .await?;
    Ok(())
}

/// What a committed organization change writes besides its row, with the one-time secret it
/// answers, if any.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn committed(
    t: &mut TenantTx,
    change: &Change,
    subject: Option<[u8; 16]>,
    exercise: &[u8; 32],
) -> Result<Option<ClientSecret>, AdminError> {
    match change {
        Change::OrgDomainClaim(d) => Ok(Some(claim_domain(t, d, exercise).await?)),
        Change::OrgSsoDraft(d) => {
            sso_draft(t, d, subject, exercise).await?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Why a role Grant submission is not the membership's.
const NOT_THE_ROLE: &str = "not-the-membership-role";

/// Only the inviter's own client issues the role it invited to (TN-89 (3)).
const INVITER_ONLY: &str = "inviter-only";

/// Why an autojoin Grant submission is not the organization's (OP-153 m.25 (i) (3)).
pub const NOT_THE_AUTOJOIN_GRANT: &str = "not-the-autojoin-grant";

/// The reserved `idp.*` actions, as `(namespace, name)`.
fn reserved_actions() -> Vec<(String, String)> {
    access_internal_api::idp::IdpAction::ALL
        .into_iter()
        .filter(|a| a.reserved())
        .map(|a| (String::from(a.namespace()), String::from(a.name())))
        .collect()
}

impl<D, G, K> super::Admin<'_, D, G, K>
where
    D: crate::ports::Decider,
    G: crate::ports::Governance + crate::ports::Instances,
    K: crate::ports::RealmKeys,
{
    /// Issues the role Grant of an accepted invitation (TN-89 (3), OP-153 m.3 (o)): `w` is the
    /// `grant_issue` the inviter's own client signed, holding the member's Party to the
    /// membership's named role version; the domain decides it against the inviter's authority
    /// now, so an inviter whose authority fell gets a DENY and the role is denied. A first
    /// acceptance never grants an `anchor_*` meta-action or a reserved action.
    ///
    /// # Errors
    /// [`AdminError`]; a pending decision leaves the role pending.
    pub async fn issue_role_grant(
        &self,
        (tenant, realm): (
            access_store::identity::TenantId,
            access_store::identity::RealmId,
        ),
        (org, subject): ([u8; 16], [u8; 16]),
        w: access_internal_api::idp::Submission,
    ) -> Result<super::Applied, AdminError> {
        use access_kernel::meta::Payload;
        use access_kernel::model::{Id, SubjectSelector};

        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let org = live_org(&mut t, org).await?;
        let member = t
            .member(org.id, subject)
            .await?
            .filter(|m| m.grant_state.as_deref() == Some("pending"))
            .ok_or(Invalid::NoMember)?;
        let party = access_store::idp::subject_party(&mut t, &subject)
            .await?
            .ok_or(Invalid::NoMember)?;
        t.commit().await?;
        let (role, version) = member.role.clone().ok_or(Invalid::NoMember)?;
        let Some(Payload::GrantIssue(content)) = w.payload.as_deref() else {
            return Err(AdminError::Refused(String::from(NOT_THE_ROLE)));
        };
        let names_role = content
            .named
            .as_ref()
            .is_some_and(|(n, v, _)| *n == role && *v == version);
        if content.holder != SubjectSelector::Party(Id(party)) || !names_role {
            return Err(AdminError::Refused(String::from(NOT_THE_ROLE)));
        }
        // TN-89 (10)
        let set = &content.authority.authority.actions;
        let reserved = reserved_actions();
        let actions: Vec<(String, String)> = set
            .exact
            .iter()
            .map(|a| (a.namespace.clone(), a.name.clone()))
            .collect();
        let whole = set.prefix.iter().any(|(ns, _)| {
            ns == access_kernel::meta::NAMESPACE || reserved.iter().any(|(r, _)| r == ns)
        });
        if whole || !crate::domain::org::first_accept_allowed(&actions, &reserved) {
            return Err(AdminError::Refused(String::from(NOT_THE_ROLE)));
        }
        // TN-89 (3)
        let signer = self
            .decider
            .signer(w.domain, &w.ais)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if signer.is_none() || signer.map(|s| s.0) != member.inviter {
            return Err(AdminError::Refused(String::from(INVITER_ONLY)));
        }
        let origin = access_kernel::meta::exercise_id(&w.domain, &w.nonce)
            .map_err(|_| AdminError::Encode)?;
        let applied = Box::pin(self.meta((tenant, realm), w)).await?;
        let settled = match &applied {
            super::Applied::Written { exercise, .. }
            | super::Applied::AlreadyWritten { exercise, .. } => Some(Some((
                access_kernel::meta::object_id(&origin, access_kernel::meta::kind::GRANT, 0).0,
                exercise.0,
            ))),
            super::Applied::NotAllowed { decision, .. }
                if decision.outcome == access_kernel::combinator::Outcome::Deny =>
            {
                Some(None)
            }
            super::Applied::NotAllowed { .. } => None,
        };
        if let Some(issued) = settled {
            let mut t = TenantTx::begin(self.app, tenant, realm).await?;
            t.settle_role_grant(member.id, issued).await?;
            t.commit().await?;
        }
        Ok(applied)
    }

    /// Issues an organization's autojoin role Grant (TN-90, C13, OP-153 m.17 (c), m.25 (i)
    /// (3)): `w` is the `grant_issue` an owner's own client signed on the organization's
    /// Anchor, held by every Party with a live `org_member` Claim naming the organization
    /// ([`crate::domain::org::org_members`]), which the realm issuer's subject-selection
    /// Acceptance admits. Only an organization with a domain whose autojoin is on takes one, and
    /// like a first acceptance it never grants an `anchor_*` meta-action or a reserved action.
    ///
    /// # Errors
    /// [`AdminError`]; the domain's DENY or pending decision is [`super::Applied::NotAllowed`].
    pub async fn issue_autojoin_grant(
        &self,
        (tenant, realm): (
            access_store::identity::TenantId,
            access_store::identity::RealmId,
        ),
        org: [u8; 16],
        w: access_internal_api::idp::Submission,
    ) -> Result<super::Applied, AdminError> {
        use access_kernel::meta::{ExerciseBasis, GrantBasis, Payload};
        use access_kernel::model::Id;

        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let found = live_org(&mut t, org).await?;
        let anchor = t.party_anchor(found.party).await?.ok_or(Invalid::NoOrg)?;
        let autojoin = t
            .open_domain_claims(Some(found.id))
            .await?
            .iter()
            .any(|d| d.autojoin && d.verified_ms.is_some());
        let mut owners = Vec::new();
        for m in t.members(found.id).await?.iter().filter(|m| m.owner) {
            if let Some(p) = access_store::idp::subject_party(&mut t, &m.subject).await? {
                owners.push(p);
            }
        }
        t.commit().await?;
        if !autojoin {
            return Err(AdminError::Refused(String::from(NOT_THE_AUTOJOIN_GRANT)));
        }
        let Some(Payload::GrantIssue(content)) = w.payload.as_deref() else {
            return Err(AdminError::Refused(String::from(NOT_THE_AUTOJOIN_GRANT)));
        };
        let on_anchor = content.basis == GrantBasis::Anchor(Id(anchor))
            && w.basis == ExerciseBasis::Anchor(Id(anchor));
        if !on_anchor || content.holder != crate::domain::org::org_members(found.party) {
            return Err(AdminError::Refused(String::from(NOT_THE_AUTOJOIN_GRANT)));
        }
        // TN-89 (10)
        let set = &content.authority.authority.actions;
        let reserved = reserved_actions();
        let actions: Vec<(String, String)> = set
            .exact
            .iter()
            .map(|a| (a.namespace.clone(), a.name.clone()))
            .collect();
        let whole = set.prefix.iter().any(|(ns, _)| {
            ns == access_kernel::meta::NAMESPACE || reserved.iter().any(|(r, _)| r == ns)
        });
        if whole || !crate::domain::org::first_accept_allowed(&actions, &reserved) {
            return Err(AdminError::Refused(String::from(NOT_THE_AUTOJOIN_GRANT)));
        }
        let signer = self
            .decider
            .signer(w.domain, &w.ais)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if !signer.is_some_and(|s| owners.contains(&s.0)) {
            return Err(AdminError::Refused(String::from(
                super::transfers::OWNER_ONLY,
            )));
        }
        Box::pin(self.meta((tenant, realm), w)).await
    }
}
