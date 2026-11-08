//! The person's side of B2B organizations on the hosted Frontend API (TN-89, TN-90, OP-153 m.3
//! (o)): reading and accepting an invitation, the organizations the person belongs to, and an
//! access request. Organization names are attacker input, answered as text.

use access_identity_account::domain::invitation::{code_hash, token_hash};
use access_identity_events::domain::catalog::{IdentityEvent, IdentityKind};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::StoreError;
use access_store::identity::TenantTx;
use access_store::orgs::{InvitationRow, Source};
use serde::Deserialize;
use serde_json::json;

use super::{Browser, Hosted, Reply};
use crate::ports::{Kits, Messages, RealmKit};
use access_identity_account::domain::login::Problem;

/// The invitation does not exist, was accepted or revoked, or expired.
pub const INVITATION_GONE: Problem = Problem {
    status: 404,
    code: "invitation-gone",
    title: "This invitation is no longer open",
    retry_after_s: None,
};

/// The signed-in person holds no verified identifier the invitation was sent to (TN-89 (5)).
pub const INVITATION_MISMATCH: Problem = Problem {
    status: 403,
    code: "invitation-mismatch",
    title: "This invitation was sent to another address",
    retry_after_s: None,
};

/// The invitee's domain is not one the organization verified: the person confirms the
/// organization by name first (TN-89 (10)).
pub const INTERSTITIAL_REQUIRED: Problem = Problem {
    status: 409,
    code: "interstitial-required",
    title: "Confirm the organization before joining",
    retry_after_s: None,
};

/// The inviter no longer stands in the organization, so its invitation grants nothing
/// (TN-89 (3)).
pub const INVITER_NOT_AUTHORIZED: Problem = Problem {
    status: 403,
    code: "inviter-not-authorized",
    title: "The person who invited you can no longer add members",
    retry_after_s: None,
};

/// The person is already an active member, or already asked.
pub const ALREADY_MEMBER: Problem = Problem {
    status: 409,
    code: "already-member",
    title: "You are already a member or already asked",
    retry_after_s: None,
};

/// No such organization.
pub const NO_ORGANIZATION: Problem = Problem {
    status: 404,
    code: "not-found",
    title: "No such organization",
    retry_after_s: None,
};

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Try again shortly",
    retry_after_s: Some(5),
};

/// `POST /v1/invitations/{code}`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptBody {
    /// The person confirmed the organization on the interstitial (TN-89 (10)).
    #[serde(default)]
    pub confirm: bool,
}

fn store_failed(e: &StoreError) -> Reply {
    tracing::warn!(error = %e, "organization step failed");
    Reply::problem(UNAVAILABLE)
}

/// The invitation `secret` names: its link token, else its magic code among the open
/// invitations of one of `invitees`.
async fn find(
    t: &mut TenantTx,
    secret: &str,
    invitees: &[[u8; 32]],
) -> Result<Option<InvitationRow>, StoreError> {
    if let Some(row) = t.invitation_by_token(&token_hash(secret)).await? {
        return Ok(Some(row));
    }
    if invitees.is_empty() || secret.trim().len() != 8 {
        return Ok(None);
    }
    for token in t.invitations_by_code(&code_hash(secret), invitees).await? {
        if let Some(row) = t.invitation_by_token(&token).await? {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn org_tx(&self, kit: &RealmKit) -> Result<TenantTx, Reply> {
        TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|e| store_failed(&e))
    }

    /// `GET /v1/invitations/{code}` (TN-89 (9)): the organization's name and the role, as text.
    /// A browser's or mail scanner's fetch never consumes the invitation; it is counted.
    pub async fn invitation(&self, entry: &RealmEntry, secret: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let mut t = match self.org_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let row = match t.invitation_by_token(&token_hash(secret)).await {
            Ok(Some(r)) if r.open => r,
            Ok(_) => return Reply::problem(INVITATION_GONE),
            Err(e) => return store_failed(&e),
        };
        let org = match t.org(row.org).await {
            Ok(Some(o)) if !o.ended => o,
            Ok(_) => return Reply::problem(INVITATION_GONE),
            Err(e) => return store_failed(&e),
        };
        if let Err(e) = t.count_scanner_click(row.id).await {
            return store_failed(&e);
        }
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        Reply::json(
            200,
            json!({
                "organization": {
                    "id": b64url_encode(&org.party),
                    "display_name": org.display_name,
                },
                "invitee_domain": row.invitee_domain,
                "role": { "name": row.role.0, "version": row.role.1 },
            }),
        )
    }

    /// `POST /v1/invitations/{code}` (TN-89, OP-153 m.3 (o)): accepts with the signed-in
    /// person's verified identifier; never as owner; the inviter must still stand in the
    /// organization; an invitee domain the organization has not verified needs the person's
    /// confirmation first. Opens the membership with the invitation's role and queues
    /// `membership.added`.
    #[expect(
        clippy::too_many_lines,
        reason = "the acceptance rules in the order TN-89 lists them"
    )]
    pub async fn accept_invitation(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        secret: &str,
        body: &AcceptBody,
    ) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.org_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let mine = match t.email_indexes(me).await {
            Ok(m) => m,
            Err(e) => return store_failed(&e),
        };
        let row = match find(&mut t, secret, &mine).await {
            Ok(Some(r)) if r.open => r,
            Ok(_) => return Reply::problem(INVITATION_GONE),
            Err(e) => return store_failed(&e),
        };
        // TN-89 (4), (5)
        if !mine.contains(&row.invitee_index) {
            return Reply::problem(INVITATION_MISMATCH);
        }
        let org = match t.org(row.org).await {
            Ok(Some(o)) if !o.ended => o,
            Ok(_) => return Reply::problem(INVITATION_GONE),
            Err(e) => return store_failed(&e),
        };
        let members = match t.memberships(org.id).await {
            Ok(m) => m,
            Err(e) => return store_failed(&e),
        };
        if members.iter().any(|m| m.subject == me) {
            return Reply::problem(ALREADY_MEMBER);
        }
        // TN-89 (3)
        let mut inviter_stands = false;
        for m in &members {
            let party = match access_store::idp::subject_party(&mut t, &m.subject).await {
                Ok(p) => p,
                Err(e) => return store_failed(&e),
            };
            if party != Some(row.inviter) {
                continue;
            }
            inviter_stands = match t.subject(m.subject, false).await {
                Ok(Some(s)) => s.status == "active",
                Ok(None) => false,
                Err(e) => return store_failed(&e),
            };
            break;
        }
        if !inviter_stands {
            return Reply::problem(INVITER_NOT_AUTHORIZED);
        }
        // TN-89 (10)
        let verified = match t.domain_claims(&row.invitee_domain).await {
            Ok(c) => c.iter().any(|c| c.org == org.id && c.verified),
            Err(e) => return store_failed(&e),
        };
        if !verified && !body.confirm {
            let mut r = Reply::problem(INTERSTITIAL_REQUIRED);
            r.body = super::Body::Json(json!({
                "type": format!("urn:suiss:access:problem:{}", INTERSTITIAL_REQUIRED.code),
                "title": INTERSTITIAL_REQUIRED.title,
                "status": INTERSTITIAL_REQUIRED.status,
                "organization": {
                    "id": b64url_encode(&org.party),
                    "display_name": org.display_name,
                },
                "invitee_domain": row.invitee_domain,
            }));
            return r;
        }
        match t.accept_invitation(row.id, me).await {
            Ok(true) => {}
            Ok(false) => return Reply::problem(INVITATION_GONE),
            Err(e) => return store_failed(&e),
        }
        // TN-89 (10), OP-153 m.3 (o): never owner at first acceptance
        if let Err(e) = t
            .insert_membership(
                org.id,
                me,
                Source::Invite,
                false,
                Some((row.role.0.as_str(), row.role.1)),
            )
            .await
        {
            return store_failed(&e);
        }
        if let Err(e) = membership_added(&mut t, &kit, me, org.id).await {
            return store_failed(&e);
        }
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        Reply::json(
            200,
            json!({
                "organization": {
                    "id": b64url_encode(&org.party),
                    "display_name": org.display_name,
                },
                "owner": false,
                "role": { "name": row.role.0, "version": row.role.1 },
            }),
        )
    }

    /// `GET /v1/account/organizations`: the organizations the signed-in person belongs to.
    pub async fn organizations(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let mut t = match self.org_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let rows = match t.orgs_of(me).await {
            Ok(r) => r,
            Err(e) => return store_failed(&e),
        };
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        let items: Vec<_> = rows
            .into_iter()
            .map(|(o, m)| {
                json!({
                    "id": b64url_encode(&o.party),
                    "display_name": o.display_name,
                    "owner": m.owner,
                    "source": m.source.word(),
                    "role": m.role.map(|(n, v)| json!({ "name": n, "version": v })),
                })
            })
            .collect();
        Reply::json(200, json!({ "items": items }))
    }

    /// `POST /v1/organizations/{organization}/access-requests` (TN-90): asks the
    /// organization's administrators for access; they decide it once.
    pub async fn request_access(&self, entry: &RealmEntry, b: &Browser<'_>, org: &str) -> Reply {
        let (kit, me) = match self.me(entry, b).await {
            Ok(m) => m,
            Err(r) => return r,
        };
        let Some(party) = b64url_decode(org)
            .ok()
            .and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        else {
            return Reply::problem(NO_ORGANIZATION);
        };
        let mut t = match self.org_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let org = match t.org_by_party(party).await {
            Ok(Some(o)) if !o.ended => o,
            Ok(_) => return Reply::problem(NO_ORGANIZATION),
            Err(e) => return store_failed(&e),
        };
        let member = match t.memberships(org.id).await {
            Ok(m) => m.iter().any(|m| m.subject == me),
            Err(e) => return store_failed(&e),
        };
        let asked = match t.access_requested(org.id, me).await {
            Ok(a) => a,
            Err(e) => return store_failed(&e),
        };
        if member || asked {
            return Reply::problem(ALREADY_MEMBER);
        }
        if let Err(e) = t.insert_access_request(org.id, me).await {
            return store_failed(&e);
        }
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        Reply::json(202, json!({ "status": "requested" }))
    }
}

/// Queues `membership.added` (OP-153 m.4).
async fn membership_added(
    t: &mut TenantTx,
    kit: &RealmKit,
    subject: [u8; 16],
    org: [u8; 16],
) -> Result<(), StoreError> {
    let account = kit
        .realm()
        .external(subject)
        .map_err(|_| StoreError::Range)?;
    let id = access_crypto::random::bytes::<32>().map_err(|_| StoreError::Range)?;
    let at = t.server_time().await?;
    let event = IdentityEvent::membership(
        IdentityKind::MembershipAdded,
        id,
        kit.realm.as_bytes(),
        &account,
        &org,
        at,
    );
    access_identity_events::app::emit(t, &event).await
}
