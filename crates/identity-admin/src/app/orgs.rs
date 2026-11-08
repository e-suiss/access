//! Organization events and use cases of the identity plane (TN-5, TN-89, TN-90, OP-153 m.3 (b),
//! (o), (p)): what a committed `idp.org.*` Exercise writes besides its rows.

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_events::app::emit;
use access_identity_events::domain::catalog::{IdentityEvent, IdentityKind, TENANT_PREFIX};
use access_store::identity::TenantTx;

use crate::AdminError;

/// Queues `organization.created` or `organization.updated` of `org` in `t` (OP-149 m.4).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn organization_event(
    t: &mut TenantTx,
    ids: &IdKey,
    kind: IdentityKind,
    org: [u8; 16],
    at: u64,
) -> Result<(), AdminError> {
    let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
    let tenant = ids.encode(TENANT_PREFIX, *t.tenant().as_bytes())?;
    emit(t, &IdentityEvent::organization(kind, id, &tenant, &org, at)).await?;
    Ok(())
}

/// Queues `membership.added` or `membership.removed` of `subject` in `org` in `t` (OP-151 m.3
/// (i), OP-153 m.4).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn membership_event(
    t: &mut TenantTx,
    ids: &IdKey,
    kind: IdentityKind,
    (subject, org): ([u8; 16], [u8; 16]),
    at: u64,
) -> Result<(), AdminError> {
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
    let account = ids.encode(SUBJECT_PREFIX, subject)?;
    let event = IdentityEvent::membership(kind, id, realm.as_bytes(), &account, &org, at);
    emit(t, &event).await?;
    Ok(())
}

/// Invitations one organization may send an hour and a day (OP-153 m.3 (o), PD).
pub const INVITES_PER_HOUR: i64 = 50;
/// See [`INVITES_PER_HOUR`].
pub const INVITES_PER_DAY: i64 = 500;

const HOUR_S: i64 = 3_600;
const DAY_S: i64 = 86_400;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An invitation's magic code: 40 random bits as 8 base32 characters (OP-153 m.3 (o)).
fn magic_code(bits: [u8; 5]) -> String {
    let v = bits.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b));
    (0..8u32)
        .rev()
        .map(|i| {
            let at = usize::try_from((v >> i.saturating_mul(5)) & 31).unwrap_or(0);
            char::from(BASE32.get(at).copied().unwrap_or(b'A'))
        })
        .collect()
}

/// The organization of `org`'s Party, live.
pub(crate) async fn live_org(
    t: &mut TenantTx,
    org: [u8; 16],
) -> Result<access_store::orgs::OrgRow, AdminError> {
    t.org_by_party(org)
        .await?
        .filter(|o| !o.ended)
        .ok_or_else(|| crate::domain::Invalid::NoOrg.into())
}

/// TN-89, OP-153 m.3 (o): the organization lives, and it has sent fewer than
/// [`INVITES_PER_HOUR`] invitations this hour and [`INVITES_PER_DAY`] today.
pub(crate) async fn invite_current(
    t: &mut TenantTx,
    i: &crate::domain::OrgInvite,
) -> Result<(), AdminError> {
    let org = live_org(t, i.org).await?;
    if t.invitations_since(org.id, HOUR_S).await? >= INVITES_PER_HOUR
        || t.invitations_since(org.id, DAY_S).await? >= INVITES_PER_DAY
    {
        return Err(crate::domain::Invalid::InviteLimit.into());
    }
    Ok(())
}

/// What a committed `idp.org.invite` writes with (TN-89, OP-153 m.3 (o)).
pub(crate) struct Invite<'a> {
    /// The realm's vault keys.
    pub vault: &'a access_identity_account::app::vault::Vault,
    /// The cell's id key.
    pub ids: &'a IdKey,
    /// The inviter's subject and Party.
    pub inviter: ([u8; 16], [u8; 16]),
    /// The realm's issuer, which the accept link lives under.
    pub issuer: &'a str,
    /// The Exercise that allowed it.
    pub exercise: &'a [u8; 32],
    /// Now, Unix ms.
    pub at: u64,
}

/// Records the invitation as hashes of its link token and magic code and the realm's blind
/// index of the invitee, and queues its mail through Relay in the same transaction; the token
/// and code exist only in the mail (TN-89, OP-153 m.3 (o)). The mail is sealed under the
/// inviter's subject key: the invitee may have no account yet.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn invite(
    t: &mut TenantTx,
    w: &Invite<'_>,
    i: &crate::domain::OrgInvite,
) -> Result<[u8; 16], AdminError> {
    use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
    use access_identity_account::notify::message::{Address, Body, Message};
    use access_identity_account::notify::notifier::OutboxNotifier;
    use access_identity_account::notify::ports::Notifier as _;

    let org = live_org(t, i.org).await?;
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let tenant = t.tenant();
    let token = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
    );
    let code = magic_code(access_crypto::random::bytes::<5>().map_err(|_| AdminError::Encode)?);
    let invitee = w
        .vault
        .index
        .index(tenant.as_bytes(), realm.as_bytes(), &i.email)
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
    let ttl_s = i64::from(i.days).saturating_mul(DAY_S);
    let id = t
        .insert_invitation(&access_store::orgs::NewInvitation {
            org: org.id,
            token_hash: &access_identity_account::domain::invitation::token_hash(&token),
            code_hash: &access_identity_account::domain::invitation::code_hash(&code),
            invitee_index: &invitee,
            invitee_domain: i.domain(),
            inviter: w.inviter.1,
            role: (i.role.0.as_str(), i.role.1),
            exercise: Some(w.exercise),
            ttl_s,
        })
        .await?;
    let named = access_identity_account::app::Realm {
        tenant,
        realm,
        kek: &*w.vault.kek,
        ids: w.ids,
    };
    let message = Message {
        subject: w.inviter.0,
        to: Address::Email(i.email.clone()),
        locale: None,
        // OP-153 m.3 (i), m.9 (d)
        valid_since_ms: Some(w.at),
        body: Body::Invitation {
            link: access_crypto::Secret::new(format!(
                "{}/login/invitations/{token}#code={code}",
                w.issuer.trim_end_matches('/')
            )),
            organization: org.display_name,
            inviter: i.inviter_name.clone(),
            expires_at_ms: w
                .at
                .saturating_add(u64::try_from(ttl_s).unwrap_or(0).saturating_mul(1000)),
        },
    };
    OutboxNotifier::new(&named, &SystemEntropy, &SystemClock)
        .notify(t, &message)
        .await
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
    Ok(id)
}

/// TN-98, §10.2.6: the organization lives; home realm discovery goes on only with a verified
/// domain of it that no other organization claims.
pub(crate) async fn update_current(
    t: &mut TenantTx,
    u: &crate::domain::OrgUpdate,
) -> Result<(), AdminError> {
    let org = live_org(t, u.org).await?;
    if u.hrd == Some(true) && t.hrd_domains(org.id).await?.is_empty() {
        return Err(crate::domain::Invalid::HrdUnverified.into());
    }
    // TN-90, OP-153 m.1 (d)
    if let Some((domain, true)) = &u.autojoin {
        let consumer =
            access_identity_account::domain::consumer_domains::ConsumerDomains::embedded()
                .map_err(|_| AdminError::Unavailable(String::from("consumer-domains")))?;
        let claims = t.domain_claims(domain).await?;
        crate::domain::org::autojoin(domain, org.id, &claims, &consumer).map_err(|r| match r {
            crate::domain::org::AutojoinRefused::ConsumerDomain => {
                crate::domain::Invalid::ConsumerDomain
            }
            crate::domain::org::AutojoinRefused::Contested => {
                crate::domain::Invalid::DomainContested
            }
            crate::domain::org::AutojoinRefused::Unverified => {
                crate::domain::Invalid::DomainUnverified
            }
        })?;
    }
    Ok(())
}

/// Writes a committed `idp.org.update` and queues `organization.updated` (OP-149 m.4).
pub(crate) async fn update(
    t: &mut TenantTx,
    ids: &IdKey,
    u: &crate::domain::OrgUpdate,
    app: &access_store::Pool,
) -> Result<bool, AdminError> {
    let org = live_org(t, u.org).await?;
    let mut done = true;
    if let Some(n) = &u.display_name {
        done &= t.set_org_name(org.id, n).await?;
    }
    if let Some(h) = u.hrd {
        done &= t.set_org_hrd(org.id, h).await?;
    }
    if let Some((domain, on)) = &u.autojoin {
        let claim = t
            .domain_claims(domain)
            .await?
            .into_iter()
            .find(|c| c.org == org.id)
            .ok_or(crate::domain::Invalid::NoDomain)?;
        done &= t.set_autojoin(claim.id, *on).await?;
    }
    let at = access_store::authority::server_time(app).await?;
    organization_event(t, ids, IdentityKind::OrganizationUpdated, org.id, at).await?;
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.3 (o)
    #[test]
    fn a_magic_code_is_eight_base32_characters() {
        assert_eq!(magic_code([0; 5]), "AAAAAAAA");
        assert_eq!(magic_code([0xff; 5]), "77777777");
    }
}
