//! What a committed organization SSO Exercise writes besides its decision (OP-155 m.3 (i),
//! TN-94, TN-95, TN-134): enforcement's sweep of the members' sign-ins, refresh families and
//! API keys with the pending invitations' fate, a setup link and its Relay message, and the SCIM
//! source that closes invitations.

use access_identity_account::adapters::pg::PgTx;
use access_store::identity::TenantTx;

use super::ClientSecret;
use super::orgs::live_org;
use crate::AdminError;
use crate::domain::sso::{InviteFate, SETUP_LINK_TTL_S, SetupLinkOrder, SsoEnforcement};
use crate::domain::{Change, Invalid};

/// The audit actor of the sweep.
const SWEEP_ACTOR: &str = "idp.org.sso_enforce";

/// TN-94: enforcing needs an organization whose SSO is not enforced; lifting needs one whose SSO
/// is.
///
/// # Errors
/// [`AdminError::Conflict`], [`Invalid::NoOrg`].
pub(crate) async fn enforce_current(
    t: &mut TenantTx,
    e: &SsoEnforcement,
) -> Result<(), AdminError> {
    let org = live_org(t, e.org).await?;
    let enforced = t.sso_enforcement(org.id).await?.is_some_and(|s| s.enforced);
    if enforced == e.invites.is_some() {
        return Err(AdminError::Conflict);
    }
    Ok(())
}

/// TN-95: an organization whose SCIM source is bound takes no invitation.
///
/// # Errors
/// [`Invalid::ScimAuthoritative`].
pub(crate) async fn invite_open(t: &mut TenantTx, org: [u8; 16]) -> Result<(), AdminError> {
    if t.scim_sources(org).await?.is_empty() {
        Ok(())
    } else {
        Err(Invalid::ScimAuthoritative.into())
    }
}

/// Writes the next enforcement version under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &access_store::idp::Bound,
    e: &SsoEnforcement,
) -> Result<bool, AdminError> {
    let org = live_org(t, e.org).await?;
    t.put_sso_enforcement(bound, org.id, e.invites.map(InviteFate::word))
        .await?;
    Ok(true)
}

/// What the sweep ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Swept {
    /// Members whose sign-ins and refresh families ended.
    pub(crate) members: u64,
    /// Directory app passwords revoked.
    pub(crate) api_keys: u64,
    /// Pending invitations revoked.
    pub(crate) invitations: u64,
}

/// The sweep of a committed `idp.org.sso_enforce` (TN-94, OP-155 m.3 (i)): every active member's
/// identity sessions and refresh families end at a new `session_epoch`, their directory app
/// passwords are revoked, and the pending invitations are revoked when the fate is `cancel`.
/// Passwords are not deleted: while SSO is enforced, sign-in refuses every local method of a
/// member, and lifting the enforcement gives them back.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn sweep(
    t: &mut PgTx,
    realm: &access_identity_account::app::Realm<'_>,
    e: &SsoEnforcement,
    (correlation, at): (&str, u64),
) -> Result<Swept, AdminError> {
    use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
    use access_identity_account::notify::notifier::OutboxNotifier;

    let Some(fate) = e.invites else {
        return Ok(Swept::default());
    };
    let org = live_org(&mut t.0, e.org).await?;
    let who = access_identity_account::app::Actor {
        actor: SWEEP_ACTOR,
        correlation,
    };
    let notifier = OutboxNotifier::new(realm, &SystemEntropy, &SystemClock);
    let mut swept = Swept::default();
    for m in t.0.memberships(org.id).await? {
        if access_identity_account::app::accounts::end_for_sso(t, realm, m.subject, &who)
            .await
            .map_err(account)?
            .is_some()
        {
            swept.members = swept.members.saturating_add(1);
        }
        for c in t.0.ldap_credentials(m.subject).await? {
            let done = access_identity_account::app::ldap::revoke(
                t,
                &notifier,
                m.subject,
                c.id,
                access_identity_account::app::ldap::Context {
                    actor: SWEEP_ACTOR,
                    correlation,
                    at_ms: at,
                },
            )
            .await
            .map_err(account)?;
            if done.is_ok() {
                swept.api_keys = swept.api_keys.saturating_add(1);
            }
        }
    }
    if fate == InviteFate::Cancel {
        for i in t.0.open_invitations(org.id).await? {
            if t.0.revoke_invitation(i).await? {
                swept.invitations = swept.invitations.saturating_add(1);
            }
        }
    }
    Ok(swept)
}

/// What a setup link needs to be issued.
pub(crate) struct Issue<'a> {
    /// The realm's account context, for the Relay message.
    pub(crate) realm: &'a access_identity_account::app::Realm<'a>,
    /// The realm's issuer, which the link lives under.
    pub(crate) issuer: &'a str,
    /// The Exercise that allowed it.
    pub(crate) exercise: &'a [u8; 32],
    /// Now, Unix ms.
    pub(crate) at: u64,
}

/// Issues a committed `idp.org.setup_link` (TN-134, OP-155 m.3 (i)): 256 random bits kept only
/// as SHA-256, bound to the organization, valid 72 hours, sent by Relay `SsoSetupLink` when the
/// order names an address, and shown to the caller once. The message is sealed under the key of
/// one of the organization's owners: the recipient may have no account.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn setup_link(
    t: &mut TenantTx,
    w: &Issue<'_>,
    order: &SetupLinkOrder,
) -> Result<ClientSecret, AdminError> {
    use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
    use access_identity_account::notify::message::{Address, Body, Message, Prompt};
    use access_identity_account::notify::notifier::OutboxNotifier;
    use access_identity_account::notify::ports::Notifier as _;

    let org = live_org(t, order.org).await?;
    let token = access_kernel::json::b64url_encode(
        &access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?,
    );
    let hash = suiss_crypto::digest::sha256(token.as_bytes());
    t.insert_setup_link(org.id, &hash, w.exercise, SETUP_LINK_TTL_S)
        .await?;
    let by = t
        .memberships(org.id)
        .await?
        .into_iter()
        .find(|m| m.owner)
        .map(|m| m.subject)
        .ok_or(Invalid::NoOrg)?;
    let link = format!("{}/login/sso-setup/{token}", w.issuer.trim_end_matches('/'));
    if let Some(email) = &order.email {
        let message = Message {
            subject: by,
            to: Address::Email(email.clone()),
            locale: None,
            valid_since_ms: Some(w.at),
            body: Body::Prompt {
                prompt: Prompt::SsoSetupLink,
                link: access_crypto::Secret::new(link.clone()),
                name: org.display_name,
                expires_at_ms: w.at.saturating_add(
                    u64::try_from(SETUP_LINK_TTL_S)
                        .unwrap_or(0)
                        .saturating_mul(1000),
                ),
            },
        };
        OutboxNotifier::new(w.realm, &SystemEntropy, &SystemClock)
            .notify(t, &message)
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?;
    }
    Ok(ClientSecret(link))
}

/// The SCIM source a committed `idp.scim.client_register` binds, and the binding a retirement
/// ends (TN-95).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn scim_source(
    t: &mut TenantTx,
    change: &Change,
    exercise: &[u8; 32],
) -> Result<(), AdminError> {
    use crate::domain::scim::ScimChange;
    match change {
        Change::Scim(ScimChange::ClientRegister {
            name,
            org: Some(org),
            ..
        }) => {
            let org = live_org(t, *org).await?;
            t.bind_scim_source(org.id, name, exercise).await?;
        }
        Change::Scim(ScimChange::ClientRetire(name)) => {
            t.end_scim_source(name).await?;
        }
        _ => {}
    }
    Ok(())
}

fn account(e: access_identity_account::AccountError) -> AdminError {
    match e {
        access_identity_account::AccountError::Store(s) => s.into(),
        other => AdminError::Unavailable(format!("account: {other}")),
    }
}
