//! Home realm discovery (TN-98, TN-3, §10.2.6, OP-155 m.3 (h)): off until the realm turns it on
//! with `idp.realm.hrd`; the realm's switch comes before any organization's and before any
//! client hint. When on, the organization is confirmed on an interstitial, which names the
//! organization's own upstream connection to continue to; nothing routes by an e-mail domain.

use access_identity_federation::domain::connection::Profile;
use access_store::StoreError;
use access_store::identity::TenantTx;

/// An organization's upstream connection, as the interstitial names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The connection's name in routes.
    pub connection: String,
    /// The name on its button.
    pub display_name: String,
}

/// Whether the realm has home realm discovery on (TN-98).
///
/// # Errors
/// [`StoreError`].
pub async fn realm_on(t: &mut TenantTx) -> Result<bool, StoreError> {
    t.realm_hrd().await
}

/// The active connection of the organization whose Party is `party`, if one names it.
///
/// # Errors
/// [`StoreError`].
pub async fn target(t: &mut TenantTx, party: [u8; 16]) -> Result<Option<Target>, StoreError> {
    let mut after = String::new();
    loop {
        let rows = access_store::idp::realm::upstreams(t, &after, 100).await?;
        let Some(last) = rows.last() else {
            return Ok(None);
        };
        after.clone_from(&last.name);
        for r in rows.iter().filter(|r| r.active) {
            let Ok(p) = Profile::stored(r.profile.as_deref(), r.client_secret_ref.is_some()) else {
                continue;
            };
            if p.organization_party() == Some(party) {
                return Ok(Some(Target {
                    connection: r.name.clone(),
                    display_name: p.display_name.unwrap_or_else(|| r.name.clone()),
                }));
            }
        }
        if rows.len() < 100 {
            return Ok(None);
        }
    }
}
