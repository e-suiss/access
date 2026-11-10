//! `idp.federation.*` changes (OP-155 m.3 (j), IDP-19): the realm's federation settings and its
//! trust anchors, each written under its committed ALLOW; and the trust anchors read.

use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::oidf::{FederationSettingsRow, NO_SUBORDINATES};
use serde_json::Value as Json;

use crate::AdminError;
use crate::domain::Invalid;
use crate::domain::federation::FederationChange;

/// What must hold now for `change`: the role and registration need the leaf on, removing an
/// anchor needs it live, and a change that changes nothing is a conflict.
///
/// # Errors
/// [`Invalid::NoTrustAnchor`], [`Invalid::Federation`]; [`AdminError`].
pub(crate) async fn current(t: &mut TenantTx, change: &FederationChange) -> Result<(), AdminError> {
    let s = t.federation_settings().await?;
    match change {
        FederationChange::TaEnable(_) | FederationChange::Registration(true) if !s.enabled => {
            Err(Invalid::Federation.into())
        }
        FederationChange::Disable if !s.enabled => Err(AdminError::Conflict),
        FederationChange::Registration(false) if !s.registration_open => Err(AdminError::Conflict),
        FederationChange::TrustAnchorRemove(id) => {
            let live = t
                .trust_anchors()
                .await?
                .iter()
                .any(|a| a.live && &a.entity_id == id);
            if live {
                Ok(())
            } else {
                Err(Invalid::NoTrustAnchor.into())
            }
        }
        _ => Ok(()),
    }
}

/// Writes `change` under `bound`.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &FederationChange,
) -> Result<bool, AdminError> {
    let s = t.federation_settings().await?;
    let next = match change {
        FederationChange::Enable { authority_hints } => FederationSettingsRow {
            enabled: true,
            authority_hints: authority_hints.clone(),
            ..s
        },
        FederationChange::Disable => FederationSettingsRow::default(),
        FederationChange::TaEnable(subs) => FederationSettingsRow {
            ta_enabled: true,
            subordinates: FederationChange::subordinates_json(subs),
            ..s
        },
        FederationChange::Registration(open) => FederationSettingsRow {
            registration_open: *open,
            ..s
        },
        FederationChange::TrustAnchorAdd { entity_id, jwks } => {
            t.put_trust_anchor(bound, entity_id, jwks.as_bytes(), true)
                .await?;
            return Ok(true);
        }
        FederationChange::TrustAnchorRemove(entity_id) => {
            let row = t
                .trust_anchors()
                .await?
                .into_iter()
                .find(|a| a.live && &a.entity_id == entity_id)
                .ok_or(Invalid::NoTrustAnchor)?;
            t.put_trust_anchor(bound, entity_id, &row.jwks, false)
                .await?;
            return Ok(true);
        }
    };
    t.put_federation_settings(bound, &next).await?;
    Ok(true)
}

/// The realm's trust anchors as administrators read them, keyed by the base64url of the entity
/// identifier, with the federation settings beside each.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn anchors(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let s = t.federation_settings().await?;
    let rows = t.trust_anchors().await?;
    Ok(rows
        .into_iter()
        .map(|a| (b64url_encode(a.entity_id.as_bytes()), a))
        .filter(|(id, _)| key.is_none_or(|k| k == id))
        .map(|(id, a)| {
            let jwks: Json = serde_json::from_slice(&a.jwks).unwrap_or(Json::Null);
            (
                serde_json::json!({
                    "anchor": id,
                    "entity_id": a.entity_id,
                    "jwks": jwks,
                    "status": if a.live { "live" } else { "removed" },
                    "federation": {
                        "enabled": s.enabled,
                        "authority_hints": s.authority_hints,
                        "authority_role": s.ta_enabled,
                        "registration_open": s.registration_open,
                        "subordinates": s.subordinates != NO_SUBORDINATES,
                    },
                }),
                0,
            )
        })
        .collect())
}

/// The entity identifier an anchor's external id names: the base64url of its bytes.
///
/// # Errors
/// [`Invalid::NoTrustAnchor`].
pub fn anchor_of(id: &str) -> Result<String, Invalid> {
    access_kernel::json::b64url_decode(id)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(Invalid::NoTrustAnchor)
}
