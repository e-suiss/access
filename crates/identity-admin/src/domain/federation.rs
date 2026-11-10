//! `idp.federation.*` changes (OP-155 m.3 (a), (j), IDP-19): the realm issuer as an OpenID
//! Federation leaf, the trust anchors whose keys the realm pins, the optional intermediate or
//! trust anchor role and its subordinates, and OIDF client registration. Every one is off by
//! default; narrowing changes are CT1, the others CT2, adding a trust anchor is reserved (CT3).

use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_encode;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

/// Most authority hints a leaf names.
pub const MAX_HINTS: usize = 8;
/// Most subordinates the intermediate or trust anchor role vouches for.
pub const MAX_SUBORDINATES: usize = 256;
/// Most keys in a pinned JWKS.
pub const MAX_KEYS: usize = 32;
/// Longest entity identifier.
pub const MAX_ENTITY_ID: usize = 2048;

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A subordinate the realm's intermediate or trust anchor role issues statements about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subordinate {
    /// Its entity identifier.
    pub entity_id: String,
    /// The federation keys the realm vouches for, a JWKS object.
    pub jwks: String,
    /// The metadata policy the realm sets on it, an object per entity type.
    pub metadata_policy: Option<String>,
}

/// One `idp.federation.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FederationChange {
    /// `enable` (CT2): the realm issuer becomes a leaf under these superiors.
    Enable {
        /// The superiors its entity configuration names.
        authority_hints: Vec<String>,
    },
    /// `disable` (CT1): the leaf, the authority role and registration all stop.
    Disable,
    /// `trust_anchor_add` (reserved, CT3): a trust anchor and its pinned keys.
    TrustAnchorAdd {
        /// Its entity identifier.
        entity_id: String,
        /// Its keys, a JWKS object.
        jwks: String,
    },
    /// `trust_anchor_remove` (CT1).
    TrustAnchorRemove(String),
    /// `ta_enable` (CT2): the intermediate or trust anchor role with its subordinates.
    TaEnable(Vec<Subordinate>),
    /// `registration_open` (CT2) or `registration_close` (CT1).
    Registration(bool),
}

/// Why a federation body is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bad;

/// Whether `s` is an entity identifier: an `https` URL without query, fragment or user info.
#[must_use]
pub fn entity_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    s.len() <= MAX_ENTITY_ID
        && !host.is_empty()
        && !s.contains(['?', '#', '@', ' '])
        && s.bytes().all(|c| c.is_ascii_graphic())
}

/// Whether `v` is a public JWKS of P-256 or RSA signature keys, each with a `kid`.
#[must_use]
pub fn public_jwks(v: &Json) -> bool {
    let Some(keys) = v.get("keys").and_then(Json::as_array) else {
        return false;
    };
    !keys.is_empty()
        && keys.len() <= MAX_KEYS
        && keys.iter().all(|k| {
            let Some(m) = k.as_object() else {
                return false;
            };
            let kty = m.get("kty").and_then(Json::as_str);
            !PRIVATE_MEMBERS.iter().any(|p| m.contains_key(*p))
                && m.get("kid")
                    .and_then(Json::as_str)
                    .is_some_and(|k| !k.is_empty())
                && (kty == Some("RSA")
                    || (kty == Some("EC") && m.get("crv").and_then(Json::as_str) == Some("P-256")))
                && m.get("use")
                    .and_then(Json::as_str)
                    .is_none_or(|u| u == "sig")
        })
}

fn parsed(s: &str) -> Json {
    serde_json::from_str(s).unwrap_or(Json::Null)
}

fn texts(m: &Map<String, Json>, k: &str) -> Result<Vec<String>, Bad> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(String::from).ok_or(Bad))
            .collect(),
        _ => Err(Bad),
    }
}

fn only(m: &Map<String, Json>, allowed: &[&str]) -> Result<(), Bad> {
    if m.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Bad)
    }
}

fn bool_of(m: &Map<String, Json>, k: &str) -> Result<bool, Bad> {
    m.get(k).and_then(Json::as_bool).ok_or(Bad)
}

fn sorted_unique(list: &[String]) -> bool {
    list.windows(2).all(|w| w.first() < w.get(1))
}

impl FederationChange {
    /// The change `putFederation` asks: `{"enabled", "authority_hints"}`.
    ///
    /// # Errors
    /// [`Bad`].
    pub fn put_federation(m: &Map<String, Json>) -> Result<Self, Bad> {
        only(m, &["enabled", "authority_hints"])?;
        let mut hints = texts(m, "authority_hints")?;
        hints.sort();
        if bool_of(m, "enabled")? {
            Ok(Self::Enable {
                authority_hints: hints,
            })
        } else if hints.is_empty() {
            Ok(Self::Disable)
        } else {
            Err(Bad)
        }
    }

    /// The change `addTrustAnchor` asks: `{"entity_id", "jwks"}`.
    ///
    /// # Errors
    /// [`Bad`].
    pub fn add_anchor(m: &Map<String, Json>) -> Result<Self, Bad> {
        only(m, &["entity_id", "jwks"])?;
        Ok(Self::TrustAnchorAdd {
            entity_id: String::from(m.get("entity_id").and_then(Json::as_str).ok_or(Bad)?),
            jwks: m.get("jwks").ok_or(Bad)?.to_string(),
        })
    }

    /// The change `putFederationAuthority` asks: `{"subordinates": [...]}`.
    ///
    /// # Errors
    /// [`Bad`].
    pub fn put_authority(m: &Map<String, Json>) -> Result<Self, Bad> {
        only(m, &["subordinates"])?;
        let list = m.get("subordinates").and_then(Json::as_array).ok_or(Bad)?;
        let mut out = list
            .iter()
            .map(|s| {
                let s = s.as_object().ok_or(Bad)?;
                only(s, &["entity_id", "jwks", "metadata_policy"])?;
                Ok(Subordinate {
                    entity_id: String::from(s.get("entity_id").and_then(Json::as_str).ok_or(Bad)?),
                    jwks: s.get("jwks").ok_or(Bad)?.to_string(),
                    metadata_policy: s.get("metadata_policy").map(Json::to_string),
                })
            })
            .collect::<Result<Vec<_>, Bad>>()?;
        out.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        Ok(Self::TaEnable(out))
    }

    /// The change `putFederationRegistration` asks: `{"open"}`.
    ///
    /// # Errors
    /// [`Bad`].
    pub fn put_registration(m: &Map<String, Json>) -> Result<Self, Bad> {
        only(m, &["open"])?;
        Ok(Self::Registration(bool_of(m, "open")?))
    }

    /// The catalog action.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Enable { .. } => IdpAction::FederationEnable,
            Self::Disable => IdpAction::FederationDisable,
            Self::TrustAnchorAdd { .. } => IdpAction::FederationTrustAnchorAdd,
            Self::TrustAnchorRemove(_) => IdpAction::FederationTrustAnchorRemove,
            Self::TaEnable(_) => IdpAction::FederationTaEnable,
            Self::Registration(true) => IdpAction::FederationRegistrationOpen,
            Self::Registration(false) => IdpAction::FederationRegistrationClose,
        }
    }

    /// Checks the change on its own.
    ///
    /// # Errors
    /// [`Bad`].
    pub fn check(&self) -> Result<(), Bad> {
        let ok = match self {
            Self::Enable { authority_hints } => {
                authority_hints.len() <= MAX_HINTS
                    && sorted_unique(authority_hints)
                    && authority_hints.iter().all(|h| entity_id(h))
            }
            Self::Disable | Self::Registration(_) => true,
            Self::TrustAnchorAdd {
                entity_id: id,
                jwks,
            } => entity_id(id) && public_jwks(&parsed(jwks)),
            Self::TrustAnchorRemove(id) => entity_id(id),
            Self::TaEnable(subs) => {
                let ids: Vec<String> = subs.iter().map(|s| s.entity_id.clone()).collect();
                subs.len() <= MAX_SUBORDINATES
                    && sorted_unique(&ids)
                    && subs.iter().all(|s| {
                        entity_id(&s.entity_id)
                            && public_jwks(&parsed(&s.jwks))
                            && s.metadata_policy
                                .as_deref()
                                .is_none_or(|p| parsed(p).is_object())
                    })
            }
        };
        if ok { Ok(()) } else { Err(Bad) }
    }

    /// The Exercise payload.
    #[must_use]
    pub fn body(&self) -> Value {
        let json = |v: &String| Value::text(v);
        match self {
            Self::Enable { authority_hints } => Value::Map(vec![
                (Value::text("enabled"), Value::Bool(true)),
                (
                    Value::text("authority_hints"),
                    Value::Array(authority_hints.iter().map(|h| Value::text(h)).collect()),
                ),
            ]),
            Self::Disable => Value::Map(vec![(Value::text("enabled"), Value::Bool(false))]),
            Self::TrustAnchorAdd { entity_id, jwks } => Value::Map(vec![
                (Value::text("entity_id"), Value::text(entity_id)),
                (Value::text("jwks"), json(jwks)),
            ]),
            Self::TrustAnchorRemove(id) => {
                Value::Map(vec![(Value::text("entity_id"), Value::text(id))])
            }
            Self::TaEnable(subs) => Value::Map(vec![(
                Value::text("subordinates"),
                Value::Array(
                    subs.iter()
                        .map(|s| {
                            let mut m = vec![
                                (Value::text("entity_id"), Value::text(&s.entity_id)),
                                (Value::text("jwks"), json(&s.jwks)),
                            ];
                            if let Some(p) = &s.metadata_policy {
                                m.push((Value::text("metadata_policy"), json(p)));
                            }
                            Value::Map(m)
                        })
                        .collect(),
                ),
            )]),
            Self::Registration(open) => Value::Map(vec![(Value::text("open"), Value::Bool(*open))]),
        }
    }

    /// The resource path below the realm.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::TrustAnchorAdd { entity_id, .. } | Self::TrustAnchorRemove(entity_id) => vec![
                String::from("federation"),
                String::from("trust-anchor"),
                b64url_encode(entity_id.as_bytes()),
            ],
            _ => vec![String::from("federation")],
        }
    }

    /// The subordinates as stored, a JSON array.
    #[must_use]
    pub fn subordinates_json(subs: &[Subordinate]) -> Vec<u8> {
        Json::Array(
            subs.iter()
                .map(|s| {
                    let mut m = Map::new();
                    m.insert(String::from("entity_id"), Json::from(s.entity_id.clone()));
                    m.insert(String::from("jwks"), parsed(&s.jwks));
                    if let Some(p) = &s.metadata_policy {
                        m.insert(String::from("metadata_policy"), parsed(p));
                    }
                    Json::Object(m)
                })
                .collect(),
        )
        .to_string()
        .into_bytes()
    }
}

#[cfg(test)]
mod tests;
