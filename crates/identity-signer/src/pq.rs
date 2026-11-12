//! A realm's post-quantum signing key set (CR-41, OP-159 m.3 (o), (d)): opened by
//! `idp.realm.signing_profile`, an ML-DSA key set beside the realm's classical one. It rotates on
//! the realm's schedule, is published as `AKP` in the realm's JWKS and signs only the tokens of
//! clients that registered its algorithm. `signing_profile_close` drops every key in it.

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::Value;

use crate::protocol::{FrameError, Realm};

/// The refusal when no ML-DSA key can be held: the HSM lacks the mechanism, or the build is the
/// FIPS one (OP-159 m.3 (d), (r), HL-27). There is no classical key in its place.
pub const PQ_KEY_UNAVAILABLE: &str = "pq-key-unavailable";

/// The refusal for a realm without an open post-quantum key set.
pub const NO_PQ: &str = "signer-no-pq";

/// A request about a realm's post-quantum key set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqRequest {
    /// Whether this signer can hold an ML-DSA key of `alg` (OP-159 m.3 (d)).
    Ready {
        /// The parameter set.
        alg: JwsAlg,
    },
    /// Opens the realm's key set with `alg`; repeating it changes nothing, another `alg`
    /// replaces the set.
    Open {
        /// Realm.
        realm: Realm,
        /// The parameter set.
        alg: JwsAlg,
    },
    /// Drops every key of the realm's set; repeating it changes nothing.
    Close {
        /// Realm.
        realm: Realm,
    },
    /// Signs a JSON object as a compact ML-DSA JWS of type `typ` at `at`.
    Sign {
        /// Realm.
        realm: Realm,
        /// JWS `typ`.
        typ: String,
        /// JSON payload.
        payload: Vec<u8>,
        /// Signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
}

fn pq_alg(v: Option<&Value>) -> Result<JwsAlg, FrameError> {
    match v {
        Some(Value::Text(t)) => JwsAlg::ml_dsa(t).ok_or(FrameError::Malformed),
        _ => Err(FrameError::Malformed),
    }
}

fn realm_of(v: Option<&Value>) -> Result<Realm, FrameError> {
    match v {
        Some(Value::Bytes(b)) => Ok(Realm(
            b.as_slice().try_into().map_err(|_| FrameError::Malformed)?,
        )),
        _ => Err(FrameError::Malformed),
    }
}

fn entries(e: Vec<(&str, Value)>) -> Value {
    Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
}

impl PqRequest {
    /// The realm the request is about, if any.
    #[must_use]
    pub const fn realm(&self) -> Option<Realm> {
        match self {
            Self::Ready { .. } => None,
            Self::Open { realm, .. } | Self::Close { realm } | Self::Sign { realm, .. } => {
                Some(*realm)
            }
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::Ready { alg } => entries(vec![(
                "ready",
                entries(vec![("alg", Value::text(alg.name()))]),
            )]),
            Self::Open { realm, alg } => entries(vec![(
                "open",
                entries(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("alg", Value::text(alg.name())),
                ]),
            )]),
            Self::Close { realm } => entries(vec![(
                "close",
                entries(vec![("realm", Value::Bytes(realm.0.to_vec()))]),
            )]),
            Self::Sign {
                realm,
                typ,
                payload,
                at,
            } => entries(vec![(
                "sign",
                entries(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("typ", Value::text(typ)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
        }
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, FrameError> {
        if let Some(r) = v.get("ready") {
            return Ok(Self::Ready {
                alg: pq_alg(r.get("alg"))?,
            });
        }
        if let Some(o) = v.get("open") {
            return Ok(Self::Open {
                realm: realm_of(o.get("realm"))?,
                alg: pq_alg(o.get("alg"))?,
            });
        }
        if let Some(c) = v.get("close") {
            return Ok(Self::Close {
                realm: realm_of(c.get("realm"))?,
            });
        }
        let s = v.get("sign").ok_or(FrameError::Malformed)?;
        let text = match s.get("typ") {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(FrameError::Malformed),
        };
        let payload = match s.get("payload") {
            Some(Value::Bytes(b)) => b.clone(),
            _ => return Err(FrameError::Malformed),
        };
        let at = match s.get("at") {
            Some(Value::Unsigned(n)) => *n,
            _ => return Err(FrameError::Malformed),
        };
        Ok(Self::Sign {
            realm: realm_of(s.get("realm"))?,
            typ: text,
            payload,
            at,
        })
    }
}

/// The vault slot of `realm`'s post-quantum key set, apart from its JOSE key set.
#[must_use]
pub fn slot(realm: Realm) -> Realm {
    let d = suiss_crypto::digest::context_digest("access/identity-signer/pq/v1", &realm.0);
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Realm(out)
}

/// The JWKS `a` with the keys of `b` appended (OP-159 m.3 (o)).
#[must_use]
pub fn merged(a: &str, b: &str) -> String {
    let tail = b
        .strip_prefix(r#"{"keys":["#)
        .and_then(|s| s.strip_suffix("]}"))
        .unwrap_or_default();
    if tail.is_empty() {
        return String::from(a);
    }
    match a.strip_suffix("]}") {
        Some(head) if head.ends_with('[') => format!("{head}{tail}]}}"),
        Some(head) => format!("{head},{tail}]}}"),
        None => String::from(a),
    }
}

#[cfg(test)]
mod tests;
