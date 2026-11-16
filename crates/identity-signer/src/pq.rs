//! An environment's post-quantum signing key set (CR-41, OP-159 m.3 (o), (d)): opened by
//! `idp.environment.signing_profile`, an ML-DSA key set beside the environment's classical one. It rotates on
//! the environment's schedule, is published as `AKP` in the environment's JWKS and signs only the tokens of
//! clients that registered its algorithm. `signing_profile_close` drops every key in it.

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::Value;

use crate::protocol::{Environment, FrameError};

/// The refusal when no ML-DSA key can be held: the HSM lacks the mechanism, or the build is the
/// FIPS one (OP-159 m.3 (d), (r), HL-27). There is no classical key in its place.
pub const PQ_KEY_UNAVAILABLE: &str = "pq-key-unavailable";

/// The refusal for an environment without an open post-quantum key set.
pub const NO_PQ: &str = "signer-no-pq";

/// A request about an environment's post-quantum key set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqRequest {
    /// Whether this signer can hold an ML-DSA key of `alg` (OP-159 m.3 (d)).
    Ready {
        /// The parameter set.
        alg: JwsAlg,
    },
    /// Opens the environment's key set with `alg`; repeating it changes nothing, another `alg`
    /// replaces the set.
    Open {
        /// Environment.
        environment: Environment,
        /// The parameter set.
        alg: JwsAlg,
    },
    /// Drops every key of the environment's set; repeating it changes nothing.
    Close {
        /// Environment.
        environment: Environment,
    },
    /// Signs a JSON object as a compact ML-DSA JWS of type `typ` at `at`.
    Sign {
        /// Environment.
        environment: Environment,
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

fn environment_of(v: Option<&Value>) -> Result<Environment, FrameError> {
    match v {
        Some(Value::Bytes(b)) => Ok(Environment(
            b.as_slice().try_into().map_err(|_| FrameError::Malformed)?,
        )),
        _ => Err(FrameError::Malformed),
    }
}

fn entries(e: Vec<(&str, Value)>) -> Value {
    Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
}

impl PqRequest {
    /// The environment the request is about, if any.
    #[must_use]
    pub const fn environment(&self) -> Option<Environment> {
        match self {
            Self::Ready { .. } => None,
            Self::Open { environment, .. }
            | Self::Close { environment }
            | Self::Sign { environment, .. } => Some(*environment),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::Ready { alg } => entries(vec![(
                "ready",
                entries(vec![("alg", Value::text(alg.name()))]),
            )]),
            Self::Open { environment, alg } => entries(vec![(
                "open",
                entries(vec![
                    ("environment", Value::Bytes(environment.0.to_vec())),
                    ("alg", Value::text(alg.name())),
                ]),
            )]),
            Self::Close { environment } => entries(vec![(
                "close",
                entries(vec![("environment", Value::Bytes(environment.0.to_vec()))]),
            )]),
            Self::Sign {
                environment,
                typ,
                payload,
                at,
            } => entries(vec![(
                "sign",
                entries(vec![
                    ("environment", Value::Bytes(environment.0.to_vec())),
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
                environment: environment_of(o.get("environment"))?,
                alg: pq_alg(o.get("alg"))?,
            });
        }
        if let Some(c) = v.get("close") {
            return Ok(Self::Close {
                environment: environment_of(c.get("environment"))?,
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
            environment: environment_of(s.get("environment"))?,
            typ: text,
            payload,
            at,
        })
    }
}

/// The vault slot of `environment`'s post-quantum key set, apart from its JOSE key set.
#[must_use]
pub fn slot(environment: Environment) -> Environment {
    let d = suiss_crypto::digest::context_digest("access/identity-signer/pq/v1", &environment.0);
    let mut out = [0; 16];
    out.copy_from_slice(&d.0[..16]);
    Environment(out)
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
