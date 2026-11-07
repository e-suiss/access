//! What a token's contract bounds at the resource server (§9.9.1, §9.12, §5.3, OP-109 m.7,
//! OP-150 m.8 (b), m.9 (b)): a bounds token is evaluated against the intent with the Kernel's
//! `covers` (action, resource scope, typed parameters, recipient, purpose), each detail must
//! repeat the contract's bounds, and every local requirement of the contract must be one this
//! server satisfied. What the SDK cannot read back into the Kernel's model, or cannot decide
//! (party selectors carry pseudonyms, intensional and foreign selectors need claims, an
//! extension it must understand), is refused, never assumed (MD-8, TI-9).

use alloc::vec::Vec;

use access_kernel::algebra::Catalog;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, covers};
use access_kernel::json::{Json, b64url_decode};
use access_kernel::model::{AuthoritySet, RequirementTerm};
use suiss_crypto::dcbor::Value;

use super::Denied;

/// The bounds members a bounds detail repeats from the contract (OP-150 m.9 (b)).
const REPEATED: [&str; 4] = ["resource", "params", "recipient", "purpose"];

/// The Kernel value a JOSE JSON member stands for: the inverse of the token's JSON form, where
/// a digest is its `sha-256:` text and every other string is text. Byte strings and party
/// pseudonyms do not come back, so a model value that holds them is not read (fail closed).
#[must_use]
pub fn model_value(j: &Json) -> Option<Value> {
    Some(match j {
        Json::Null => return None,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(i) => Value::int(*i),
        Json::Str(s) => match s
            .strip_prefix("sha-256:")
            .and_then(|b| b64url_decode(b).ok())
            .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
        {
            Some(raw) => Digest(raw).to_value(),
            None => Value::text(s),
        },
        Json::Array(items) => Value::Array(items.iter().map(model_value).collect::<Option<_>>()?),
        Json::Object(members) => Value::Map(
            members
                .iter()
                .map(|(k, v)| Some((Value::text(k), model_value(v)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

fn read<T: Canonical>(j: &Json, what: &'static str) -> Result<T, Denied> {
    model_value(j)
        .and_then(|v| T::from_value(&v).ok())
        .ok_or(Denied::Unevaluable(what))
}

/// The contract's bounds as the Kernel's [`AuthoritySet`].
///
/// # Errors
/// [`Denied::Unevaluable`].
pub fn authority_set(validity: &Json) -> Result<AuthoritySet, Denied> {
    read(
        validity
            .get("bounds")
            .ok_or(Denied::Unevaluable("bounds"))?,
        "bounds",
    )
}

/// The contract's local requirements (§9.12, OP-150 m.8 (b)).
///
/// # Errors
/// [`Denied::Unevaluable`].
pub fn local_requirements(validity: &Json) -> Result<Vec<RequirementTerm>, Denied> {
    match validity.get("local_requirements") {
        None => Ok(Vec::new()),
        Some(Json::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|t| read(t, "local_requirements"))
            .collect(),
        Some(_) => Err(Denied::Unevaluable("local_requirements")),
    }
}

/// Checks the contract part every token kind shares: no extension the SDK must understand, and
/// every local requirement among those this server `satisfied` (OP-150 m.8 (b)).
///
/// # Errors
/// [`Denied::Unevaluable`] or [`Denied::LocalRequirement`].
pub fn contract(validity: &Json, satisfied: &[RequirementTerm]) -> Result<(), Denied> {
    if validity.get("must_understand").is_some() {
        return Err(Denied::Unevaluable("must_understand"));
    }
    if local_requirements(validity)?
        .iter()
        .all(|t| satisfied.contains(t))
    {
        Ok(())
    } else {
        Err(Denied::LocalRequirement)
    }
}

/// Checks a bounds token against `envelope` (§9.9.1, §5.3): every detail repeats the contract's
/// bounds, and the bounds cover the intent by the Kernel's `covers`. Without the envelope the
/// resource scope and parameters cannot be evaluated, so nothing is accepted.
///
/// # Errors
/// [`Denied::Unevaluable`], [`Denied::Claim`] or [`Denied::Bounds`].
pub fn bounds(
    claims: &Json,
    validity: &Json,
    envelope: Option<&IntentEnvelope>,
) -> Result<(), Denied> {
    let set = authority_set(validity)?;
    let bounds = validity
        .get("bounds")
        .ok_or(Denied::Unevaluable("bounds"))?;
    let Some(Json::Array(details)) = claims.get("authorization_details") else {
        return Err(Denied::Claim("authorization_details"));
    };
    // OP-150 m.9 (b)
    if details
        .iter()
        .any(|d| REPEATED.iter().any(|m| d.get(m) != bounds.get(m)))
    {
        return Err(Denied::Claim("authorization_details"));
    }
    let envelope = envelope.ok_or(Denied::Unevaluable("intent"))?;
    if covers(&set, envelope, &Catalog::default()) {
        Ok(())
    } else {
        Err(Denied::Bounds)
    }
}
