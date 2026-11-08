//! What a token's contract bounds at the resource server (§9.9.1, §9.12, §5.3, OP-109 m.7,
//! OP-150 m.8 (b), m.9 (b)): a bounds token is evaluated against the intent with the Kernel's
//! `covers` (action, resource scope, typed parameters, recipient, purpose), each detail must
//! repeat the contract's bounds, and every local requirement of the contract must be one this
//! server satisfied. What the SDK cannot read back into the Kernel's model, or cannot decide
//! (party selectors carry pseudonyms, intensional and foreign selectors need claims, an
//! extension it must understand), is refused, never assumed (MD-8, TI-9).

use alloc::vec::Vec;
use core::fmt::Write as _;

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
    let unmet: Vec<RequirementTerm> = local_requirements(validity)?
        .into_iter()
        .filter(|t| !satisfied.contains(t))
        .collect();
    if unmet.is_empty() {
        return Ok(());
    }
    Err(StepUp::of(&unmet).map_or(Denied::LocalRequirement, Denied::StepUp))
}

/// The RFC 9470 error code.
pub const INSUFFICIENT_USER_AUTHENTICATION: &str = "insufficient_user_authentication";

/// What an RFC 9470 challenge asks the client to obtain (§3): authentication at most
/// `max_age_s` old, and the AAL in `acr_values` when a term's floors name one above 1. The
/// challenge is not authority; a term bound to the intent digest never travels this way, it is
/// met by `REQUIRE_ACTION` and an approval (TN-44, X29, X-L4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUp {
    /// Seconds since the user authenticated, at most.
    pub max_age_s: u64,
    /// The AAL asked for, 2 or 3; `None` asks freshness only.
    pub aal: Option<u8>,
}

fn aal_of(term: &RequirementTerm) -> u8 {
    let floor = |dim: &str| term.assurance.get(dim).copied().unwrap_or(0);
    let hardware = floor("hardware_bound") >= 1 || floor("non_custodial") >= 1;
    let uv = floor("uv") >= 1;
    let implied = match (hardware, uv) {
        (true, true) => 3,
        (_, true) => 2,
        _ => 1,
    };
    let named = match floor("aal") {
        3 => 3,
        2 => 2,
        _ => 1,
    };
    named.max(implied)
}

impl StepUp {
    /// The challenge for `unmet`: `Some` only when every unmet term is an `authentication`
    /// Claim term not bound to the intent and with a freshness ceiling; the tightest freshness
    /// and the highest AAL win. Any other unmet term has no RFC 9470 answer (§12.2.3, TN-44).
    #[must_use]
    pub fn of(unmet: &[RequirementTerm]) -> Option<Self> {
        use access_kernel::model::{Binding, ProofKind};
        let mut out: Option<Self> = None;
        for term in unmet {
            if term.proof_kind != ProofKind::Claim
                || term.class != "authentication"
                || !matches!(term.binding, Binding::None | Binding::ActorInstance)
            {
                return None;
            }
            let max_age_s = term.freshness_ms?.div_ceil(1_000).max(1);
            let aal = Some(aal_of(term)).filter(|a| *a > 1);
            out = Some(match out {
                None => Self { max_age_s, aal },
                Some(o) => Self {
                    max_age_s: o.max_age_s.min(max_age_s),
                    aal: o.aal.max(aal),
                },
            });
        }
        out
    }

    /// The `WWW-Authenticate` value (RFC 9470 §3, RFC 6750 §3).
    #[must_use]
    pub fn www_authenticate(&self) -> alloc::string::String {
        let mut out = alloc::format!(
            "Bearer error=\"{INSUFFICIENT_USER_AUTHENTICATION}\", error_description=\"A fresher or stronger user authentication is required\", max_age={}",
            self.max_age_s
        );
        if let Some(a) = self.aal {
            let _ = write!(
                out,
                ", acr_values=\"http://idmanagement.gov/ns/assurance/aal/{a}\""
            );
        }
        out
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
