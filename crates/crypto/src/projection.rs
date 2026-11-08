//! JOSE containers of authority projections (§9.9.1, §9.10, OP-143 m.6 (a), m.11 (c)): the
//! SD-JWT container of a PAP and the RFC 9068 access token whose authority is in RFC 9396
//! `authorization_details`. Production only; verification is the Kernel's
//! (`verify::projection`). The signer is the domain's operational key, never a realm key
//! (§9.9.3 rule 7, CR-5).
//!
//! A `PartyRef` leaves the domain only as a domain-pairwise pseudonym (MD-10, P52): every party
//! the projection names goes through [`PartyRefs`].

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{Json, b64url_encode};
use access_kernel::meta::capacity_value;
use access_kernel::model::{ActionRef, Id, TrustedTime};
use access_kernel::pap::Pap;
use access_kernel::validity::ValidityContract;
use access_kernel::verify::key_scope::thumbprint;
use access_kernel::verify::projection::{ACCESS_TOKEN_TYP, Confirmation, PAP_TYP, digest_text};
use suiss_crypto::dcbor::Value;
use suiss_crypto::signer::Signer;

use crate::jose::output::{self, JsonOutError, digest, from_cbor, int, text};
use crate::jose::{JoseError, confirmation_jwk, sign_compact};
use crate::random::RandomError;
use crate::sd_jwt::{self, Issued, SdJwtIssueError};

/// Longest pseudonym, in bytes.
pub const MAX_PSEUDONYM: usize = 255;

/// A domain-pairwise pseudonym of a party (MD-10, INV-38): stable within one domain,
/// unrelated across domains. Its derivation `f(domain_key, PartyID)` is not fixed yet; the
/// caller derives it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyPseudonym(String);

impl PartyPseudonym {
    /// A pseudonym of 1 to [`MAX_PSEUDONYM`] visible ASCII characters.
    ///
    /// # Errors
    /// [`ProjectionError::Pseudonym`].
    pub fn new(value: &str) -> Result<Self, ProjectionError> {
        if value.is_empty()
            || value.len() > MAX_PSEUDONYM
            || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(ProjectionError::Pseudonym);
        }
        Ok(Self(String::from(value)))
    }

    /// The pseudonym.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The domain's pseudonyms of its parties (MD-10).
pub trait PartyRefs {
    /// The pseudonym of `party`, or `None` when the domain has none.
    fn pseudonym(&self, party: &Id) -> Option<PartyPseudonym>;
}

impl PartyRefs for BTreeMap<Id, PartyPseudonym> {
    fn pseudonym(&self, party: &Id) -> Option<PartyPseudonym> {
        self.get(party).cloned()
    }
}

/// Why a projection could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// Signing failed.
    #[error("jose: {0}")]
    Jose(#[from] JoseError),
    /// The SD-JWT could not be produced.
    #[error("sd-jwt: {0}")]
    SdJwt(#[from] SdJwtIssueError),
    /// A value has no JSON form.
    #[error("json: {0}")]
    Json(#[from] JsonOutError),
    /// A model value could not be encoded.
    #[error("encode")]
    Encode,
    /// A party has no pseudonym, or a pseudonym is malformed.
    #[error("pseudonym")]
    Pseudonym,
    /// The audience is empty or outside the contract's audience.
    #[error("audience")]
    Audience,
    /// `issuer` or `client_id` is empty.
    #[error("member")]
    Member,
    /// Issued after its horizon.
    #[error("time")]
    Time,
    /// The bounds name no exact action, or a catalog prefix a RAR `type` cannot name.
    #[error("authority")]
    Authority,
}

impl ProjectionError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Jose(e) => e.code(),
            Self::SdJwt(e) => e.code(),
            Self::Json(_) => "projection-json",
            Self::Encode => "projection-encode",
            Self::Pseudonym => "projection-pseudonym",
            Self::Audience => "projection-audience",
            Self::Member => "projection-member",
            Self::Time => "projection-time",
            Self::Authority => "projection-authority",
        }
    }
}

// MD-10
const PARTY_TAGS: [&str; 3] = ["party", "subject", "for"];

fn pseudonymize(v: &mut Value, parties: &dyn PartyRefs) -> Result<(), ProjectionError> {
    match v {
        Value::Map(entries) => {
            if let [(Value::Text(tag), inner @ Value::Bytes(_))] = entries.as_mut_slice()
                && PARTY_TAGS.contains(&tag.as_str())
            {
                let Value::Bytes(raw) = inner else {
                    return Err(ProjectionError::Encode);
                };
                let id =
                    <[u8; 16]>::try_from(raw.as_slice()).map_err(|_| ProjectionError::Encode)?;
                let p = parties
                    .pseudonym(&Id(id))
                    .ok_or(ProjectionError::Pseudonym)?;
                *inner = Value::Text(p.0);
                return Ok(());
            }
            for (_, value) in entries {
                pseudonymize(value, parties)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                pseudonymize(item, parties)?;
            }
        }
        Value::Tag(_, inner) => pseudonymize(inner, parties)?,
        _ => {}
    }
    Ok(())
}

fn model_json(value: Value, parties: &dyn PartyRefs) -> Result<Json, ProjectionError> {
    let mut value = value;
    pseudonymize(&mut value, parties)?;
    Ok(from_cbor(&value)?)
}

fn member(name: &str, value: Json) -> (String, Json) {
    (String::from(name), value)
}

fn members(object: Json, keep: &[&str]) -> Vec<(String, Json)> {
    match object {
        Json::Object(m) => m
            .into_iter()
            .filter(|(k, _)| keep.contains(&k.as_str()))
            .collect(),
        _ => Vec::new(),
    }
}

fn seconds(ms: TrustedTime) -> Result<Json, ProjectionError> {
    Ok(int(ms / 1000)?)
}

/// The claims of a PAP's SD-JWT container, in this order: `iss` (the `DomainID` in text form,
/// L0-ENC-20), `iat` and `exp` (the contract's horizon) in seconds rounded down, `cnf.jwk`
/// (the holder key, RFC 7800), then the PAP members of L2-PAP-1 by their CDDL names:
/// `projection_exercise`, `holder` (its `instance`; the key is `cnf`), `capacity`, `bounds`,
/// `local_requirements` when not empty, `validity` and `lineage_commitment`. Digests are in
/// text form, other binaries base64url; parties are pseudonyms.
///
/// # Errors
/// [`ProjectionError`].
pub fn pap_claims(
    pap: &Pap,
    parties: &dyn PartyRefs,
) -> Result<Vec<(String, Json)>, ProjectionError> {
    if pap.validity.horizon < pap.iat {
        return Err(ProjectionError::Time);
    }
    let mut claims = vec![
        member("iss", digest(&pap.domain)),
        member("iat", seconds(pap.iat)?),
        member("exp", seconds(pap.validity.horizon)?),
        member(
            "cnf",
            Json::Object(vec![member("jwk", confirmation_jwk(&pap.holder.key)?)]),
        ),
        member("projection_exercise", digest(&pap.projection_exercise)),
        member(
            "holder",
            Json::Object(vec![member(
                "instance",
                Json::Str(b64url_encode(&pap.holder.instance.0)),
            )]),
        ),
        member(
            "capacity",
            model_json(capacity_value(pap.capacity), parties)?,
        ),
        member("bounds", model_json(pap.bounds.to_value(), parties)?),
    ];
    if !pap.local_requirements.is_empty() {
        let terms = pap
            .local_requirements
            .iter()
            .map(|t| model_json(t.to_value(), parties))
            .collect::<Result<_, _>>()?;
        claims.push(member("local_requirements", Json::Array(terms)));
    }
    claims.push(member(
        "validity",
        model_json(pap.validity.to_value(), parties)?,
    ));
    claims.push(member(
        "lineage_commitment",
        digest(&pap.lineage_commitment),
    ));
    Ok(claims)
}

/// A PAP in its SD-JWT container, signed by the domain's operational key (OP-143 m.6 (a)).
/// No member is selectively disclosable: a verifier needs them all (L2-PAP-3).
///
/// # Errors
/// [`ProjectionError`].
pub fn pap_sd_jwt(
    signer: &dyn Signer,
    pap: &Pap,
    parties: &dyn PartyRefs,
) -> Result<Issued, ProjectionError> {
    let claims = pap_claims(pap, parties)?;
    Ok(sd_jwt::issue(
        signer,
        PAP_TYP,
        claims,
        &BTreeSet::new(),
        &mut || Err(RandomError),
    )?)
}

/// The authority an access token carries (§9.9.1, §9.13.5).
#[derive(Clone, Copy, Debug)]
pub enum Authority<'a> {
    /// An exact-intent token: this intent, `kind = intent`.
    Intent(&'a IntentEnvelope),
    /// A bounds token: the contract's bounds, `kind = bounds`, one detail per action.
    Bounds,
}

/// What an access token projects (§9.9, §9.9.4, RFC 9068).
#[derive(Clone, Copy, Debug)]
pub struct AccessTokenProjection<'a> {
    /// The authorization server's issuer identifier.
    pub issuer: &'a str,
    /// The domain.
    pub domain: &'a Digest,
    /// The `projection.issue` exercise; also the `jti`.
    pub projection_exercise: &'a Digest,
    /// The actor Instance's party.
    pub actor_party: &'a Id,
    /// The capacity.
    pub capacity: Capacity,
    /// The contract.
    pub validity: &'a ValidityContract,
    /// The authority.
    pub authority: Authority<'a>,
    /// The one resource server (RFC 8707); one of the contract's audience.
    pub audience: &'a str,
    /// The OAuth client; not the actor (PI-7).
    pub client_id: &'a str,
    /// The holder binding.
    pub confirmation: Confirmation,
    /// Signing time.
    pub iat: TrustedTime,
}

/// The RAR `type` of an action: `<namespace>:<name>:<major>`; the schema digest is the
/// separate `schema` member (§9.13.5).
#[must_use]
pub fn action_type(action: &ActionRef) -> String {
    format!("{}:{}:{}", action.namespace, action.name, action.major)
}

fn detail(
    action: &ActionRef,
    kind: &str,
    common: &[(String, Json)],
    specific: Vec<(String, Json)>,
) -> Json {
    let mut d = vec![
        member("type", text(&action_type(action))),
        member("kind", text(kind)),
        member("schema", digest(&action.schema)),
    ];
    d.extend(common.iter().cloned());
    d.extend(specific);
    Json::Object(d)
}

fn authorization_details(
    p: &AccessTokenProjection<'_>,
    parties: &dyn PartyRefs,
) -> Result<Json, ProjectionError> {
    let common = [
        member("domain", digest(p.domain)),
        member("exercise", digest(p.projection_exercise)),
        member("basis_ref", Json::Str(b64url_encode(&p.validity.basis_ref))),
        member("capacity", model_json(capacity_value(p.capacity), parties)?),
        member("validity", model_json(p.validity.to_value(), parties)?),
    ];
    match p.authority {
        Authority::Intent(intent) => {
            let d = intent_digest(intent).map_err(|_| ProjectionError::Encode)?;
            let mut specific = vec![member("intent", digest(&d))];
            specific.extend(members(
                model_json(intent.to_value(), parties)?,
                &["resources", "params", "opaque", "purpose"],
            ));
            if let Some(r) = &intent.recipient {
                let r = parties.pseudonym(r).ok_or(ProjectionError::Pseudonym)?;
                specific.push(member("recipient", text(r.as_str())));
            }
            Ok(Json::Array(vec![detail(
                &intent.action,
                "intent",
                &common,
                specific,
            )]))
        }
        Authority::Bounds => {
            let bounds = &p.validity.bounds;
            if bounds.actions.exact.is_empty() || !bounds.actions.prefix.is_empty() {
                return Err(ProjectionError::Authority);
            }
            let constraints = members(
                model_json(bounds.to_value(), parties)?,
                &["resource", "params", "recipient", "purpose"],
            );
            Ok(Json::Array(
                bounds
                    .actions
                    .exact
                    .iter()
                    .map(|a| detail(a, "bounds", &common, constraints.clone()))
                    .collect(),
            ))
        }
    }
}

/// The claims of an access token projection, in this order: `iss`, `sub` (the principal's
/// pseudonym: the actor's party for `own`, P for `for(P)`), `act` (for `for(P)` only:
/// `{sub: actor's pseudonym, iss}`), `aud`, `exp` (the contract's horizon) and `iat` in seconds
/// rounded down, `jti` (the projection exercise in text form), `client_id`, `cnf` and
/// `authorization_details` (§9.9.4, §9.13.5).
///
/// # Errors
/// [`ProjectionError`].
pub fn access_token_claims(
    p: &AccessTokenProjection<'_>,
    parties: &dyn PartyRefs,
) -> Result<Json, ProjectionError> {
    if p.issuer.is_empty() || p.client_id.is_empty() {
        return Err(ProjectionError::Member);
    }
    // §9.9.3 rule 1
    if p.audience.is_empty() || !p.validity.audience.contains(p.audience) {
        return Err(ProjectionError::Audience);
    }
    if p.validity.horizon < p.iat {
        return Err(ProjectionError::Time);
    }
    let pseudonym = |party: &Id| parties.pseudonym(party).ok_or(ProjectionError::Pseudonym);
    let actor = pseudonym(p.actor_party)?;
    let mut claims = vec![member("iss", text(p.issuer))];
    match p.capacity {
        Capacity::Own => claims.push(member("sub", text(actor.as_str()))),
        Capacity::For(principal) => {
            claims.push(member("sub", text(pseudonym(&principal)?.as_str())));
            claims.push(member(
                "act",
                Json::Object(vec![
                    member("sub", text(actor.as_str())),
                    member("iss", text(p.issuer)),
                ]),
            ));
        }
    }
    claims.extend([
        member("aud", text(p.audience)),
        member("exp", seconds(p.validity.horizon)?),
        member("iat", seconds(p.iat)?),
        member("jti", Json::Str(digest_text(p.projection_exercise))),
        member("client_id", text(p.client_id)),
        // §9.9.3 rule 2
        member(
            "cnf",
            Json::Object(vec![member(
                p.confirmation.member(),
                Json::Str(b64url_encode(p.confirmation.thumbprint())),
            )]),
        ),
        member("authorization_details", authorization_details(p, parties)?),
    ]);
    Ok(Json::Object(claims))
}

/// An access token projection: an `at+jwt` JWS signed by the domain's operational key with
/// `kid` its RFC 7638 thumbprint (§9.9.3 rule 7, CR-24).
///
/// # Errors
/// [`ProjectionError`].
pub fn access_token(
    signer: &dyn Signer,
    p: &AccessTokenProjection<'_>,
    parties: &dyn PartyRefs,
) -> Result<String, ProjectionError> {
    let claims = access_token_claims(p, parties)?;
    let kid = thumbprint(&signer.public_key());
    Ok(sign_compact(
        signer,
        &kid,
        ACCESS_TOKEN_TYP,
        output::to_string(&claims).as_bytes(),
    )?)
}

#[cfg(test)]
mod tests;
