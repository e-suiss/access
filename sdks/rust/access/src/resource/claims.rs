//! Reading the Access members of an authority token (§9.9.3, §9.9.4, L2-JOS-1, L2-JOS-4,
//! OP-150 m.9 (b), (d), (f)): the RAR details, the `ValidityContract` view, the capacity the
//! `sub`/`act` claims project, the reserved claim shapes and the family.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::digest::Digest;
use access_kernel::json::{Json, b64url_decode};
use access_kernel::model::{ActionRef, TrustedTime};
use access_kernel::status::StatusRef;
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_kernel::verify::projection::Kind;
use suiss_crypto::dcbor::{self, Limits, Value};

use super::Denied;

/// Deepest `act` chain read (§9.9.4: at least 4 levels).
pub const MAX_ACT_DEPTH: usize = 8;

/// Longest text claim accepted.
const MAX_TEXT: usize = 1024;

/// The digest named by its text form `sha-256:<base64url>` (L0-ENC-20).
#[must_use]
pub fn digest_of_text(text: &str) -> Option<Digest> {
    let b64 = text.strip_prefix("sha-256:")?;
    let raw = b64url_decode(b64).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok().map(Digest)
}

fn text<'a>(v: &'a Json, name: &'static str) -> Result<&'a str, Denied> {
    v.get(name)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_TEXT)
        .ok_or(Denied::Claim(name))
}

fn uint(v: &Json, name: &'static str) -> Result<u64, Denied> {
    v.get(name)
        .and_then(Json::as_int)
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(Denied::Claim(name))
}

/// The action a RAR detail names: `type` `<namespace>:<name>:<major>` and its `schema`
/// digest (OP-150 m.9 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionType {
    /// Namespace.
    pub namespace: String,
    /// Name.
    pub name: String,
    /// Major version.
    pub major: u64,
    /// Schema digest.
    pub schema: Digest,
}

impl ActionType {
    /// Whether this is `action`, down to the pinned schema.
    #[must_use]
    pub fn is(&self, action: &ActionRef) -> bool {
        self.namespace == action.namespace
            && self.name == action.name
            && self.major == action.major
            && self.schema == action.schema
    }
}

fn action_type(detail: &Json) -> Result<ActionType, Denied> {
    let mut parts = text(detail, "type")?.split(':');
    let (Some(namespace), Some(name), Some(major), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Denied::Claim("type"));
    };
    if namespace.is_empty() || name.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Denied::Claim("type"));
    }
    let major: u64 = major.parse().map_err(|_| Denied::Claim("type"))?;
    let schema = digest_of_text(text(detail, "schema")?).ok_or(Denied::Claim("schema"))?;
    Ok(ActionType {
        namespace: String::from(namespace),
        name: String::from(name),
        major,
        schema,
    })
}

/// One RAR detail as the resource server reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detail {
    /// The action.
    pub action: ActionType,
    /// `intent` or `bounds`.
    pub kind: Kind,
    /// The intent digest of an exact-intent detail.
    pub intent: Option<Digest>,
    /// The `projection.issue` Exercise.
    pub exercise: Digest,
    /// The position of the `AuthorityStateBasis` the projection reflects (OP-150 m.3 (l), m.7 (d)).
    pub basis_position: u64,
    /// The detail's declared capacity: `own`, or the principal acted for.
    pub capacity: DetailCapacity,
}

/// The `capacity` member of a detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetailCapacity {
    /// `"own"`.
    Own,
    /// `{"for": <principal pseudonym>}`.
    For(String),
}

/// The plain position inside a `basis_ref`: dCBOR `[DomainID, pos]` (OP-150 m.7 (d)).
#[must_use]
pub fn basis_position(basis_ref: &[u8], domain: &Digest) -> Option<u64> {
    let v = dcbor::decode(basis_ref, Limits::CEILING).ok()?;
    let Value::Array(items) = v else {
        return None;
    };
    match items.as_slice() {
        [d, Value::Unsigned(pos)] if Digest::from_value(d).as_ref() == Some(domain) => Some(*pos),
        _ => None,
    }
}

fn detail(v: &Json, domain: &Digest) -> Result<Detail, Denied> {
    let action = action_type(v)?;
    let kind = match text(v, "kind")? {
        "intent" => Kind::Intent,
        "bounds" => Kind::Bounds,
        _ => return Err(Denied::Claim("kind")),
    };
    let intent = match kind {
        Kind::Intent => Some(digest_of_text(text(v, "intent")?).ok_or(Denied::Claim("intent"))?),
        Kind::Bounds => None,
    };
    let exercise = digest_of_text(text(v, "exercise")?).ok_or(Denied::Claim("exercise"))?;
    let basis_ref = b64url_decode(text(v, "basis_ref")?).map_err(|_| Denied::Claim("basis_ref"))?;
    let basis_position = basis_position(&basis_ref, domain).ok_or(Denied::Basis)?;
    let capacity = match v.get("capacity") {
        Some(Json::Str(s)) if s == "own" => DetailCapacity::Own,
        Some(c @ Json::Object(_)) => DetailCapacity::For(String::from(text(c, "for")?)),
        _ => return Err(Denied::Claim("capacity")),
    };
    Ok(Detail {
        action,
        kind,
        intent,
        exercise,
        basis_position,
        capacity,
    })
}

/// The details of a token, read after the Kernel's L2-JOS-4 checks.
///
/// # Errors
/// [`Denied`].
pub fn details(claims: &Json, domain: &Digest) -> Result<Vec<Detail>, Denied> {
    let Some(Json::Array(items)) = claims.get("authorization_details") else {
        return Err(Denied::Claim("authorization_details"));
    };
    let out: Vec<Detail> = items
        .iter()
        .map(|d| detail(d, domain))
        .collect::<Result<_, _>>()?;
    if out.is_empty() {
        return Err(Denied::Claim("authorization_details"));
    }
    let first = out.first().ok_or(Denied::Claim("authorization_details"))?;
    if out
        .iter()
        .any(|d| d.exercise != first.exercise || d.basis_position != first.basis_position)
    {
        return Err(Denied::Claim("authorization_details"));
    }
    Ok(out)
}

/// What the resource server reads of the token's `ValidityContract` (§9.12, OP-150 m.9 (f)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// `access_contract`: the `access/validity/v1` digest the token names its contract by.
    pub digest: Digest,
    /// Absolute expiry, Unix milliseconds.
    pub horizon: TrustedTime,
    /// Δ of `bounded-staleness`.
    pub max_staleness_ms: Option<u64>,
    /// The verifiers it is valid for.
    pub audience: Vec<String>,
    /// Profile class.
    pub class: ProfileClass,
    /// Profile variant.
    pub variant: ProfileVariant,
    /// The projection's status list entry, when the contract carries it.
    pub status: Option<StatusRef>,
}

fn status_ref(v: &Json) -> Result<StatusRef, Denied> {
    let list = v.get("status_list").ok_or(Denied::Claim("status"))?;
    let uri = text(list, "uri")?;
    if uri.len() > access_kernel::status::MAX_URI {
        return Err(Denied::Claim("status"));
    }
    Ok(StatusRef {
        idx: uint(list, "idx")?,
        uri: String::from(uri),
    })
}

/// The token's top-level `status` claim (L2-STL-1), when present.
///
/// # Errors
/// [`Denied::Claim`] for a present claim of another shape.
pub fn status_claim(claims: &Json) -> Result<Option<StatusRef>, Denied> {
    claims.get("status").map(status_ref).transpose()
}

/// Reads the contract from the detail's `validity` object and the token's `access_contract`.
///
/// # Errors
/// [`Denied`].
pub fn contract(claims: &Json, validity: &Json) -> Result<Contract, Denied> {
    let digest =
        digest_of_text(text(claims, "access_contract")?).ok_or(Denied::Claim("access_contract"))?;
    let horizon = uint(validity, "horizon")?;
    let max_staleness_ms = match validity.get("max_staleness_ms") {
        None => None,
        Some(_) => Some(uint(validity, "max_staleness_ms")?),
    };
    let Some(Json::Array(aud)) = validity.get("audience") else {
        return Err(Denied::Claim("validity"));
    };
    let audience = aud
        .iter()
        .map(|a| {
            a.as_str()
                .map(String::from)
                .ok_or(Denied::Claim("validity"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let profile = validity.get("profile").ok_or(Denied::Claim("validity"))?;
    let class = match text(profile, "class")? {
        "online" => ProfileClass::Online,
        "intermittent" => ProfileClass::Intermittent,
        "offline" => ProfileClass::Offline,
        "long-running" => ProfileClass::LongRunning,
        _ => return Err(Denied::Claim("profile")),
    };
    let variant = match text(profile, "variant")? {
        "online-strict" => ProfileVariant::OnlineStrict,
        "bounded-staleness" => ProfileVariant::BoundedStaleness,
        "revalidate-on-reconnect" => ProfileVariant::RevalidateOnReconnect,
        "checkpointed-offline" => ProfileVariant::CheckpointedOffline,
        "checkpoint-continuation" => ProfileVariant::CheckpointContinuation,
        _ => return Err(Denied::Claim("profile")),
    };
    if variant.class() != class {
        return Err(Denied::Claim("profile"));
    }
    let status = validity.get("status").map(status_ref).transpose()?;
    Ok(Contract {
        digest,
        horizon,
        max_staleness_ms,
        audience,
        class,
        variant,
        status,
    })
}

/// The `validity` object of the first detail.
///
/// # Errors
/// [`Denied::Claim`].
pub fn validity(claims: &Json) -> Result<&Json, Denied> {
    let Some(Json::Array(items)) = claims.get("authorization_details") else {
        return Err(Denied::Claim("authorization_details"));
    };
    items
        .first()
        .and_then(|d| d.get("validity"))
        .filter(|v| matches!(v, Json::Object(_)))
        .ok_or(Denied::Claim("validity"))
}

/// One actor of a `FOR(P)` chain (§9.9.4): the canonical identity is `(iss, sub)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorRef {
    /// `act.sub`, the actor's pairwise reference.
    pub sub: String,
    /// `act.iss`, the domain issuer.
    pub iss: Option<String>,
}

/// The capacity a token projects (§9.9.4, P53): a hint for audit, never the authority, which
/// is in the details (S-2, S-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenCapacity {
    /// `OWN`: `sub` is the basis holder, no `act`.
    Own {
        /// `sub`.
        subject: String,
    },
    /// `FOR(P)`: `sub` is P, `act` the actor, nested `act`s the earlier links, outermost first.
    For {
        /// `sub`.
        principal: String,
        /// The chain from the direct actor inwards.
        actors: Vec<ActorRef>,
    },
}

fn act_chain(act: &Json, depth: usize, out: &mut Vec<ActorRef>) -> Result<(), Denied> {
    if depth >= MAX_ACT_DEPTH {
        return Err(Denied::Claim("act"));
    }
    if !matches!(act, Json::Object(_)) {
        return Err(Denied::Claim("act"));
    }
    out.push(ActorRef {
        sub: String::from(text(act, "sub")?),
        iss: match act.get("iss") {
            None => None,
            Some(_) => Some(String::from(text(act, "iss")?)),
        },
    });
    match act.get("act") {
        None => Ok(()),
        Some(inner) => act_chain(inner, depth.saturating_add(1), out),
    }
}

/// The capacity of the claims, consistent with the details' declared capacity.
///
/// # Errors
/// [`Denied::Claim`].
pub fn capacity(claims: &Json, declared: &DetailCapacity) -> Result<TokenCapacity, Denied> {
    let sub = String::from(text(claims, "sub")?);
    let capacity = match claims.get("act") {
        None => TokenCapacity::Own { subject: sub },
        Some(act) => {
            let mut actors = Vec::new();
            act_chain(act, 0, &mut actors)?;
            TokenCapacity::For {
                principal: sub,
                actors,
            }
        }
    };
    let consistent = match (&capacity, declared) {
        (TokenCapacity::Own { .. }, DetailCapacity::Own) => true,
        (TokenCapacity::For { principal, .. }, DetailCapacity::For(p)) => principal == p,
        _ => false,
    };
    if !consistent {
        return Err(Denied::Claim("capacity"));
    }
    Ok(capacity)
}

/// The reserved claim names and the shape each must have when present (§9.9.4 k.1, §9.9.6,
/// P55): the tenant cannot write them, so a value of another shape is not a token of this
/// profile.
pub const RESERVED: [(&str, Shape); 12] = [
    ("iss", Shape::Text),
    ("sub", Shape::Text),
    ("aud", Shape::Text),
    ("exp", Shape::Int),
    ("iat", Shape::Int),
    ("jti", Shape::Text),
    ("nbf", Shape::Int),
    ("act", Shape::Object),
    ("may_act", Shape::Object),
    ("cnf", Shape::Object),
    ("scope", Shape::Text),
    ("client_id", Shape::Text),
];

/// The JSON shape of a reserved claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A string.
    Text,
    /// An integer.
    Int,
    /// An object.
    Object,
}

/// Checks the shape of every reserved claim present.
///
/// # Errors
/// [`Denied::Claim`] naming the first claim of another shape.
pub fn reserved_shapes(claims: &Json) -> Result<(), Denied> {
    for (name, shape) in RESERVED {
        let ok = match (claims.get(name), shape) {
            (None, _) | (Some(Json::Object(_)), Shape::Object) => true,
            (Some(Json::Str(s)), Shape::Text) => !s.is_empty() && s.len() <= MAX_TEXT,
            (Some(Json::Int(i)), Shape::Int) => *i >= 0,
            _ => false,
        };
        if !ok {
            return Err(Denied::Claim(name));
        }
    }
    Ok(())
}

/// The token's refresh family (OP-150 m.9 (d)): base64url of 16 bytes.
///
/// # Errors
/// [`Denied::Claim`].
pub fn family(claims: &Json) -> Result<[u8; 16], Denied> {
    let raw = b64url_decode(text(claims, "family")?).map_err(|_| Denied::Claim("family"))?;
    <[u8; 16]>::try_from(raw.as_slice()).map_err(|_| Denied::Claim("family"))
}

/// `rev`, when present (OP-150 m.9 (h)).
///
/// # Errors
/// [`Denied::Claim`].
pub fn rev(claims: &Json) -> Result<Option<u64>, Denied> {
    match claims.get("rev") {
        None => Ok(None),
        Some(_) => uint(claims, "rev").map(Some),
    }
}

/// `jti` as the `projection.issue` `ExerciseID` (L2-JOS-1), or the `exercise` member of an
/// introspection answer that carries no `jti` (OP-150 m.9 (i)).
///
/// # Errors
/// [`Denied::Claim`].
pub fn exercise(claims: &Json) -> Result<Digest, Denied> {
    if claims.get("jti").is_some() {
        return digest_of_text(text(claims, "jti")?).ok_or(Denied::Claim("jti"));
    }
    let raw = b64url_decode(text(claims, "exercise")?).map_err(|_| Denied::Claim("exercise"))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map(Digest)
        .map_err(|_| Denied::Claim("exercise"))
}

/// `client_id`.
///
/// # Errors
/// [`Denied::Claim`].
pub fn client_id(claims: &Json) -> Result<String, Denied> {
    text(claims, "client_id").map(String::from)
}

/// A time claim in seconds, as milliseconds.
///
/// # Errors
/// [`Denied::Claim`].
pub fn time_ms(claims: &Json, name: &'static str) -> Result<TrustedTime, Denied> {
    uint(claims, name)?
        .checked_mul(1000)
        .ok_or(Denied::Claim(name))
}

/// `cnf.jkt` or `cnf.x5t#S256` of a claims object.
///
/// # Errors
/// [`Denied::Claim`].
pub fn confirmation_thumbprint(claims: &Json) -> Result<(&'static str, [u8; 32]), Denied> {
    let Some(Json::Object(members)) = claims.get("cnf") else {
        return Err(Denied::Claim("cnf"));
    };
    let [(name, Json::Str(value))] = members.as_slice() else {
        return Err(Denied::Claim("cnf"));
    };
    let member = match name.as_str() {
        "jkt" => "jkt",
        "x5t#S256" => "x5t#S256",
        _ => return Err(Denied::Claim("cnf")),
    };
    let raw = b64url_decode(value).map_err(|_| Denied::Claim("cnf"))?;
    let thumbprint = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| Denied::Claim("cnf"))?;
    Ok((member, thumbprint))
}
