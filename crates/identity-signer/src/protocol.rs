//! The identity signer's wire protocol over a Unix domain socket, framed as the authority
//! signer's is: one request, one response, each a big-endian `u32` length and a deterministic
//! CBOR body (CMP-22b, OP-143 m.4, m.9 (e)). Sans-I/O.

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::rotation::Policy;

/// Largest frame body.
pub const MAX_FRAME: usize = 1 << 20;

/// A realm, by its identifier's 16 bytes; the signer's key sets are keyed by it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Realm(pub [u8; 16]);

impl core::fmt::Debug for Realm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Realm(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A request to the identity signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Whether the signer answers.
    Ping,
    /// Opens the key set of a realm whose new keys use `alg`; repeating it changes nothing,
    /// and on an open set another `alg` applies to its next keys (OP-146 m.8 (e)).
    Open {
        /// Realm.
        realm: Realm,
        /// ES256 by default, Ed25519 when the realm selects it (CR-2, MD-3).
        alg: JwsAlg,
    },
    /// The realm's JWKS.
    Jwks(Realm),
    /// Signs a JSON object as a compact JWS of type `typ` at `at`.
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
    /// Signs deterministic CBOR as a tagged `COSE_Sign1` of `content_type` at `at` with the key
    /// that signs the realm's tokens (OP-149 m.8).
    SignCose {
        /// Realm.
        realm: Realm,
        /// The protected header's content type.
        content_type: String,
        /// CBOR payload.
        payload: Vec<u8>,
        /// Signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// The cell's audit log origin and the verifier key of its `audit-checkpoint` key
    /// (OP-150 m.3 (h)).
    CellKey,
    /// Signs a checkpoint body of the cell's identity audit log as a C2SP note (OP-143 m.10).
    SignCheckpoint {
        /// The `tlog-checkpoint` body.
        body: String,
    },
    /// Rotates the realm's active key `retire` out now (TN-118, `idp.realm.key_rotate`).
    Rotate {
        /// Realm.
        realm: Realm,
        /// The active key's `kid`.
        retire: [u8; 32],
    },
    /// Drops one key of the realm at once (§13.2, `idp.realm.key_drop`).
    DropKey {
        /// Realm.
        realm: Realm,
        /// The key's `kid`.
        kid: [u8; 32],
    },
    /// Replaces the realm's rotation policy (TN-118, `idp.realm.key_policy`).
    SetPolicy {
        /// Realm.
        realm: Realm,
        /// The policy.
        policy: Policy,
    },
    /// Opens the realm's Claim issuer key, bound to its issuer Party `party` when it is made
    /// (§10.1.7); repeating it changes nothing, another Party is refused.
    OpenIssuer {
        /// Realm.
        realm: Realm,
        /// The realm's issuer Party.
        party: [u8; 16],
    },
    /// Signs a JSON object as an RS256 compact JWS of type `typ` at `at` with the realm's
    /// `rsa-id` key, made on first use (MD-6, OP-155 m.3 (k)): identity assertions of clients
    /// that opted in, never an authority artefact.
    SignRs256 {
        /// Realm.
        realm: Realm,
        /// JWS `typ`.
        typ: String,
        /// JSON payload.
        payload: Vec<u8>,
        /// Signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// Signs a canonical `claim-statement` of the realm's issuer as a `COSE_Sign1` Claim at `at`
    /// with the realm's Claim issuer key (L2-CLM-1).
    SignClaim {
        /// Realm.
        realm: Realm,
        /// The statement.
        payload: Vec<u8>,
        /// Signing time; the statement's `issued_at`, within the signer's clock skew.
        at: u64,
    },
    /// Signs the AIS of one self-signed registration Exercise of the issuer Party with the
    /// realm's Claim issuer key (OP-149 m.16 (a)).
    SignIssuerRegistration {
        /// Realm.
        realm: Realm,
        /// What to sign.
        registration: crate::issuer::Registration,
    },
    /// The realm's OpenID Federation JWKS; the `federation` key set is made on this first
    /// request (OP-155 m.3 (j), MD-6).
    FederationJwks(Realm),
    /// Signs a JSON object as a compact JWS of a federation `typ` at `at` with the realm's
    /// `federation` key: an entity statement, a trust mark, a resolve or trust mark status answer.
    SignFederation {
        /// Realm.
        realm: Realm,
        /// JWS `typ`, one of [`crate::service::FEDERATION_TYPES`].
        typ: String,
        /// JSON payload.
        payload: Vec<u8>,
        /// Signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// A request about the realm's SAML keys (OP-155 m.3 (d)).
    Saml(crate::saml::SamlRequest),
    /// A request about the cell's ACME account key (OP-156 m.3 (i)).
    Acme(crate::acme::AcmeRequest),
    /// A request about the realm's SSH CA keys (OP-156 m.3 (o)).
    Ssh(crate::ssh::SshRequest),
}

/// The identity signer's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The signer answers.
    Pong,
    /// The key set is open.
    Opened,
    /// The realm's JWKS document.
    Jwks(String),
    /// A compact JWS.
    Signed {
        /// The token.
        token: String,
        /// Its key's `kid`.
        kid: [u8; 32],
    },
    /// A tagged `COSE_Sign1`.
    SignedCose {
        /// The message.
        sign1: Vec<u8>,
        /// Its key's `kid`.
        kid: [u8; 32],
    },
    /// The cell's audit log origin and its C2SP verifier key.
    CellKey {
        /// Log origin and note key name.
        origin: String,
        /// Verifier key.
        vkey: String,
    },
    /// A note signature line over a checkpoint body.
    Noted {
        /// The signature line, newline-terminated.
        line: String,
    },
    /// The key set changed outside the schedule; its JWKS document now.
    Rekeyed(String),
    /// The realm's Claim issuer key.
    Issuer {
        /// Its Party.
        party: [u8; 16],
        /// Ed25519 public key.
        key: [u8; 32],
        /// Its RFC 7638 `kid`.
        kid: [u8; 32],
    },
    /// An answer about the realm's SAML keys.
    Saml(crate::saml::SamlResponse),
    /// An answer about the cell's ACME account key.
    Acme(crate::acme::AcmeResponse),
    /// An answer about the realm's SSH CA keys.
    Ssh(crate::ssh::SshResponse),
    /// A refusal, by stable code.
    Error(String),
}

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Larger than [`MAX_FRAME`].
    #[error("frame too large")]
    TooLarge,
    /// Not a message of this protocol.
    #[error("malformed frame")]
    Malformed,
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn text(v: Option<&Value>) -> Result<String, FrameError> {
    match v {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, FrameError> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn uint(v: Option<&Value>) -> Result<u64, FrameError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

fn fixed<const N: usize>(v: Option<&Value>) -> Result<[u8; N], FrameError> {
    bytes(v)?.try_into().map_err(|_| FrameError::Malformed)
}

fn realm(v: Option<&Value>) -> Result<Realm, FrameError> {
    bytes(v)?
        .try_into()
        .map(Realm)
        .map_err(|_| FrameError::Malformed)
}

fn kid(v: Option<&Value>) -> Result<[u8; 32], FrameError> {
    bytes(v)?.try_into().map_err(|_| FrameError::Malformed)
}

/// A rotation policy as the protocol and the vault carry it.
#[must_use]
pub fn policy_value(p: &Policy) -> Value {
    map(vec![
        ("lifetime_ms", Value::Unsigned(p.lifetime_ms)),
        ("window_ms", Value::Unsigned(p.window_ms)),
        ("publish_lead_ms", Value::Unsigned(p.publish_lead_ms)),
        ("retain_ms", Value::Unsigned(p.retain_ms)),
        ("max_signatures", Value::Unsigned(p.max_signatures)),
        (
            "jitter_permille",
            Value::Unsigned(u64::from(p.jitter_permille)),
        ),
    ])
}

/// The policy of a [`policy_value`].
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn policy_of(v: &Value) -> Result<Policy, FrameError> {
    Ok(Policy {
        lifetime_ms: uint(v.get("lifetime_ms"))?,
        window_ms: uint(v.get("window_ms"))?,
        publish_lead_ms: uint(v.get("publish_lead_ms"))?,
        retain_ms: uint(v.get("retain_ms"))?,
        max_signatures: uint(v.get("max_signatures"))?,
        jitter_permille: u16::try_from(uint(v.get("jitter_permille"))?)
            .map_err(|_| FrameError::Malformed)?,
    })
}

/// The algorithm by its JOSE name.
#[must_use]
pub fn alg_of(name: &str) -> Option<JwsAlg> {
    [JwsAlg::Es256, JwsAlg::Ed25519]
        .into_iter()
        .find(|a| a.name() == name)
}

impl Request {
    #[expect(clippy::too_many_lines, reason = "one arm per request of the protocol")]
    fn to_value(&self) -> Value {
        match self {
            Self::Ping => map(vec![("ping", Value::Bool(true))]),
            Self::Open { realm, alg } => map(vec![(
                "open",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("alg", Value::text(alg.name())),
                ]),
            )]),
            Self::Jwks(r) => map(vec![("jwks", Value::Bytes(r.0.to_vec()))]),
            Self::Sign {
                realm,
                typ,
                payload,
                at,
            } => map(vec![(
                "sign",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("typ", Value::text(typ)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::SignCose {
                realm,
                content_type,
                payload,
                at,
            } => map(vec![(
                "sign_cose",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("content_type", Value::text(content_type)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::CellKey => map(vec![("cell_key", Value::Bool(true))]),
            Self::SignCheckpoint { body } => map(vec![(
                "sign_checkpoint",
                map(vec![("body", Value::text(body))]),
            )]),
            Self::Rotate { realm, retire } => map(vec![(
                "rotate",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("retire", Value::Bytes(retire.to_vec())),
                ]),
            )]),
            Self::DropKey { realm, kid } => map(vec![(
                "drop_key",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
            Self::SetPolicy { realm, policy } => map(vec![(
                "set_policy",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("policy", policy_value(policy)),
                ]),
            )]),
            Self::FederationJwks(r) => map(vec![("federation_jwks", Value::Bytes(r.0.to_vec()))]),
            Self::SignFederation {
                realm,
                typ,
                payload,
                at,
            } => map(vec![(
                "sign_federation",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("typ", Value::text(typ)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::OpenIssuer { realm, party } => map(vec![(
                "open_issuer",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("party", Value::Bytes(party.to_vec())),
                ]),
            )]),
            Self::SignClaim { realm, payload, at } => map(vec![(
                "sign_claim",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::SignRs256 {
                realm,
                typ,
                payload,
                at,
            } => map(vec![(
                "sign_rs256",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("typ", Value::text(typ)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::SignIssuerRegistration {
                realm,
                registration: r,
            } => map(vec![(
                "sign_issuer_registration",
                map(vec![
                    ("realm", Value::Bytes(realm.0.to_vec())),
                    ("domain", Value::Bytes(r.domain.to_vec())),
                    ("nonce", Value::Bytes(r.nonce.clone())),
                    ("from", Value::Unsigned(r.validity.0)),
                    ("until", Value::Unsigned(r.validity.1)),
                    ("iat", Value::Unsigned(r.iat)),
                    ("pep", Value::text(&r.pep)),
                    ("step", Value::text(r.step.name())),
                ]),
            )]),
            Self::Saml(s) => map(vec![("saml", s.to_value())]),
            Self::Acme(a) => map(vec![("acme", a.to_value())]),
            Self::Ssh(s) => map(vec![("ssh", s.to_value())]),
        }
    }

    #[expect(clippy::too_many_lines, reason = "one branch per request kind")]
    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("ping").is_some() {
            return Ok(Self::Ping);
        }
        if v.get("cell_key").is_some() {
            return Ok(Self::CellKey);
        }
        if let Some(c) = v.get("sign_checkpoint") {
            return Ok(Self::SignCheckpoint {
                body: text(c.get("body"))?,
            });
        }
        if let Some(r) = v.get("federation_jwks") {
            return Ok(Self::FederationJwks(realm(Some(r))?));
        }
        if let Some(s) = v.get("sign_federation") {
            return Ok(Self::SignFederation {
                realm: realm(s.get("realm"))?,
                typ: text(s.get("typ"))?,
                payload: bytes(s.get("payload"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(o) = v.get("open_issuer") {
            return Ok(Self::OpenIssuer {
                realm: realm(o.get("realm"))?,
                party: fixed(o.get("party"))?,
            });
        }
        if let Some(s) = v.get("sign_claim") {
            return Ok(Self::SignClaim {
                realm: realm(s.get("realm"))?,
                payload: bytes(s.get("payload"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(s) = v.get("sign_issuer_registration") {
            return Ok(Self::SignIssuerRegistration {
                realm: realm(s.get("realm"))?,
                registration: crate::issuer::Registration {
                    domain: fixed(s.get("domain"))?,
                    nonce: bytes(s.get("nonce"))?,
                    validity: (uint(s.get("from"))?, uint(s.get("until"))?),
                    iat: uint(s.get("iat"))?,
                    pep: text(s.get("pep"))?,
                    step: crate::issuer::Step::parse(&text(s.get("step"))?)
                        .ok_or(FrameError::Malformed)?,
                },
            });
        }
        if let Some(s) = v.get("sign_rs256") {
            return Ok(Self::SignRs256 {
                realm: realm(s.get("realm"))?,
                typ: text(s.get("typ"))?,
                payload: bytes(s.get("payload"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(o) = v.get("open") {
            return Ok(Self::Open {
                realm: realm(o.get("realm"))?,
                alg: alg_of(&text(o.get("alg"))?).ok_or(FrameError::Malformed)?,
            });
        }
        if let Some(r) = v.get("jwks") {
            return Ok(Self::Jwks(realm(Some(r))?));
        }
        if let Some(r) = v.get("rotate") {
            return Ok(Self::Rotate {
                realm: realm(r.get("realm"))?,
                retire: kid(r.get("retire"))?,
            });
        }
        if let Some(d) = v.get("drop_key") {
            return Ok(Self::DropKey {
                realm: realm(d.get("realm"))?,
                kid: kid(d.get("kid"))?,
            });
        }
        if let Some(p) = v.get("set_policy") {
            return Ok(Self::SetPolicy {
                realm: realm(p.get("realm"))?,
                policy: policy_of(p.get("policy").ok_or(FrameError::Malformed)?)?,
            });
        }
        if let Some(s) = v.get("sign_cose") {
            return Ok(Self::SignCose {
                realm: realm(s.get("realm"))?,
                content_type: text(s.get("content_type"))?,
                payload: bytes(s.get("payload"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(s) = v.get("saml") {
            return Ok(Self::Saml(crate::saml::SamlRequest::from_value(s)?));
        }
        if let Some(a) = v.get("acme") {
            return Ok(Self::Acme(crate::acme::AcmeRequest::from_value(a)?));
        }
        if let Some(s) = v.get("ssh") {
            return Ok(Self::Ssh(crate::ssh::SshRequest::from_value(s)?));
        }
        let s = v.get("sign").ok_or(FrameError::Malformed)?;
        Ok(Self::Sign {
            realm: realm(s.get("realm"))?,
            typ: text(s.get("typ"))?,
            payload: bytes(s.get("payload"))?,
            at: uint(s.get("at"))?,
        })
    }
}

impl Response {
    fn to_value(&self) -> Value {
        match self {
            Self::Pong => map(vec![("pong", Value::Bool(true))]),
            Self::Opened => map(vec![("opened", Value::Bool(true))]),
            Self::Jwks(doc) => map(vec![("jwks", Value::text(doc))]),
            Self::Signed { token, kid } => map(vec![(
                "signed",
                map(vec![
                    ("token", Value::text(token)),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
            Self::SignedCose { sign1, kid } => map(vec![(
                "signed_cose",
                map(vec![
                    ("sign1", Value::Bytes(sign1.clone())),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
            Self::CellKey { origin, vkey } => map(vec![(
                "cell_key",
                map(vec![
                    ("origin", Value::text(origin)),
                    ("vkey", Value::text(vkey)),
                ]),
            )]),
            Self::Noted { line } => map(vec![("noted", map(vec![("line", Value::text(line))]))]),
            Self::Rekeyed(doc) => map(vec![("rekeyed", Value::text(doc))]),
            Self::Issuer { party, key, kid } => map(vec![(
                "issuer",
                map(vec![
                    ("party", Value::Bytes(party.to_vec())),
                    ("key", Value::Bytes(key.to_vec())),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
            Self::Saml(s) => map(vec![("saml", s.to_value())]),
            Self::Acme(a) => map(vec![("acme", a.to_value())]),
            Self::Ssh(s) => map(vec![("ssh", s.to_value())]),
            Self::Error(code) => map(vec![("error", Value::text(code))]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("pong").is_some() {
            return Ok(Self::Pong);
        }
        if v.get("opened").is_some() {
            return Ok(Self::Opened);
        }
        if let Some(d) = v.get("jwks") {
            return Ok(Self::Jwks(text(Some(d))?));
        }
        if let Some(s) = v.get("signed") {
            return Ok(Self::Signed {
                token: text(s.get("token"))?,
                kid: bytes(s.get("kid"))?
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            });
        }
        if let Some(s) = v.get("signed_cose") {
            return Ok(Self::SignedCose {
                sign1: bytes(s.get("sign1"))?,
                kid: bytes(s.get("kid"))?
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            });
        }
        if let Some(c) = v.get("cell_key") {
            return Ok(Self::CellKey {
                origin: text(c.get("origin"))?,
                vkey: text(c.get("vkey"))?,
            });
        }
        if let Some(i) = v.get("issuer") {
            return Ok(Self::Issuer {
                party: fixed(i.get("party"))?,
                key: fixed(i.get("key"))?,
                kid: fixed(i.get("kid"))?,
            });
        }
        if let Some(n) = v.get("noted") {
            return Ok(Self::Noted {
                line: text(n.get("line"))?,
            });
        }
        if let Some(d) = v.get("rekeyed") {
            return Ok(Self::Rekeyed(text(Some(d))?));
        }
        if let Some(s) = v.get("saml") {
            return Ok(Self::Saml(crate::saml::SamlResponse::from_value(s)?));
        }
        if let Some(a) = v.get("acme") {
            return Ok(Self::Acme(crate::acme::AcmeResponse::from_value(a)?));
        }
        if let Some(s) = v.get("ssh") {
            return Ok(Self::Ssh(crate::ssh::SshResponse::from_value(s)?));
        }
        Ok(Self::Error(text(v.get("error"))?))
    }
}

fn frame(v: &Value) -> Result<Vec<u8>, FrameError> {
    let body = dcbor::encode(v, Limits::CEILING).map_err(|_| FrameError::Malformed)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut out = len.to_be_bytes().to_vec();
    out.extend(body);
    Ok(out)
}

/// The length a frame header announces.
///
/// # Errors
/// [`FrameError::TooLarge`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| FrameError::TooLarge)?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    Ok(len)
}

fn body(bytes: &[u8]) -> Result<Value, FrameError> {
    dcbor::decode(bytes, Limits::CEILING).map_err(|_| FrameError::Malformed)
}

/// A request as a frame.
///
/// # Errors
/// [`FrameError`].
pub fn encode_request(r: &Request) -> Result<Vec<u8>, FrameError> {
    encode_request_traced(r, None)
}

/// The request key of the caller's W3C trace context (OP-67 m.1): carried for correlation,
/// never read by the signing logic.
const TRACEPARENT: &str = "traceparent";

/// Longest `traceparent` carried (version 00 is 55 bytes).
const TRACEPARENT_MAX: usize = 55;

/// A request as a frame, with the caller's `traceparent` when it has one (OP-67 m.1).
///
/// # Errors
/// [`FrameError`].
pub fn encode_request_traced(
    r: &Request,
    traceparent: Option<&str>,
) -> Result<Vec<u8>, FrameError> {
    let mut v = r.to_value();
    if let (Some(t), Value::Map(entries)) = (traceparent, &mut v)
        && t.len() <= TRACEPARENT_MAX
    {
        entries.push((Value::text(TRACEPARENT), Value::text(t)));
    }
    frame(&v)
}

/// A request from a frame body (after its header).
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_request(b: &[u8]) -> Result<Request, FrameError> {
    decode_request_traced(b).map(|(r, _)| r)
}

/// A request from a frame body with the caller's `traceparent`, if it sent one; the caller
/// checks its form before using it.
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_request_traced(b: &[u8]) -> Result<(Request, Option<String>), FrameError> {
    let v = body(b)?;
    let traceparent = match v.get(TRACEPARENT) {
        Some(Value::Text(t)) if t.len() <= TRACEPARENT_MAX => Some(t.clone()),
        _ => None,
    };
    Ok((Request::from_value(&v)?, traceparent))
}

/// A response as a frame.
///
/// # Errors
/// [`FrameError`].
pub fn encode_response(r: &Response) -> Result<Vec<u8>, FrameError> {
    frame(&r.to_value())
}

/// A response from a frame body (after its header).
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_response(b: &[u8]) -> Result<Response, FrameError> {
    Response::from_value(&body(b)?)
}

#[cfg(test)]
mod tests;
