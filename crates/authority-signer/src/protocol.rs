//! The signer's wire protocol over a Unix domain socket: one request, one response, each a
//! big-endian `u32` length and a deterministic CBOR body (OP-143 m.4). Sans-I/O.

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{
    Declarations, DrClass, Durability, Hybrid, KeyUsage, Mmd, Replica, Residency, SpecVersions,
    VerifierCaps, Witness,
};
use suiss_crypto::cose::Algorithm;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::domain::Template;

/// Largest frame body.
pub const MAX_FRAME: usize = 1 << 20;

/// A request to the signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Opens the keyring of a domain; repeating it changes nothing.
    Open(Box<Template>),
    /// Signs an artefact of a domain whose signing time is `at`.
    Sign {
        /// Domain.
        domain: Digest,
        /// What the artefact is.
        usage: KeyUsage,
        /// `COSE_Sign1` content type.
        content_type: String,
        /// Payload.
        payload: Vec<u8>,
        /// The artefact's signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// The current Domain Metadata of a domain.
    Metadata(Digest),
    /// Signs a checkpoint body of a domain's log as a C2SP note at `at` (usage `checkpoint`).
    SignNote {
        /// Domain.
        domain: Digest,
        /// Checkpoint body whose origin is the domain's.
        body: String,
        /// The signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// The binding-signed Genesis statement of a domain.
    Genesis(Digest),
    /// Signs an authority-carrying access token of a domain (usage `token`, `typ` `at+jwt`,
    /// §9.9.3 rule 7): `claims` is its JSON claims set, holder-bound by `cnf` (PI-11), with an
    /// `exp` no later than the time the signing key stays published (CR-19).
    SignToken {
        /// Domain.
        domain: Digest,
        /// The JSON claims set.
        claims: Vec<u8>,
        /// The signing time; within the signer's clock skew of its own clock.
        at: u64,
    },
    /// Replaces what an open domain's metadata declares and signs it again (OP-158 m.3 (b),
    /// (f)).
    Declare {
        /// Domain.
        domain: Digest,
        /// The declarations.
        declared: Box<Declarations>,
    },
    /// The binding key of an open domain, or with `next` the key of its next binding
    /// generation, created in the HSM when missing (OP-60, RB-2, OP-158 m.3 (l)).
    Binding {
        /// Domain.
        domain: Digest,
        /// The next generation rather than the current one.
        next: bool,
    },
    /// Signs a handover statement with the current binding, or with `next` the next
    /// generation's (HO-6, RB-4).
    Statement {
        /// Domain.
        domain: Digest,
        /// The next generation rather than the current one.
        next: bool,
        /// One of the handover statement content types.
        content_type: String,
        /// The statement.
        payload: Vec<u8>,
    },
    /// RB-5, RB-6: the domain moves to its next binding generation; the current binding is
    /// superseded at `at` (`C_{h+1}`) citing `cited` (`C_k`), and `transcript` is the
    /// re-anchor's ceremony transcript digest.
    Rebind {
        /// Domain.
        domain: Digest,
        /// `C_{h+1}`'s root.
        at: Digest,
        /// `C_k`'s root.
        cited: Digest,
        /// The transcript digest.
        transcript: Digest,
    },
    /// HO-8: the outgoing provider's binding keys, each superseded, are published beside this
    /// install's binding.
    Supersede {
        /// Domain.
        domain: Digest,
        /// The superseded binding keys.
        keys: Vec<access_kernel::verify::key_scope::BindingKey>,
    },
}

/// The signer's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The keyring is open.
    Opened,
    /// An artefact signature.
    Signed {
        /// `COSE_Sign1`.
        sign1: Vec<u8>,
        /// Binding-signed excerpt.
        excerpt: Vec<u8>,
    },
    /// Binding-signed Domain Metadata.
    Metadata(Vec<u8>),
    /// A note signature.
    Noted {
        /// The signature line, newline included.
        line: String,
        /// Binding-signed excerpt.
        excerpt: Vec<u8>,
    },
    /// Binding-signed Genesis statement.
    Genesis(Vec<u8>),
    /// A signed access token.
    Token {
        /// The compact JWS.
        jws: String,
        /// Binding-signed excerpt of the key that signed it.
        excerpt: Vec<u8>,
    },
    /// A binding key.
    Binding(access_kernel::verify::key_scope::BindingKey),
    /// A binding-signed handover statement.
    Statement(Vec<u8>),
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

const USAGES: [(&str, KeyUsage); 8] = [
    ("receipt", KeyUsage::Receipt),
    ("pap", KeyUsage::Pap),
    ("token", KeyUsage::Token),
    ("checkpoint", KeyUsage::Checkpoint),
    ("set", KeyUsage::Set),
    ("status-list", KeyUsage::StatusList),
    ("key-lookup", KeyUsage::KeyLookup),
    ("party-lookup", KeyUsage::PartyLookup),
];

fn usage_name(u: KeyUsage) -> &'static str {
    USAGES
        .iter()
        .find(|(_, x)| *x == u)
        .map_or("receipt", |(n, _)| n)
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

fn flag(v: Option<&Value>) -> Result<bool, FrameError> {
    match v {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(FrameError::Malformed),
    }
}

fn digest(v: Option<&Value>) -> Result<Digest, FrameError> {
    v.and_then(Digest::from_value).ok_or(FrameError::Malformed)
}

const HYBRIDS: [(&str, Hybrid); 3] = [
    ("classic", Hybrid::Classic),
    ("both", Hybrid::Both),
    ("pq", Hybrid::Pq),
];

/// The template as a request carries it.
fn template_value(t: &Template) -> Value {
    let mut entries = vec![
        ("domain", t.domain.to_value()),
        ("genesis", t.genesis.to_value()),
        (
            "algorithms",
            Value::Array(t.algorithms.iter().map(|a| Value::int(a.cose())).collect()),
        ),
        ("alg", Value::int(t.operational_alg.cose())),
        (
            "operational_window_max_ms",
            Value::Unsigned(t.operational_window_max_ms),
        ),
        ("min_versions", t.min_versions.to_value()),
        ("adopted", t.adopted.to_value()),
    ];
    if let Some(c) = &t.caps {
        entries.push(("caps", c.to_value()));
    }
    if let Some(h) = t.hybrid
        && let Some((n, _)) = HYBRIDS.iter().find(|(_, x)| *x == h)
    {
        entries.push(("hybrid", Value::text(n)));
    }
    if let Some(d) = &t.discovery {
        entries.push(("discovery", Value::Bytes(d.clone())));
    }
    entries.push(("declared", declared_value(&t.declared)));
    map(entries)
}

// OP-158 m.3 (b), (d), m.6 (e)
fn declared_value(d: &Declarations) -> Value {
    let mut entries = vec![(
        "witnesses",
        Value::Array(
            d.witnesses
                .iter()
                .map(|w| {
                    map(vec![
                        ("name", Value::text(&w.name)),
                        ("key", w.key.to_value()),
                        ("alg", Value::int(w.algorithm.cose())),
                        ("operator", Value::text(&w.operator)),
                        ("independent", Value::Bool(w.independent)),
                    ])
                })
                .collect(),
        ),
    )];
    // OP-158 m.3 (f)
    if !d.replicas.is_empty() {
        entries.push((
            "replicas",
            Value::Array(
                d.replicas
                    .iter()
                    .map(|r| {
                        map(vec![
                            ("name", Value::text(&r.name)),
                            ("key", r.key.to_value()),
                            ("operator", Value::text(&r.operator)),
                            ("independent", Value::Bool(r.independent)),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    // OP-157 m.7 (i), OP-158 m.3 (l)
    if let Some(t) = &d.ceremony_transcript {
        entries.push(("ceremony_transcript", t.to_value()));
    }
    // HL-40, OP-158 m.3 (o), (p), m.4 (b) (W9)
    if let Some(durability) = d.durability {
        entries.push((
            "durability",
            Value::text(match durability {
                Durability::SingleNode => "single-node",
                Durability::Replicated => "replicated",
            }),
        ));
    }
    if let Some(r) = &d.residency {
        entries.push((
            "residency",
            map(vec![
                ("region", Value::text(&r.region)),
                (
                    "class",
                    Value::text(match r.class {
                        DrClass::MultiRegionSync => "multi-region-sync",
                        DrClass::Regional => "regional",
                    }),
                ),
            ]),
        ));
    }
    if let Some(m) = d.mmd {
        entries.push((
            "mmd",
            map(vec![
                ("authority_ms", Value::Unsigned(m.authority_ms)),
                ("identity_ms", Value::Unsigned(m.identity_ms)),
            ]),
        ));
    }
    map(entries)
}

fn text_of(v: Option<&Value>) -> Result<String, FrameError> {
    match v {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= 255 => Ok(t.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn uint_of(v: Option<&Value>) -> Result<u64, FrameError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

fn declared_of(v: Option<&Value>) -> Result<Declarations, FrameError> {
    let Some(v) = v else {
        return Ok(Declarations::default());
    };
    let mut d = Declarations::default();
    if let Some(Value::Array(ws)) = v.get("witnesses") {
        for w in ws {
            let key = w
                .get("key")
                .and_then(|k| <suiss_crypto::cose::PublicKey as Canonical>::from_value(k).ok())
                .ok_or(FrameError::Malformed)?;
            d.witnesses.push(Witness::new(
                text_of(w.get("name"))?,
                key,
                alg(w.get("alg").ok_or(FrameError::Malformed)?)?,
                text_of(w.get("operator"))?,
                matches!(w.get("independent"), Some(Value::Bool(true))),
            ));
        }
    }
    if let Some(Value::Array(rs)) = v.get("replicas") {
        for r in rs {
            let key = r
                .get("key")
                .and_then(|k| <suiss_crypto::cose::PublicKey as Canonical>::from_value(k).ok())
                .ok_or(FrameError::Malformed)?;
            d.replicas.push(Replica::new(
                text_of(r.get("name"))?,
                key,
                text_of(r.get("operator"))?,
                matches!(r.get("independent"), Some(Value::Bool(true))),
            ));
        }
    }
    if let Some(t) = v.get("ceremony_transcript") {
        d.ceremony_transcript = Some(digest(Some(t))?);
    }
    // HL-40, OP-158 m.3 (o), (p), m.4 (b) (W9)
    d.durability = match v.get("durability") {
        None => None,
        Some(Value::Text(t)) if t == "single-node" => Some(Durability::SingleNode),
        Some(Value::Text(t)) if t == "replicated" => Some(Durability::Replicated),
        Some(_) => return Err(FrameError::Malformed),
    };
    if let Some(r) = v.get("residency") {
        let class = match r.get("class") {
            Some(Value::Text(t)) if t == "regional" => DrClass::Regional,
            Some(Value::Text(t)) if t == "multi-region-sync" => DrClass::MultiRegionSync,
            _ => return Err(FrameError::Malformed),
        };
        d.residency = Some(Residency::new(text_of(r.get("region"))?, class));
    }
    if let Some(m) = v.get("mmd") {
        d.mmd = Some(Mmd::new(
            uint_of(m.get("authority_ms"))?,
            uint_of(m.get("identity_ms"))?,
        ));
    }
    Ok(d)
}

fn alg(v: &Value) -> Result<Algorithm, FrameError> {
    v.as_i64()
        .and_then(Algorithm::from_cose)
        .ok_or(FrameError::Malformed)
}

fn template_of(v: &Value) -> Result<Template, FrameError> {
    let field = |k: &str| v.get(k).ok_or(FrameError::Malformed);
    let Value::Array(algs) = field("algorithms")? else {
        return Err(FrameError::Malformed);
    };
    let versions = |k: &str| SpecVersions::from_value(field(k)?).map_err(|_| FrameError::Malformed);
    Ok(Template {
        domain: digest(v.get("domain"))?,
        genesis: digest(v.get("genesis"))?,
        algorithms: algs.iter().map(alg).collect::<Result<_, _>>()?,
        operational_alg: alg(field("alg")?)?,
        operational_window_max_ms: match field("operational_window_max_ms")? {
            Value::Unsigned(n) => *n,
            _ => return Err(FrameError::Malformed),
        },
        min_versions: versions("min_versions")?,
        adopted: versions("adopted")?,
        caps: v
            .get("caps")
            .map(|c| VerifierCaps::from_value(c).map_err(|_| FrameError::Malformed))
            .transpose()?,
        hybrid: match v.get("hybrid") {
            None => None,
            Some(Value::Text(t)) => Some(
                HYBRIDS
                    .iter()
                    .find(|(n, _)| n == t)
                    .map(|(_, h)| *h)
                    .ok_or(FrameError::Malformed)?,
            ),
            Some(_) => return Err(FrameError::Malformed),
        },
        discovery: v.get("discovery").map(|d| bytes(Some(d))).transpose()?,
        declared: declared_of(v.get("declared"))?,
    })
}

impl Request {
    fn to_value(&self) -> Value {
        match self {
            Self::Open(t) => map(vec![("open", template_value(t))]),
            Self::Sign {
                domain,
                usage,
                content_type,
                payload,
                at,
            } => map(vec![(
                "sign",
                map(vec![
                    ("domain", domain.to_value()),
                    ("usage", Value::text(usage_name(*usage))),
                    ("content_type", Value::text(content_type)),
                    ("payload", Value::Bytes(payload.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::Metadata(d) => map(vec![("metadata", d.to_value())]),
            Self::SignNote { domain, body, at } => map(vec![(
                "sign_note",
                map(vec![
                    ("domain", domain.to_value()),
                    ("body", Value::text(body)),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::Genesis(d) => map(vec![("genesis", d.to_value())]),
            Self::SignToken { domain, claims, at } => map(vec![(
                "sign_token",
                map(vec![
                    ("domain", domain.to_value()),
                    ("claims", Value::Bytes(claims.clone())),
                    ("at", Value::Unsigned(*at)),
                ]),
            )]),
            Self::Declare { domain, declared } => map(vec![(
                "declare",
                map(vec![
                    ("domain", domain.to_value()),
                    ("declared", declared_value(declared)),
                ]),
            )]),
            Self::Binding { domain, next } => map(vec![(
                "binding",
                map(vec![
                    ("domain", domain.to_value()),
                    ("next", Value::Bool(*next)),
                ]),
            )]),
            Self::Statement {
                domain,
                next,
                content_type,
                payload,
            } => map(vec![(
                "statement",
                map(vec![
                    ("domain", domain.to_value()),
                    ("next", Value::Bool(*next)),
                    ("content_type", Value::text(content_type)),
                    ("payload", Value::Bytes(payload.clone())),
                ]),
            )]),
            Self::Rebind {
                domain,
                at,
                cited,
                transcript,
            } => map(vec![(
                "rebind",
                map(vec![
                    ("domain", domain.to_value()),
                    ("at", at.to_value()),
                    ("cited", cited.to_value()),
                    ("transcript", transcript.to_value()),
                ]),
            )]),
            Self::Supersede { domain, keys } => map(vec![(
                "supersede",
                map(vec![
                    ("domain", domain.to_value()),
                    (
                        "keys",
                        Value::Array(keys.iter().map(Canonical::to_value).collect()),
                    ),
                ]),
            )]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        // OP-158 m.3 (l)
        if let Some(b) = v.get("binding") {
            return Ok(Self::Binding {
                domain: digest(b.get("domain"))?,
                next: flag(b.get("next"))?,
            });
        }
        if let Some(b) = v.get("statement") {
            return Ok(Self::Statement {
                domain: digest(b.get("domain"))?,
                next: flag(b.get("next"))?,
                content_type: text(b.get("content_type"))?,
                payload: bytes(b.get("payload"))?,
            });
        }
        if let Some(b) = v.get("rebind") {
            return Ok(Self::Rebind {
                domain: digest(b.get("domain"))?,
                at: digest(b.get("at"))?,
                cited: digest(b.get("cited"))?,
                transcript: digest(b.get("transcript"))?,
            });
        }
        if let Some(b) = v.get("supersede") {
            let Some(Value::Array(keys)) = b.get("keys") else {
                return Err(FrameError::Malformed);
            };
            return Ok(Self::Supersede {
                domain: digest(b.get("domain"))?,
                keys: keys
                    .iter()
                    .map(|k| {
                        access_kernel::verify::key_scope::BindingKey::from_value(k)
                            .map_err(|_| FrameError::Malformed)
                    })
                    .collect::<Result<_, _>>()?,
            });
        }
        if let Some(d) = v.get("declare") {
            return Ok(Self::Declare {
                domain: digest(d.get("domain"))?,
                declared: Box::new(declared_of(d.get("declared"))?),
            });
        }
        if let Some(s) = v.get("sign_token") {
            return Ok(Self::SignToken {
                domain: digest(s.get("domain"))?,
                claims: bytes(s.get("claims"))?,
                at: uint(s.get("at"))?,
            });
        }
        if let Some(t) = v.get("open") {
            return Ok(Self::Open(Box::new(template_of(t)?)));
        }
        if let Some(d) = v.get("metadata") {
            return Ok(Self::Metadata(digest(Some(d))?));
        }
        if let Some(d) = v.get("genesis") {
            return Ok(Self::Genesis(digest(Some(d))?));
        }
        if let Some(s) = v.get("sign_note") {
            return Ok(Self::SignNote {
                domain: digest(s.get("domain"))?,
                body: text(s.get("body"))?,
                at: uint(s.get("at"))?,
            });
        }
        let s = v.get("sign").ok_or(FrameError::Malformed)?;
        let usage = text(s.get("usage"))?;
        Ok(Self::Sign {
            domain: digest(s.get("domain"))?,
            usage: USAGES
                .iter()
                .find(|(n, _)| *n == usage)
                .map(|(_, u)| *u)
                .ok_or(FrameError::Malformed)?,
            content_type: text(s.get("content_type"))?,
            payload: bytes(s.get("payload"))?,
            at: uint(s.get("at"))?,
        })
    }
}

impl Response {
    fn to_value(&self) -> Value {
        match self {
            Self::Opened => map(vec![("opened", Value::Bool(true))]),
            Self::Signed { sign1, excerpt } => map(vec![(
                "signed",
                map(vec![
                    ("sign1", Value::Bytes(sign1.clone())),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Metadata(b) => map(vec![("metadata", Value::Bytes(b.clone()))]),
            Self::Noted { line, excerpt } => map(vec![(
                "noted",
                map(vec![
                    ("line", Value::text(line)),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Genesis(b) => map(vec![("genesis", Value::Bytes(b.clone()))]),
            Self::Token { jws, excerpt } => map(vec![(
                "token",
                map(vec![
                    ("jws", Value::text(jws)),
                    ("excerpt", Value::Bytes(excerpt.clone())),
                ]),
            )]),
            Self::Binding(b) => map(vec![("binding", b.to_value())]),
            Self::Statement(b) => map(vec![("statement", Value::Bytes(b.clone()))]),
            Self::Error(code) => map(vec![("error", Value::text(code))]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, FrameError> {
        if v.get("opened").is_some() {
            return Ok(Self::Opened);
        }
        if let Some(s) = v.get("signed") {
            return Ok(Self::Signed {
                sign1: bytes(s.get("sign1"))?,
                excerpt: bytes(s.get("excerpt"))?,
            });
        }
        if let Some(m) = v.get("metadata") {
            return Ok(Self::Metadata(bytes(Some(m))?));
        }
        if let Some(n) = v.get("noted") {
            return Ok(Self::Noted {
                line: text(n.get("line"))?,
                excerpt: bytes(n.get("excerpt"))?,
            });
        }
        if let Some(g) = v.get("genesis") {
            return Ok(Self::Genesis(bytes(Some(g))?));
        }
        if let Some(t) = v.get("token") {
            return Ok(Self::Token {
                jws: text(t.get("jws"))?,
                excerpt: bytes(t.get("excerpt"))?,
            });
        }
        if let Some(b) = v.get("binding") {
            return Ok(Self::Binding(
                access_kernel::verify::key_scope::BindingKey::from_value(b)
                    .map_err(|_| FrameError::Malformed)?,
            ));
        }
        if let Some(b) = v.get("statement") {
            return Ok(Self::Statement(bytes(Some(b))?));
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
