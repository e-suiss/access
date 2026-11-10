//! The LDAP gateway's edge calls (§10.6.3, IDP-16, OP-155 m.3 (n)): `authenticate` checks an LDAP
//! credential or a client certificate, `directory_read` reads the realm's read-only directory
//! tree. The tree model, the filter semantics and the paging cookie live in access-server; the
//! gateway only translates the protocol.

use suiss_crypto::dcbor::Value;

use super::{WireError, decode_map, encode, fixed, only, opt_bytes, text};

/// Longest bind name: a DN or `dn=token`.
pub const MAX_BIND_NAME: usize = 512;

/// Longest bind secret.
pub const MAX_SECRET: usize = 1024;

/// Most certificates a SASL EXTERNAL chain carries.
pub const MAX_CHAIN: usize = 8;

/// Largest certificate of a chain.
pub const MAX_CERT: usize = 8 * 1024;

/// Longest opaque bind handle or paging cookie.
pub const MAX_HANDLE: usize = 256;

/// Longest DN.
pub const MAX_DN: usize = 1024;

/// Longest attribute name.
pub const MAX_ATTRIBUTE: usize = 128;

/// Longest attribute value.
pub const MAX_VALUE: usize = 4096;

/// Deepest filter (OP-155 m.3 (n)).
pub const MAX_FILTER_DEPTH: usize = 16;

/// Most nodes of one filter.
pub const MAX_FILTER_NODES: usize = 255;

/// Most entries one search returns (OP-155 m.3 (n)).
pub const MAX_RESULTS: u32 = 5000;

/// Largest page a client may ask for (OP-155 m.3 (n)).
pub const MAX_PAGE: u32 = 1000;

/// Most attributes a search names.
pub const MAX_ATTRIBUTES: usize = 64;

/// Most entries, attribute chunks or values in one array of an answer.
pub const MAX_ITEMS: usize = 256;

/// Largest `directory_read` answer; every other body stays within [`super::MAX_BODY`].
pub const MAX_DIRECTORY_BODY: usize = 1024 * 1024;

/// How a bind proves who it is (§10.6.3: no SCRAM, no DIGEST-MD5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// A simple bind with an LDAP credential.
    Simple,
    /// SASL EXTERNAL: the client certificate of the gateway's TLS session.
    External,
}

impl Mechanism {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::External => "external",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "simple" => Some(Self::Simple),
            "external" => Some(Self::External),
            _ => None,
        }
    }
}

/// [`super::Call::Authenticate`]: one LDAP bind, or an RFC 3062 change of the LDAP credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Authenticate {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// How the bind proves who it is.
    pub mechanism: Mechanism,
    /// Simple: the bind DN or `dn=token`.
    pub name: Option<String>,
    /// Simple: the LDAP credential. Never logged, never kept by the gateway.
    pub secret: Option<Vec<u8>>,
    /// External: the client certificate chain the gateway's TLS session verified, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// Simple only: replace this LDAP credential's secret (RFC 3062); the answer carries the new
    /// one.
    pub rotate: bool,
}

impl core::fmt::Debug for Authenticate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticate")
            .field("realm", &self.realm)
            .field("mechanism", &self.mechanism)
            .field("rotate", &self.rotate)
            .finish_non_exhaustive()
    }
}

/// The answer to [`Authenticate`]. An unknown name and a wrong secret answer the same: no
/// subject.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Authenticated {
    /// The subject, when the credential checked out.
    pub subject: Option<[u8; 16]>,
    /// The opaque handle the gateway presents on `directory_read` for this bind.
    pub bind: Option<Vec<u8>>,
    /// The bound entry's DN, which `WhoAmI` answers.
    pub dn: Option<String>,
    /// After a rotation: the new LDAP credential, shown to the client once.
    pub secret: Option<Vec<u8>>,
}

impl core::fmt::Debug for Authenticated {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticated")
            .field("bound", &self.subject.is_some())
            .finish_non_exhaustive()
    }
}

fn bytes(v: Option<&Value>, max: usize) -> Result<Option<Vec<u8>>, WireError> {
    match v {
        None => Ok(None),
        Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= max => Ok(Some(b.clone())),
        Some(_) => Err(WireError::Malformed),
    }
}

fn opt_text(v: Option<&Value>, max: usize) -> Result<Option<String>, WireError> {
    match v {
        None => Ok(None),
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(Some(t.clone())),
        Some(_) => Err(WireError::Malformed),
    }
}

fn flag(v: Option<&Value>) -> Result<bool, WireError> {
    match v {
        None => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err(WireError::Malformed),
    }
}

fn uint(v: Option<&Value>, max: u32) -> Result<u32, WireError> {
    match v {
        Some(Value::Unsigned(n)) if *n <= u64::from(max) => {
            u32::try_from(*n).map_err(|_| WireError::Malformed)
        }
        _ => Err(WireError::Malformed),
    }
}

impl Authenticate {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            ("realm", Value::text(&self.realm)),
            ("mechanism", Value::text(self.mechanism.name())),
        ];
        if let Some(n) = &self.name {
            entries.push(("name", Value::text(n)));
        }
        if let Some(s) = &self.secret {
            entries.push(("secret", Value::Bytes(s.clone())));
        }
        if !self.chain.is_empty() {
            entries.push((
                "chain",
                Value::Array(self.chain.iter().cloned().map(Value::Bytes).collect()),
            ));
        }
        if self.rotate {
            entries.push(("rotate", Value::Bool(true)));
        }
        encode(entries)
    }

    /// Reads the body: a simple bind carries a name and a secret and no chain; an external bind
    /// carries a chain only and never rotates.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(
            &v,
            &["realm", "mechanism", "name", "secret", "chain", "rotate"],
        )?;
        let mechanism =
            Mechanism::parse(&text(&v, "mechanism", 16)?).ok_or(WireError::Malformed)?;
        let chain = match v.get("chain") {
            None => Vec::new(),
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_CHAIN => items
                .iter()
                .map(|c| match c {
                    Value::Bytes(b) if !b.is_empty() && b.len() <= MAX_CERT => Ok(b.clone()),
                    _ => Err(WireError::Malformed),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(WireError::Malformed),
        };
        let q = Self {
            realm: text(&v, "realm", 64)?,
            mechanism,
            name: opt_text(v.get("name"), MAX_BIND_NAME)?,
            secret: bytes(v.get("secret"), MAX_SECRET)?,
            chain,
            rotate: flag(v.get("rotate"))?,
        };
        let shaped = match q.mechanism {
            Mechanism::Simple => q.name.is_some() && q.secret.is_some() && q.chain.is_empty(),
            Mechanism::External => {
                q.name.is_none() && q.secret.is_none() && !q.chain.is_empty() && !q.rotate
            }
        };
        if shaped {
            Ok(q)
        } else {
            Err(WireError::Malformed)
        }
    }
}

impl Authenticated {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = Vec::new();
        opt_bytes(&mut entries, "subject", self.subject);
        if let Some(b) = &self.bind {
            entries.push(("bind", Value::Bytes(b.clone())));
        }
        if let Some(dn) = &self.dn {
            entries.push(("dn", Value::text(dn)));
        }
        if let Some(s) = &self.secret {
            entries.push(("secret", Value::Bytes(s.clone())));
        }
        encode(entries)
    }

    /// Reads the body; a bind handle, a DN and a new secret come only with a subject.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(&v, &["subject", "bind", "dn", "secret"])?;
        let a = Self {
            subject: fixed::<16>(v.get("subject"))?,
            bind: bytes(v.get("bind"), MAX_HANDLE)?,
            dn: opt_text(v.get("dn"), MAX_DN)?,
            secret: bytes(v.get("secret"), MAX_SECRET)?,
        };
        let whole = a.subject.is_some() == a.bind.is_some() && a.bind.is_some() == a.dn.is_some();
        if whole && (a.secret.is_none() || a.subject.is_some()) {
            Ok(a)
        } else {
            Err(WireError::Malformed)
        }
    }
}

/// The scope of a search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The base entry only.
    Base,
    /// The base's children.
    One,
    /// The base and everything under it.
    Sub,
}

impl Scope {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::One => "one",
            Self::Sub => "sub",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "base" => Some(Self::Base),
            "one" => Some(Self::One),
            "sub" => Some(Self::Sub),
            _ => None,
        }
    }
}

/// One node of a filter in prefix order (RFC 4511 §4.5.1). A filter travels as a flat list of
/// nodes so that its depth never becomes CBOR nesting; [`Filter::new`] checks the shape.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    /// All of the next `n` filters (`n` ≥ 1).
    And(u16),
    /// Any of the next `n` filters (`n` ≥ 1).
    Or(u16),
    /// The negation of the next filter.
    Not,
    /// Equality.
    Eq(String, String),
    /// Greater or equal.
    Ge(String, String),
    /// Less or equal.
    Le(String, String),
    /// Approximate match.
    Approx(String, String),
    /// Presence.
    Present(String),
    /// Substrings: initial, any, final (empty when absent).
    Substr(String, String, Vec<String>, String),
    /// The in-chain matching rule `1.2.840.113556.1.4.1941` on a DN-valued attribute.
    Chain(String, String),
    /// A matching rule the directory does not know: Undefined (RFC 4511 §4.5.1.7).
    Undefined,
}

/// A filter of at most [`MAX_FILTER_NODES`] nodes and depth [`MAX_FILTER_DEPTH`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Filter(Vec<Node>);

/// Why a filter was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// Deeper than [`MAX_FILTER_DEPTH`].
    #[error("filter too deep")]
    Depth,
    /// More than [`MAX_FILTER_NODES`] nodes.
    #[error("filter too large")]
    Size,
    /// Not exactly one well-formed filter.
    #[error("malformed filter")]
    Shape,
}

impl Filter {
    /// The filter of `nodes`, checked iteratively: one complete filter, within the limits.
    ///
    /// # Errors
    /// [`FilterError`].
    pub fn new(nodes: Vec<Node>) -> Result<Self, FilterError> {
        if nodes.len() > MAX_FILTER_NODES {
            return Err(FilterError::Size);
        }
        let mut open: Vec<u16> = Vec::with_capacity(MAX_FILTER_DEPTH);
        let mut complete = false;
        for node in &nodes {
            if complete {
                return Err(FilterError::Shape);
            }
            let children = match node {
                Node::And(0) | Node::Or(0) => return Err(FilterError::Shape),
                Node::And(n) | Node::Or(n) => *n,
                Node::Not => 1,
                _ => 0,
            };
            if children > 0 {
                if open.len() >= MAX_FILTER_DEPTH {
                    return Err(FilterError::Depth);
                }
                open.push(children);
                continue;
            }
            loop {
                match open.last_mut() {
                    None => {
                        complete = true;
                        break;
                    }
                    Some(left) => {
                        *left = left.saturating_sub(1);
                        if *left > 0 {
                            break;
                        }
                        open.pop();
                    }
                }
            }
        }
        if complete && open.is_empty() {
            Ok(Self(nodes))
        } else {
            Err(FilterError::Shape)
        }
    }

    /// The nodes in prefix order.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.0
    }

    /// The deterministic CBOR of the filter, e.g. to bind a paging cookie to it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        suiss_crypto::dcbor::encode(&self.to_value(), super::limits()).unwrap_or_default()
    }

    /// `(objectClass=*)`.
    #[must_use]
    pub fn any() -> Self {
        Self(vec![Node::Present(String::from("objectClass"))])
    }

    fn to_value(&self) -> Value {
        let a = |s: &str| Value::text(s);
        Value::Array(
            self.0
                .iter()
                .map(|n| {
                    Value::Array(match n {
                        Node::And(k) => vec![a("and"), Value::Unsigned(u64::from(*k))],
                        Node::Or(k) => vec![a("or"), Value::Unsigned(u64::from(*k))],
                        Node::Not => vec![a("not")],
                        Node::Eq(t, v) => vec![a("eq"), a(t), a(v)],
                        Node::Ge(t, v) => vec![a("ge"), a(t), a(v)],
                        Node::Le(t, v) => vec![a("le"), a(t), a(v)],
                        Node::Approx(t, v) => vec![a("approx"), a(t), a(v)],
                        Node::Present(t) => vec![a("present"), a(t)],
                        Node::Substr(t, i, any, f) => vec![
                            a("substr"),
                            a(t),
                            a(i),
                            Value::Array(any.iter().map(|s| a(s)).collect()),
                            a(f),
                        ],
                        Node::Chain(t, dn) => vec![a("chain"), a(t), a(dn)],
                        Node::Undefined => vec![a("undefined")],
                    })
                })
                .collect(),
        )
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        let Value::Array(items) = v else {
            return Err(WireError::Malformed);
        };
        let nodes = items.iter().map(node).collect::<Result<Vec<_>, _>>()?;
        Self::new(nodes).map_err(|_| WireError::Malformed)
    }
}

/// Whether `name` is an attribute description the directory reads: a descriptor or an OID,
/// without options.
#[must_use]
pub fn attribute_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= MAX_ATTRIBUTE
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
}

fn attr(v: &Value) -> Result<String, WireError> {
    match v {
        Value::Text(t) if attribute_name(t) => Ok(t.clone()),
        _ => Err(WireError::Malformed),
    }
}

fn value(v: &Value) -> Result<String, WireError> {
    match v {
        Value::Text(t) if t.len() <= MAX_VALUE => Ok(t.clone()),
        _ => Err(WireError::Malformed),
    }
}

fn count(v: &Value) -> Result<u16, WireError> {
    match v {
        Value::Unsigned(n) if (1..=MAX_FILTER_NODES as u64).contains(n) => {
            u16::try_from(*n).map_err(|_| WireError::Malformed)
        }
        _ => Err(WireError::Malformed),
    }
}

fn node(v: &Value) -> Result<Node, WireError> {
    let Value::Array(parts) = v else {
        return Err(WireError::Malformed);
    };
    let Some(Value::Text(op)) = parts.first() else {
        return Err(WireError::Malformed);
    };
    Ok(match (op.as_str(), parts.get(1..).unwrap_or_default()) {
        ("and", [n]) => Node::And(count(n)?),
        ("or", [n]) => Node::Or(count(n)?),
        ("not", []) => Node::Not,
        ("eq", [t, x]) => Node::Eq(attr(t)?, value(x)?),
        ("ge", [t, x]) => Node::Ge(attr(t)?, value(x)?),
        ("le", [t, x]) => Node::Le(attr(t)?, value(x)?),
        ("approx", [t, x]) => Node::Approx(attr(t)?, value(x)?),
        ("present", [t]) => Node::Present(attr(t)?),
        ("substr", [t, i, Value::Array(any), f]) => Node::Substr(
            attr(t)?,
            value(i)?,
            any.iter().map(value).collect::<Result<_, _>>()?,
            value(f)?,
        ),
        ("chain", [t, dn]) => Node::Chain(attr(t)?, value(dn)?),
        ("undefined", []) => Node::Undefined,
        _ => return Err(WireError::Malformed),
    })
}

/// [`super::Call::DirectoryRead`]: one page of a search of the realm's directory tree, on behalf
/// of a bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRead {
    /// The realm; it must be the gateway's own.
    pub realm: String,
    /// The handle [`Authenticated::bind`] gave the bind.
    pub bind: Vec<u8>,
    /// The base DN as the client sent it.
    pub base: String,
    /// The scope.
    pub scope: Scope,
    /// The filter.
    pub filter: Filter,
    /// The attributes asked for; empty for all user attributes, `+` for the operational ones.
    pub attributes: Vec<String>,
    /// Names only, no values.
    pub types_only: bool,
    /// Most entries the whole search returns, at most [`MAX_RESULTS`].
    pub size_limit: u32,
    /// Most entries of this page, 1 to [`MAX_PAGE`].
    pub page_size: u32,
    /// The cookie of the previous page.
    pub cookie: Option<Vec<u8>>,
}

impl DirectoryRead {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            ("realm", Value::text(&self.realm)),
            ("bind", Value::Bytes(self.bind.clone())),
            ("base", Value::text(&self.base)),
            ("scope", Value::text(self.scope.name())),
            ("filter", self.filter.to_value()),
            (
                "attributes",
                Value::Array(self.attributes.iter().map(|a| Value::text(a)).collect()),
            ),
            ("size_limit", Value::Unsigned(u64::from(self.size_limit))),
            ("page_size", Value::Unsigned(u64::from(self.page_size))),
        ];
        if self.types_only {
            entries.push(("types_only", Value::Bool(true)));
        }
        if let Some(c) = &self.cookie {
            entries.push(("cookie", Value::Bytes(c.clone())));
        }
        encode(entries)
    }

    /// Reads the body.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = decode_map(body)?;
        only(
            &v,
            &[
                "realm",
                "bind",
                "base",
                "scope",
                "filter",
                "attributes",
                "types_only",
                "size_limit",
                "page_size",
                "cookie",
            ],
        )?;
        let base = match v.get("base") {
            Some(Value::Text(t)) if t.len() <= MAX_DN => t.clone(),
            _ => return Err(WireError::Malformed),
        };
        let attributes = match v.get("attributes") {
            Some(Value::Array(a)) if a.len() <= MAX_ATTRIBUTES => a
                .iter()
                .map(|x| match x {
                    Value::Text(t) if t == "*" || t == "+" || t == "1.1" => Ok(t.clone()),
                    other => attr(other),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(WireError::Malformed),
        };
        let page_size = uint(v.get("page_size"), MAX_PAGE)?;
        if page_size == 0 {
            return Err(WireError::Malformed);
        }
        Ok(Self {
            realm: text(&v, "realm", 64)?,
            bind: bytes(v.get("bind"), MAX_HANDLE)?.ok_or(WireError::Malformed)?,
            base,
            scope: Scope::parse(&text(&v, "scope", 8)?).ok_or(WireError::Malformed)?,
            filter: Filter::from_value(v.get("filter").ok_or(WireError::Malformed)?)?,
            attributes,
            types_only: flag(v.get("types_only"))?,
            size_limit: uint(v.get("size_limit"), MAX_RESULTS)?,
            page_size,
            cookie: bytes(v.get("cookie"), MAX_HANDLE)?,
        })
    }
}

/// How a search page ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The page is complete; a cookie means more pages follow.
    Done,
    /// The search reached its size limit.
    SizeLimit,
    /// The search ran out of time (10 s).
    TimeLimit,
    /// The base names no entry.
    NoSuchObject,
}

impl Outcome {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::SizeLimit => "size_limit",
            Self::TimeLimit => "time_limit",
            Self::NoSuchObject => "no_such_object",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "done" => Some(Self::Done),
            "size_limit" => Some(Self::SizeLimit),
            "time_limit" => Some(Self::TimeLimit),
            "no_such_object" => Some(Self::NoSuchObject),
            _ => None,
        }
    }
}

/// One directory entry. An attribute may appear in several consecutive chunks of at most
/// [`MAX_ITEMS`] values; a reader joins them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its DN.
    pub dn: String,
    /// Its attributes in order, values as text.
    pub attributes: Vec<(String, Vec<String>)>,
}

/// The answer to [`DirectoryRead`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryPage {
    /// At most [`MAX_ITEMS`] entries.
    pub entries: Vec<Entry>,
    /// How the page ended.
    pub outcome: Outcome,
    /// The cookie of the next page; absent on the last.
    pub cookie: Option<Vec<u8>>,
}

fn entry_value(e: &Entry) -> Value {
    let mut chunks = Vec::new();
    for (name, values) in &e.attributes {
        if values.is_empty() {
            chunks.push(Value::Array(vec![
                Value::text(name),
                Value::Array(Vec::new()),
            ]));
        }
        for part in values.chunks(MAX_ITEMS) {
            chunks.push(Value::Array(vec![
                Value::text(name),
                Value::Array(part.iter().map(|s| Value::text(s)).collect()),
            ]));
        }
    }
    Value::Map(vec![
        (Value::text("dn"), Value::text(&e.dn)),
        (Value::text("attributes"), Value::Array(chunks)),
    ])
}

fn entry_from(v: &Value) -> Result<Entry, WireError> {
    only(v, &["dn", "attributes"])?;
    let dn = match v.get("dn") {
        Some(Value::Text(t)) if t.len() <= MAX_DN => t.clone(),
        _ => return Err(WireError::Malformed),
    };
    let Some(Value::Array(chunks)) = v.get("attributes") else {
        return Err(WireError::Malformed);
    };
    let mut attributes: Vec<(String, Vec<String>)> = Vec::new();
    for c in chunks {
        let Value::Array(pair) = c else {
            return Err(WireError::Malformed);
        };
        let [name, Value::Array(values)] = pair.as_slice() else {
            return Err(WireError::Malformed);
        };
        let name = attr(name)?;
        let values = values.iter().map(value).collect::<Result<Vec<_>, _>>()?;
        match attributes.last_mut() {
            Some((last, held)) if *last == name => held.extend(values),
            _ => attributes.push((name, values)),
        }
    }
    Ok(Entry { dn, attributes })
}

impl DirectoryPage {
    /// The body; entries beyond [`MAX_ITEMS`] are not sent, so a server never builds such a
    /// page.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                "entries",
                Value::Array(
                    self.entries
                        .iter()
                        .take(MAX_ITEMS)
                        .map(entry_value)
                        .collect(),
                ),
            ),
            ("outcome", Value::text(self.outcome.name())),
        ];
        if let Some(c) = &self.cookie {
            entries.push(("cookie", Value::Bytes(c.clone())));
        }
        encode(entries)
    }

    /// Reads the body, at most [`MAX_DIRECTORY_BODY`] bytes.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let v = super::decode_map_within(body, MAX_DIRECTORY_BODY)?;
        only(&v, &["entries", "outcome", "cookie"])?;
        let Some(Value::Array(items)) = v.get("entries") else {
            return Err(WireError::Malformed);
        };
        Ok(Self {
            entries: items.iter().map(entry_from).collect::<Result<_, _>>()?,
            outcome: Outcome::parse(&text(&v, "outcome", 16)?).ok_or(WireError::Malformed)?,
            cookie: bytes(v.get("cookie"), MAX_HANDLE)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn eq(a: &str, v: &str) -> Node {
        Node::Eq(String::from(a), String::from(v))
    }

    // OP-155 m.3 (n), GHSA-qcxq-75wr-5cm8
    #[test]
    fn filters_are_checked_without_recursion() {
        let ok = Filter::new(vec![Node::And(2), eq("uid", "a"), Node::Not, eq("cn", "b")]);
        assert!(ok.is_ok());
        let mut deep: Vec<Node> = (0..MAX_FILTER_DEPTH).map(|_| Node::Not).collect();
        deep.push(eq("uid", "a"));
        assert!(Filter::new(deep.clone()).is_ok());
        deep.insert(0, Node::Not);
        assert_eq!(Filter::new(deep), Err(FilterError::Depth));
        assert_eq!(
            Filter::new(vec![Node::And(2), eq("uid", "a")]),
            Err(FilterError::Shape)
        );
        assert_eq!(
            Filter::new(vec![eq("uid", "a"), eq("uid", "b")]),
            Err(FilterError::Shape)
        );
        assert_eq!(Filter::new(vec![Node::Or(0)]), Err(FilterError::Shape));
        let wide: Vec<Node> = std::iter::once(Node::Or(255))
            .chain((0..255).map(|_| eq("uid", "a")))
            .collect();
        assert_eq!(Filter::new(wide), Err(FilterError::Size));
    }

    // OP-155 m.3 (n)
    #[test]
    fn ldap_bodies_round_trip() {
        let simple = Authenticate {
            realm: String::from("corp"),
            mechanism: Mechanism::Simple,
            name: Some(String::from("dn=token")),
            secret: Some(vec![1; 8]),
            chain: Vec::new(),
            rotate: true,
        };
        assert_eq!(Authenticate::decode(&simple.encode()).unwrap(), simple);
        let external = Authenticate {
            mechanism: Mechanism::External,
            name: None,
            secret: None,
            chain: vec![vec![2; 4]],
            rotate: false,
            ..simple.clone()
        };
        assert_eq!(Authenticate::decode(&external.encode()).unwrap(), external);
        let mixed = Authenticate {
            chain: vec![vec![2; 4]],
            ..simple
        };
        assert_eq!(
            Authenticate::decode(&mixed.encode()),
            Err(WireError::Malformed)
        );
        let read = DirectoryRead {
            realm: String::from("corp"),
            bind: vec![3; 40],
            base: String::from("ou=people,o=corp"),
            scope: Scope::Sub,
            filter: Filter::new(vec![Node::Or(2), eq("uid", "a"), Node::Undefined]).unwrap(),
            attributes: vec![String::from("cn"), String::from("+")],
            types_only: false,
            size_limit: 5000,
            page_size: 1000,
            cookie: Some(vec![4; 20]),
        };
        assert_eq!(DirectoryRead::decode(&read.encode()).unwrap(), read);
        let members: Vec<String> = (0..4000)
            .map(|i| format!("uid=u{i},ou=people,o=corp"))
            .collect();
        let page = DirectoryPage {
            entries: vec![Entry {
                dn: String::from("cn=staff,ou=groups,o=corp"),
                attributes: vec![
                    (String::from("cn"), vec![String::from("staff")]),
                    (String::from("member"), members),
                ],
            }],
            outcome: Outcome::Done,
            cookie: None,
        };
        let body = page.encode();
        assert!(body.len() > super::super::MAX_BODY);
        assert_eq!(DirectoryPage::decode(&body).unwrap(), page);
    }
}
