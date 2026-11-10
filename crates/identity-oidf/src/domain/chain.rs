//! Trust chains (OpenID Federation 1.0 §10, §10.7.1 item 3, OP-155 m.3 (j)): validation of a
//! chain given whole, online or offline, and a resolver that fetches one bottom-up. A chain is
//! at most [`MAX_LENGTH`] statements, is valid until the smallest `exp` in it, has no entity
//! twice, and ends at a trust anchor whose keys the realm pinned.

use access_kernel::json::{self, Json};

use crate::policy::{self, PolicyError};
use crate::statement::{
    self, EntityStatement, Jwk, MAX_STATEMENT, OidfError, configuration_url, entity_id_ok,
    verify_statement,
};
use crate::trust_mark::{TrustMark, issuer_allowed, verify_trust_mark};

/// Most statements in a chain, counting the leaf's configuration, every subordinate statement
/// and the trust anchor's configuration (OP-155 m.3 (j)).
pub const MAX_LENGTH: usize = 8;
/// How long a resolved chain counts as fresh for Claim ingest, Δ (OP-155 m.3 (j), IDI-12).
pub const FRESHNESS_MS: u64 = 3_600_000;
/// Most fetches one resolution makes.
pub const MAX_FETCHES: usize = 32;

/// Why a chain is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// No statements, or an offline chain that does not parse.
    #[error("format")]
    Format,
    /// More than [`MAX_LENGTH`] statements.
    #[error("too-long")]
    TooLong,
    /// An entity appears twice.
    #[error("cycle")]
    Cycle,
    /// A statement is refused.
    #[error("statement: {0}")]
    Statement(OidfError),
    /// A statement's issuer is not the next one's subject.
    #[error("link")]
    Link,
    /// The chain does not end at a pinned trust anchor.
    #[error("anchor")]
    Anchor,
    /// A `max_path_length` constraint is exceeded.
    #[error("path-length")]
    PathLength,
    /// The metadata policy conflicts or fails (fail closed).
    #[error("policy: {0}")]
    Policy(PolicyError),
    /// No path reached a pinned trust anchor.
    #[error("unresolved")]
    Unresolved,
}

impl ChainError {
    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Format => "oidf-chain-format",
            Self::TooLong => "oidf-chain-too-long",
            Self::Cycle => "oidf-chain-cycle",
            Self::Statement(e) => e.code(),
            Self::Link => "oidf-chain-link",
            Self::Anchor => "oidf-chain-anchor",
            Self::PathLength => "oidf-chain-path-length",
            Self::Policy(e) => e.code(),
            Self::Unresolved => "oidf-chain-unresolved",
        }
    }
}

impl From<OidfError> for ChainError {
    fn from(e: OidfError) -> Self {
        Self::Statement(e)
    }
}

impl From<PolicyError> for ChainError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

/// A trust anchor the realm trusts, with the keys it pinned (`idp.federation.trust_anchor_add`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The anchor's entity identifier.
    pub entity_id: String,
    /// Its pinned federation keys.
    pub jwks: Vec<Jwk>,
}

/// A validated trust chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The leaf's entity configuration.
    pub leaf: EntityStatement,
    /// The trust anchor it ends at.
    pub anchor: String,
    /// The statements, leaf first, trust anchor configuration last.
    pub statements: Vec<String>,
    /// The smallest `exp` of the chain, Unix milliseconds.
    pub exp_ms: u64,
    /// The leaf's metadata after the superior's `metadata` and the merged policy.
    pub metadata: Json,
    /// The leaf's trust marks that verified; a mark that does not is left out.
    pub trust_marks: Vec<TrustMark>,
}

impl Chain {
    /// The resolved metadata of one entity type.
    #[must_use]
    pub fn metadata_of(&self, entity_type: &str) -> Option<&Json> {
        self.metadata.get(entity_type)
    }

    /// Whether the chain is still valid and fresh at `now_ms`, `checked_ms` being when it was
    /// last resolved (IDI-12).
    #[must_use]
    pub fn fresh(&self, checked_ms: u64, now_ms: u64) -> bool {
        now_ms < self.exp_ms && now_ms.saturating_sub(checked_ms) <= FRESHNESS_MS
    }
}

/// The statements of an offline `trust-chain+json` document, or of a `trust_chain` header: a
/// JSON array of 1 to [`MAX_LENGTH`] compact JWS strings.
///
/// # Errors
/// [`ChainError::Format`], [`ChainError::TooLong`].
pub fn parse_trust_chain_json(bytes: &[u8]) -> Result<Vec<String>, ChainError> {
    let limit = MAX_STATEMENT.saturating_mul(MAX_LENGTH.saturating_add(1));
    let v = json::parse(bytes, limit).map_err(|_| ChainError::Format)?;
    from_array(&v)
}

/// The statements of a JSON array value.
pub(crate) fn from_array(v: &Json) -> Result<Vec<String>, ChainError> {
    let Json::Array(items) = v else {
        return Err(ChainError::Format);
    };
    if items.is_empty() {
        return Err(ChainError::Format);
    }
    if items.len() > MAX_LENGTH {
        return Err(ChainError::TooLong);
    }
    items
        .iter()
        .map(|i| i.as_str().map(String::from).ok_or(ChainError::Format))
        .collect()
}

fn override_metadata(base: &Json, over: &Json) -> Json {
    let mut out = match base {
        Json::Object(m) => m.clone(),
        _ => Vec::new(),
    };
    if let Json::Object(types) = over {
        for (t, params) in types {
            let Json::Object(params) = params else {
                continue;
            };
            match out.iter_mut().find(|(k, _)| k == t) {
                Some((_, Json::Object(existing))) => {
                    for (p, v) in params {
                        match existing.iter_mut().find(|(k, _)| k == p) {
                            Some(slot) => slot.1 = v.clone(),
                            None => existing.push((p.clone(), v.clone())),
                        }
                    }
                }
                Some(slot) => slot.1 = Json::Object(params.clone()),
                None => out.push((t.clone(), Json::Object(params.clone()))),
            }
        }
    }
    Json::Object(out)
}

/// Verifies every statement from the anchor's configuration down, each with the keys the one
/// above publishes for its issuer, and the leaf's configuration also with its own keys; leaf
/// first in the result.
fn verify_links(
    jwts: &[&str],
    pinned: &[Jwk],
    now_ms: u64,
) -> Result<Vec<EntityStatement>, ChainError> {
    let last = jwts.len().saturating_sub(1);
    let mut verified: Vec<EntityStatement> = Vec::with_capacity(jwts.len());
    let mut keys: Vec<Jwk> = pinned.to_vec();
    for j in (0..jwts.len()).rev() {
        let jwt = jwts.get(j).ok_or(ChainError::Format)?;
        let s = verify_statement(jwt, &keys, now_ms)?;
        let configuration = j == 0 || j == last;
        if configuration != s.is_configuration() {
            return Err(ChainError::Link);
        }
        if let Some(above) = verified.last()
            && j != last
            && s.iss != above.sub
        {
            return Err(ChainError::Link);
        }
        keys.clone_from(&s.jwks);
        verified.push(s);
    }
    verified.reverse();
    let leaf = verified.first().ok_or(ChainError::Format)?;
    verify_statement(&leaf.raw, &leaf.jwks, now_ms)?;
    Ok(verified)
}

/// The 8 steps of chain validation (OpenID Federation 1.0 §10.2): statements leaf first;
/// `ES[0]` is the leaf's configuration and the last is the trust anchor's configuration,
/// verified with the anchor's pinned keys; every other `ES[j]` is verified with the keys
/// `ES[j+1]` publishes for its issuer, and `ES[j].iss = ES[j+1].sub`; the leaf's
/// configuration is also self-signed. Lengths, cycles and `max_path_length` are checked; the
/// chain is valid until the smallest `exp`; the policies are merged from the anchor down and
/// applied to the leaf's metadata after its immediate superior's `metadata`.
///
/// # Errors
/// [`ChainError`].
pub fn verify_chain(
    jwts: &[&str],
    anchors: &[TrustAnchor],
    now_ms: u64,
) -> Result<Chain, ChainError> {
    if jwts.is_empty() {
        return Err(ChainError::Format);
    }
    if jwts.len() > MAX_LENGTH {
        return Err(ChainError::TooLong);
    }
    let peeked = jwts
        .iter()
        .map(|j| statement::peek(j))
        .collect::<Result<Vec<_>, _>>()?;
    let last = jwts.len().saturating_sub(1);
    let (ta_iss, ta_sub) = peeked.get(last).ok_or(ChainError::Format)?;
    if ta_iss != ta_sub {
        return Err(ChainError::Link);
    }
    let anchor = anchors
        .iter()
        .find(|a| &a.entity_id == ta_iss)
        .ok_or(ChainError::Anchor)?;
    let mut seen: Vec<&str> = Vec::new();
    for (iss, _) in peeked.iter().take(last.max(1)) {
        if seen.contains(&iss.as_str()) {
            return Err(ChainError::Cycle);
        }
        seen.push(iss);
    }
    let verified = verify_links(jwts, &anchor.jwks, now_ms)?;
    let leaf = verified.first().ok_or(ChainError::Format)?.clone();
    let mut allowed: Option<Vec<String>> = None;
    for (j, s) in verified.iter().enumerate().take(last).skip(1) {
        if let Some(max) = s.max_path_length {
            let between = j.saturating_sub(1);
            if usize::try_from(max).is_ok_and(|m| between > m) {
                return Err(ChainError::PathLength);
            }
        }
        if let Some(types) = &s.allowed_entity_types {
            allowed = Some(match allowed {
                None => types.clone(),
                Some(a) => a.into_iter().filter(|t| types.contains(t)).collect(),
            });
        }
    }
    let exp_ms = verified
        .iter()
        .map(|s| s.exp_ms)
        .min()
        .ok_or(ChainError::Format)?;
    let mut metadata = leaf
        .metadata
        .clone()
        .unwrap_or_else(|| Json::Object(Vec::new()));
    if let Some(over) = verified
        .get(1)
        .filter(|_| last > 0)
        .and_then(|s| s.metadata.as_ref())
    {
        metadata = override_metadata(&metadata, over);
    }
    let mut merged = Json::Object(Vec::new());
    for s in verified.iter().take(last).skip(1).rev() {
        if let Some(p) = &s.metadata_policy {
            merged = policy::merge(&merged, p)?;
        }
    }
    metadata = policy::apply(&merged, &metadata)?;
    if let (Some(types), Json::Object(m)) = (&allowed, &mut metadata) {
        m.retain(|(t, _)| t == "federation_entity" || types.contains(t));
    }
    let trust_marks = marks(&leaf, &verified, now_ms);
    Ok(Chain {
        anchor: anchor.entity_id.clone(),
        statements: jwts.iter().map(|j| String::from(*j)).collect(),
        leaf,
        exp_ms,
        metadata,
        trust_marks,
    })
}

/// The leaf's trust marks whose issuer is an entity of the chain with known keys and whom the
/// anchor lets issue that type.
fn marks(leaf: &EntityStatement, verified: &[EntityStatement], now_ms: u64) -> Vec<TrustMark> {
    let Some(anchor) = verified.last() else {
        return Vec::new();
    };
    let keys_of = |issuer: &str| -> Option<&[Jwk]> {
        if issuer == anchor.iss {
            return Some(&anchor.jwks);
        }
        verified
            .iter()
            .skip(1)
            .find(|s| s.sub == issuer)
            .map(|s| s.jwks.as_slice())
    };
    leaf.trust_marks
        .iter()
        .filter_map(|m| {
            let iss = trust_mark_iss(&m.trust_mark)?;
            let keys = keys_of(&iss)?;
            let t = verify_trust_mark(&m.trust_mark, keys, &leaf.sub, now_ms).ok()?;
            (t.trust_mark_type == m.trust_mark_type
                && issuer_allowed(anchor, &t.trust_mark_type, &t.iss))
            .then_some(t)
        })
        .collect()
}

fn trust_mark_iss(jwt: &str) -> Option<String> {
    let parts = crate::jws::split(jwt, MAX_STATEMENT).ok()?;
    Some(String::from(parts.payload.get("iss")?.as_str()?))
}

/// What the resolver needs next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Fetch `url` and [`Resolver::feed`] the answer.
    Fetch {
        /// The URL, an entity configuration or a fetch endpoint query.
        url: String,
    },
    /// A chain to a pinned anchor.
    Done(Box<Chain>),
    /// No chain.
    Failed(ChainError),
}

#[derive(Clone, Debug)]
struct Node {
    id: String,
    configuration: EntityStatement,
    about_below: Option<String>,
    next_hint: usize,
}

#[derive(Clone, Debug)]
enum Pending {
    Leaf,
    Configuration(String),
    Subordinate(Box<EntityStatement>),
}

/// Resolves a chain bottom-up, depth first over `authority_hints`, without I/O: [`Resolver::step`]
/// says what to fetch, [`Resolver::feed`] takes the answer. A path is abandoned on a non-200
/// answer or a refused statement and the next hint is tried; at most [`MAX_FETCHES`] fetches.
#[derive(Clone, Debug)]
pub struct Resolver {
    leaf: String,
    anchors: Vec<TrustAnchor>,
    now_ms: u64,
    path: Vec<Node>,
    pending: Option<(Pending, String)>,
    fetches: usize,
    started: bool,
    outcome: Option<Result<Box<Chain>, ChainError>>,
}

fn fetch_url(endpoint: &str, sub: &str) -> String {
    let mut url = String::from(endpoint);
    url.push(if endpoint.contains('?') { '&' } else { '?' });
    url.push_str("sub=");
    for b in sub.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            url.push(char::from(b));
        } else {
            url.push('%');
            for n in [b >> 4, b & 0xf] {
                url.push(char::from(
                    b"0123456789ABCDEF"
                        .get(usize::from(n))
                        .copied()
                        .unwrap_or(b'0'),
                ));
            }
        }
    }
    url
}

impl Resolver {
    /// A resolver for `leaf` towards `anchors` at `now_ms`.
    #[must_use]
    pub fn new(leaf: &str, anchors: Vec<TrustAnchor>, now_ms: u64) -> Self {
        Self {
            leaf: String::from(leaf),
            anchors,
            now_ms,
            path: Vec::new(),
            pending: None,
            fetches: 0,
            started: false,
            outcome: None,
        }
    }

    fn fetch(&mut self, p: Pending, url: String) -> Step {
        if self.fetches >= MAX_FETCHES {
            self.outcome = Some(Err(ChainError::Unresolved));
            return Step::Failed(ChainError::Unresolved);
        }
        self.fetches = self.fetches.saturating_add(1);
        self.pending = Some((p, url.clone()));
        Step::Fetch { url }
    }

    /// What to do next.
    pub fn step(&mut self) -> Step {
        if let Some(o) = &self.outcome {
            return match o {
                Ok(c) => Step::Done(c.clone()),
                Err(e) => Step::Failed(*e),
            };
        }
        if let Some((_, url)) = &self.pending {
            return Step::Fetch { url: url.clone() };
        }
        if !self.started {
            self.started = true;
            if !entity_id_ok(&self.leaf) {
                self.outcome = Some(Err(ChainError::Statement(OidfError::EntityId)));
                return Step::Failed(ChainError::Statement(OidfError::EntityId));
            }
            let url = configuration_url(&self.leaf);
            return self.fetch(Pending::Leaf, url);
        }
        loop {
            let depth = self.path.len();
            let Some(top) = self.path.last_mut() else {
                self.outcome = Some(Err(ChainError::Unresolved));
                return Step::Failed(ChainError::Unresolved);
            };
            let Some(hint) = top
                .configuration
                .authority_hints
                .get(top.next_hint)
                .cloned()
            else {
                self.path.pop();
                continue;
            };
            top.next_hint = top.next_hint.saturating_add(1);
            let entities = depth.saturating_add(1);
            if self.path.iter().any(|n| n.id == hint)
                || entities.saturating_add(1) > MAX_LENGTH
                || !entity_id_ok(&hint)
            {
                continue;
            }
            let url = configuration_url(&hint);
            return self.fetch(Pending::Configuration(hint), url);
        }
    }

    /// Takes the answer to the last [`Step::Fetch`]; an answer for another URL is ignored.
    pub fn feed(&mut self, url: &str, status: u16, body: &[u8]) {
        let Some((pending, asked)) = self.pending.take() else {
            return;
        };
        if asked != url {
            self.pending = Some((pending, asked));
            return;
        }
        let text = (status == 200 && body.len() <= MAX_STATEMENT)
            .then(|| core::str::from_utf8(body).ok())
            .flatten()
            .map(str::trim);
        match pending {
            Pending::Leaf => {
                let Some(ec) = text
                    .and_then(|t| statement::verify_configuration(t, &self.leaf, self.now_ms).ok())
                else {
                    self.outcome = Some(Err(ChainError::Unresolved));
                    return;
                };
                if self.anchors.iter().any(|a| a.entity_id == self.leaf) {
                    self.outcome = Some(
                        verify_chain(&[ec.raw.as_str()], &self.anchors, self.now_ms).map(Box::new),
                    );
                    return;
                }
                self.path.push(Node {
                    id: self.leaf.clone(),
                    configuration: ec,
                    about_below: None,
                    next_hint: 0,
                });
            }
            Pending::Configuration(hint) => {
                let Some(ec) =
                    text.and_then(|t| statement::verify_configuration(t, &hint, self.now_ms).ok())
                else {
                    return;
                };
                let (Some(endpoint), Some(below)) = (
                    ec.federation_entity_endpoint("federation_fetch_endpoint"),
                    self.path.last(),
                ) else {
                    return;
                };
                let next = fetch_url(endpoint, &below.id);
                let _step = self.fetch(Pending::Subordinate(Box::new(ec)), next);
            }
            Pending::Subordinate(ec) => {
                let Some(below) = self.path.last() else {
                    return;
                };
                let Some(stmt) = text.and_then(|t| verify_statement(t, &ec.jwks, self.now_ms).ok())
                else {
                    return;
                };
                if stmt.iss != ec.iss || stmt.sub != below.id || stmt.is_configuration() {
                    return;
                }
                let node = Node {
                    id: ec.iss.clone(),
                    configuration: *ec,
                    about_below: Some(stmt.raw),
                    next_hint: 0,
                };
                if self.anchors.iter().any(|a| a.entity_id == node.id) {
                    let mut jwts: Vec<&str> = Vec::with_capacity(self.path.len().saturating_add(2));
                    for n in &self.path {
                        match &n.about_below {
                            None => jwts.push(&n.configuration.raw),
                            Some(s) => jwts.push(s),
                        }
                    }
                    if let Some(s) = &node.about_below {
                        jwts.push(s);
                    }
                    jwts.push(&node.configuration.raw);
                    if let Ok(c) = verify_chain(&jwts, &self.anchors, self.now_ms) {
                        self.outcome = Some(Ok(Box::new(c)));
                    }
                    return;
                }
                self.path.push(node);
            }
        }
    }
}

#[cfg(test)]
mod tests;
