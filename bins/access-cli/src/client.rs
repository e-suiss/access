//! The management API client (OP-151 m.3 (c), m.6, m.11 (a), (b)).
//!
//! A read presents a read token bound to the Instance key with DPoP. The token comes from the
//! realm's token endpoint by an RFC 8693 token exchange: the subject token is the Instance's own
//! AIS in `check` mode over the surface's audience and `realm.read`, in the realm's governing
//! domain, with a single-use nonce; there is no client authentication, and the DPoP proof is made
//! by the same Instance key, which becomes the token's `cnf.jkt`. The token lives at most 60
//! minutes and is never written anywhere (TN-130, TN-27, OP-151 m.18 (b)).
//!
//! A write is two steps: `POST …/intents` drafts it (a read; nothing changes), the client checks
//! that the drafted intent's digest is the digest of the drafted intent bytes, that the domain is
//! the surface's and that every member it asked for is in the drafted body unchanged; then it
//! signs an AIS over that digest with the Instance key and sends the drafted body with the AIS
//! and `Idempotency-Key` = the AIS nonce (TN-110, TN-126). The answer names the Exercise.

use std::cell::RefCell;

use access_internal_api::instances::IDENTITY_PEP;
use access_kernel::ais::Statement;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_sdk::auth::discovery;
use access_sdk::auth::dpop::{ProofFor, proof};
use access_sdk::auth::token::{self, Secret, TokenError};
use access_sdk::auth::{OAuthClass, Random, RandomUnavailable};
use access_sdk::transport::{Answer, Response as SdkResponse};
use serde_json::{Map, Value, json};
use suiss_crypto::digest::context_digest;

use crate::api::{self, DRAFT, Method, Operation};
use crate::http::{HttpError, Request, Response, Transport};
use crate::keys::{InstanceKey, KeyError};

/// Longest read token accepted (TN-130, OP-151 m.3 (c)).
pub(crate) const MAX_TOKEN_SECONDS: u64 = 60 * 60;

/// RFC 8693 §2.1 `grant_type`.
pub(crate) const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The `subject_token_type` of an AIS subject token: unpadded base64url of its `COSE_Sign1`.
pub(crate) const AIS_TOKEN_TYPE: &str = "urn:suiss:access:token-type:ais";

/// RFC 8693 §3 token type of an access token.
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The digest context of the exchange's AIS intent.
pub(crate) const EXCHANGE_CONTEXT: &str = "access/management-read/v1";

/// The read scope of the realm-admin surface.
pub(crate) const REALM_READ: &str = "realm.read";

/// The AS metadata member naming the governing domain's Domain Metadata (§9.15.1 k.2).
const DOMAIN_METADATA_MEMBER: &str = "suiss_domain_metadata";

/// The path of a Domain Metadata address up to its `DomainID` (L0-ENC-20).
const DOMAIN_METADATA_PATH: &str = "/.well-known/access-domain-metadata/sha-256:";

/// What the exchange's AIS signs as its intent: `context_digest` over `audience‖0‖scope`
/// (TN-130, OP-151 m.18 (b)).
pub(crate) fn exchange_intent(audience: &str, scope: &str) -> Digest {
    let mut canonical =
        Vec::with_capacity(audience.len().saturating_add(scope.len()).saturating_add(1));
    canonical.extend_from_slice(audience.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(scope.as_bytes());
    Digest(context_digest(EXCHANGE_CONTEXT, &canonical).0)
}

/// The realm's governing domain, from the `DomainID` its AS metadata's Domain Metadata address
/// ends with; `None` when the metadata names none.
pub(crate) fn governing_domain(metadata: &Value) -> Option<Digest> {
    let address = metadata.get(DOMAIN_METADATA_MEMBER)?.as_str()?;
    if !discovery::is_https(address) {
        return None;
    }
    let (_, id) = address.rsplit_once(DOMAIN_METADATA_PATH)?;
    let bytes = b64url_decode(id).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok().map(Digest)
}

/// Why a call produced nothing.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientError {
    /// No answer.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The key failed.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// No randomness.
    #[error("random source unavailable")]
    Random,
    /// The realm's metadata cannot be used.
    #[error("discovery: {0}")]
    Discovery(discovery::DiscoveryError),
    /// No read token (P15: an unknown OAuth error is `Refused`).
    #[error("read token refused: {0:?}")]
    Token(OAuthClass),
    /// A token that is not DPoP-bound, or lives over 60 minutes (TN-130).
    #[error("read token not acceptable: {0}")]
    TokenShape(&'static str),
    /// The API answered with a problem (RFC 9457).
    #[error("{status} {code}: {detail}")]
    Problem {
        /// HTTP status.
        status: u16,
        /// Stable code.
        code: String,
        /// Detail or title.
        detail: String,
    },
    /// The draft does not match what was asked or what it claims (fail closed).
    #[error("draft refused: {0}")]
    Draft(&'static str),
    /// The answer is not what the contract says.
    #[error("unexpected answer: {0}")]
    Unexpected(&'static str),
}

impl From<RandomUnavailable> for ClientError {
    fn from(_: RandomUnavailable) -> Self {
        Self::Random
    }
}

/// Time and randomness for the client.
pub(crate) trait Env {
    /// Unix milliseconds.
    fn now_ms(&self) -> u64;
    /// A CSPRNG.
    fn random(&self) -> &dyn RandomSource;
}

/// The randomness port, object-safe.
pub(crate) trait RandomSource {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), RandomUnavailable>;
}

struct Rng<'a>(&'a dyn RandomSource);

impl Random for Rng<'_> {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        self.0.fill_bytes(out)
    }
}

/// The operating system's CSPRNG and clock.
pub(crate) struct System;

impl RandomSource for System {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in out.chunks_mut(32) {
            let b = access_crypto::random::bytes::<32>().map_err(|_| RandomUnavailable)?;
            chunk.copy_from_slice(b.get(..chunk.len()).ok_or(RandomUnavailable)?);
        }
        Ok(())
    }
}

impl Env for System {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn random(&self) -> &dyn RandomSource {
        self
    }
}

/// Where the realm's management surface and token endpoint are.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    /// The management API origin, `https://host[:port]`.
    pub(crate) api: String,
    /// The realm slug.
    pub(crate) realm: String,
    /// The realm issuer; its metadata names the token endpoint.
    pub(crate) issuer: String,
    /// The basis every AIS declares (the caller's Grant holding or anchor).
    pub(crate) basis: ExerciseBasis,
}

impl Target {
    /// The read token's audience (TN-119).
    pub(crate) fn audience(&self) -> String {
        format!("access-admin:realm:{}", self.realm)
    }
}

/// A committed write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Written {
    pub(crate) exercise_id: String,
    pub(crate) position: String,
    pub(crate) body: Value,
}

struct Token {
    value: Secret,
    nonce: Option<String>,
}

/// The client.
pub(crate) struct Client<'a, T, E> {
    transport: &'a T,
    key: &'a InstanceKey,
    target: &'a Target,
    env: &'a E,
    token: RefCell<Option<Token>>,
    domain: RefCell<Option<Digest>>,
}

fn problem(r: &Response) -> ClientError {
    let v = r.json();
    let text = |n: &str| v.get(n).and_then(Value::as_str).map(String::from);
    ClientError::Problem {
        status: r.status,
        code: text("code").unwrap_or_else(|| String::from("unknown")),
        detail: text("detail").or_else(|| text("title")).unwrap_or_default(),
    }
}

fn sdk_answer(r: &Response) -> Answer {
    let mut out = SdkResponse::new(r.status, r.body.clone());
    out.content_type = r.header("content-type").map(String::from);
    Answer::Response(out)
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", api::segment(k), api::segment(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn nonce_retry(r: &Response) -> Option<String> {
    let asked = r
        .header("www-authenticate")
        .is_some_and(|w| w.contains("use_dpop_nonce"))
        || r.json().get("error").and_then(Value::as_str) == Some("use_dpop_nonce");
    if asked {
        r.header("dpop-nonce").map(String::from)
    } else {
        None
    }
}

impl<'a, T: Transport, E: Env> Client<'a, T, E> {
    pub(crate) fn new(
        transport: &'a T,
        key: &'a InstanceKey,
        target: &'a Target,
        env: &'a E,
    ) -> Self {
        Self {
            transport,
            key,
            target,
            env,
            token: RefCell::new(None),
            domain: RefCell::new(None),
        }
    }

    fn proof(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String, ClientError> {
        proof(
            self.key,
            &ProofFor {
                method,
                uri: url,
                access_token: token,
                nonce,
            },
            self.env.now_ms(),
            &Rng(self.env.random()),
        )
        .map_err(|_| ClientError::Key(KeyError::Sign))
    }

    /// The Instance's own AIS in `check` mode over the exchange's intent, as a subject token
    /// (TN-130, OP-151 m.18 (b)); a fresh nonce every time, since the server uses each once.
    fn exchange_statement(&self, domain: Digest, audience: &str) -> Result<String, ClientError> {
        let mut nonce = vec![0u8; 32];
        self.env.random().fill_bytes(&mut nonce)?;
        let statement = Statement {
            domain,
            nonce,
            intent: exchange_intent(audience, REALM_READ),
            mode: Mode::Check,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis: self.target.basis,
            iat: self.env.now_ms(),
            exercise: None,
        };
        let bytes = statement
            .to_bytes()
            .map_err(|_| ClientError::Unexpected("statement encoding"))?;
        Ok(b64url_encode(&self.key.sign_ais(&bytes)?))
    }

    /// Obtains the read token (TN-130, OP-151 m.18 (b)): an RFC 8693 token exchange of the
    /// Instance's own `check` AIS, without client authentication, with a DPoP proof by the same
    /// Instance key.
    async fn read_token(&self) -> Result<(), ClientError> {
        if self.token.borrow().is_some() {
            return Ok(());
        }
        let meta_url = discovery::well_known(&self.target.issuer);
        let answer = self
            .transport
            .send(Request {
                method: "GET",
                url: meta_url,
                headers: Vec::new(),
                body: None,
            })
            .await?;
        let meta = discovery::parse(&sdk_answer(&answer), &self.target.issuer)
            .map_err(ClientError::Discovery)?;
        let domain =
            governing_domain(&answer.json()).ok_or(ClientError::Unexpected("governing domain"))?;
        let audience = self.target.audience();
        let mut nonce: Option<String> = None;
        for _ in 0..2 {
            let subject = self.exchange_statement(domain, &audience)?;
            let body = form(&[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token_type", AIS_TOKEN_TYPE),
                ("subject_token", &subject),
                ("requested_token_type", ACCESS_TOKEN_TYPE),
                ("audience", &audience),
                ("scope", REALM_READ),
            ]);
            let dpop = self.proof("POST", &meta.token_endpoint, None, nonce.as_deref())?;
            let r = self
                .transport
                .send(Request {
                    method: "POST",
                    url: meta.token_endpoint.clone(),
                    headers: vec![(String::from("DPoP"), dpop)],
                    body: Some(("application/x-www-form-urlencoded", body.into_bytes())),
                })
                .await?;
            if nonce.is_none()
                && let Some(n) = nonce_retry(&r)
            {
                nonce = Some(n);
                continue;
            }
            let tokens = match token::parse_response(&sdk_answer(&r), true) {
                Ok(t) => t,
                Err(TokenError::Refused { class, .. }) => return Err(ClientError::Token(class)),
                Err(TokenError::Unbound) => return Err(ClientError::TokenShape("not DPoP-bound")),
                Err(_) => return Err(ClientError::Unexpected("token response")),
            };
            if tokens.expires_in > MAX_TOKEN_SECONDS {
                return Err(ClientError::TokenShape("lifetime over 60 minutes"));
            }
            *self.token.borrow_mut() = Some(Token {
                value: tokens.access_token,
                nonce: None,
            });
            return Ok(());
        }
        Err(ClientError::Token(OAuthClass::UseDpopNonce))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.target.api.trim_end_matches('/'))
    }

    /// A read (`GET`, or the drafting `POST`) with the DPoP-bound read token; one retry with
    /// the server's `DPoP-Nonce`.
    pub(crate) async fn read(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, ClientError> {
        self.read_token().await?;
        let url = self.url(path);
        let htu = url.split('?').next().unwrap_or(&url).to_owned();
        for attempt in 0..2 {
            let (value, nonce) = {
                let t = self.token.borrow();
                let t = t.as_ref().ok_or(ClientError::Unexpected("token"))?;
                (t.value.clone(), t.nonce.clone())
            };
            let dpop = self.proof(
                method.as_str(),
                &htu,
                Some(value.expose()),
                nonce.as_deref(),
            )?;
            let r = self
                .transport
                .send(Request {
                    method: method.as_str(),
                    url: url.clone(),
                    headers: vec![
                        (
                            String::from("Authorization"),
                            format!("DPoP {}", value.expose()),
                        ),
                        (String::from("DPoP"), dpop),
                    ],
                    body: body.map(|b| ("application/json", b.to_string().into_bytes())),
                })
                .await?;
            if attempt == 0
                && let Some(n) = nonce_retry(&r)
            {
                if let Some(t) = self.token.borrow_mut().as_mut() {
                    t.nonce = Some(n);
                }
                continue;
            }
            return Ok(r);
        }
        Err(ClientError::Unexpected("nonce"))
    }

    /// A `GET` that must answer 200, its body and `ETag`.
    pub(crate) async fn get(&self, path: &str) -> Result<(Value, Option<String>), ClientError> {
        let r = self.read(Method::Get, path, None).await?;
        if r.status != 200 {
            return Err(problem(&r));
        }
        Ok((r.json(), r.header("etag").map(String::from)))
    }

    /// Every item of a listing, following `Link: <…>; rel="next"` (OP-65).
    pub(crate) async fn list(&self, path: &str) -> Result<Vec<Value>, ClientError> {
        let mut out = Vec::new();
        let mut next = Some(path.to_owned());
        let mut pages = 0u32;
        while let Some(p) = next.take() {
            pages = pages.saturating_add(1);
            if pages > 10_000 {
                return Err(ClientError::Unexpected("too many pages"));
            }
            let r = self.read(Method::Get, &p, None).await?;
            if r.status != 200 {
                return Err(problem(&r));
            }
            let v = r.json();
            let items = v
                .get("items")
                .and_then(Value::as_array)
                .ok_or(ClientError::Unexpected("page"))?;
            out.extend(items.iter().cloned());
            next = r.header("link").and_then(next_link).map(|l| {
                l.strip_prefix(self.target.api.trim_end_matches('/'))
                    .unwrap_or(&l)
                    .to_owned()
            });
        }
        Ok(out)
    }

    /// The surface's governing domain (`GET /admin/v1/realms/{slug}`).
    pub(crate) async fn domain(&self) -> Result<Digest, ClientError> {
        if let Some(d) = *self.domain.borrow() {
            return Ok(d);
        }
        let path = format!("/admin/v1/realms/{}", api::segment(&self.target.realm));
        let (root, _) = self.get(&path).await?;
        let d = root
            .get("domain")
            .and_then(Value::as_str)
            .and_then(|t| b64url_decode(t).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Digest)
            .ok_or(ClientError::Unexpected("surface domain"))?;
        *self.domain.borrow_mut() = Some(d);
        Ok(d)
    }

    /// Drafts and commits one write; one Exercise (TN-110).
    pub(crate) async fn write(
        &self,
        op: &Operation,
        key: Option<&str>,
        body: &Map<String, Value>,
        if_match: Option<&str>,
    ) -> Result<Written, ClientError> {
        let basis = self.target.basis;
        let domain = self.domain().await?;
        let draft_path = format!(
            "/admin/v1/realms/{}/intents",
            api::segment(&self.target.realm)
        );
        let request = json!({ "operation": op.id, "key": key, "body": body });
        let r = self.read(Method::Post, &draft_path, Some(&request)).await?;
        if r.status != 200 {
            return Err(problem(&r));
        }
        let draft = r.json();
        let checked = check_draft(&draft, op, body, &domain)?;
        let mut nonce = vec![0u8; 32];
        self.env.random().fill_bytes(&mut nonce)?;
        let statement = Statement {
            domain,
            nonce: nonce.clone(),
            intent: checked.digest,
            mode: Mode::Commit,
            pep: checked.pep,
            capacity: Capacity::Own,
            basis,
            iat: self.env.now_ms(),
            exercise: None,
        };
        let bytes = statement
            .to_bytes()
            .map_err(|_| ClientError::Draft("statement encoding"))?;
        let ais = self.key.sign_ais(&bytes)?;
        let mut headers = vec![
            (String::from("X-Access-AIS"), b64url_encode(&ais)),
            (String::from("Idempotency-Key"), b64url_encode(&nonce)),
        ];
        if let Some(tag) = if_match {
            headers.push((String::from("If-Match"), tag.to_owned()));
        }
        let r = self
            .transport
            .send(Request {
                method: op.method.as_str(),
                url: self.url(&op.url_path(&self.target.realm, key)),
                headers,
                body: Some(("application/json", checked.body.to_string().into_bytes())),
            })
            .await?;
        if !matches!(r.status, 200 | 201) {
            return Err(problem(&r));
        }
        let v = r.json();
        let text = |n: &str| v.get(n).and_then(Value::as_str).map(String::from);
        Ok(Written {
            exercise_id: text("exercise_id").ok_or(ClientError::Unexpected("exercise_id"))?,
            position: text("position").ok_or(ClientError::Unexpected("position"))?,
            body: v,
        })
    }
}

/// The `next` target of a `Link` header.
pub(crate) fn next_link(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (target, params) = part.trim().split_once(';')?;
        let next = params
            .split(';')
            .any(|p| matches!(p.trim(), "rel=\"next\"" | "rel=next"));
        next.then(|| {
            target
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_owned()
        })
    })
}

/// What a checked draft yields.
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) digest: Digest,
    pub(crate) pep: String,
    pub(crate) body: Value,
}

/// Checks a draft before anything is signed: the operation is the one asked, the domain is the
/// surface's, `intent_digest` is the digest of `intent`, and every member asked for is in the
/// drafted body unchanged. Anything else is refused (TN-110: the caller signs only what it
/// computed).
pub(crate) fn check_draft(
    draft: &Value,
    op: &Operation,
    asked: &Map<String, Value>,
    domain: &Digest,
) -> Result<Checked, ClientError> {
    let text = |n: &str| draft.get(n).and_then(Value::as_str);
    if text("operation") != Some(op.id.as_str()) || op.id == DRAFT {
        return Err(ClientError::Draft("operation"));
    }
    let named = text("domain")
        .and_then(|t| b64url_decode(t).ok())
        .ok_or(ClientError::Draft("domain"))?;
    if named.as_slice() != domain.0.as_slice() {
        return Err(ClientError::Draft("domain"));
    }
    let bytes = text("intent")
        .and_then(|t| b64url_decode(t).ok())
        .ok_or(ClientError::Draft("intent"))?;
    let envelope = IntentEnvelope::from_bytes(&bytes).map_err(|_| ClientError::Draft("intent"))?;
    let digest = intent_digest(&envelope).map_err(|_| ClientError::Draft("intent"))?;
    let claimed = text("intent_digest")
        .and_then(|t| b64url_decode(t).ok())
        .ok_or(ClientError::Draft("intent_digest"))?;
    if claimed.as_slice() != digest.0.as_slice() {
        return Err(ClientError::Draft("intent_digest"));
    }
    let body = draft
        .get("body")
        .and_then(Value::as_object)
        .ok_or(ClientError::Draft("body"))?;
    for (k, v) in asked {
        if body.get(k) != Some(v) {
            return Err(ClientError::Draft("body member changed"));
        }
    }
    let pep = text("pep")
        .filter(|p| !p.is_empty())
        .ok_or(ClientError::Draft("pep"))?
        .to_owned();
    Ok(Checked {
        digest,
        pep,
        body: Value::Object(body.clone()),
    })
}

#[cfg(test)]
mod tests;
