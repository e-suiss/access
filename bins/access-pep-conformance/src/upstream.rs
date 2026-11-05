//! Fake upstreams per case: ADP, AS introspection, JWKS, Token Status List and the
//! protected resource that counts effects.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use access_kernel::json::b64url_encode;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer, SoftSigner};

use crate::case::{Case, Mode, Reply};
use crate::fixture::{Fixture, hex};
use crate::protocol::{CaseMessage, Pep, Request, Upstreams};

/// Key ID of the token signing key.
pub const KID: &str = "pep-conformance-1";

/// Why an upstream cannot be built or a token issued.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// Key generation or signing failed.
    #[error("signing: {0}")]
    Sign(String),
}

/// The fake upstreams of a run.
pub struct Upstream {
    base: String,
    fixture: Fixture,
    cases: BTreeMap<String, Case>,
    signer: SoftSigner,
    public: [u8; 32],
    effects: Mutex<BTreeMap<String, u32>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("base", &self.base)
            .field("cases", &self.cases.len())
            .finish_non_exhaustive()
    }
}

/// zlib (RFC 1950) of `data` in one stored DEFLATE block, as the Token Status List
/// carries it.
#[must_use]
pub fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let data = data.get(..usize::from(len)).unwrap_or_default();
    let (mut a, mut b) = (1_u32, 0_u32);
    for &byte in data {
        a = a.wrapping_add(u32::from(byte)) % 65_521;
        b = b.wrapping_add(a) % 65_521;
    }
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

impl Upstream {
    /// Upstreams for `cases`, reachable at `base` (no trailing slash).
    ///
    /// # Errors
    /// [`UpstreamError::Sign`].
    pub fn new(base: &str, cases: &[Case], fixture: Fixture) -> Result<Self, UpstreamError> {
        let (signer, _) =
            SoftSigner::generate_ed25519().map_err(|e| UpstreamError::Sign(e.to_string()))?;
        let PublicKey::Ed25519(public) = signer.public_key() else {
            return Err(UpstreamError::Sign(String::from("not an Ed25519 key")));
        };
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            fixture,
            cases: cases.iter().map(|c| (c.id.clone(), c.clone())).collect(),
            signer,
            public,
            effects: Mutex::new(BTreeMap::new()),
        })
    }

    /// The fixture the ADP speaks for.
    #[must_use]
    pub const fn fixture(&self) -> &Fixture {
        &self.fixture
    }

    /// The routes of every case.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/{case}/access/v1/evaluation", post(adp))
            .route("/{case}/introspect", post(introspection))
            .route("/{case}/jwks", get(jwks))
            .route("/{case}/status", get(status_list))
            .route("/{case}/effect", post(effect))
            .with_state(self)
    }

    /// Effects the resource received for `case`.
    #[must_use]
    pub fn effects(&self, case: &str) -> u32 {
        self.effects
            .lock()
            .map_or(u32::MAX, |m| m.get(case).copied().unwrap_or(0))
    }

    fn url(&self, case: &str, path: &str) -> String {
        format!("{}/{case}/{path}", self.base)
    }

    fn now_s(&self) -> u64 {
        self.fixture.now / 1000
    }

    fn audience(&self, case: &Case) -> String {
        case.audience
            .clone()
            .unwrap_or_else(|| self.fixture.audience.clone())
    }

    fn jws(&self, typ: &str, claims: &Value) -> Result<String, UpstreamError> {
        let header = json!({ "alg": "Ed25519", "typ": typ, "kid": KID });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let sig = self
            .signer
            .sign(input.as_bytes())
            .map_err(|e| UpstreamError::Sign(e.to_string()))?;
        Ok(format!("{input}.{}", b64url_encode(&sig)))
    }

    fn token(&self, case: &Case) -> Result<Option<String>, UpstreamError> {
        let now = self.now_s();
        match case.mode {
            Mode::Decision => Ok(None),
            Mode::Introspection => Ok(Some(format!("opaque.{}", case.id))),
            Mode::Jwt => self
                .jws(
                    "at+jwt",
                    &json!({
                        "iss": self.url(&case.id, "").trim_end_matches('/'),
                        "aud": self.audience(case),
                        "sub": "conformance-actor",
                        "client_id": "conformance",
                        "iat": now.saturating_sub(60),
                        "exp": now.saturating_add(300),
                        "jti": case.id,
                        "status": { "status_list": { "idx": 0, "uri": self.url(&case.id, "status") } },
                    }),
                )
                .map(Some),
        }
    }

    /// The message the adapter receives for `case`.
    ///
    /// # Errors
    /// [`UpstreamError`].
    pub fn message(&self, case: &Case, deadline_ms: u64) -> Result<CaseMessage, UpstreamError> {
        let intent = case
            .intent
            .clone()
            .unwrap_or_else(|| hex(&self.fixture.intent));
        Ok(CaseMessage {
            case: case.id.clone(),
            now: self.fixture.now,
            deadline_ms,
            pep: Pep {
                audience: self.audience(case),
                domain: hex(&self.fixture.domain),
                metadata: hex(&self.fixture.metadata),
                issuer: format!("{}/{}", self.base, case.id),
            },
            upstream: Upstreams {
                adp: self.url(&case.id, "access/v1/evaluation"),
                introspection: self.url(&case.id, "introspect"),
                jwks: self.url(&case.id, "jwks"),
                effect: self.url(&case.id, "effect"),
            },
            request: Request {
                mode: case.mode,
                evaluation: json!({
                    "subject": { "type": "instance", "id": "conformance-actor" },
                    "action": { "name": "door.open" },
                    "resource": { "type": "door", "id": "1" },
                    "context": { "intent_digest": intent },
                }),
                intent,
                token: self.token(case)?,
            },
        })
    }

    async fn reply(
        &self,
        case: &str,
        pick: fn(&Case) -> Option<Reply>,
        healthy: Reply,
    ) -> Response {
        let Some(c) = self.cases.get(case) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let reply = pick(c).unwrap_or(healthy);
        if reply == Reply::Hang {
            return std::future::pending::<Response>().await;
        }
        self.render(c, &reply)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }

    fn render(&self, case: &Case, reply: &Reply) -> Result<Response, UpstreamError> {
        let now = self.now_s();
        Ok(match reply {
            Reply::Status { status: code } => (
                status(*code),
                [(header::CONTENT_TYPE, "application/problem+json")],
                json!({ "type": "about:blank", "title": "conformance fault", "status": code })
                    .to_string(),
            )
                .into_response(),
            Reply::Raw { status: code, body } => (status(*code), body.clone()).into_response(),
            Reply::Json { status: code, body } => {
                (status(*code), axum::Json(body.clone())).into_response()
            }
            Reply::Hang => StatusCode::GATEWAY_TIMEOUT.into_response(),
            Reply::Decision { decision, receipt } => {
                let mut context = json!({ "versions": { "core": 1, "meta_schema": 1 } });
                if *receipt && let Some(m) = context.as_object_mut() {
                    m.insert(
                        String::from("receipt"),
                        json!({
                            "sign1": b64url_encode(&self.fixture.sign1),
                            "excerpt": b64url_encode(&self.fixture.excerpt),
                        }),
                    );
                }
                axum::Json(json!({ "decision": decision, "context": context })).into_response()
            }
            Reply::Keys => axum::Json(json!({
                "keys": [{
                    "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig",
                    "kid": KID, "x": b64url_encode(&self.public),
                }]
            }))
            .into_response(),
            Reply::List { stale, revoked } => {
                let (iat, exp) = if *stale {
                    (now.saturating_sub(7_200), now.saturating_sub(3_600))
                } else {
                    (now.saturating_sub(60), now.saturating_add(600))
                };
                let token = self.jws(
                    "statuslist+jwt",
                    &json!({
                        "sub": self.url(&case.id, "status"),
                        "iat": iat,
                        "exp": exp,
                        "ttl": 300,
                        "status_list": {
                            "bits": 1,
                            "lst": b64url_encode(&zlib_stored(&[u8::from(*revoked)])),
                        },
                    }),
                )?;
                (
                    [(header::CONTENT_TYPE, "application/statuslist+jwt")],
                    token,
                )
                    .into_response()
            }
        })
    }

    fn count_effect(&self, case: &str) -> StatusCode {
        if !self.cases.contains_key(case) {
            return StatusCode::NOT_FOUND;
        }
        match self.effects.lock() {
            Ok(mut m) => {
                let n = m.entry(case.to_owned()).or_insert(0);
                *n = n.saturating_add(1);
                StatusCode::NO_CONTENT
            }
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

type Shared = State<Arc<Upstream>>;

async fn adp(State(u): Shared, Path(case): Path<String>) -> Response {
    let healthy = Reply::Decision {
        decision: true,
        receipt: true,
    };
    u.reply(&case, |c| c.adp.clone(), healthy).await
}

async fn introspection(State(u): Shared, Path(case): Path<String>) -> Response {
    let Some(c) = u.cases.get(&case) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = u.now_s();
    let healthy = Reply::Json {
        status: 200,
        body: json!({
            "active": true,
            "aud": u.audience(c),
            "sub": "conformance-actor",
            "client_id": "conformance",
            "token_type": "Bearer",
            "iat": now.saturating_sub(60),
            "exp": now.saturating_add(300),
        }),
    };
    u.reply(&case, |c| c.introspection.clone(), healthy).await
}

async fn jwks(State(u): Shared, Path(case): Path<String>) -> Response {
    u.reply(&case, |c| c.jwks.clone(), Reply::Keys).await
}

async fn status_list(State(u): Shared, Path(case): Path<String>) -> Response {
    let healthy = Reply::List {
        stale: false,
        revoked: false,
    };
    u.reply(&case, |c| c.status_list.clone(), healthy).await
}

async fn effect(State(u): Shared, Path(case): Path<String>) -> StatusCode {
    u.count_effect(&case)
}
