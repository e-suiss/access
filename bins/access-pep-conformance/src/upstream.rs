//! Fake upstreams per case: ADP, AS introspection, JWKS, Token Status List and the
//! protected resource that counts effects. Receipts and tokens are real artefacts of the
//! fixture's domain (L2-RCP-2, L2-JOS-1), so the PEP under test verifies them with the Kernel.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use access_crypto::jose::{output, sign_compact};
use access_crypto::projection::{
    AccessTokenProjection, Authority, PartyPseudonym, access_token_claims,
};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::json::{Json, b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, exercise_id};
use access_kernel::model::{
    ActionSet, AuthoritySet, Id, ResourceRef, ResourceSelector, TrustedTime,
};
use access_kernel::receipt::Receipt;
use access_kernel::status::StatusRef;
use access_kernel::validity::{ProfileVariant, Revalidation, ValidityContract};
use access_kernel::verify::dpop::ath;
use access_kernel::verify::key_scope::thumbprint;
use access_kernel::verify::projection::Confirmation;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::signer::{Signer, SoftSigner};

use crate::case::{Case, Dpop, Mode, Reply, TokenFault, TokenKind};
use crate::fixture::{ACTOR, CLIENT, Fixture, ed25519_public, hex};
use crate::protocol::{CaseMessage, Pep, Request, Upstreams};

/// Position of the decision record every receipt names.
pub const RECORD: u64 = 41;

/// Position of the `AuthorityStateBasis` every token reflects.
pub const BASIS_POS: u64 = 40;

/// Horizon of every token after `now`, milliseconds: within the fast profile.
pub const HORIZON_MS: u64 = 240_000;

/// A signed receipt and the excerpt of the key that signed it.
type SignedReceipt = (Vec<u8>, Vec<u8>);

/// Why an upstream cannot be built or a token issued.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// Key generation or signing failed.
    #[error("signing: {0}")]
    Sign(String),
    /// A model value could not be encoded.
    #[error("encoding: {0}")]
    Encode(String),
}

fn sign_err(e: impl std::fmt::Display) -> UpstreamError {
    UpstreamError::Sign(e.to_string())
}

fn encode_err(e: impl std::fmt::Display) -> UpstreamError {
    UpstreamError::Encode(e.to_string())
}

/// The fake upstreams of a run.
pub struct Upstream {
    base: String,
    fixture: Fixture,
    cases: BTreeMap<String, Case>,
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

/// The nonce of a case: 32 bytes derived from its id.
#[must_use]
pub fn nonce_of(case: &str) -> Vec<u8> {
    suiss_crypto::digest::sha256(case.as_bytes()).to_vec()
}

struct Parties;

impl access_crypto::projection::PartyRefs for Parties {
    fn pseudonym(&self, _party: &Id) -> Option<PartyPseudonym> {
        PartyPseudonym::new(ACTOR).ok()
    }
}

fn digest_text(d: &Digest) -> String {
    format!("sha-256:{}", b64url_encode(&d.0))
}

impl Upstream {
    /// Upstreams for `cases`, reachable at `base` (no trailing slash).
    #[must_use]
    pub fn new(base: &str, cases: &[Case], fixture: Fixture) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            fixture,
            cases: cases.iter().map(|c| (c.id.clone(), c.clone())).collect(),
            effects: Mutex::new(BTreeMap::new()),
        }
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

    fn issuer(&self, case: &str) -> String {
        format!("{}/{case}", self.base)
    }

    fn now_s(&self) -> u64 {
        self.fixture.now / 1000
    }

    /// The PEP's audience: the case's override or the fixture's.
    fn pep_audience(&self, case: &Case) -> String {
        case.audience
            .clone()
            .unwrap_or_else(|| self.fixture.audience.clone())
    }

    /// The audience receipts and tokens are made for: the fixture's, or another server's
    /// when the case says so.
    fn token_audience(&self, case: &Case) -> String {
        if case.token == Some(TokenFault::OtherAudience) {
            String::from("https://other-rs.example")
        } else {
            self.fixture.audience.clone()
        }
    }

    fn exercise(case: &str) -> Digest {
        Digest(suiss_crypto::digest::context_digest("access/exercise/v1", case.as_bytes()).0)
    }

    fn contract(&self, case: &Case) -> Result<ValidityContract, UpstreamError> {
        let variant = match case.kind.unwrap_or_default() {
            TokenKind::Intent => ProfileVariant::OnlineStrict,
            TokenKind::Bounds => ProfileVariant::BoundedStaleness,
        };
        let basis_ref = dcbor::encode(
            &suiss_crypto::dcbor::Value::Array(vec![
                self.fixture.domain.to_value(),
                suiss_crypto::dcbor::Value::Unsigned(BASIS_POS),
            ]),
            Limits::CEILING,
        )
        .map_err(encode_err)?;
        let envelope = &self.fixture.envelope;
        Ok(ValidityContract {
            issuing_exercise: Self::exercise(&case.id),
            basis_ref,
            holder: Digest(thumbprint(&self.fixture.holder().public_key())),
            audience: [self.token_audience(case)].into_iter().collect(),
            bounds: AuthoritySet {
                actions: ActionSet {
                    exact: [envelope.action.clone()].into_iter().collect(),
                    prefix: BTreeSet::new(),
                },
                resource: ResourceSelector::Exact(
                    envelope
                        .resources
                        .first()
                        .cloned()
                        .unwrap_or_else(|| ResourceRef {
                            namespace: "door".to_owned(),
                            path: vec!["1".to_owned()],
                            incarnation: 0,
                        }),
                ),
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            class: variant.class(),
            variant,
            profile_version: 1,
            params: BTreeMap::new(),
            horizon: self.fixture.now.saturating_add(HORIZON_MS),
            max_staleness_ms: (variant == ProfileVariant::BoundedStaleness).then_some(300_000),
            freshness_sources: BTreeSet::new(),
            revalidation: Revalidation::default(),
            offline_slice: BTreeSet::new(),
            local_requirements: BTreeSet::new(),
            verifier_profile_ref: Digest([3; 32]),
            clock_source: "monotonic_signed".to_owned(),
            clock_skew_ms: 60_000,
            must_understand: BTreeSet::new(),
            status: Some(StatusRef {
                idx: 0,
                uri: self.url(&case.id, "status"),
            }),
        })
    }

    /// The claims of the case's authority token (§9.9.3, §9.9.4, OP-150 m.9).
    fn token_claims(&self, case: &Case) -> Result<Json, UpstreamError> {
        let contract = self.contract(case)?;
        let exercise = Self::exercise(&case.id);
        let projection = AccessTokenProjection {
            issuer: &self.issuer(&case.id),
            domain: &self.fixture.domain,
            projection_exercise: &exercise,
            actor_party: &Fixture::actor_party(),
            capacity: Capacity::Own,
            validity: &contract,
            authority: match case.kind.unwrap_or_default() {
                TokenKind::Intent => Authority::Intent(&self.fixture.envelope),
                TokenKind::Bounds => Authority::Bounds,
            },
            audience: &self.token_audience(case),
            client_id: CLIENT,
            confirmation: Confirmation::Jkt(thumbprint(&self.fixture.holder().public_key())),
            iat: self.fixture.now.saturating_sub(60_000),
        };
        let Json::Object(mut claims) =
            access_token_claims(&projection, &Parties).map_err(sign_err)?
        else {
            return Err(UpstreamError::Encode(String::from("claims")));
        };
        let family = exercise.0.get(..16).unwrap_or_default();
        claims.push((String::from("family"), Json::Str(b64url_encode(family))));
        let contract_digest = suiss_crypto::digest::context_digest(
            "access/validity/v1",
            &contract.to_bytes().map_err(encode_err)?,
        );
        claims.push((
            String::from("access_contract"),
            Json::Str(digest_text(&Digest(contract_digest.0))),
        ));
        claims.push((
            String::from("status"),
            Json::Object(vec![(
                String::from("status_list"),
                Json::Object(vec![
                    (String::from("idx"), Json::Int(0)),
                    (String::from("uri"), Json::Str(self.url(&case.id, "status"))),
                ]),
            )]),
        ));
        if case.token == Some(TokenFault::Oversized) {
            claims.push((String::from("pad"), Json::Str("x".repeat(9 * 1024))));
        }
        Ok(Json::Object(claims))
    }

    fn token(&self, case: &Case) -> Result<Option<String>, UpstreamError> {
        match case.mode {
            Mode::Decision => Ok(None),
            Mode::Introspection => Ok(Some(format!("opaque.{}", case.id))),
            Mode::Jwt => {
                let claims = self.token_claims(case)?;
                let signer = self.fixture.token_signer();
                let kid = thumbprint(&signer.public_key());
                sign_compact(
                    signer,
                    &kid,
                    "at+jwt",
                    output::to_string(&claims).as_bytes(),
                )
                .map(Some)
                .map_err(sign_err)
            }
        }
    }

    fn proof(
        &self,
        signer: &SoftSigner,
        token: &str,
        jti: &str,
        request: &Request,
    ) -> Result<String, UpstreamError> {
        let x = ed25519_public(signer).map_err(sign_err)?;
        let header = json!({
            "alg": "Ed25519",
            "jwk": { "crv": "Ed25519", "kty": "OKP", "x": b64url_encode(&x) },
            "typ": "dpop+jwt",
        });
        let payload = json!({
            "ath": ath(token),
            "htm": request.method,
            "htu": request.uri,
            "iat": self.now_s().saturating_sub(1),
            "jti": jti,
        });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(payload.to_string().as_bytes())
        );
        let sig = signer.sign(input.as_bytes()).map_err(sign_err)?;
        Ok(format!("{input}.{}", b64url_encode(&sig)))
    }

    fn proofs(
        &self,
        case: &Case,
        token: &str,
        request: &Request,
    ) -> Result<Vec<String>, UpstreamError> {
        let repeat = case.repeat.unwrap_or(1);
        let holder = self.fixture.holder();
        match case.dpop.unwrap_or_default() {
            Dpop::Missing => Ok(Vec::new()),
            Dpop::Replayed => {
                let one = self.proof(holder, token, &format!("{}-0", case.id), request)?;
                Ok(vec![one; usize::try_from(repeat).unwrap_or(1)])
            }
            Dpop::Fresh | Dpop::OtherKey => {
                let signer = if case.dpop == Some(Dpop::OtherKey) {
                    self.fixture.other()
                } else {
                    holder
                };
                (0..repeat)
                    .map(|i| self.proof(signer, token, &format!("{}-{i}", case.id), request))
                    .collect()
            }
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
            .unwrap_or_else(|| hex(&self.fixture.intent.to_bytes().unwrap_or_default()));
        let token = self.token(case)?;
        let mut request = Request {
            mode: case.mode,
            evaluation: json!({
                "subject": { "type": "access_actor", "id": "-" },
                "action": { "name": "open" },
                "resource": { "type": "door", "id": "1" },
                "context": {
                    "domain": b64url_encode(&self.fixture.domain.0),
                    "mode": "commit",
                    "nonce": b64url_encode(&nonce_of(&case.id)),
                    "intent_digest": intent,
                },
            }),
            intent,
            token: token.clone(),
            method: String::from("POST"),
            uri: String::from("https://rs.example/doors/1"),
            proofs: Vec::new(),
            repeat: case.repeat.unwrap_or(1),
        };
        if let Some(t) = &token {
            request.proofs = self.proofs(case, t, &request)?;
        }
        Ok(CaseMessage {
            case: case.id.clone(),
            now: self.fixture.now,
            deadline_ms,
            pep: Pep {
                audience: self.pep_audience(case),
                domain: hex(&self.fixture.domain.to_bytes().map_err(encode_err)?),
                metadata: hex(&self.fixture.metadata),
                issuer: self.issuer(&case.id),
            },
            upstream: Upstreams {
                adp: self.url(&case.id, "access/v1/evaluation"),
                introspection: self.url(&case.id, "introspect"),
                jwks: self.url(&case.id, "jwks"),
                effect: self.url(&case.id, "effect"),
            },
            request,
        })
    }

    async fn reply(
        &self,
        case: &str,
        pick: fn(&Case) -> Option<Reply>,
        healthy: Reply,
        body: Option<&[u8]>,
    ) -> Response {
        let Some(c) = self.cases.get(case) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let reply = pick(c).unwrap_or(healthy);
        if reply == Reply::Hang {
            return std::future::pending::<Response>().await;
        }
        self.render(c, &reply, body)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }

    /// A receipt for the request's nonce: the fixture's intent and audience, this domain,
    /// record [`RECORD`] (L2-RCP-1, L2-RCP-2).
    fn receipt(&self, body: Option<&[u8]>) -> Result<Option<SignedReceipt>, UpstreamError> {
        let nonce = body
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
            .and_then(|v| {
                v.get("context")?
                    .get("nonce")?
                    .as_str()
                    .and_then(|n| b64url_decode(n).ok())
            })
            .filter(|n| (16..=64).contains(&n.len()));
        let Some(nonce) = nonce else {
            return Ok(None);
        };
        let receipt = Receipt {
            domain: self.fixture.domain,
            exercise: exercise_id(&self.fixture.domain, &nonce).map_err(encode_err)?,
            record: RECORD,
            intent: self.fixture.intent,
            instance: None,
            ais: None,
            capacity: Capacity::Own,
            basis: ExerciseBasis::Public(Id([7; 16])),
            audience: self.fixture.audience.clone(),
            iat: self.fixture.now.saturating_sub(1_000),
            drawn: false,
            agency: Vec::new(),
        };
        let payload = receipt.to_bytes().map_err(encode_err)?;
        Ok(Some(self.fixture.sign_receipt(&payload).map_err(sign_err)?))
    }

    fn render(
        &self,
        case: &Case,
        reply: &Reply,
        body: Option<&[u8]>,
    ) -> Result<Response, UpstreamError> {
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
                let mut context = json!({
                    "outcome": if *decision { "allow" } else { "deny" },
                    "versions": { "core": 1, "meta_schema": 1 },
                });
                if *receipt && let Some(m) = context.as_object_mut() {
                    // L1-ADP-7: a request without a nonce is a protocol error, 400
                    let Some((sign1, excerpt)) = self.receipt(body)? else {
                        return Ok((
                            StatusCode::BAD_REQUEST,
                            [(header::CONTENT_TYPE, "application/problem+json")],
                            json!({ "type": "about:blank", "title": "nonce", "status": 400, "code": "nonce" }).to_string(),
                        )
                            .into_response());
                    };
                    m.insert(
                        String::from("receipt"),
                        json!({
                            "sign1": b64url_encode(&sign1),
                            "excerpt": b64url_encode(&excerpt),
                        }),
                    );
                }
                axum::Json(json!({ "decision": decision, "context": context })).into_response()
            }
            Reply::Keys => {
                let signer = self.fixture.token_signer();
                let x = ed25519_public(signer).map_err(sign_err)?;
                axum::Json(json!({
                    "keys": [{
                        "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig",
                        "kid": b64url_encode(&thumbprint(&signer.public_key())),
                        "x": b64url_encode(&x),
                    }]
                }))
                .into_response()
            }
            Reply::List { stale, revoked } => {
                let (iat, exp) = if *stale {
                    (now.saturating_sub(7_200), now.saturating_sub(3_600))
                } else {
                    (now.saturating_sub(60), now.saturating_add(600))
                };
                let claims = json!({
                    "sub": self.url(&case.id, "status"),
                    "iat": iat,
                    "exp": exp,
                    "ttl": 300,
                    "as_of": BASIS_POS,
                    "status_list": {
                        "bits": 1,
                        "lst": b64url_encode(&zlib_stored(&[u8::from(*revoked)])),
                    },
                });
                let signer = self.fixture.token_signer();
                let kid = thumbprint(&signer.public_key());
                let token = sign_compact(
                    signer,
                    &kid,
                    "statuslist+jwt",
                    claims.to_string().as_bytes(),
                )
                .map_err(sign_err)?;
                (
                    [(header::CONTENT_TYPE, "application/statuslist+jwt")],
                    token,
                )
                    .into_response()
            }
        })
    }

    /// The healthy introspection answer: the token's claims, active, `at_least` the head
    /// (OP-150 m.9 (i)).
    fn introspection_answer(&self, case: &Case) -> Result<Value, UpstreamError> {
        let claims = self.token_claims(case)?;
        let mut v: Value = serde_json::from_str(&output::to_string(&claims))
            .map_err(|e| UpstreamError::Encode(e.to_string()))?;
        if let Some(m) = v.as_object_mut() {
            m.insert(String::from("active"), json!(true));
            m.insert(String::from("token_type"), json!("DPoP"));
            m.insert(
                String::from("as_of"),
                json!(BASIS_POS.saturating_add(2).to_string()),
            );
            m.insert(
                String::from("exercise"),
                json!(b64url_encode(&Self::exercise(&case.id).0)),
            );
        }
        Ok(v)
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

async fn adp(State(u): Shared, Path(case): Path<String>, body: Bytes) -> Response {
    let healthy = Reply::Decision {
        decision: true,
        receipt: true,
    };
    u.reply(&case, |c| c.adp.clone(), healthy, Some(&body))
        .await
}

async fn introspection(State(u): Shared, Path(case): Path<String>) -> Response {
    let Some(c) = u.cases.get(&case) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(body) = u.introspection_answer(c) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let healthy = Reply::Json { status: 200, body };
    u.reply(&case, |c| c.introspection.clone(), healthy, None)
        .await
}

async fn jwks(State(u): Shared, Path(case): Path<String>) -> Response {
    u.reply(&case, |c| c.jwks.clone(), Reply::Keys, None).await
}

async fn status_list(State(u): Shared, Path(case): Path<String>) -> Response {
    let healthy = Reply::List {
        stale: false,
        revoked: false,
    };
    u.reply(&case, |c| c.status_list.clone(), healthy, None)
        .await
}

async fn effect(State(u): Shared, Path(case): Path<String>) -> StatusCode {
    u.count_effect(&case)
}

/// The time a token of the fixture expires, seconds.
#[must_use]
pub const fn token_exp_s(now_ms: TrustedTime) -> u64 {
    now_ms.saturating_add(HORIZON_MS) / 1000
}
