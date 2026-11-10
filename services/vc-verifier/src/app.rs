//! The verifier's use cases (OP-155 m.3 (p); Ek B 4831–4835, 4837, 4921, 4982): open a
//! presentation request, serve its signed request object, verify the wallet's encrypted answer
//! and send what it proves to Claim Ingest, and tell the caller that started it how it ended.
//! Every check fails closed: without trusted time, fresh trusted lists, a resolvable issuer key,
//! a readable valid status or an exact DCQL match, nothing is sent to Access.

use std::sync::RwLock;

use access_kernel::claim::{CONTENT_TYPE, claim_id};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::{Json, b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{Signer, sign_sign1};

use crate::domain::claims::{self, Reporter, Verified};
use crate::domain::dcql::{CredentialQuery, Format, Query};
use crate::domain::did::{self, Resolution};
use crate::domain::presentation;
use crate::domain::request::{self, Mode, Object};
use crate::domain::sd_jwt_vc::{self, Rules};
use crate::domain::status::{self, Reference};
use crate::domain::trust::{self, Standing, TrustedLists};
use crate::domain::{jwe, mdoc, x509};
use crate::ports::{Access, Answer, Clock, Fetch, Random};
use crate::store::{OutcomeRow, RequestRow, Store, StoreError};

/// How long a request stays open, milliseconds.
pub const REQUEST_TTL_MS: u64 = 10 * 60 * 1000;
/// Clock skew allowed on credential times, milliseconds.
pub const SKEW_MS: u64 = 60_000;
/// How old a key binding may be, milliseconds.
pub const KB_MAX_AGE_MS: u64 = 5 * 60 * 1000;
/// Largest fetched document the verifier reads.
pub const MAX_FETCH: usize = 4 * 1024 * 1024;

/// The verifier's configuration.
pub struct Config {
    /// The verifier's public origin, `https://host[:port]`.
    pub origin: String,
    /// The verifier's certificate chain, leaf first; its leaf names the `client_id`.
    pub chain: Vec<Vec<u8>>,
    /// The secret the per-request response keys derive from.
    pub response_secret: Secret<[u8; 32]>,
    /// The Claims' issuer and signer.
    pub reporter: Reporter,
    /// SHA-256 of each caller key allowed to open requests.
    pub callers: Vec<[u8; 32]>,
    /// Issuers trusted outside the trusted lists (`did:web`, `did:jwk` or `https` with JWT VC
    /// issuer metadata); never PID providers.
    pub issuers: Vec<String>,
}

/// Why a use case did not complete.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifierError {
    /// The input is not in the contract.
    #[error("{0}")]
    Malformed(&'static str),
    /// The caller is not one of the configured callers, or not the one that opened it.
    #[error("caller-unauthenticated")]
    Caller,
    /// No such request, or not the caller's.
    #[error("request-unknown")]
    Unknown,
    /// The request expired.
    #[error("request-expired")]
    Expired,
    /// The request already has its outcome.
    #[error("request-answered")]
    Answered,
    /// A dependency is not available; nothing was recorded.
    #[error("{0}")]
    Unavailable(String),
}

impl VerifierError {
    /// Stable code.
    #[must_use]
    pub fn code(&self) -> String {
        self.to_string()
    }
}

impl From<StoreError> for VerifierError {
    fn from(_: StoreError) -> Self {
        Self::Unavailable(String::from("verifier-store"))
    }
}

/// A request to open.
#[derive(Clone, Debug)]
pub struct Open {
    /// The domain the Claims are for.
    pub domain: [u8; 32],
    /// The subject Party the presentation is about.
    pub subject: [u8; 16],
    /// The DCQL query.
    pub query: Value,
    /// How the wallet is reached.
    pub mode: Mode,
    /// For `same-device`: where the wallet sends the person back.
    pub return_uri: Option<String>,
}

/// An opened request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The request id, base64url.
    pub request: String,
    /// The `request_uri` the wallet fetches.
    pub request_uri: String,
    /// The `openid4vp://` link (same device) or QR content (cross device).
    pub wallet_link: String,
    /// Expiry, milliseconds.
    pub expires_ms: u64,
}

/// The verifier.
pub struct Verifier<A, F, C, R, S> {
    store: Store,
    access: A,
    fetch: F,
    clock: C,
    random: R,
    signer: S,
    config: Config,
    lists: RwLock<TrustedLists>,
}

/// The issuer key a credential was checked with, and how far it is trusted.
struct Issuer {
    key: PublicKey,
    standing: Standing,
    name: String,
}

/// One verified credential.
struct Checked {
    verified: Verified,
    standing: Standing,
    format: Format,
}

fn refusal(code: impl Into<String>) -> Refused {
    Refused(code.into())
}

/// A presentation refused, with its stable code.
#[derive(Debug)]
struct Refused(String);

fn random_text(bytes: [u8; 16]) -> String {
    b64url_encode(&bytes)
}

fn caller_digest(key: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(key.as_bytes())
}

fn body_of(a: &Answer) -> Option<(u16, &[u8])> {
    match a {
        Answer::Response(r) => Some((r.status, r.body.as_slice())),
        Answer::Unanswered(_) => None,
    }
}

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    Some(authority.split(':').next().unwrap_or(authority))
}

impl<A, F, C, R, S> Verifier<A, F, C, R, S>
where
    A: Access,
    F: Fetch,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    /// A verifier over its store, ports and signer.
    pub fn new(
        store: Store,
        (access, fetch): (A, F),
        (clock, random, signer): (C, R, S),
        config: Config,
    ) -> Self {
        Self {
            store,
            access,
            fetch,
            clock,
            random,
            signer,
            config,
            lists: RwLock::new(TrustedLists::default()),
        }
    }

    /// The `client_id`.
    #[must_use]
    pub fn client_id(&self) -> String {
        self.config
            .chain
            .first()
            .map(|leaf| request::client_id(leaf))
            .unwrap_or_default()
    }

    fn now(&self) -> Result<u64, VerifierError> {
        self.clock
            .now()
            .ok_or_else(|| VerifierError::Unavailable(String::from("trusted-time")))
    }

    fn fresh(&self) -> Result<[u8; 16], VerifierError> {
        self.random
            .bytes()
            .ok_or_else(|| VerifierError::Unavailable(String::from("random")))
    }

    /// Checks a caller key against the configured ones.
    ///
    /// # Errors
    /// [`VerifierError::Caller`].
    pub fn authenticate(&self, key: &str) -> Result<[u8; 32], VerifierError> {
        let d = caller_digest(key);
        let known = self
            .config
            .callers
            .iter()
            .fold(false, |acc, c| acc | Secret::new(*c).ct_eq_bytes(&d));
        if known && !key.is_empty() {
            Ok(d)
        } else {
            Err(VerifierError::Caller)
        }
    }

    /// Installs a trusted list snapshot and keeps it.
    ///
    /// # Errors
    /// [`VerifierError::Unavailable`].
    pub async fn install_lists(&self, lists: TrustedLists) -> Result<(), VerifierError> {
        let now = self.now()?;
        let snapshot = serde_json::to_string(&lists)
            .map_err(|_| VerifierError::Unavailable(String::from("encode")))?;
        self.store.put_lists(now, &snapshot).await?;
        if let Ok(mut l) = self.lists.write() {
            *l = lists;
        }
        Ok(())
    }

    /// Loads the latest kept snapshot, after a restart.
    ///
    /// # Errors
    /// [`VerifierError::Unavailable`].
    pub async fn restore_lists(&self) -> Result<(), VerifierError> {
        if let Some(s) = self.store.latest_lists().await?
            && let Ok(lists) = serde_json::from_str::<TrustedLists>(&s)
            && let Ok(mut l) = self.lists.write()
        {
            *l = lists;
        }
        Ok(())
    }

    /// The trusted lists' state (`getTrustedListState`): never the certificates themselves.
    #[must_use]
    pub fn list_state(&self) -> Value {
        let now = self.clock.now().unwrap_or(0);
        let Ok(l) = self.lists.read() else {
            return json!({ "usable": false });
        };
        let pid = l
            .services
            .iter()
            .filter(|s| s.standing() == Some(Standing::Pid))
            .count();
        let eaa = l
            .services
            .iter()
            .filter(|s| s.standing() == Some(Standing::Attestation))
            .count();
        json!({
            "sequence": l.sequence,
            "next_update_ms": l.next_update_ms,
            "signature_verified": l.signature_verified,
            "usable": l.usable(now),
            "digests": l.digests.iter().map(|d| b64url_encode(d)).collect::<Vec<_>>(),
            "granted_pid_providers": pid,
            "granted_attestation_providers": eaa,
        })
    }

    /// Opens a request (`createPresentationRequest`).
    ///
    /// # Errors
    /// [`VerifierError`].
    pub async fn open(&self, caller_key: &str, o: Open) -> Result<Opened, VerifierError> {
        let caller = self.authenticate(caller_key)?;
        let query = Query::parse(&o.query).map_err(|e| VerifierError::Malformed(e.code()))?;
        let return_uri = match (o.mode, o.return_uri) {
            (Mode::SameDevice, Some(u))
                if u.starts_with("https://")
                    && u.len() <= 2048
                    && !u.contains(['#', ' ', '\r', '\n']) =>
            {
                Some(u)
            }
            (Mode::CrossDevice, None) => None,
            _ => return Err(VerifierError::Malformed("return-uri")),
        };
        let now = self.now()?;
        let request = self.fresh()?;
        let row = RequestRow {
            request,
            caller,
            domain: o.domain,
            subject: o.subject,
            mode: String::from(o.mode.name()),
            query: query.to_json().to_string(),
            nonce: random_text(self.fresh()?),
            state: random_text(self.fresh()?),
            return_uri,
            created_ms: now,
            expires_ms: now.saturating_add(REQUEST_TTL_MS),
        };
        self.store.open(&row).await?;
        let id = b64url_encode(&request);
        let request_uri = format!("{}/vc-verifier/v1/requests/{id}", self.config.origin);
        Ok(Opened {
            wallet_link: request::wallet_link(&self.client_id(), &request_uri),
            request: id,
            request_uri,
            expires_ms: row.expires_ms,
        })
    }

    async fn open_row(&self, id: &str) -> Result<RequestRow, VerifierError> {
        let request: [u8; 16] = b64url_decode(id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(VerifierError::Unknown)?;
        let (row, outcome) = self
            .store
            .get(&request)
            .await?
            .ok_or(VerifierError::Unknown)?;
        if outcome.is_some() {
            return Err(VerifierError::Answered);
        }
        if self.now()? > row.expires_ms {
            return Err(VerifierError::Expired);
        }
        Ok(row)
    }

    fn response_uri(&self, row: &RequestRow) -> String {
        format!(
            "{}/vc-verifier/v1/responses/{}",
            self.config.origin,
            b64url_encode(&row.request)
        )
    }

    /// The signed request object (`getRequestObject`).
    ///
    /// # Errors
    /// [`VerifierError`].
    pub async fn request_object(&self, id: &str) -> Result<String, VerifierError> {
        let row = self.open_row(id).await?;
        let query = serde_json::from_str::<Value>(&row.query)
            .ok()
            .and_then(|v| Query::parse(&v).ok())
            .ok_or(VerifierError::Unavailable(String::from("verifier-store")))?;
        let key = jwe::response_key(&self.config.response_secret, &row.request)
            .map_err(|_| VerifierError::Unavailable(String::from("response-key")))?;
        let (x, y, thumb) = jwe::public_jwk(&key)
            .map_err(|_| VerifierError::Unavailable(String::from("response-key")))?;
        let kid = b64url_encode(&thumb);
        let client_id = self.client_id();
        let response_uri = self.response_uri(&row);
        let object = Object {
            client_id: &client_id,
            response_uri: &response_uri,
            nonce: &row.nonce,
            state: &row.state,
            query: &query,
            key: (&x, &y, &kid),
            now_ms: self.now()?,
        };
        object
            .sign(&self.signer, &self.config.chain)
            .map_err(|_| VerifierError::Unavailable(String::from("sign")))
    }

    /// Verifies the wallet's encrypted answer (`postWalletResponse`) and sends what it proves to
    /// Claim Ingest. Answers the `redirect_uri` a same-device wallet returns to.
    ///
    /// # Errors
    /// [`VerifierError`]; a refused presentation is an outcome, not an error.
    pub async fn respond(&self, id: &str, response: &str) -> Result<Option<String>, VerifierError> {
        let row = self.open_row(id).await?;
        let now = self.now()?;
        let outcome = match self.verify(&row, response, now).await {
            Ok(checked) => self.ingest(&row, &checked, now).await?,
            Err(Refused(code)) => (String::from("refused"), Some(code), json!({})),
        };
        let (redirect, response_code) = match &row.return_uri {
            Some(uri) => {
                let code = random_text(self.fresh()?);
                (
                    Some(format!("{uri}#response_code={code}")),
                    Some(suiss_crypto::digest::sha256(code.as_bytes())),
                )
            }
            None => (None, None),
        };
        let recorded = self
            .store
            .record(
                &row.request,
                &OutcomeRow {
                    outcome: outcome.0,
                    reason: outcome.1,
                    detail: outcome.2.to_string(),
                    response_code,
                    recorded_ms: now,
                },
            )
            .await?;
        if !recorded {
            return Err(VerifierError::Answered);
        }
        Ok(redirect)
    }

    /// The outcome for the caller that opened the request (`getPresentationResult`): never a
    /// disclosed value. A same-device request needs the response code the wallet returned with.
    ///
    /// # Errors
    /// [`VerifierError`].
    pub async fn result(
        &self,
        caller_key: &str,
        id: &str,
        response_code: Option<&str>,
    ) -> Result<Value, VerifierError> {
        let caller = self.authenticate(caller_key)?;
        let request: [u8; 16] = b64url_decode(id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(VerifierError::Unknown)?;
        let (row, outcome) = self
            .store
            .get(&request)
            .await?
            .ok_or(VerifierError::Unknown)?;
        if !Secret::new(row.caller).ct_eq_bytes(&caller) {
            return Err(VerifierError::Unknown);
        }
        let Some(o) = outcome else {
            let state = if self.now()? > row.expires_ms {
                "expired"
            } else {
                "pending"
            };
            return Ok(json!({ "request": id, "mode": row.mode, "state": state }));
        };
        if let Some(expected) = o.response_code {
            let given = response_code.map(|c| suiss_crypto::digest::sha256(c.as_bytes()));
            if !given.is_some_and(|g| Secret::new(expected).ct_eq_bytes(&g)) {
                return Err(VerifierError::Unknown);
            }
        }
        let mut v = json!({ "request": id, "mode": row.mode, "state": o.outcome });
        if let (Some(reason), Some(m)) = (o.reason, v.as_object_mut()) {
            m.insert(String::from("reason"), Value::from(reason));
        }
        if let (Ok(Value::Object(detail)), Some(m)) =
            (serde_json::from_str::<Value>(&o.detail), v.as_object_mut())
        {
            m.extend(detail);
        }
        Ok(v)
    }

    async fn verify(
        &self,
        row: &RequestRow,
        response: &str,
        now: u64,
    ) -> Result<Vec<Checked>, Refused> {
        let query = serde_json::from_str::<Value>(&row.query)
            .ok()
            .and_then(|v| Query::parse(&v).ok())
            .ok_or_else(|| refusal("request-corrupt"))?;
        let key = jwe::response_key(&self.config.response_secret, &row.request)
            .map_err(|e| refusal(e.to_string()))?;
        let (_, _, thumb) = jwe::public_jwk(&key).map_err(|e| refusal(e.to_string()))?;
        let params = jwe::decrypt(response, &key, &b64url_encode(&thumb))
            .map_err(|e| refusal(e.to_string()))?;
        let presentations = presentation::presentations(&params, &query, &row.state)
            .map_err(|e| refusal(e.code()))?;
        let mut out = Vec::with_capacity(presentations.len());
        for (c, p) in query.credentials.iter().zip(presentations.iter()) {
            let checked = match c.format {
                Format::SdJwtVc => self.sd_jwt(row, c, p, now).await?,
                Format::Mdoc => self.mdoc(row, c, p, &thumb, now).await?,
            };
            out.push(checked);
        }
        Ok(out)
    }

    fn anchors(&self, now: u64) -> (Vec<Vec<u8>>, Vec<Standing>) {
        self.lists
            .read()
            .map(|l| l.anchors(now))
            .unwrap_or_default()
    }

    async fn fetch(&self, url: String, accept: &'static str) -> Result<Vec<u8>, Refused> {
        let a = self.fetch.get(url, accept).await;
        match body_of(&a) {
            Some((200, body)) if body.len() <= MAX_FETCH => Ok(body.to_vec()),
            _ => Err(refusal("fetch-failed")),
        }
    }

    async fn keyed_issuer(&self, iss: &str, kid: &str) -> Result<PublicKey, Refused> {
        if !self.config.issuers.iter().any(|i| i == iss) {
            return Err(refusal("issuer-untrusted"));
        }
        if iss.starts_with("did:") {
            let (did, _) = did::split(kid);
            if did != iss {
                return Err(refusal("issuer-binding"));
            }
            return match did::resolution(did).map_err(|e| refusal(e.to_string()))? {
                Resolution::Jwk(k) => Ok(k),
                Resolution::Web(url) => {
                    let body = self.fetch(url, "application/did+json").await?;
                    did::key_in_document(&body, did, kid).map_err(|e| refusal(e.to_string()))
                }
            };
        }
        let host = host_of(iss).ok_or_else(|| refusal("issuer-untrusted"))?;
        let path = iss
            .strip_prefix("https://")
            .and_then(|r| r.find('/').and_then(|i| r.get(i..)))
            .unwrap_or("");
        let url = format!("https://{host}/.well-known/jwt-vc-issuer{path}");
        let body = self.fetch(url, "application/json").await?;
        let meta =
            access_kernel::json::parse(&body, 64 * 1024).map_err(|_| refusal("issuer-metadata"))?;
        if meta.get("issuer").and_then(Json::as_str) != Some(iss) {
            return Err(refusal("issuer-metadata"));
        }
        let keys = match meta.get("jwks").and_then(|j| j.get("keys")) {
            Some(Json::Array(k)) => k.as_slice(),
            _ => return Err(refusal("issuer-metadata")),
        };
        keys.iter()
            .filter(|k| k.get("kid").and_then(Json::as_str) == Some(kid))
            .find_map(sd_jwt_vc::jwk_p256)
            .ok_or_else(|| refusal("issuer-key"))
    }

    async fn sd_jwt_issuer(
        &self,
        header: &sd_jwt_vc::Header,
        iss: &str,
        now: u64,
    ) -> Result<Issuer, Refused> {
        if !header.x5c.is_empty() {
            let (anchors, standing) = self.anchors(now);
            if anchors.is_empty() {
                return Err(refusal("trusted-list-unusable"));
            }
            let (key, i) = x509::trusted(&header.x5c, &anchors, now, x509::Usage::SdJwtIssuer)
                .map_err(|e| refusal(e.to_string()))?;
            let leaf = header.x5c.first().ok_or_else(|| refusal("issuer-chain"))?;
            if !binds(leaf, iss) {
                return Err(refusal("issuer-binding"));
            }
            return Ok(Issuer {
                key,
                standing: standing
                    .get(i)
                    .copied()
                    .ok_or_else(|| refusal("issuer-untrusted"))?,
                name: String::from(iss),
            });
        }
        let kid = header.kid.as_deref().ok_or_else(|| refusal("issuer-key"))?;
        Ok(Issuer {
            key: self.keyed_issuer(iss, kid).await?,
            standing: Standing::Listed,
            name: String::from(iss),
        })
    }

    async fn status(
        &self,
        reference: Option<Reference>,
        issuer: &Issuer,
        now: u64,
    ) -> Result<(), Refused> {
        let Some(r) = reference else {
            return Ok(());
        };
        let accept = match r {
            Reference::TokenList { .. } => "application/statuslist+jwt",
            Reference::Bitstring { .. } => "application/vc+jwt",
        };
        let body = self.fetch(String::from(r.uri()), accept).await?;
        let text = std::str::from_utf8(&body).map_err(|_| refusal("status-list"))?;
        let list = status::parse(text.trim()).map_err(|e| refusal(e.code()))?;
        let key = if list.x5c.is_empty() {
            let kid = list.kid.as_deref().ok_or_else(|| refusal("status-list"))?;
            if issuer.standing != Standing::Listed {
                return Err(refusal("status-list"));
            }
            self.keyed_issuer(&issuer.name, kid).await?
        } else {
            let (anchors, _) = self.anchors(now);
            x509::trusted(&list.x5c, &anchors, now, x509::Usage::SdJwtIssuer)
                .map_err(|_| refusal("status-list"))?
                .0
        };
        list.check(&PureBackend, &key, &r, now)
            .map_err(|e| refusal(e.code()))
    }

    async fn sd_jwt(
        &self,
        row: &RequestRow,
        c: &CredentialQuery,
        p: &str,
        now: u64,
    ) -> Result<Checked, Refused> {
        let parsed = sd_jwt_vc::parse(p).map_err(|e| refusal(e.code()))?;
        let iss = parsed
            .issuer()
            .map(String::from)
            .ok_or_else(|| refusal("sd-jwt-claims"))?;
        let issuer = self.sd_jwt_issuer(&parsed.header, &iss, now).await?;
        let client_id = self.client_id();
        let presented = parsed
            .verify(
                &PureBackend,
                &issuer.key,
                &Rules {
                    audience: &client_id,
                    nonce: &row.nonce,
                    now,
                    skew_ms: SKEW_MS,
                    kb_max_age_ms: KB_MAX_AGE_MS,
                },
            )
            .map_err(|e| refusal(e.code()))?;
        let vct = parsed.vct().unwrap_or_default().to_owned();
        let values = presentation::check(c, &vct, &presented.claims, &presented.disclosed)
            .map_err(|e| refusal(e.code()))?;
        let reference = status::reference(&presented.claims).map_err(|e| refusal(e.code()))?;
        self.status(reference, &issuer, now).await?;
        let until = parsed
            .payload
            .get("exp")
            .and_then(Json::as_int)
            .and_then(|e| u64::try_from(e).ok())
            .and_then(|e| e.checked_mul(1000))
            .unwrap_or(now);
        Ok(Self::checked(
            row,
            (Format::SdJwtVc, &vct),
            &issuer,
            values,
            until,
        ))
    }

    async fn mdoc(
        &self,
        row: &RequestRow,
        c: &CredentialQuery,
        p: &str,
        thumb: &[u8; 32],
        now: u64,
    ) -> Result<Checked, Refused> {
        let bytes = b64url_decode(p).map_err(|_| refusal("mdoc-malformed"))?;
        let parsed = mdoc::parse(&bytes).map_err(|e| refusal(e.code()))?;
        let (anchors, standing) = self.anchors(now);
        if anchors.is_empty() {
            return Err(refusal("trusted-list-unusable"));
        }
        let (key, i) = x509::trusted(&parsed.chain, &anchors, now, x509::Usage::MdocSigner)
            .map_err(|e| refusal(e.to_string()))?;
        let transcript = mdoc::session_transcript(
            &self.client_id(),
            &row.nonce,
            thumb,
            &self.response_uri(row),
        );
        let presented = parsed
            .verify(&PureBackend, &key, &transcript, now, SKEW_MS)
            .map_err(|e| refusal(e.code()))?;
        let values =
            presentation::check(c, &parsed.doctype, &presented.claims, &presented.disclosed)
                .map_err(|e| refusal(e.code()))?;
        let leaf = parsed
            .chain
            .first()
            .ok_or_else(|| refusal("issuer-chain"))?;
        let issuer = Issuer {
            key,
            standing: standing
                .get(i)
                .copied()
                .ok_or_else(|| refusal("issuer-untrusted"))?,
            name: format!(
                "x5t#S256:{}",
                b64url_encode(&suiss_crypto::digest::sha256(leaf))
            ),
        };
        let reference = presented
            .status
            .map(|(idx, uri)| Reference::TokenList { idx, uri });
        self.status(reference, &issuer, now).await?;
        let until = presented.until;
        Ok(Self::checked(
            row,
            (Format::Mdoc, &parsed.doctype),
            &issuer,
            values,
            until,
        ))
    }

    fn checked(
        row: &RequestRow,
        (format, credential_type): (Format, &str),
        issuer: &Issuer,
        values: Vec<(crate::domain::dcql::Path, Json)>,
        until: u64,
    ) -> Checked {
        let loa = trust::loa_eidas(issuer.standing, format, credential_type);
        Checked {
            verified: Verified {
                domain: Digest(row.domain),
                subject: Id(row.subject),
                issuer: issuer.name.clone(),
                credential_type: String::from(credential_type),
                pid: loa.is_some(),
                loa_eidas: loa,
                values,
                until,
            },
            standing: issuer.standing,
            format,
        }
    }

    async fn ingest(
        &self,
        row: &RequestRow,
        checked: &[Checked],
        now: u64,
    ) -> Result<(String, Option<String>, Value), VerifierError> {
        let kid = thumbprint(&self.signer.public_key());
        let mut sent = Vec::new();
        let mut credentials = Vec::new();
        for c in checked {
            credentials.push(json!({
                "format": c.format.name(),
                "type": c.verified.credential_type,
                "issuer_standing": c.standing.name(),
                "loa_eidas": c.verified.loa_eidas,
                "evidence": b64url_encode(&claims::evidence(&c.verified).0),
            }));
            for report in claims::reports(&c.verified, self.config.reporter, now) {
                let payload = report
                    .statement
                    .to_bytes()
                    .map_err(|_| VerifierError::Unavailable(String::from("encode")))?;
                let claim = sign_sign1(&self.signer, kid, CONTENT_TYPE, &payload)
                    .map_err(|_| VerifierError::Unavailable(String::from("sign")))?;
                let id = claim_id(&claim);
                let mut body = json!({
                    "domain": format!("sha-256:{}", b64url_encode(&row.domain)),
                    "carrier": "cose",
                    "claim": b64url_encode(&claim),
                });
                if let (Some(b), Some(m)) = (&report.body, body.as_object_mut()) {
                    m.insert(String::from("body"), Value::from(b64url_encode(b)));
                }
                let answer = self
                    .access
                    .ingest(b64url_encode(&id.0), body.to_string().into_bytes())
                    .await;
                let disposition = match body_of(&answer) {
                    Some((200, b)) => serde_json::from_slice::<Value>(b)
                        .ok()
                        .and_then(|v| {
                            v.get("disposition")
                                .and_then(Value::as_str)
                                .map(String::from)
                        })
                        .unwrap_or_else(|| String::from("admit")),
                    Some((s, b)) if (400..500).contains(&s) => format!(
                        "refused:{}",
                        serde_json::from_slice::<Value>(b)
                            .ok()
                            .and_then(|v| v.get("code").and_then(Value::as_str).map(String::from))
                            .unwrap_or_else(|| String::from("claim-invalid"))
                    ),
                    _ => {
                        return Err(VerifierError::Unavailable(String::from("claim-ingest")));
                    }
                };
                sent.push(json!({
                    "claim": b64url_encode(&id.0),
                    "class": report.statement.class,
                    "disposition": disposition,
                }));
            }
        }
        Ok((
            String::from("verified"),
            None,
            json!({ "credentials": credentials, "claims": sent }),
        ))
    }
}

/// SD-JWT VC: `iss` matches a URI SAN of the leaf, or is an `https` URL whose host is a DNS SAN.
fn binds(leaf: &[u8], iss: &str) -> bool {
    let der = rustls_pki_types::CertificateDer::from(leaf);
    let Ok(ee) = webpki::EndEntityCert::try_from(&der) else {
        return false;
    };
    if ee.valid_uri_names().any(|u| u == iss) {
        return true;
    }
    host_of(iss).is_some_and(|h| ee.valid_dns_names().any(|d| d.eq_ignore_ascii_case(h)))
}
