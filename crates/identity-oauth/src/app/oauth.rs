//! The realm's OAuth 2.1 authorization server and OpenID Provider (OP-146 I7, §10.4): client
//! authentication, `/authorize`, `/par`, `/token`, `/userinfo`, `/revoke`, `/introspect` and
//! RP-initiated logout with back-channel logout. Everything is decided against the primary
//! (Δ = 0, MD-7); when the database, the signer or trusted time cannot answer, the answer is
//! `503 + Retry-After`, never `invalid_grant` (G50, EP-2), except introspection, which answers
//! `active: false` (MD-8).

mod authority;
mod authorize;
mod logout;
mod management;
mod resource;
mod service;
mod token;

use std::sync::Arc;

use access_crypto::dpop::{NonceRing, Role};
use access_crypto::oauth::opaque_digest;
use access_identity_account::domain::status::AccountStatus;
use access_identity_session::domain::assurance::{Aal, AssuranceVector};
use access_identity_session::domain::session::{SessionCheck, SessionFacts, check};
use access_internal_api::projections::Projections;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::identity::{RealmId, TenantId};
use access_store::oauth::GrantRow;
use access_store::sessions::SessionRow;
use serde_json::{Value, json};

use crate::app::dpop::{Accepted, DpopChecker, DpopRequest};
use crate::domain::client::{
    Client, ClientAuth, ClientAuthError, Presented, check_method, presented, previous_matches,
};
use crate::domain::dpop::{DpopProfile, Failure};
use crate::domain::jwt::{AssertionRules, assertion_subject, parse_jwks, verify_assertion};
use crate::domain::request::Params;
use crate::domain::tokens::{
    ACCESS_TTL_MS, ACCESS_TYP, GrantDetails, ID_TYP, TokenFacts, access_token_claims,
    id_token_claims,
};
use crate::ports::dpop::{Clock, ReplayCache};
use crate::ports::oauth::{
    ClientKeys, LoginPages, ManagementHolders, NoManagement, OAuthDb, OAuthTx, Random, TenantIds,
    TokenSigner,
};
use crate::ports::{Directory, RealmEntry, Unavailable};
use access_identity_hooks::domain::{Call, Outcome, TokenIssuance, with_claims};
use access_identity_hooks::ports::{HookCaller, NoHooks};

pub use crate::app::oauth::authorize::REQUEST_CONTEXT;
pub use crate::app::oauth::token::TokenHttp;

/// `Retry-After` of a shed request, seconds (PD).
pub const RETRY_AFTER_S: u64 = 1;

/// One day in milliseconds; ephemeral rows are partitioned by day.
const DAY_MS: u64 = 86_400_000;

const CODE_CONTEXT: &str = "access/oauth-code/v1";
const REFRESH_CONTEXT: &str = "access/oauth-refresh/v1";

/// What the authorization server needs, as one bundle so the HTTP layer carries one type.
pub trait Env: Send + Sync + 'static {
    /// The realm rows.
    type Db: OAuthDb;
    /// The identity signer.
    type Signer: TokenSigner;
    /// Client JWKS documents.
    type ClientKeys: ClientKeys;
    /// The hosted login.
    type Pages: LoginPages;
    /// Trusted time.
    type Clock: Clock + Send + Sync;
    /// Randomness.
    type Random: Random;
    /// The realm directory.
    type Directory: Directory;
    /// A realm's DPoP replay cache.
    type Replay: ReplayCache + Send + Sync;
    /// The authority plane's token projections (OP-150 m.2).
    type Projections: Projections;
    /// The cell's opaque tenant ids (OP-149 m.15 (i), m.19 (a)).
    type Tenants: TenantIds;

    /// The realm rows.
    fn db(&self) -> &Self::Db;
    /// The identity signer.
    fn signer(&self) -> &Self::Signer;
    /// Client JWKS documents.
    fn client_keys(&self) -> &Self::ClientKeys;
    /// The hosted login.
    fn pages(&self) -> &Self::Pages;
    /// Trusted time.
    fn clock(&self) -> &Self::Clock;
    /// Randomness.
    fn random(&self) -> &Self::Random;
    /// The realm directory.
    fn directory(&self) -> &Self::Directory;
    /// The replay cache of a realm (TN-30).
    fn replay(&self, tenant: TenantId, realm: RealmId) -> Self::Replay;
    /// The nonce keys of a realm for one role (TN-29); `None` when they cannot be loaded.
    fn nonces(&self, realm: RealmId, role: Role) -> Option<Arc<NonceRing>>;
    /// The DPoP profile.
    fn dpop(&self) -> &DpopProfile;
    /// The authority plane's token projections.
    fn projections(&self) -> &Self::Projections;
    /// The cell's opaque tenant ids.
    fn tenant_ids(&self) -> &Self::Tenants;
    /// The realm's inline hooks (TN-135); none unless the server wires them.
    fn hooks(&self) -> &(dyn HookCaller + Sync) {
        &NoHooks
    }
    /// The Instances management read token exchanges read (TN-130); none unless the server
    /// wires them.
    fn management(&self) -> &(dyn ManagementHolders + Sync) {
        &NoManagement
    }
}

/// What an endpoint answers; the HTTP layer only renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `303 See Other` to this location.
    Redirect(String),
    /// A JSON body, `Cache-Control: no-store`.
    Json {
        /// Status.
        status: u16,
        /// Body.
        body: String,
        /// `DPoP-Nonce` to send (TN-29).
        dpop_nonce: Option<String>,
        /// `WWW-Authenticate` to send.
        challenge: Option<String>,
    },
    /// An RFC 9457 problem shown to the user; nothing is redirected (TN-104).
    Problem {
        /// Status.
        status: u16,
        /// Stable code.
        code: &'static str,
    },
    /// `503 + Retry-After` (G50).
    Unavailable,
    /// No realm here.
    NotFound,
}

impl Reply {
    fn json(status: u16, body: &Value) -> Self {
        Self::Json {
            status,
            body: body.to_string(),
            dpop_nonce: None,
            challenge: None,
        }
    }

    /// An OAuth error body (RFC 6749 §5.2).
    #[must_use]
    pub fn oauth_error(status: u16, error: &str, description: &str) -> Self {
        Self::json(
            status,
            &json!({ "error": error, "error_description": description }),
        )
    }

    fn with_nonce(self, nonce: Option<String>) -> Self {
        match self {
            Self::Json {
                status,
                body,
                challenge,
                ..
            } => Self::Json {
                status,
                body,
                dpop_nonce: nonce,
                challenge,
            },
            other => other,
        }
    }
}

/// The authorization server of every realm.
pub struct OAuth<E> {
    env: E,
}

/// A realm as a request reached it.
pub type Realm = RealmEntry;

pub(crate) fn day(ms: u64) -> i32 {
    i32::try_from(ms / DAY_MS).unwrap_or(i32::MAX)
}

pub(crate) fn from_day(ms: u64) -> i32 {
    day(ms).saturating_sub(1).max(0)
}

pub(crate) fn signed(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

pub(crate) fn unsigned(ms: i64) -> u64 {
    u64::try_from(ms).unwrap_or(0)
}

pub(crate) fn decode32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 43 {
        return None;
    }
    b64url_decode(text).ok()?.try_into().ok()
}

pub(crate) fn code_digest(code: &[u8; 32]) -> [u8; 32] {
    opaque_digest(CODE_CONTEXT, code)
}

pub(crate) fn refresh_digest(token: &[u8; 32]) -> [u8; 32] {
    opaque_digest(REFRESH_CONTEXT, token)
}

pub(crate) fn active(status: &str) -> bool {
    AccountStatus::parse(status).is_some_and(AccountStatus::can_authenticate)
}

/// Whether a login session is live now (TN-36, TN-50, G57).
pub(crate) fn session_live(r: &SessionRow, now: u64) -> bool {
    let facts = SessionFacts {
        session_epoch: r.session_epoch,
        subject_epoch: r.subject_epoch,
        subject_active: active(&r.subject_status),
        last_seen_ms: unsigned(r.last_seen_ms),
        idle_ms: unsigned(r.idle_ms),
        expires_ms: unsigned(r.expires_ms),
        ended: r.ended_ms.is_some(),
    };
    check(&facts, now) == SessionCheck::Valid
}

/// The AAL a session's stored assurance vector records.
pub(crate) fn session_aal(r: &SessionRow) -> Result<Aal, Unavailable> {
    serde_json::from_slice::<AssuranceVector>(&r.assurance)
        .map(|v| v.aal)
        .map_err(|_| Unavailable)
}

/// Whether a grant may still issue or be honoured: not revoked, not past its end, not behind
/// its subject's epoch (TN-50, MD-7).
pub(crate) fn grant_live(g: &GrantRow, now: u64) -> bool {
    g.revoked_ms.is_none()
        && unsigned(g.expires_ms) > now
        && g.session_epoch >= g.subject_epoch
        && active(&g.subject_status)
}

/// What an authenticated token, PAR, revocation or introspection request presented.
pub(crate) struct ClientRequest<'a> {
    pub(crate) authorization: Option<&'a str>,
    pub(crate) params: &'a Params,
    pub(crate) endpoint: &'a str,
}

impl<E: Env> OAuth<E> {
    /// The server over `env`.
    pub const fn new(env: E) -> Self {
        Self { env }
    }

    /// Its environment.
    pub const fn env(&self) -> &E {
        &self.env
    }

    /// The realm a request reached (§17.9.6): see [`crate::app::resolve`].
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn realm(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> Result<Option<Realm>, Unavailable> {
        crate::app::resolve(self.env.directory(), authority, slug).await
    }

    pub(crate) fn now(&self) -> Result<u64, Unavailable> {
        self.env.clock().now().map_err(|_| Unavailable)
    }

    pub(crate) fn random<const N: usize>(&self) -> Result<[u8; N], Unavailable> {
        let mut out = [0; N];
        self.env.random().fill(&mut out)?;
        Ok(out)
    }

    pub(crate) async fn begin(&self, realm: &Realm) -> Result<<E::Db as OAuthDb>::Tx, Unavailable> {
        self.env.db().begin(realm.tenant, realm.realm).await
    }

    /// The realm's tenant by its opaque `tnt_` id, as every product-facing surface names it
    /// (OP-149 m.19 (a)); nothing when the cell's id key cannot be used (G50).
    pub(crate) fn tenant_name(&self, realm: &Realm) -> Result<String, Unavailable> {
        self.env
            .tenant_ids()
            .external(realm.tenant.as_bytes())
            .ok_or(Unavailable)
    }

    /// The registered platform product client a request's `resource` names, when it names one
    /// (RFC 8707, OP-149 m.26 (a)); the realm issuer names none.
    pub(crate) async fn product_resource(
        &self,
        realm: &Realm,
        params: &Params,
    ) -> Result<Option<String>, Unavailable> {
        let Some(resource) = params
            .get("resource")
            .filter(|r| *r != realm.issuer.as_str())
        else {
            return Ok(None);
        };
        Ok(self
            .env
            .db()
            .platform_product(resource)
            .await?
            .map(|_| String::from(resource)))
    }

    /// RFC 6749 §2.3, RFC 7523 §3, §10.4.5: the request's client, authenticated by its
    /// registered method. A `private_key_jwt` assertion is checked against the client's keys
    /// with `aud` the issuer or this endpoint, and its `jti` is recorded once.
    pub(crate) async fn authenticate(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        req: &ClientRequest<'_>,
        now: u64,
    ) -> Result<Result<Client, ClientAuthError>, Unavailable> {
        let p = req.params;
        let presented = match presented(
            req.authorization,
            p.get("client_id"),
            p.get("client_assertion_type"),
            p.get("client_assertion"),
        ) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(Err(ClientAuthError::Malformed)),
            Err(e) => return Ok(Err(e)),
        };
        let client_id = match &presented {
            Presented::Assertion {
                client_id: None,
                assertion,
            } => match assertion_subject(assertion) {
                Ok(sub) => sub,
                Err(_) => return Ok(Err(ClientAuthError::Rejected)),
            },
            other => other.client_id().map(String::from).unwrap_or_default(),
        };
        let Some(client) = tx.client(&client_id).await?.and_then(Client::from_row) else {
            return Ok(Err(ClientAuthError::Unknown));
        };
        if let Err(e) = check_method(&client, &presented) {
            // CR-38
            let previous = match e {
                ClientAuthError::Rejected => tx.previous_secret(&client.id).await?,
                _ => None,
            };
            if !previous.is_some_and(|p| previous_matches(&client, &p, &presented)) {
                return Ok(Err(e));
            }
        }
        if let Presented::Assertion { assertion, .. } = &presented {
            let doc = match &client.auth {
                ClientAuth::PrivateKeyJwt { jwks_uri } => {
                    self.env.client_keys().fetch(jwks_uri).await?
                }
                ClientAuth::PrivateKeyJwtKey { jwks } => jwks.clone().into_bytes(),
                ClientAuth::None | ClientAuth::SecretBasic { .. } => {
                    return Ok(Err(ClientAuthError::Method));
                }
            };
            let Ok(keys) = parse_jwks(&doc) else {
                return Ok(Err(ClientAuthError::Rejected));
            };
            let endpoint = realm.issuer.endpoint(req.endpoint);
            let rules = AssertionRules {
                client_id: &client.id,
                issuer: realm.issuer.as_str(),
                endpoint: &endpoint,
                now_ms: now,
            };
            let Ok(a) = verify_assertion(assertion, &keys, &rules) else {
                return Ok(Err(ClientAuthError::Rejected));
            };
            if !tx.assertion_first_use(day(a.exp_ms), &a.replay_key).await? {
                return Ok(Err(ClientAuthError::Rejected));
            }
        }
        Ok(Ok(client))
    }

    /// The DPoP check of a request (IDP-11) for `role` at `uri`.
    pub(crate) async fn dpop(
        &self,
        realm: &Realm,
        role: Role,
        request: &DpopRequest<'_>,
    ) -> Result<Accepted, Failure> {
        let ring = self
            .env
            .nonces(realm.realm, role)
            .ok_or(Failure::Unavailable)?;
        let replay = self.env.replay(realm.tenant, realm.realm);
        DpopChecker::new(self.env.dpop(), &ring, &replay, self.env.clock())
            .check(request)
            .await
    }

    /// A fresh nonce for a response that carried no proof (TN-29).
    pub(crate) fn nonce(&self, realm: &Realm, role: Role) -> Option<String> {
        let ring = self.env.nonces(realm.realm, role)?;
        let now = self.now().ok()?;
        ring.issue(now).ok()
    }

    /// The `sub` of a subject in `sector` (MD-10, OP-146 m.5 (b)): a client's pairwise sector
    /// or the realm's public one ([`Client::sector`]).
    pub(crate) async fn pairwise(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        subject: [u8; 16],
        client: [u8; 16],
    ) -> Result<String, Unavailable> {
        let candidate = b64url_encode(&self.random::<32>()?);
        tx.pairwise(subject, client, &candidate).await
    }

    /// Issues the tokens of a grant: a rotated refresh token, the access token bound to `jkt`
    /// and, for `openid`, the ID token (OP-146 m.5 (c)).
    #[expect(clippy::too_many_arguments, reason = "the facts of one issuance")]
    pub(crate) async fn issue(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        grant: &GrantRow,
        details: &GrantDetails,
        jkt: &str,
        nonce: Option<&str>,
        now: u64,
    ) -> Result<Value, Unavailable> {
        let refresh = self.random::<32>()?;
        tx.insert_refresh(&refresh_digest(&refresh), grant.id, signed(now))
            .await?;
        let sub = self.pairwise(tx, grant.subject, client.sector()).await?;
        let sid = b64url_encode(&grant.sid);
        let tenant = if details.resource.is_some() {
            Some(self.tenant_name(realm)?)
        } else {
            None
        };
        let facts = TokenFacts {
            issuer: &realm.issuer,
            audience: details.audience(&realm.issuer),
            tenant: tenant.as_deref(),
            client_id: &client.id,
            sub: &sub,
            sid: &sid,
            auth_time_ms: details.auth_time_ms,
            aal: details.aal,
            now_ms: now,
            rev: grant.session_epoch,
        };
        let alg = tx.jose_alg().await?;
        let jti = b64url_encode(&self.random::<16>()?);
        let access = self
            .env
            .signer()
            .sign(
                realm.realm,
                alg,
                ACCESS_TYP,
                &access_token_claims(&facts, &details.scope, &jti, jkt),
                now,
            )
            .await?;
        let mut body = json!({
            "access_token": access,
            "token_type": "DPoP",
            "expires_in": ACCESS_TTL_MS / 1000,
            "refresh_token": b64url_encode(&refresh),
            "scope": details.scope,
        });
        if details.openid {
            let claims = self.id_claims(realm, &facts, &details.scope, nonce).await?;
            let id = self
                .env
                .signer()
                .sign(realm.realm, alg, ID_TYP, &claims, now)
                .await?;
            if let Value::Object(m) = &mut body {
                m.insert("id_token".into(), id.into());
            }
        }
        Ok(body)
    }

    /// The ID token of a grant (OIDC Core §2): an identity assertion, sector-pairwise `sub`
    /// (MD-10, §9.9.3 rule 8).
    #[expect(clippy::too_many_arguments, reason = "the facts of one issuance")]
    pub(crate) async fn id_token(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        grant: &GrantRow,
        details: &GrantDetails,
        nonce: Option<&str>,
        now: u64,
    ) -> Result<String, Unavailable> {
        let sub = self.pairwise(tx, grant.subject, client.sector()).await?;
        let sid = b64url_encode(&grant.sid);
        let facts = TokenFacts {
            issuer: &realm.issuer,
            audience: details.audience(&realm.issuer),
            tenant: None,
            client_id: &client.id,
            sub: &sub,
            sid: &sid,
            auth_time_ms: details.auth_time_ms,
            aal: details.aal,
            now_ms: now,
            rev: grant.session_epoch,
        };
        let alg = tx.jose_alg().await?;
        let claims = self.id_claims(realm, &facts, &details.scope, nonce).await?;
        self.env
            .signer()
            .sign(realm.realm, alg, ID_TYP, &claims, now)
            .await
    }

    /// The ID token claims with what the realm's `token_issuance` hook adds (TN-135, OP-151
    /// m.3 (j)): identity claims only, never a reserved or authority claim (must-never #18). A
    /// hook that fails refuses the token (MD-8), unless it continues without claims.
    async fn id_claims(
        &self,
        realm: &Realm,
        facts: &TokenFacts<'_>,
        scope: &str,
        nonce: Option<&str>,
    ) -> Result<Vec<u8>, Unavailable> {
        let base = id_token_claims(facts, nonce);
        let call = Call::TokenIssuance(TokenIssuance {
            client_id: String::from(facts.client_id),
            subject: String::from(facts.sub),
            scope: String::from(scope),
            acr: String::from(crate::domain::tokens::acr(facts.aal)),
        });
        match self.env.hooks().call(realm.tenant, realm.realm, call).await {
            Outcome::Proceed { claims } => with_claims(&base, &claims).map_err(|_| Unavailable),
            Outcome::Refused(r) => {
                tracing::info!(reason = r.code(), "token not issued: token_issuance hook");
                Err(Unavailable)
            }
        }
    }
}
