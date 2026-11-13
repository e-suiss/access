//! The realm's OAuth 2.1 authorization server and OpenID Provider (OP-146 I7, §10.4): client
//! authentication, `/authorize`, `/par`, `/token`, `/userinfo`, `/revoke`, `/introspect` and
//! RP-initiated logout with back-channel logout. Everything is decided against the primary
//! (Δ = 0, MD-7); when the database, the signer or trusted time cannot answer, the answer is
//! `503 + Retry-After`, never `invalid_grant` (G50, EP-2), except introspection, which answers
//! `active: false` (MD-8). While the identity database is down no token is issued, refreshed or
//! revoked here; tokens already signed are checked only locally by resource servers within their
//! declared lifetime (`domain::jwt::verify_local`), and no surface of this server opens a window
//! (OP-45, EP-6, U39).

mod approval;
mod authority;
mod authorize;
pub mod ciba;
mod client_auth;
pub mod clients;
pub mod dcr;
pub mod device;
mod exchange;
mod logout;
mod management;
pub mod pep;
mod profile;
pub mod proxy;
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
    Client, ClientAuth, ClientAuthError, Presented, check_method, previous_matches,
};
use crate::domain::dpop::{DpopProfile, Failure};
use crate::domain::jwt::{AssertionRules, assertion_subject, parse_jwks, verify_assertion};
use crate::domain::request::Params;
use crate::domain::tokens::{
    ACCESS_TTL_MS, ACCESS_TYP, GrantDetails, ID_TYP, TokenFacts, id_token_claims,
};
use crate::ports::dpop::{Clock, ReplayCache};
use crate::ports::oauth::{
    ClaimSource, ClientKeys, LoginPages, ManagementHolders, NoClaims, NoManagement, OAuthDb,
    OAuthTx, Random, TenantIds, TokenSigner,
};
use crate::ports::{Directory, RealmEntry, Unavailable};
use access_identity_hooks::domain::{Call, Outcome, TokenIssuance, with_claims};
use access_identity_hooks::ports::{HookCaller, NoHooks};

pub use crate::app::oauth::approval::{
    ApprovalDraft, ApprovalView, CONSENT_STATE_TTL_MS, NotApproved, consent_csrf,
};
pub use crate::app::oauth::authorize::{REQUEST_CONTEXT, consent_resource};
pub use crate::app::oauth::ciba::{CibaRefused, CibaView, ciba_csrf};
pub use crate::app::oauth::device::{DeviceRefused, DeviceView, device_csrf};
pub use crate::app::oauth::resource::RealmHolder;
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
    /// What accounts hold to release as identity claims (§10.4.6); nothing unless the server
    /// wires the realms' PII vaults.
    fn claims(&self) -> &(dyn ClaimSource + Sync) {
        &NoClaims
    }
    /// The URLs CIMD clients name (OP-154 m.3 (i)); none unless the server wires the guarded
    /// outbound client, so every CIMD client is refused.
    fn documents(&self) -> &(dyn crate::ports::oauth::ClientDocuments + Sync) {
        &crate::ports::oauth::NoDocuments
    }
    /// Whether a consent record's Grant stands (P58); none unless the server wires the
    /// authority plane, so consent is always asked for again.
    fn standing(&self) -> &(dyn crate::ports::oauth::GrantStanding + Sync) {
        &crate::ports::oauth::NoStanding
    }
    /// What CIBA needs beyond the realm's rows (OP-155 m.3 (l)); none unless the server wires
    /// the authority plane, Relay and the guarded outbound client, so nothing can be invited.
    fn ciba(&self) -> &(dyn crate::ports::oauth::CibaServices + Sync) {
        &crate::ports::oauth::NoCiba
    }
    /// The country an IP address is in (OP-155 m.3 (l)); none unless the operator supplied a
    /// list, so the device page shows no country.
    fn geo(&self) -> &(dyn crate::ports::oauth::GeoLookup + Sync) {
        &crate::ports::oauth::NoGeo
    }
    /// The issuers whose assertions the token endpoint takes as Claim input (OP-154 m.3 (m),
    /// (q)); none unless the server wires the authority plane, so every assertion is refused.
    fn issuers(&self) -> &(dyn crate::ports::oauth::AssertionIssuers + Sync) {
        &crate::ports::oauth::NoIssuers
    }
    /// The realm's SPIFFE bundles (OP-154 m.3 (r)); none unless the server wires the store and
    /// the guarded outbound client, so every SVID is refused.
    fn bundles(&self) -> &(dyn access_identity_attest::ports::Bundles + Sync) {
        &access_identity_attest::ports::NoBundles
    }
    /// Which trust domains the authority plane accepts (OP-154 m.3 (r)); none unless the server
    /// wires it, so every workload client is refused.
    fn workload_trust(&self) -> &(dyn crate::ports::oauth::WorkloadTrust + Sync) {
        &crate::ports::oauth::NoWorkloadTrust
    }
    /// The realm's client certificate trust and revocation checks (OP-155 m.3 (m)); none
    /// unless the server wires them, so every `tls_client_auth` client is refused.
    fn client_certificates(&self) -> &(dyn crate::ports::profile::ClientCertificates + Sync) {
        &crate::ports::profile::NoClientCertificates
    }
    /// The realm KEK that opens `client_secret_jwt` secrets (OP-148 m.16 (l)); none unless the
    /// server wires it, so every such assertion is refused.
    fn jwt_secrets(&self) -> &(dyn crate::ports::profile::JwtSecrets + Sync) {
        &crate::ports::profile::NoJwtSecrets
    }
    /// SAML assertions verified in the parser worker (OP-155 m.3 (k)); none unless the server
    /// wires them, so every SAML assertion is refused.
    fn saml_assertions(&self) -> &(dyn crate::ports::profile::SamlAssertions + Sync) {
        &crate::ports::profile::NoSamlAssertions
    }
    /// The realm's `jwe-enc` key (OP-155 m.3 (k)); none unless the server wires it, so every
    /// encrypted request object is refused.
    fn request_keys(&self) -> &(dyn crate::ports::profile::RequestKeys + Sync) {
        &crate::ports::profile::NoRequestKeys
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
    /// `200` with an HTML page that posts the authorization response to `action`
    /// (`form_post.jwt`, OP-155 m.3 (k)).
    FormPost {
        /// Where the page posts.
        action: String,
        /// The page.
        body: String,
    },
    /// `200` with a signed or encrypted JWT, `application/jwt`, `Cache-Control: no-store`
    /// (OIDC Core §5.3.2, OP-155 m.3 (k)).
    Jwt {
        /// The JWT.
        body: String,
        /// Its media type: `application/jwt`, or `application/token-introspection+jwt`.
        media: &'static str,
        /// `DPoP-Nonce` to send (TN-29).
        dpop_nonce: Option<String>,
    },
    /// `200` with an HTML page that may frame only `frames` (front-channel logout, IDP-24).
    Page {
        /// The page.
        body: String,
        /// The origins it frames.
        frames: Vec<String>,
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

    /// RFC 7662 `{"active": false}`: what introspection answers when freshness cannot be proven
    /// (OP-45 rule 3, EP-3, MD-8).
    #[must_use]
    pub fn oauth_inactive() -> Self {
        Self::json(200, &json!({ "active": false }))
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
    refetched: std::sync::Mutex<std::collections::BTreeMap<[u8; 16], u64>>,
    pep_audience: Option<String>,
}

/// Shortest time between two JWKS fetches for an unknown `kid` of one client (§10.4.5).
pub const JWKS_REFETCH_MS: u64 = 60_000;

const REFETCH_ENTRIES: usize = 4096;

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
/// N5: whether a session tied to a DBSC key came with its live bound cookie (TN-33,
/// OP-153 m.3 (y)); `cookie` is the session cookie, followed by `.` and the bound cookie when
/// the request carried both.
pub(crate) fn bound_live(r: &SessionRow, cookie: &str, now: u64) -> bool {
    use access_identity_session::domain::dbsc::{bound_ok, split_cookie};
    let bound = split_cookie(cookie)
        .1
        .and_then(decode32)
        .map(|b| access_identity_session::domain::session::cookie_digest(&b));
    bound_ok(
        r.dbsc_key.is_some(),
        r.dbsc_cookie.as_ref().map(|(d, e)| (d.as_slice(), *e)),
        bound,
        now,
    )
}

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
    pub(crate) chain: &'a [Vec<u8>],
}

impl<E: Env> OAuth<E> {
    /// The server over `env`.
    pub const fn new(env: E) -> Self {
        Self {
            env,
            refetched: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            pep_audience: None,
        }
    }

    /// Also issues PEP tokens for the deployment's ADP at `api_base`, its `resource` and `aud`
    /// (OP-155 m.3 (q)); without it no PEP token is issued or accepted.
    #[must_use]
    pub fn with_pep_audience(mut self, api_base: String) -> Self {
        self.pep_audience = Some(api_base);
        self
    }

    pub(crate) fn pep_audience(&self) -> Option<&str> {
        self.pep_audience.as_deref()
    }

    /// §10.4.5, Ek B 5098: whether the JWKS of client `client` may be fetched again for an
    /// unknown `kid` now, at most once per [`JWKS_REFETCH_MS`]; a poisoned record refuses.
    pub(crate) fn may_refetch(&self, client: [u8; 16], now: u64) -> bool {
        let Ok(mut seen) = self.refetched.lock() else {
            return false;
        };
        if seen
            .get(&client)
            .is_some_and(|at| now < at.saturating_add(JWKS_REFETCH_MS))
        {
            return false;
        }
        if seen.len() >= REFETCH_ENTRIES {
            seen.retain(|_, at| now < at.saturating_add(JWKS_REFETCH_MS));
        }
        if seen.len() >= REFETCH_ENTRIES {
            return false;
        }
        seen.insert(client, now);
        true
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

    /// The resource a request's `resource` names, in its canonical form, when it is a
    /// registered platform product client (RFC 8707, OP-149 m.26 (a)) or one of the realm's
    /// registered protected resources (AG-8, §11.4.3); the realm issuer names none.
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
        if self.env.db().platform_product(resource).await?.is_some() {
            return Ok(Some(String::from(resource)));
        }
        let Some(canonical) = crate::domain::client::canonical_resource(resource) else {
            return Ok(None);
        };
        let mut tx = self.begin(realm).await?;
        let known = tx.protected_resource(&canonical).await?;
        tx.commit().await?;
        Ok(known.then_some(canonical))
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
        // OP-154 m.3 (r), AG-30
        if let Some(answer) = self.workload_client(tx, realm, req, now).await? {
            return Ok(answer);
        }
        let p = req.params;
        // OP-155 m.3 (k)
        let presented = match crate::domain::client::presented_with_secret(
            req.authorization,
            p.get("client_id"),
            p.get("client_secret"),
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
        let Some(client) = self.client_of(tx, &client_id).await? else {
            return Ok(Err(ClientAuthError::Unknown));
        };
        // RFC 8705 §2, OP-155 m.3 (k)
        if let Some(tls) = client.profile.tls.clone() {
            return self
                .mtls_client(realm, client, &tls, &presented, req.chain, now)
                .await;
        }
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
            // OP-148 m.16 (l)
            if let Some(crate::domain::fapi::LegacyAuth::SecretJwt(sealed)) =
                client.profile.legacy.clone()
            {
                return self
                    .secret_jwt_client(tx, realm, client, &sealed, assertion, req, now)
                    .await;
            }
            let mut doc = match &client.auth {
                ClientAuth::PrivateKeyJwt { jwks_uri } => {
                    self.env.client_keys().fetch(jwks_uri).await?
                }
                ClientAuth::PrivateKeyJwtKey { jwks } => jwks.clone().into_bytes(),
                ClientAuth::None | ClientAuth::SecretBasic { .. } | ClientAuth::Workload(_) => {
                    return Ok(Err(ClientAuthError::Method));
                }
            };
            let Ok(mut keys) = parse_jwks(&doc) else {
                return Ok(Err(ClientAuthError::Rejected));
            };
            // §10.4.5, Ek B 5098
            if let ClientAuth::PrivateKeyJwt { jwks_uri } = &client.auth
                && crate::domain::jwt::kid_unknown(assertion, &keys)
                && self.may_refetch(client.uuid, now)
            {
                doc = self.env.client_keys().refetch(jwks_uri).await?;
                let Ok(fresh) = parse_jwks(&doc) else {
                    return Ok(Err(ClientAuthError::Rejected));
                };
                keys = fresh;
            }
            // OP-155 m.3 (k)
            let endpoint = if client.profile.fapi2 {
                String::from(realm.issuer.as_str())
            } else {
                realm.issuer.endpoint(req.endpoint)
            };
            let rules = AssertionRules {
                client_id: &client.id,
                issuer: realm.issuer.as_str(),
                endpoint: &endpoint,
                now_ms: now,
                rs256: client.rs256,
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

    /// Issues the tokens of a grant: a rotated refresh token, the access token under
    /// `binding` and, for `openid`, the ID token (OP-146 m.5 (c)).
    #[expect(clippy::too_many_arguments, reason = "the facts of one issuance")]
    pub(crate) async fn issue(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        grant: &GrantRow,
        details: &GrantDetails,
        binding: &crate::domain::fapi::Binding,
        nonce: Option<&str>,
        now: u64,
    ) -> Result<Value, Unavailable> {
        self.issue_with(tx, realm, client, grant, details, binding, nonce, true, now)
            .await
    }

    /// [`Self::issue`]; without `refresh` the client keeps the refresh token it holds (FAPI 2.0
    /// refresh without rotation, OP-155 m.3 (k)). The ID token is signed with the client's
    /// algorithm and encrypted when it asked (CR-4).
    #[expect(clippy::too_many_arguments, reason = "the facts of one issuance")]
    pub(crate) async fn issue_with(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        grant: &GrantRow,
        details: &GrantDetails,
        binding: &crate::domain::fapi::Binding,
        nonce: Option<&str>,
        refresh: bool,
        now: u64,
    ) -> Result<Value, Unavailable> {
        let refresh = if refresh {
            let token = self.random::<32>()?;
            tx.insert_refresh(&refresh_digest(&token), grant.id, signed(now))
                .await?;
            Some(token)
        } else {
            None
        };
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
        let jti = b64url_encode(&self.random::<16>()?);
        // CR-41, OP-159 m.21 (b), (g)
        let alg = match details.resource.as_deref() {
            Some(r) => tx.resource_alg(r).await?,
            None => None,
        };
        let access = self
            .sign_as(
                tx,
                realm,
                alg,
                ACCESS_TYP,
                &crate::domain::tokens::bound_access_token_claims(
                    &facts,
                    &details.scope,
                    &jti,
                    binding,
                ),
                now,
            )
            .await?;
        let mut body = json!({
            "access_token": access,
            "token_type": binding.token_type(),
            "expires_in": ACCESS_TTL_MS / 1000,
            "scope": details.scope,
        });
        if let (Some(token), Value::Object(m)) = (refresh, &mut body) {
            m.insert("refresh_token".into(), b64url_encode(&token).into());
        }
        if details.openid {
            let claims = self
                .id_claims(realm, client, &facts, details, grant.subject, nonce)
                .await?;
            let encrypt = client
                .profile
                .encryption
                .as_ref()
                .is_some_and(|e| e.id_token);
            let id = self
                .client_jwt(tx, realm, client, ID_TYP, &claims, encrypt, now)
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
        let claims = self
            .id_claims(realm, client, &facts, details, grant.subject, nonce)
            .await?;
        let encrypt = client
            .profile
            .encryption
            .as_ref()
            .is_some_and(|e| e.id_token);
        self.client_jwt(tx, realm, client, ID_TYP, &claims, encrypt, now)
            .await
    }

    /// The identity claims released to `target` for a grant (§10.4.6, OP-153 m.3 (l)): the
    /// scopes and the `claims` request it was given with, over what the account holds.
    pub(crate) async fn released(
        &self,
        realm: &Realm,
        client: &Client,
        details: &GrantDetails,
        subject: [u8; 16],
        target: crate::domain::claims_request::Target,
    ) -> Result<serde_json::Map<String, Value>, Unavailable> {
        let scopes: Vec<&str> = details.scope.split(' ').filter(|s| !s.is_empty()).collect();
        let requested = details
            .claims
            .as_ref()
            .map(crate::domain::claims_request::ClaimsAsk::requested)
            .unwrap_or_default();
        let asked = match target {
            crate::domain::claims_request::Target::IdToken => &requested.id_token,
            crate::domain::claims_request::Target::Userinfo => &requested.userinfo,
        };
        if asked.is_empty() && !scopes.iter().any(|s| matches!(*s, "email" | "profile")) {
            return Ok(serde_json::Map::new());
        }
        // OP-153 m.3 (z)
        let consented = if client.third_party {
            let mut tx = self.begin(realm).await?;
            let given = tx.consent(subject, client.uuid).await?;
            tx.commit().await?;
            match given {
                Some(g) => Some(g),
                None => return Ok(serde_json::Map::new()),
            }
        } else {
            None
        };
        let held = self
            .env
            .claims()
            .held(realm.tenant, realm.realm, subject)
            .await?;
        let mut out = crate::domain::claims_request::release(&scopes, &requested, target, &held);
        if let Some(given) = consented {
            out.retain(|name, _| given.iter().any(|g| g == name));
        }
        Ok(out)
    }

    /// The ID token claims with what the realm's `token_issuance` hook adds (TN-135, OP-151
    /// m.3 (j)): identity claims only, never a reserved or authority claim (must-never #18). A
    /// hook that fails refuses the token (MD-8), unless it continues without claims.
    async fn id_claims(
        &self,
        realm: &Realm,
        client: &Client,
        facts: &TokenFacts<'_>,
        details: &GrantDetails,
        subject: [u8; 16],
        nonce: Option<&str>,
    ) -> Result<Vec<u8>, Unavailable> {
        let scope = details.scope.as_str();
        let released = self
            .released(
                realm,
                client,
                details,
                subject,
                crate::domain::claims_request::Target::IdToken,
            )
            .await?;
        let base = id_token_claims(facts, nonce, &released);
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
