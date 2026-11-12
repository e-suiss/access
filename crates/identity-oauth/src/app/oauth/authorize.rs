//! `/authorize` and `/par` (RFC 6749 §4.1, RFC 7636, RFC 9126, RFC 9207, OIDC Core §3.1.2).

use access_crypto::dpop::Role;
use access_crypto::oauth::opaque_digest;
use access_identity_session::domain::dbsc::split_cookie;
use access_identity_session::domain::session::cookie_digest;
use access_kernel::json::b64url_encode;
use access_store::oauth::{NewCode, NewRequest};
use serde_json::json;

use super::{
    ClientRequest, Env, OAuth, Realm, Reply, code_digest, day, decode32, from_day, session_aal,
    session_live, signed, unsigned,
};
use crate::app::dpop::DpopRequest;
use crate::domain::client::Client;
use crate::domain::dpop::Failure;
use crate::domain::jarm;
use crate::domain::login::return_to;
use crate::domain::metadata::Endpoint;
use crate::domain::request::{
    AuthError, AuthRequest, Params, Prompt, REQUEST_URI_PREFIX, ResponseMode, Unredirectable,
    code_redirect, error_redirect, stage_one, stage_two,
};
use crate::domain::tokens::{
    CODE_TTL_MS, CodeDetails, GrantDetails, INTERACTIVE_TTL_MS, PAR_TTL_MS, Signed, needs_login,
};
use crate::ports::Unavailable;
use crate::ports::oauth::{LoginPages, OAuthTx};

/// Context of a stored request handle's digest.
pub const REQUEST_CONTEXT: &str = "access/oauth-request/v1";

fn problem(u: Unredirectable) -> Reply {
    Reply::Problem {
        status: 400,
        code: u.code(),
    }
}

/// AG-8: a client the realm did not register names one registered protected resource; no
/// default audience is used for it.
fn mcp_without_resource(client: &Client, request: &AuthRequest) -> bool {
    client.approval_required() && request.resource.is_none() && request.authority.is_none()
}

/// The protected resource a consent record is kept for: the token's audience.
#[must_use]
pub fn consent_resource(request: &AuthRequest) -> Option<&str> {
    request
        .resource
        .as_deref()
        .or_else(|| request.authority.as_ref().map(|a| a.resource.as_str()))
}

/// Where and how an authorization response goes back.
#[derive(Clone, Copy)]
struct Answer<'a> {
    redirect_uri: &'a str,
    mode: ResponseMode,
    state: Option<&'a str>,
}

/// What an authorization response says.
#[derive(Clone, Copy)]
enum Outcome<'a> {
    /// The code.
    Code(&'a str),
    /// The error.
    Error(AuthError),
}

/// The request a browser brings: parsed now, or stored earlier under a `request_uri`.
struct Loaded {
    client: Client,
    request: AuthRequest,
    created_ms: u64,
    stored: Option<(i32, [u8; 32])>,
}

impl<E: Env> OAuth<E> {
    /// `GET /authorize` (RFC 6749 §4.1.1, OIDC Core §3.1.2). A bad `client_id` or
    /// `redirect_uri` is shown, never redirected (TN-104); every other answer goes to the
    /// client with `iss` (RFC 9207). Without a live session the browser goes to the hosted
    /// login with the request stored; `prompt=none` answers `login_required` instead, the same
    /// whatever account exists (CR-40).
    pub async fn authorize(&self, realm: &Realm, params: &Params, cookie: Option<&str>) -> Reply {
        match self.authorize_inner(realm, params, cookie).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn load(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        params: &Params,
        now: u64,
    ) -> Result<Result<Loaded, Reply>, Unavailable> {
        let client = match params.get("client_id") {
            Some(id) => self.client_of(tx, id).await?,
            None => None,
        };
        if let Some(uri) = params.get("request_uri") {
            // RFC 9126 §4
            let Some(client) = client else {
                return Ok(Err(problem(Unredirectable::Client)));
            };
            let Some(handle) = uri.strip_prefix(REQUEST_URI_PREFIX).and_then(decode32) else {
                return Ok(Err(problem(Unredirectable::RequestUri)));
            };
            let hash = opaque_digest(REQUEST_CONTEXT, &handle);
            let row = tx.request(from_day(now), &hash).await?;
            let Some(row) = row.filter(|r| {
                r.client == client.uuid && r.used_ms.is_none() && unsigned(r.expires_ms) > now
            }) else {
                return Ok(Err(problem(Unredirectable::RequestUri)));
            };
            let request: AuthRequest =
                serde_json::from_slice(&row.params).map_err(|_| Unavailable)?;
            if !client.redirect_allowed(&request.redirect_uri) {
                return Ok(Err(problem(Unredirectable::RedirectUri)));
            }
            return Ok(Ok(Loaded {
                client,
                request,
                created_ms: unsigned(row.created_ms),
                stored: Some((row.day, hash)),
            }));
        }
        let redirect = match stage_one(params, client.as_ref()) {
            Ok(r) => r,
            Err(u) => return Ok(Err(problem(u))),
        };
        let Some(client) = client else {
            return Ok(Err(problem(Unredirectable::Client)));
        };
        // RFC 9126 §6, OP-155 m.3 (k)
        if client.require_par || client.profile.fapi2 {
            let mode = ResponseMode::parse(params.get("response_mode"))
                .unwrap_or_default()
                .max_jwt(client.profile.fapi2);
            return Ok(Err(self
                .answer(
                    tx,
                    realm,
                    &client,
                    Answer {
                        redirect_uri: redirect,
                        mode,
                        state: params.get("state"),
                    },
                    Outcome::Error(AuthError::PAR_REQUIRED),
                    now,
                )
                .await?));
        }
        let product = self.product_resource(realm, params).await?;
        match stage_two(params, &client, redirect, &realm.issuer, product.as_deref()) {
            // AG-8, §11.4.3
            Ok(request) if mcp_without_resource(&client, &request) => {
                Ok(Err(Reply::Redirect(error_redirect(
                    redirect,
                    AuthError::RESOURCE_REQUIRED,
                    params.get("state"),
                    &realm.issuer,
                ))))
            }
            Ok(request) => Ok(Ok(Loaded {
                client,
                request,
                created_ms: now,
                stored: None,
            })),
            Err(e) => {
                // OP-155 m.3 (k)
                let mode = ResponseMode::parse(params.get("response_mode"))
                    .unwrap_or_default()
                    .max_jwt(client.profile.fapi2);
                Ok(Err(self
                    .answer(
                        tx,
                        realm,
                        &client,
                        Answer {
                            redirect_uri: redirect,
                            mode,
                            state: params.get("state"),
                        },
                        Outcome::Error(e),
                        now,
                    )
                    .await?))
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the authorization steps in the order they run"
    )]
    async fn authorize_inner(
        &self,
        realm: &Realm,
        params: &Params,
        cookie: Option<&str>,
    ) -> Result<Reply, Unavailable> {
        // IDP-1, AG-4
        if self.prepare_client(realm, params).await?.is_err() {
            return Ok(problem(Unredirectable::Client));
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let l = match self.load(&mut tx, realm, params, now).await? {
            Ok(l) => l,
            Err(reply) => return Ok(reply),
        };
        // TN-33, OP-153 m.3 (y)
        let session = match cookie.and_then(|c| decode32(split_cookie(c).0).map(|v| (c, v))) {
            Some((c, value)) => tx
                .session_by_cookie(&cookie_digest(&value))
                .await?
                .filter(|s| session_live(s, now) && super::bound_live(s, c, now)),
            None => None,
        };
        let signed_in = session
            .as_ref()
            .map(|s| {
                Ok(Signed {
                    auth_time_ms: unsigned(s.auth_time_ms),
                    aal: session_aal(s)?,
                })
            })
            .transpose()?;
        let req = &l.request;
        let back_to = Answer {
            redirect_uri: &req.redirect_uri,
            mode: req.response_mode,
            state: req.state.as_deref(),
        };
        if let Some(reason) = needs_login(req, signed_in, l.created_ms, now) {
            if req.prompt == Prompt::None {
                let members = Outcome::Error(AuthError::LOGIN_REQUIRED);
                return self
                    .answer(&mut tx, realm, &l.client, back_to, members, now)
                    .await;
            }
            return self.to_login(tx, realm, &l, now, reason).await;
        }
        let (Some(session), Some(s)) = (session, signed_in) else {
            let members = Outcome::Error(AuthError::LOGIN_REQUIRED);
            return self
                .answer(&mut tx, realm, &l.client, back_to, members, now)
                .await;
        };
        // §11.6, P58, EI-18
        if l.client.approval_required() && !self.approved(&mut tx, &l, session.subject, now).await?
        {
            if req.prompt == Prompt::None {
                let members = Outcome::Error(AuthError::CONSENT_REQUIRED);
                return self
                    .answer(&mut tx, realm, &l.client, back_to, members, now)
                    .await;
            }
            return self
                .to_login(
                    tx,
                    realm,
                    &l,
                    now,
                    crate::domain::tokens::LoginReason::Approve,
                )
                .await;
        }
        // OP-153 m.3 (z)
        if self.unshared(&mut tx, &l, session.subject).await? {
            if req.prompt == Prompt::None {
                let members = Outcome::Error(AuthError::CONSENT_REQUIRED);
                return self
                    .answer(&mut tx, realm, &l.client, back_to, members, now)
                    .await;
            }
            return self
                .to_login(
                    tx,
                    realm,
                    &l,
                    now,
                    crate::domain::tokens::LoginReason::Share,
                )
                .await;
        }
        if let Some((d, hash)) = l.stored
            && !tx.use_request(d, &hash, signed(now)).await?
        {
            return Ok(problem(Unredirectable::RequestUri));
        }
        let code = self.random::<32>()?;
        let details = CodeDetails {
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge,
            dpop_jkt: req.dpop_jkt,
            nonce: req.nonce.clone(),
            grant: GrantDetails {
                scope: req.scope_text(),
                auth_time_ms: s.auth_time_ms,
                aal: s.aal,
                openid: req.openid(),
                authority: req.authority.clone(),
                family: None,
                projection: None,
                resource: req.resource.clone(),
                claims: req.claims.clone(),
            },
        };
        let encoded = serde_json::to_vec(&details).map_err(|_| Unavailable)?;
        tx.insert_code(&NewCode {
            day: day(now),
            hash: &code_digest(&code),
            client: l.client.uuid,
            session: session.id,
            details: &encoded,
            created_ms: signed(now),
            expires_ms: signed(now.saturating_add(CODE_TTL_MS)),
        })
        .await?;
        let code = b64url_encode(&code);
        let reply = self
            .answer(
                &mut tx,
                realm,
                &l.client,
                back_to,
                Outcome::Code(&code),
                now,
            )
            .await?;
        tx.commit().await?;
        Ok(reply)
    }

    /// The authorization response (RFC 6749 §4.1.2, RFC 9207): the query with `iss`, or a JARM
    /// response JWT signed with the client's algorithm and encrypted when it asked, in the
    /// query or a posted form (OP-155 m.3 (k)).
    async fn answer(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        to: Answer<'_>,
        outcome: Outcome<'_>,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        if !to.mode.jwt() {
            let uri = match outcome {
                Outcome::Code(code) => {
                    code_redirect(to.redirect_uri, code, to.state, &realm.issuer)
                }
                Outcome::Error(e) => error_redirect(to.redirect_uri, e, to.state, &realm.issuer),
            };
            return Ok(Reply::Redirect(uri));
        }
        let mut all: Vec<(&str, &str)> = match outcome {
            Outcome::Code(code) => vec![("code", code)],
            Outcome::Error(e) => vec![("error", e.error), ("error_description", e.description)],
        };
        if let Some(st) = to.state {
            all.push(("state", st));
        }
        let claims = jarm::claims(&realm.issuer, &client.id, now, &all);
        let encrypt = client.profile.encryption.as_ref().is_some_and(|e| e.jarm);
        let response = self
            .client_jwt(tx, realm, client, jarm::JARM_TYP, &claims, encrypt, now)
            .await?;
        Ok(match to.mode {
            ResponseMode::FormPostJwt => Reply::FormPost {
                action: String::from(to.redirect_uri),
                body: jarm::form_post(to.redirect_uri, &response),
            },
            _ => Reply::Redirect(jarm::query(to.redirect_uri, &response)),
        })
    }

    /// To the hosted login with the request stored for `reason`.
    async fn to_login(
        &self,
        mut tx: <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        l: &Loaded,
        now: u64,
        reason: crate::domain::tokens::LoginReason,
    ) -> Result<Reply, Unavailable> {
        if let Some((d, hash)) = l.stored
            && !tx.use_request(d, &hash, signed(now)).await?
        {
            return Ok(problem(Unredirectable::RequestUri));
        }
        let uri = self
            .store_request(
                &mut tx,
                &l.client,
                &l.request,
                false,
                now,
                INTERACTIVE_TTL_MS,
            )
            .await?;
        tx.commit().await?;
        let back_to = return_to(&realm.issuer, &l.client.id, &uri);
        Ok(Reply::Redirect(self.env.pages().login(
            &realm.issuer,
            &back_to,
            reason,
        )))
    }

    /// §11.6 rule 1, P58: whether the person's consent record for this client and resource
    /// covers the request's scopes and the Grant it names still stands. A record whose Grant
    /// ended ends too, and consent is asked again.
    async fn approved(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        l: &Loaded,
        subject: [u8; 16],
        now: u64,
    ) -> Result<bool, Unavailable> {
        let Some(resource) = consent_resource(&l.request) else {
            return Ok(false);
        };
        let Some(record) = tx.consent_record(subject, l.client.uuid, resource).await? else {
            return Ok(false);
        };
        if !l.request.scope.iter().all(|s| record.scopes.contains(s)) {
            return Ok(false);
        }
        if self
            .env
            .standing()
            .live(record.grant_domain, record.grant_ref)
            .await?
        {
            return Ok(true);
        }
        tx.end_consent_record(record.consent_id, "grant_ended", now)
            .await?;
        Ok(false)
    }

    /// Whether a third-party client asks for claims the person has not shared with it
    /// (OP-153 m.3 (z)); a first-party client is never asked.
    async fn unshared(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        l: &Loaded,
        subject: [u8; 16],
    ) -> Result<bool, Unavailable> {
        use crate::domain::claims_request::{ClaimsAsk, covers, shared_set};
        if !l.client.third_party {
            return Ok(false);
        }
        let scopes: Vec<&str> = l.request.scope.iter().map(String::as_str).collect();
        let requested = l
            .request
            .claims
            .as_ref()
            .map(ClaimsAsk::requested)
            .unwrap_or_default();
        let wanted = shared_set(&scopes, &requested);
        if wanted.is_empty() {
            return Ok(false);
        }
        let given = tx.consent(subject, l.client.uuid).await?;
        Ok(!given.as_deref().is_some_and(|g| covers(g, &wanted)))
    }

    async fn store_request(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        client: &Client,
        req: &AuthRequest,
        pushed: bool,
        now: u64,
        ttl_ms: u64,
    ) -> Result<String, Unavailable> {
        let handle = self.random::<32>()?;
        let params = serde_json::to_vec(req).map_err(|_| Unavailable)?;
        tx.insert_request(&NewRequest {
            day: day(now),
            hash: &opaque_digest(REQUEST_CONTEXT, &handle),
            client: client.uuid,
            pushed,
            params: &params,
            created_ms: signed(now),
            expires_ms: signed(now.saturating_add(ttl_ms)),
        })
        .await?;
        Ok(format!("{REQUEST_URI_PREFIX}{}", b64url_encode(&handle)))
    }

    /// `POST /par` (RFC 9126): the client authenticates, the request is validated as
    /// `/authorize` would, and a single-use `request_uri` comes back. A `DPoP` proof sent with
    /// it binds the code to its key, as `dpop_jkt` does (RFC 9449 §10.1).
    pub async fn par(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
        dpop: &[&str],
    ) -> Reply {
        self.par_mtls(realm, params, authorization, dpop, &[]).await
    }

    /// [`Self::par`] over a connection that presented the client certificate `chain`, leaf
    /// first (RFC 8705 §2, OP-155 m.3 (k)).
    pub async fn par_mtls(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
        dpop: &[&str],
        chain: &[Vec<u8>],
    ) -> Reply {
        match self
            .par_inner(realm, params, authorization, dpop, chain)
            .await
        {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the pushed request steps in the order they run"
    )]
    async fn par_inner(
        &self,
        realm: &Realm,
        outer: &Params,
        authorization: Option<&str>,
        dpop: &[&str],
        chain: &[Vec<u8>],
    ) -> Result<Reply, Unavailable> {
        let params = outer;
        // IDP-1, AG-4
        if self.prepare_client(realm, params).await?.is_err() {
            return Ok(Reply::oauth_error(
                401,
                "invalid_client",
                "client authentication failed",
            ));
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let req = ClientRequest {
            authorization,
            params,
            endpoint: Endpoint::Par.path(),
            chain,
        };
        let client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) => c,
            Err(e) => {
                return Ok(Reply::oauth_error(
                    401,
                    e.error(),
                    "client authentication failed",
                ));
            }
        };
        // RFC 9101, OP-155 m.3 (k)
        let (inner, signed) = match outer.get("request") {
            Some(object) => match self
                .request_object(realm, &client, outer, object, now)
                .await?
            {
                Ok(p) => (p, true),
                Err(e) => {
                    return Ok(Reply::oauth_error(
                        400,
                        "invalid_request_object",
                        e.description(),
                    ));
                }
            },
            None if client.profile.fapi2 => {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_request",
                    "this client sends signed request objects",
                ));
            }
            None => (outer.clone(), false),
        };
        let params = &inner;
        let Ok(redirect) = stage_one(params, Some(&client)) else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "redirect_uri is not registered",
            ));
        };
        let product = self.product_resource(realm, params).await?;
        let mut request =
            match stage_two(params, &client, redirect, &realm.issuer, product.as_deref()) {
                Ok(r) => r,
                Err(e) => return Ok(Reply::oauth_error(400, e.error, e.description)),
            };
        // AG-8
        if mcp_without_resource(&client, &request) {
            let e = AuthError::RESOURCE_REQUIRED;
            return Ok(Reply::oauth_error(400, e.error, e.description));
        }
        request.signed = signed;
        // OP-155 m.3 (k)
        if client.profile.fapi2 {
            if params.get("response_mode") == Some("query") {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_request",
                    "this client receives signed authorization responses",
                ));
            }
            request.response_mode = request.response_mode.max_jwt(true);
        }
        // RFC 9449 §10.1
        let mut nonce = None;
        if !dpop.is_empty() {
            let par_uri = realm.issuer.endpoint(Endpoint::Par.path());
            let proof = match self
                .dpop(
                    realm,
                    Role::AuthorizationServer,
                    &DpopRequest {
                        proofs: dpop,
                        method: "POST",
                        uri: &par_uri,
                        access_token: None,
                        bound: None,
                    },
                )
                .await
            {
                Ok(p) => p,
                Err(Failure::Unavailable) => return Err(Unavailable),
                Err(f) => {
                    let nonce = f.nonce().map(String::from);
                    return Ok(Reply::oauth_error(
                        400,
                        f.error(),
                        "the DPoP proof was not accepted",
                    )
                    .with_nonce(nonce));
                }
            };
            if request.dpop_jkt.is_some_and(|j| j != proof.jkt.0) {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_dpop_proof",
                    "dpop_jkt does not match the DPoP proof",
                )
                .with_nonce(Some(proof.nonce)));
            }
            request.dpop_jkt = Some(proof.jkt.0);
            nonce = Some(proof.nonce);
        }
        let uri = self
            .store_request(&mut tx, &client, &request, true, now, PAR_TTL_MS)
            .await?;
        tx.commit().await?;
        Ok(Reply::json(
            201,
            &json!({ "request_uri": uri, "expires_in": PAR_TTL_MS / 1000 }),
        )
        .with_nonce(nonce))
    }
}
