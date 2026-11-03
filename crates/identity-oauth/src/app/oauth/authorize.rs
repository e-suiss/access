//! `/authorize` and `/par` (RFC 6749 §4.1, RFC 7636, RFC 9126, RFC 9207, OIDC Core §3.1.2).

use access_crypto::oauth::opaque_digest;
use access_identity_session::domain::session::cookie_digest;
use access_kernel::json::b64url_encode;
use access_store::oauth::{NewCode, NewRequest};
use serde_json::json;

use super::{
    ClientRequest, Env, OAuth, Realm, Reply, code_digest, day, decode32, from_day, session_aal,
    session_live, signed, unsigned,
};
use crate::domain::client::Client;
use crate::domain::login::return_to;
use crate::domain::metadata::Endpoint;
use crate::domain::request::{
    AuthError, AuthRequest, Params, Prompt, REQUEST_URI_PREFIX, Unredirectable, code_redirect,
    error_redirect, stage_one, stage_two,
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
            Some(id) => tx.client(id).await?.and_then(Client::from_row),
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
        match stage_two(params, &client, redirect, &realm.issuer) {
            Ok(request) => Ok(Ok(Loaded {
                client,
                request,
                created_ms: now,
                stored: None,
            })),
            Err(e) => Ok(Err(Reply::Redirect(error_redirect(
                redirect,
                e,
                params.get("state"),
                &realm.issuer,
            )))),
        }
    }

    async fn authorize_inner(
        &self,
        realm: &Realm,
        params: &Params,
        cookie: Option<&str>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let l = match self.load(&mut tx, realm, params, now).await? {
            Ok(l) => l,
            Err(reply) => return Ok(reply),
        };
        let session = match cookie.and_then(decode32) {
            Some(value) => tx
                .session_by_cookie(&cookie_digest(&value))
                .await?
                .filter(|s| session_live(s, now)),
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
        let back = |e: AuthError| {
            Reply::Redirect(error_redirect(
                &req.redirect_uri,
                e,
                req.state.as_deref(),
                &realm.issuer,
            ))
        };
        if let Some(reason) = needs_login(req, signed_in, l.created_ms, now) {
            if req.prompt == Prompt::None {
                return Ok(back(AuthError::LOGIN_REQUIRED));
            }
            if let Some((d, hash)) = l.stored
                && !tx.use_request(d, &hash, signed(now)).await?
            {
                return Ok(problem(Unredirectable::RequestUri));
            }
            let uri = self
                .store_request(&mut tx, &l.client, req, false, now, INTERACTIVE_TTL_MS)
                .await?;
            tx.commit().await?;
            let back_to = return_to(&realm.issuer, &l.client.id, &uri);
            return Ok(Reply::Redirect(self.env.pages().login(
                &realm.issuer,
                &back_to,
                reason,
            )));
        }
        let (Some(session), Some(s)) = (session, signed_in) else {
            return Ok(back(AuthError::LOGIN_REQUIRED));
        };
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
        tx.commit().await?;
        Ok(Reply::Redirect(code_redirect(
            &req.redirect_uri,
            &b64url_encode(&code),
            req.state.as_deref(),
            &realm.issuer,
        )))
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
    /// `/authorize` would, and a single-use `request_uri` comes back.
    pub async fn par(&self, realm: &Realm, params: &Params, authorization: Option<&str>) -> Reply {
        match self.par_inner(realm, params, authorization).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn par_inner(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let req = ClientRequest {
            authorization,
            params,
            endpoint: Endpoint::Par.path(),
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
        let Ok(redirect) = stage_one(params, Some(&client)) else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "redirect_uri is not registered",
            ));
        };
        let request = match stage_two(params, &client, redirect, &realm.issuer) {
            Ok(r) => r,
            Err(e) => return Ok(Reply::oauth_error(400, e.error, e.description)),
        };
        let uri = self
            .store_request(&mut tx, &client, &request, true, now, PAR_TTL_MS)
            .await?;
        tx.commit().await?;
        Ok(Reply::json(
            201,
            &json!({ "request_uri": uri, "expires_in": PAR_TTL_MS / 1000 }),
        ))
    }
}
