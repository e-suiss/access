//! OIDC RP-Initiated Logout 1.0 and Back-Channel Logout 1.0 (§10.4.6): a sign-out tied to the
//! browser's session by a valid `id_token_hint` ends the session and revokes its grants in one
//! transaction (G57); a logout notice for every client with a back-channel endpoint is queued
//! in the same transaction and delivered by [`crate::app::backchannel`]. Delivery is best
//! effort; revocation does not rest on it (MD-7).

use access_crypto::AwsLcBackend;
use access_identity_session::domain::session::cookie_digest;
use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};

use super::{Env, OAuth, Realm, Reply, decode32, session_live, signed};
use crate::domain::client::Client;
use crate::domain::issuer::form_encode;
use crate::domain::jwt::realm_key_set;
use crate::domain::request::Params;
use crate::domain::tokens::ID_TYP;
use crate::ports::Unavailable;
use crate::ports::oauth::{LoginPages, OAuthTx, TokenSigner};

/// What a verified `id_token_hint` names.
struct Hint {
    client_id: String,
    sid: [u8; 16],
}

impl<E: Env> OAuth<E> {
    /// Reads an ID token of this realm; an expired one is still a hint (RP-Initiated Logout
    /// §2).
    async fn id_token_hint(&self, realm: &Realm, token: &str) -> Result<Option<Hint>, Unavailable> {
        let jwks = self.env.signer().jwks(realm.realm).await?;
        let keys = realm_key_set(jwks.as_bytes()).map_err(|_| Unavailable)?;
        let Ok(v) = verify_compact(&AwsLcBackend, token, &keys, ID_TYP, Origin::Native) else {
            return Ok(None);
        };
        let Ok(c) = json::parse(&v.payload, MAX_PAYLOAD) else {
            return Ok(None);
        };
        if c.get("iss").and_then(Json::as_str) != Some(realm.issuer.as_str()) {
            return Ok(None);
        }
        let sid = c
            .get("sid")
            .and_then(Json::as_str)
            .and_then(|s| b64url_decode(s).ok())
            .and_then(|s| <[u8; 16]>::try_from(s).ok());
        let client_id = c.get("aud").and_then(Json::as_str).map(String::from);
        Ok(sid
            .zip(client_id)
            .map(|(sid, client_id)| Hint { client_id, sid }))
    }

    /// `GET`/`POST /end-session` (OIDC RP-Initiated Logout 1.0): `post_logout_redirect_uri`
    /// must match the client's registration exactly, else nothing is redirected.
    pub async fn end_session(&self, realm: &Realm, params: &Params, cookie: Option<&str>) -> Reply {
        match self.end_session_inner(realm, params, cookie).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn end_session_inner(
        &self,
        realm: &Realm,
        params: &Params,
        cookie: Option<&str>,
    ) -> Result<Reply, Unavailable> {
        let now = self.now()?;
        let hint = match params.get("id_token_hint") {
            Some(t) => self.id_token_hint(realm, t).await?,
            None => None,
        };
        let client_id = match (params.get("client_id"), &hint) {
            (Some(c), Some(h)) if c != h.client_id => {
                return Ok(Reply::Problem {
                    status: 400,
                    code: "invalid-logout-request",
                });
            }
            (Some(c), _) => Some(String::from(c)),
            (None, Some(h)) => Some(h.client_id.clone()),
            (None, None) => None,
        };
        let mut tx = self.begin(realm).await?;
        let client = match &client_id {
            Some(id) => tx.client(id).await?.and_then(Client::from_row),
            None => None,
        };
        let target = match params.get("post_logout_redirect_uri") {
            Some(uri) => match &client {
                Some(c) if c.post_logout_allowed(uri) => {
                    let mut out = String::from(uri);
                    if let Some(state) = params.get("state") {
                        out.push(if uri.contains('?') { '&' } else { '?' });
                        out.push_str("state=");
                        form_encode(state, &mut out);
                    }
                    out
                }
                _ => {
                    return Ok(Reply::Problem {
                        status: 400,
                        code: "invalid-post-logout-redirect-uri",
                    });
                }
            },
            None => self.env.pages().signed_out(&realm.issuer),
        };
        let session = match cookie
            .map(|c| access_identity_session::domain::dbsc::split_cookie(c).0)
            .and_then(decode32)
        {
            Some(v) => tx
                .session_by_cookie(&cookie_digest(&v))
                .await?
                .filter(|s| session_live(s, now)),
            None => None,
        };
        let Some(session) = session else {
            tx.commit().await?;
            return Ok(Reply::Redirect(target));
        };
        let tied = match &hint {
            Some(h) => tx
                .grant_by_sid(&h.sid)
                .await?
                .is_some_and(|g| g.session == session.id),
            None => false,
        };
        if !tied {
            tx.commit().await?;
            return Ok(Reply::Redirect(
                self.env.pages().confirm_sign_out(&realm.issuer),
            ));
        }
        // G57, §10.4.6
        tx.end_session(session.id, signed(now), "logout").await?;
        tx.commit().await?;
        Ok(Reply::Redirect(target))
    }
}
