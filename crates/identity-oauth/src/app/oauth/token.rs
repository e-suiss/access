//! `POST /token` (RFC 6749 §3.2, §4.1.3, §6; RFC 7636 §4.6; RFC 9449 §5): the code exchange
//! and refresh rotation. Every token request carries a DPoP proof: there is no bearer access
//! token (TN-27). ROPC and implicit do not exist; client credentials and device code are later
//! stages (OP-146 m.6).

use access_crypto::dpop::Role;
use access_crypto::oauth::pkce_matches;
use access_store::oauth::NewGrant;

use super::{
    ClientRequest, Env, OAuth, Realm, Reply, code_digest, decode32, from_day, grant_live,
    refresh_digest, session_live, signed, unsigned,
};
use crate::app::dpop::DpopRequest;
use crate::domain::client::Client;
use crate::domain::dpop::{
    BindingError, Failure, Jkt, check_code_exchange, check_refresh, refresh_binding,
};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::domain::tokens::{CodeDetails, GrantDetails};
use crate::ports::Unavailable;
use crate::ports::oauth::OAuthTx;

/// What a token request presents besides its form.
#[derive(Clone, Copy, Debug)]
pub struct TokenHttp<'a> {
    /// `Authorization`, when sent.
    pub authorization: Option<&'a str>,
    /// Every `DPoP` header value.
    pub dpop: &'a [&'a str],
}

fn invalid_grant() -> Reply {
    Reply::oauth_error(400, "invalid_grant", "the grant is not valid")
}

fn binding(e: BindingError) -> Reply {
    Reply::oauth_error(400, e.error(), "the DPoP key does not match the grant")
}

fn verifier_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

impl<E: Env> OAuth<E> {
    /// `POST /token`, form-encoded (§11.4.5 #19).
    pub async fn token(&self, realm: &Realm, params: &Params, http: TokenHttp<'_>) -> Reply {
        match self.token_inner(realm, params, http).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn token_inner(
        &self,
        realm: &Realm,
        params: &Params,
        http: TokenHttp<'_>,
    ) -> Result<Reply, Unavailable> {
        let grant_type = params.get("grant_type");
        if !matches!(grant_type, Some("authorization_code" | "refresh_token")) {
            return Ok(match grant_type {
                None => Reply::oauth_error(400, "invalid_request", "grant_type is required"),
                Some(_) => Reply::oauth_error(
                    400,
                    "unsupported_grant_type",
                    "the grant type is not supported",
                ),
            });
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let req = ClientRequest {
            authorization: http.authorization,
            params,
            endpoint: Endpoint::Token.path(),
        };
        let client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) => c,
            Err(e) => {
                let status = if e.error() == "invalid_client" {
                    401
                } else {
                    400
                };
                return Ok(Reply::oauth_error(
                    status,
                    e.error(),
                    "client authentication failed",
                ));
            }
        };
        tx.commit().await?;
        let token_uri = realm.issuer.endpoint(Endpoint::Token.path());
        // IDP-11, TN-27
        let proof = match self
            .dpop(
                realm,
                Role::AuthorizationServer,
                &DpopRequest {
                    proofs: http.dpop,
                    method: "POST",
                    uri: &token_uri,
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
                let reply = if http.dpop.is_empty() {
                    Reply::oauth_error(400, "invalid_dpop_proof", "a DPoP proof is required")
                } else {
                    Reply::oauth_error(400, f.error(), "the DPoP proof was not accepted")
                };
                return Ok(reply.with_nonce(nonce));
            }
        };
        let mut tx = self.begin(realm).await?;
        let reply = if grant_type == Some("authorization_code") {
            self.exchange(&mut tx, realm, &client, params, proof.jkt, now)
                .await?
        } else {
            self.rotate(&mut tx, realm, &client, params, proof.jkt, now)
                .await?
        };
        tx.commit().await?;
        Ok(reply.with_nonce(Some(proof.nonce)))
    }

    /// RFC 6749 §4.1.3, §11.4.5 #20: the code is redeemed once by compare-and-set; a second
    /// redemption revokes what the first one issued.
    async fn exchange(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(code) = params.get("code").and_then(decode32) else {
            return Ok(invalid_grant());
        };
        let hash = code_digest(&code);
        let Some(row) = tx.code(from_day(now), &hash).await? else {
            return Ok(invalid_grant());
        };
        if row.client != client.uuid {
            return Ok(invalid_grant());
        }
        if let Some(issued) = row.grant {
            tx.revoke_grant(issued, signed(now), "code_reuse").await?;
            return Ok(invalid_grant());
        }
        if unsigned(row.expires_ms) <= now {
            return Ok(invalid_grant());
        }
        let details: CodeDetails = serde_json::from_slice(&row.details).map_err(|_| Unavailable)?;
        // IDP-7
        if params.get("redirect_uri") != Some(details.redirect_uri.as_str()) {
            return Ok(invalid_grant());
        }
        // IDP-7, CR-39
        let verified = params
            .get("code_verifier")
            .filter(|v| verifier_ok(v))
            .is_some_and(|v| pkce_matches(&details.code_challenge, v));
        if !verified {
            return Ok(invalid_grant());
        }
        if let Err(e) = check_code_exchange(details.dpop_jkt.map(Jkt), Some(jkt)) {
            return Ok(binding(e));
        }
        // G57
        let Some(session) = tx
            .session(row.session)
            .await?
            .filter(|s| session_live(s, now))
        else {
            return Ok(invalid_grant());
        };
        let Ok(bound) = refresh_binding(client.client_type(), Some(jkt)) else {
            return Ok(binding(BindingError::ProofRequired));
        };
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&details.grant).map_err(|_| Unavailable)?;
        let grant_id = tx
            .insert_grant(&NewGrant {
                sid,
                client: client.uuid,
                subject: session.subject,
                session: session.id,
                session_epoch: session.session_epoch,
                dpop_jkt: bound.as_ref().map(|j| &j.0),
                details: &encoded,
                created_ms: signed(now),
                expires_ms: session.expires_ms,
            })
            .await?;
        if !tx
            .redeem_code(row.day, &hash, signed(now), grant_id)
            .await?
        {
            return Ok(invalid_grant());
        }
        let grant = tx.grant(grant_id).await?.ok_or(Unavailable)?;
        let body = self
            .issue(
                tx,
                realm,
                client,
                &grant,
                &details.grant,
                &jkt.text(),
                details.nonce.as_deref(),
                now,
            )
            .await?;
        Ok(Reply::json(200, &body))
    }

    /// RFC 6749 §6, TN-31: the refresh token rotates on every use; a rotated token presented
    /// again revokes the whole grant and raises the subject's `session_epoch`. A refresh never
    /// outlives the session it came from (G57, EP-2).
    async fn rotate(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(token) = params.get("refresh_token").and_then(decode32) else {
            return Ok(invalid_grant());
        };
        let hash = refresh_digest(&token);
        let Some(row) = tx.refresh(&hash).await? else {
            return Ok(invalid_grant());
        };
        let Some(grant) = tx.grant(row.grant).await? else {
            return Err(Unavailable);
        };
        if grant.client != client.uuid {
            return Ok(invalid_grant());
        }
        if row.rotated_ms.is_some() {
            // TN-31, RR-18
            tx.revoke_grant(grant.id, signed(now), "reuse").await?;
            tx.end_sessions(grant.subject).await?;
            return Ok(invalid_grant());
        }
        if !grant_live(&grant, now) {
            return Ok(invalid_grant());
        }
        if !tx
            .session(grant.session)
            .await?
            .is_some_and(|s| session_live(&s, now))
        {
            return Ok(invalid_grant());
        }
        if let Err(e) = check_refresh(grant.dpop_jkt.map(Jkt), Some(jkt)) {
            return Ok(binding(e));
        }
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        if let Some(scope) = params.get("scope")
            && scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .any(|s| !details.scope.split(' ').any(|g| g == s))
        {
            return Ok(Reply::oauth_error(
                400,
                "invalid_scope",
                "the scope exceeds the grant",
            ));
        }
        if !tx.rotate_refresh(&hash, signed(now)).await? {
            return Ok(invalid_grant());
        }
        let body = self
            .issue(tx, realm, client, &grant, &details, &jkt.text(), None, now)
            .await?;
        Ok(Reply::json(200, &body))
    }
}
