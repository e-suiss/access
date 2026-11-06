//! `POST /token` (RFC 6749 §3.2, §4.1.3, §4.4, §6; RFC 7636 §4.6; RFC 9449 §5): the code
//! exchange, refresh rotation and client credentials. Every token request carries a DPoP proof:
//! there is no bearer access token (TN-27). A request for authority (RFC 9396
//! `authorization_details`) is a `projection.issue` decision of the authority plane (§9.9);
//! client credentials exist for it and, towards a platform product, for the identity-assertion
//! service token (OP-149 m.31 (a), m.34 (b)). ROPC and implicit do not exist; device code is a later
//! stage (OP-146 m.6). A refused request is written to the identity audit log (OP-39).

use access_crypto::dpop::Role;
use access_crypto::oauth::pkce_matches;
use access_kernel::digest::Digest;
use access_store::oauth::NewGrant;

use super::authority::Asked;
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
use crate::domain::scope;
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

/// RFC 8707 §2.2, OP-149 m.26 (a): a `resource` sent to the token endpoint for a protocol-scope
/// grant must be the one the authorization request named, the realm itself when it named
/// none; an authority grant's resource is read with its details instead.
fn resource_matches(params: &Params, details: &GrantDetails, realm: &Realm) -> bool {
    details.authority.is_some()
        || params
            .get("resource")
            .is_none_or(|r| r == details.audience(&realm.issuer))
}

fn invalid_target() -> Reply {
    Reply::oauth_error(400, "invalid_target", "not the authorized resource")
}

/// A request value as an audit field: identifiers only (OP-10); anything else is `-`.
fn audit_text(v: Option<&str>, max: usize) -> &str {
    v.filter(|s| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'.' | b'-'))
    })
    .unwrap_or("-")
}

fn verifier_ok(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

impl<E: Env> OAuth<E> {
    /// `POST /token`, form-encoded (§11.4.5 #19).
    pub async fn token(&self, realm: &Realm, params: &Params, http: TokenHttp<'_>) -> Reply {
        let reply = match self.token_inner(realm, params, http).await {
            Ok(r) => r,
            Err(Unavailable) => return Reply::Unavailable,
        };
        // OP-39: every refused token request, unsampled
        if let Some(error) = super::authority::error_of(&reply)
            && self.audit_refusal(realm, params, &error).await.is_err()
        {
            return Reply::Unavailable;
        }
        reply
    }

    async fn audit_refusal(
        &self,
        realm: &Realm,
        params: &Params,
        error: &str,
    ) -> Result<(), Unavailable> {
        let mut tx = self.begin(realm).await?;
        tx.audit(
            "oauth.token.refused",
            audit_text(params.get("client_id"), 200),
            audit_text(Some(error), 200),
            audit_text(params.get("grant_type"), 128),
        )
        .await?;
        tx.commit().await
    }

    async fn token_inner(
        &self,
        realm: &Realm,
        params: &Params,
        http: TokenHttp<'_>,
    ) -> Result<Reply, Unavailable> {
        let grant_type = params.get("grant_type");
        if !matches!(
            grant_type,
            Some("authorization_code" | "refresh_token" | "client_credentials")
        ) {
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
        if grant_type == Some("client_credentials") {
            // OP-149 m.31 (a), m.34 (b): a client naming a product gets a service token
            let reply = match self.service_target(realm, &client, params).await? {
                Some(Ok(target)) => {
                    self.service_token(realm, &client, &target, proof.jkt, now)
                        .await?
                }
                Some(Err(refusal)) => refusal,
                None => {
                    self.client_credentials(realm, &client, params, proof.jkt, now)
                        .await?
                }
            };
            return Ok(reply.with_nonce(Some(proof.nonce)));
        }
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
        if !resource_matches(params, &details.grant, realm) {
            return Ok(invalid_target());
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
        let mut grant_details = details.grant.clone();
        let projected = match self
            .code_projection(realm, client, params, &mut grant_details, jkt)
            .await?
        {
            Ok(p) => p,
            Err(r) => return Ok(r),
        };
        let sid = self.random::<16>()?;
        let encoded = serde_json::to_vec(&grant_details).map_err(|_| Unavailable)?;
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
            if let Some(p) = &projected {
                self.invalidate(tx, p.domain, p.token.family, &p.token.exercise, now)
                    .await?;
            }
            return Ok(invalid_grant());
        }
        let grant = tx.grant(grant_id).await?.ok_or(Unavailable)?;
        let nonce = details.nonce.as_deref();
        if let Some(p) = &projected {
            let body = self
                .authority_tokens(tx, realm, client, &grant, &grant_details, p, nonce, now)
                .await?;
            return Ok(Reply::json(200, &body));
        }
        let body = self
            .issue(
                tx,
                realm,
                client,
                &grant,
                &details.grant,
                &jkt.text(),
                nonce,
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
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        if row.rotated_ms.is_some() {
            // TN-31, RR-18
            tx.revoke_grant(grant.id, signed(now), "reuse").await?;
            tx.end_sessions(grant.subject).await?;
            // §9.9.3 rule 6, P50: the whole family of authority tokens ends
            if let (Some(family), Some(root), Some(domain)) =
                (details.family, details.projection, tx.governing().await?)
            {
                self.invalidate(tx, Digest(domain), family, &Digest(root), now)
                    .await?;
            }
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
        if !resource_matches(params, &details, realm) {
            return Ok(invalid_target());
        }
        if let (Some(a), Some(family)) = (&details.authority, details.family) {
            // §9.9.3 rule 6, L19: every refresh is a new decision of the family
            let asked = Asked {
                params,
                authorized: Some(a),
                family: Some(family),
            };
            let p = match self.project(realm, client, &asked, jkt).await? {
                Ok(p) => p,
                Err(r) => return Ok(r),
            };
            if !tx.rotate_refresh(&hash, signed(now)).await? {
                self.invalidate(tx, p.domain, family, &p.token.exercise, now)
                    .await?;
                return Ok(invalid_grant());
            }
            let body = self
                .authority_tokens(tx, realm, client, &grant, &details, &p, None, now)
                .await?;
            return Ok(Reply::json(200, &body));
        }
        if let Some(scope) = params.get("scope") {
            let mut asked = scope.split(' ').filter(|s| !s.is_empty());
            // §2.2.2 #2, L24, S-1
            if asked
                .clone()
                .any(|s| scope::classify(s) == scope::ScopeClass::Resource)
            {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_scope",
                    scope::RESOURCE_SCOPE,
                ));
            }
            if asked.any(|s| !details.scope.split(' ').any(|g| g == s)) {
                return Ok(Reply::oauth_error(
                    400,
                    "invalid_scope",
                    "the scope exceeds the grant",
                ));
            }
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
