//! The realm's own resource and token management: `/userinfo` (OIDC Core §5.3, MD-10),
//! `/revoke` (RFC 7009) and `/introspect` (RFC 7662, MD-8). Access tokens are read back by
//! signature and then held against their grant on the primary (Δ = 0).

use access_crypto::AwsLcBackend;
use access_crypto::dpop::Role;
use access_kernel::json::{Json, b64url_decode};
use access_kernel::verify::jws::{ClaimRules, Origin, check_claims, verify_compact};
use access_store::oauth::GrantRow;
use serde_json::{Value, json};

use super::{
    ClientRequest, Env, OAuth, Realm, Reply, decode32, grant_live, refresh_digest, session_live,
};
use crate::app::dpop::DpopRequest;
use crate::domain::client::Client;
use crate::domain::dpop::{DpopProfile, Failure, Jkt};
use crate::domain::jwt::{SKEW_MS, realm_key_set};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::domain::tokens::{ACCESS_TYP, GrantDetails};
use crate::ports::Unavailable;
use crate::ports::oauth::{OAuthTx, TokenSigner};

/// A verified access token of this realm.
pub(crate) struct AccessToken {
    pub(crate) sub: String,
    pub(crate) client_id: String,
    pub(crate) sid: [u8; 16],
    pub(crate) jkt: Jkt,
    pub(crate) scope: String,
    pub(crate) exp: i64,
    pub(crate) iat: i64,
}

fn text(c: &Json, name: &str) -> Option<String> {
    c.get(name).and_then(Json::as_str).map(String::from)
}

fn active_false() -> Reply {
    Reply::json(200, &json!({ "active": false }))
}

impl<E: Env> OAuth<E> {
    /// Reads back an access token of this realm: signature with the realm's keys, `typ`
    /// `at+jwt`, `iss`, `aud` and times (RFC 9068 §4); `Ok(None)` when it is not one.
    pub(crate) async fn access_token(
        &self,
        realm: &Realm,
        token: &str,
        now: u64,
        check_time: bool,
    ) -> Result<Option<AccessToken>, Unavailable> {
        let jwks = self.env.signer().jwks(realm.realm).await?;
        let Ok(keys) = realm_key_set(jwks.as_bytes()) else {
            return Err(Unavailable);
        };
        let Ok(v) = verify_compact(&AwsLcBackend, token, &keys, ACCESS_TYP, Origin::Native) else {
            return Ok(None);
        };
        let rules = ClaimRules {
            issuer: realm.issuer.as_str(),
            audience: realm.issuer.as_str(),
            now,
            skew_ms: SKEW_MS,
        };
        let claims = if check_time {
            check_claims(&v.payload, &rules).ok()
        } else {
            access_kernel::json::parse(&v.payload, access_kernel::verify::jws::MAX_PAYLOAD)
                .ok()
                .filter(|c| c.get("iss").and_then(Json::as_str) == Some(realm.issuer.as_str()))
        };
        let Some(c) = claims else {
            return Ok(None);
        };
        // AG-8, §9.9.3 k.1
        if !matches!(c.get("aud"), Some(Json::Str(a)) if a == realm.issuer.as_str()) {
            return Ok(None);
        }
        let sid = text(&c, "sid")
            .and_then(|s| b64url_decode(&s).ok())
            .and_then(|s| <[u8; 16]>::try_from(s).ok());
        let jkt = c
            .get("cnf")
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(Json::as_str)
            .and_then(|j| Jkt::parse(j).ok());
        let (Some(sub), Some(client_id), Some(sid), Some(jkt)) =
            (text(&c, "sub"), text(&c, "client_id"), sid, jkt)
        else {
            return Ok(None);
        };
        Ok(Some(AccessToken {
            sub,
            client_id,
            sid,
            jkt,
            scope: text(&c, "scope").unwrap_or_default(),
            exp: c.get("exp").and_then(Json::as_int).unwrap_or(0),
            iat: c.get("iat").and_then(Json::as_int).unwrap_or(0),
        }))
    }

    /// The grant behind `sid` when it, its session and its subject are all live now.
    pub(crate) async fn live_grant(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        sid: &[u8; 16],
        now: u64,
    ) -> Result<Option<GrantRow>, Unavailable> {
        let Some(g) = tx.grant_by_sid(sid).await?.filter(|g| grant_live(g, now)) else {
            return Ok(None);
        };
        let live = tx
            .session(g.session)
            .await?
            .is_some_and(|s| session_live(&s, now));
        Ok(live.then_some(g))
    }

    /// `GET`/`POST /userinfo` with a DPoP-bound access token (RFC 9449 §7, OIDC Core §5.3):
    /// the pairwise `sub` only (MD-10). A bearer token is refused: there is none (TN-27).
    pub async fn userinfo(
        &self,
        realm: &Realm,
        method: &str,
        authorization: Option<&str>,
        dpop: &[&str],
    ) -> Reply {
        let profile = self.env.dpop().clone();
        match self
            .userinfo_inner(realm, method, authorization, dpop, &profile)
            .await
        {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn userinfo_inner(
        &self,
        realm: &Realm,
        method: &str,
        authorization: Option<&str>,
        dpop: &[&str],
        profile: &DpopProfile,
    ) -> Result<Reply, Unavailable> {
        let challenge = |error: &str| {
            Some(format!(
                r#"DPoP error="{error}", algs="{}""#,
                profile.signing_alg_values().join(" ")
            ))
        };
        let unauthorized = |error: &str| Reply::Json {
            status: 401,
            body: json!({ "error": error }).to_string(),
            dpop_nonce: self.nonce(realm, Role::ResourceServer),
            challenge: challenge(error),
        };
        let Some(token) = authorization
            .and_then(|a| a.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("dpop"))
            .map(|(_, t)| t.trim())
        else {
            return Ok(unauthorized("invalid_token"));
        };
        let now = self.now()?;
        let Some(at) = self.access_token(realm, token, now, true).await? else {
            return Ok(unauthorized("invalid_token"));
        };
        let uri = realm.issuer.endpoint(Endpoint::Userinfo.path());
        let proof = self
            .dpop(
                realm,
                Role::ResourceServer,
                &DpopRequest {
                    proofs: dpop,
                    method,
                    uri: &uri,
                    access_token: Some(token),
                    bound: Some(at.jkt),
                },
            )
            .await;
        let nonce = match proof {
            Ok(p) => p.nonce,
            Err(Failure::Unavailable) => return Err(Unavailable),
            Err(f) => {
                return Ok(Reply::Json {
                    status: f.status(Role::ResourceServer),
                    body: json!({ "error": f.error() }).to_string(),
                    dpop_nonce: f.nonce().map(String::from),
                    challenge: f.challenge(Role::ResourceServer, profile),
                });
            }
        };
        let mut tx = self.begin(realm).await?;
        let live = self.live_grant(&mut tx, &at.sid, now).await?;
        tx.commit().await?;
        if live.is_none() {
            return Ok(unauthorized("invalid_token"));
        }
        Ok(Reply::json(200, &json!({ "sub": at.sub })).with_nonce(Some(nonce)))
    }

    async fn token_grant(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        token: &str,
        now: u64,
    ) -> Result<Option<(GrantRow, Option<AccessToken>)>, Unavailable> {
        if let Some(raw) = decode32(token) {
            let Some(row) = tx.refresh(&refresh_digest(&raw)).await? else {
                return Ok(None);
            };
            if row.rotated_ms.is_some() {
                return Ok(None);
            }
            return Ok(tx.grant(row.grant).await?.map(|g| (g, None)));
        }
        let Some(at) = self.access_token(realm, token, now, false).await? else {
            return Ok(None);
        };
        Ok(tx.grant_by_sid(&at.sid).await?.map(|g| (g, Some(at))))
    }

    /// `POST /revoke` (RFC 7009): revoking a refresh or access token revokes its grant, a
    /// projection cleanup that cascades nowhere else (PI-10). An unknown token, or one of
    /// another client, is answered 200 without effect (RFC 7009 §2.2).
    pub async fn revoke(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
    ) -> Reply {
        match self.revoke_inner(realm, params, authorization).await {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    async fn revoke_inner(
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
            endpoint: Endpoint::Revoke.path(),
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
        let Some(token) = params.get("token") else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "token is required",
            ));
        };
        if let Some((grant, _)) = self.token_grant(&mut tx, realm, token, now).await?
            && grant.client == client.uuid
        {
            tx.revoke_grant(grant.id, super::signed(now), "revoked")
                .await?;
        }
        tx.commit().await?;
        Ok(Reply::json(200, &json!({})))
    }

    /// `POST /introspect` (RFC 7662, MD-8): a confidential client learns whether its own token
    /// is active now. When freshness cannot be proven, the primary or the signer being out of
    /// reach included, every token is `active: false`, never 503 (P-ID-8, EP-3).
    pub async fn introspect(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
    ) -> Reply {
        self.introspect_inner(realm, params, authorization)
            .await
            .unwrap_or_else(|Unavailable| active_false())
    }

    async fn introspect_inner(
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
            endpoint: Endpoint::Introspect.path(),
        };
        let client: Client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) if c.client_type() == crate::domain::dpop::ClientType::Confidential => c,
            Ok(_) | Err(_) => {
                return Ok(Reply::oauth_error(
                    401,
                    "invalid_client",
                    "client authentication failed",
                ));
            }
        };
        let Some(token) = params.get("token") else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "token is required",
            ));
        };
        let Some((grant, at)) = self.token_grant(&mut tx, realm, token, now).await? else {
            tx.commit().await?;
            return Ok(active_false());
        };
        let live = grant.client == client.uuid
            && self.live_grant(&mut tx, &grant.sid, now).await?.is_some();
        let sub = if live {
            Some(self.pairwise(&mut tx, grant.subject, grant.client).await?)
        } else {
            None
        };
        tx.commit().await?;
        let Some(sub) = sub else {
            return Ok(active_false());
        };
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        let mut body = json!({
            "active": true,
            "client_id": client.id,
            "sub": sub,
            "iss": realm.issuer.as_str(),
        });
        let Value::Object(m) = &mut body else {
            return Err(Unavailable);
        };
        if let Some(at) = at {
            let expired = u64::try_from(at.exp).map_or(true, |e| e.saturating_mul(1000) <= now);
            if at.client_id != client.id || expired {
                return Ok(active_false());
            }
            m.insert("token_type".into(), "DPoP".into());
            m.insert("scope".into(), at.scope.into());
            m.insert("exp".into(), at.exp.into());
            m.insert("iat".into(), at.iat.into());
            m.insert("aud".into(), realm.issuer.as_str().into());
            m.insert("cnf".into(), json!({ "jkt": at.jkt.text() }));
            if at.sub != sub {
                return Ok(active_false());
            }
        } else {
            m.insert("token_type".into(), "refresh_token".into());
            m.insert("scope".into(), details.scope.into());
            m.insert("exp".into(), (grant.expires_ms / 1000).into());
        }
        Ok(Reply::json(200, &body))
    }
}
