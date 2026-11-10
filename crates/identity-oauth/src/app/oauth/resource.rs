//! The realm's own resource and token management: `/userinfo` (OIDC Core §5.3, MD-10),
//! `/revoke` (RFC 7009) and `/introspect` (RFC 7662, MD-8). Access tokens are read back by
//! signature and then held against their grant on the primary (Δ = 0); a product's service
//! token (OP-149 m.31 (a)) has no grant and is held against both products' registrations.

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
use crate::domain::fapi::Binding;
use crate::domain::jwt::{SKEW_MS, realm_key_set};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::domain::tokens::{ACCESS_TYP, GrantDetails};
use crate::ports::Unavailable;
use access_internal_api::projections::Projections as _;

use crate::ports::oauth::{OAuthTx, TokenSigner};

/// `typ` of a JWT introspection answer (RFC 9701 §5).
pub(crate) const INTROSPECTION_TYP: &str = "token-introspection+jwt";

/// `typ` of a signed userinfo answer (OIDC Core §5.3.2).
pub(crate) const USERINFO_TYP: &str = "JWT";

/// A verified access token of this realm: a grant's protocol-scope token (`sid`) or a client's
/// service token for a product (no `sid`, `access_tenant`; OP-149 m.31 (a), m.34 (b)).
pub(crate) struct AccessToken {
    pub(crate) sub: String,
    /// Its one audience: the realm, or a registered platform product (OP-149 m.26 (a)).
    pub(crate) aud: String,
    pub(crate) client_id: String,
    /// The grant's `sid`; a service token has none.
    pub(crate) sid: Option<[u8; 16]>,
    /// The `tnt_` tenant: of a service token always, of a grant's token when its audience is a
    /// product (OP-149 m.34 (a)).
    pub(crate) access_tenant: Option<String>,
    /// How it is bound: DPoP, a client certificate, or the legacy bearer exception (OP-155
    /// m.3 (k)).
    pub(crate) binding: Binding,
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
    /// `at+jwt`, `iss`, its one string `aud` and times (RFC 9068 §4); `Ok(None)` when it is not
    /// one. The caller holds `aud` against the resource it serves (AG-8, §9.9.3 k.1).
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
        let Ok(parsed) =
            access_kernel::json::parse(&v.payload, access_kernel::verify::jws::MAX_PAYLOAD)
        else {
            return Ok(None);
        };
        let Some(Json::Str(aud)) = parsed.get("aud") else {
            return Ok(None);
        };
        let aud = aud.clone();
        let rules = ClaimRules {
            issuer: realm.issuer.as_str(),
            audience: &aud,
            now,
            skew_ms: SKEW_MS,
        };
        let claims = if check_time {
            check_claims(&v.payload, &rules).ok()
        } else {
            Some(parsed)
                .filter(|c| c.get("iss").and_then(Json::as_str) == Some(realm.issuer.as_str()))
        };
        let Some(c) = claims else {
            return Ok(None);
        };
        let sid = text(&c, "sid")
            .and_then(|s| b64url_decode(&s).ok())
            .and_then(|s| <[u8; 16]>::try_from(s).ok());
        // TN-27, RFC 8705 §3, OP-155 m.3 (k)
        let binding = match c.get("cnf") {
            None => Some(Binding::Bearer),
            Some(cnf) => match (cnf.get("jkt"), cnf.get("x5t#S256")) {
                (Some(j), None) => j
                    .as_str()
                    .and_then(|j| Jkt::parse(j).ok())
                    .map(Binding::Dpop),
                (None, Some(x)) => x
                    .as_str()
                    .and_then(|x| b64url_decode(x).ok())
                    .and_then(|x| <[u8; 32]>::try_from(x).ok())
                    .map(Binding::Mtls),
                _ => None,
            },
        };
        let access_tenant = text(&c, "access_tenant");
        let (Some(sub), Some(client_id), Some(binding)) =
            (text(&c, "sub"), text(&c, "client_id"), binding)
        else {
            return Ok(None);
        };
        if sid.is_none() && (access_tenant.is_none() || binding.jkt().is_none()) {
            return Ok(None);
        }
        Ok(Some(AccessToken {
            sub,
            aud,
            client_id,
            sid,
            access_tenant,
            binding,
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
        self.userinfo_mtls(realm, method, authorization, dpop, &[])
            .await
    }

    /// [`Self::userinfo`] over a connection that presented the client certificate `chain`,
    /// leaf first: a certificate-bound token is taken only with the certificate it names
    /// (RFC 8705 §3); a client holding the legacy bearer exception may send its token as
    /// `Bearer` (OP-155 m.3 (k), Ek B 5090).
    pub async fn userinfo_mtls(
        &self,
        realm: &Realm,
        method: &str,
        authorization: Option<&str>,
        dpop: &[&str],
        chain: &[Vec<u8>],
    ) -> Reply {
        let profile = self.env.dpop().clone();
        match self
            .userinfo_inner(realm, method, authorization, dpop, chain, &profile)
            .await
        {
            Ok(r) => r,
            Err(Unavailable) => Reply::Unavailable,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one userinfo request, its bindings and answer forms in order"
    )]
    async fn userinfo_inner(
        &self,
        realm: &Realm,
        method: &str,
        authorization: Option<&str>,
        dpop: &[&str],
        chain: &[Vec<u8>],
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
        let Some((scheme, token)) = authorization
            .and_then(|a| a.split_once(' '))
            .map(|(scheme, t)| (scheme, t.trim()))
        else {
            return Ok(unauthorized("invalid_token"));
        };
        let dpop_scheme = scheme.eq_ignore_ascii_case("dpop");
        if !dpop_scheme && !scheme.eq_ignore_ascii_case("bearer") {
            return Ok(unauthorized("invalid_token"));
        }
        let now = self.now()?;
        // RFC 9068 §4, AG-8
        let Some((at, sid)) = self
            .access_token(realm, token, now, true)
            .await?
            .filter(|at| at.aud == realm.issuer.as_str())
            .and_then(|at| at.sid.map(|sid| (at, sid)))
        else {
            return Ok(unauthorized("invalid_token"));
        };
        let uri = realm.issuer.endpoint(Endpoint::Userinfo.path());
        let nonce = match (at.binding, dpop_scheme) {
            (Binding::Dpop(jkt), true) => {
                let proof = self
                    .dpop(
                        realm,
                        Role::ResourceServer,
                        &DpopRequest {
                            proofs: dpop,
                            method,
                            uri: &uri,
                            access_token: Some(token),
                            bound: Some(jkt),
                        },
                    )
                    .await;
                match proof {
                    Ok(p) => Some(p.nonce),
                    Err(Failure::Unavailable) => return Err(Unavailable),
                    Err(f) => {
                        return Ok(Reply::Json {
                            status: f.status(Role::ResourceServer),
                            body: json!({ "error": f.error() }).to_string(),
                            dpop_nonce: f.nonce().map(String::from),
                            challenge: f.challenge(Role::ResourceServer, profile),
                        });
                    }
                }
            }
            // RFC 8705 §3
            (Binding::Mtls(x5t), false)
                if chain
                    .first()
                    .is_some_and(|leaf| access_crypto::webauthn::sha256(leaf) == x5t) =>
            {
                None
            }
            (Binding::Bearer, false) => None,
            _ => return Ok(unauthorized("invalid_token")),
        };
        let mut tx = self.begin(realm).await?;
        let live = self.live_grant(&mut tx, &sid, now).await?;
        tx.commit().await?;
        let Some(grant) = live else {
            return Ok(unauthorized("invalid_token"));
        };
        let details: GrantDetails =
            serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
        let mut tx = self.begin(realm).await?;
        let client = tx.client_by_uuid(grant.client).await?;
        tx.commit().await?;
        let client = match client.and_then(crate::domain::client::Client::from_row) {
            Some(c) => {
                let mut tx = self.begin(realm).await?;
                let c = self.profiled(&mut tx, c).await?;
                tx.commit().await?;
                c
            }
            None => None,
        };
        let Some(client) = client else {
            return Ok(unauthorized("invalid_token"));
        };
        // OP-155 m.3 (k)
        if at.binding == Binding::Bearer && (!client.profile.legacy_bearer || client.profile.fapi2)
        {
            return Ok(unauthorized("invalid_token"));
        }
        // §10.4.6
        let mut body = self
            .released(
                realm,
                &client,
                &details,
                grant.subject,
                crate::domain::claims_request::Target::Userinfo,
            )
            .await?;
        body.insert(String::from("sub"), Value::from(at.sub));
        let encrypt = client
            .profile
            .encryption
            .as_ref()
            .is_some_and(|e| e.userinfo);
        if client.profile.userinfo_signed || encrypt {
            body.insert(String::from("iss"), Value::from(realm.issuer.as_str()));
            body.insert(String::from("aud"), Value::from(client.id.as_str()));
            let claims = Value::Object(body).to_string().into_bytes();
            let mut tx = self.begin(realm).await?;
            let jwt = self
                .client_jwt(&mut tx, realm, &client, USERINFO_TYP, &claims, encrypt, now)
                .await?;
            tx.commit().await?;
            return Ok(Reply::Jwt {
                body: jwt,
                media: "application/jwt",
                dpop_nonce: nonce,
            });
        }
        Ok(Reply::json(200, &Value::Object(body)).with_nonce(nonce))
    }

    /// The token `token` names when it is not a refresh token: an access token of this realm,
    /// read without its times.
    async fn presented(
        &self,
        realm: &Realm,
        token: &str,
        now: u64,
    ) -> Result<Option<AccessToken>, Unavailable> {
        if decode32(token).is_some() {
            return Ok(None);
        }
        self.access_token(realm, token, now, false).await
    }

    /// The grant behind a refresh token or a grant's access token `at`.
    async fn token_grant(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        token: &str,
        at: Option<AccessToken>,
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
        let Some(sid) = at.as_ref().and_then(|at| at.sid) else {
            return Ok(None);
        };
        Ok(tx.grant_by_sid(&sid).await?.map(|g| (g, at)))
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
            chain: &[],
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
        if super::authority::looks_authority(token) {
            tx.commit().await?;
            self.revoke_authority(realm, &client, token).await?;
            return Ok(Reply::json(200, &json!({})));
        }
        let at = self.presented(realm, token, now).await?;
        if let Some((grant, _)) = self.token_grant(&mut tx, token, at).await?
            && grant.client == client.uuid
        {
            tx.revoke_grant(grant.id, super::signed(now), "revoked")
                .await?;
            // §9.9, PI-10
            let details: GrantDetails =
                serde_json::from_slice(&grant.details).map_err(|_| Unavailable)?;
            if let (Some(family), Some(domain)) = (details.family, tx.governing().await?) {
                self.env()
                    .projections()
                    .revoke_family(access_kernel::digest::Digest(domain), family)
                    .await
                    .map_err(|_| Unavailable)?;
            }
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
        self.introspect_as(realm, params, authorization, false, &[])
            .await
    }

    /// [`Self::introspect`]; when the client asked for `application/token-introspection+jwt`
    /// (`accept_jwt`) or is under FAPI 2.0 Message Signing, the answer is a JWT the realm signs
    /// with the client's algorithm, encrypted when it asked (RFC 9701, OP-155 m.3 (k)). `chain`
    /// is the connection's client certificate, leaf first (RFC 8705 §2).
    pub async fn introspect_as(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
        accept_jwt: bool,
        chain: &[Vec<u8>],
    ) -> Reply {
        match self
            .introspect_inner(realm, params, authorization, chain)
            .await
        {
            Ok((reply, Some(client))) if accept_jwt || client.profile.fapi2 => self
                .introspection_jwt(realm, &client, reply)
                .await
                .unwrap_or_else(|Unavailable| active_false()),
            Ok((reply, _)) => reply,
            Err(Unavailable) => active_false(),
        }
    }

    /// RFC 9701 §5: the introspection answer as a signed JWT: `iss`, `aud` the client, `iat`,
    /// and the answer under `token_introspection`.
    async fn introspection_jwt(
        &self,
        realm: &Realm,
        client: &Client,
        reply: Reply,
    ) -> Result<Reply, Unavailable> {
        let Reply::Json {
            status: 200, body, ..
        } = reply
        else {
            return Ok(reply);
        };
        let answer: Value = serde_json::from_str(&body).map_err(|_| Unavailable)?;
        let now = self.now()?;
        let claims = json!({
            "iss": realm.issuer.as_str(),
            "aud": client.id,
            "iat": now / 1000,
            "token_introspection": answer,
        })
        .to_string()
        .into_bytes();
        let encrypt = client.profile.encryption.is_some();
        let mut tx = self.begin(realm).await?;
        let jwt = self
            .client_jwt(
                &mut tx,
                realm,
                client,
                INTROSPECTION_TYP,
                &claims,
                encrypt,
                now,
            )
            .await?;
        tx.commit().await?;
        Ok(Reply::Jwt {
            body: jwt,
            media: "application/token-introspection+jwt",
            dpop_nonce: None,
        })
    }

    async fn introspect_inner(
        &self,
        realm: &Realm,
        params: &Params,
        authorization: Option<&str>,
        chain: &[Vec<u8>],
    ) -> Result<(Reply, Option<Client>), Unavailable> {
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let req = ClientRequest {
            authorization,
            params,
            endpoint: Endpoint::Introspect.path(),
            chain,
        };
        let client: Client = match self.authenticate(&mut tx, realm, &req, now).await? {
            Ok(c) if c.client_type() == crate::domain::dpop::ClientType::Confidential => c,
            Ok(_) | Err(_) => {
                return Ok((
                    Reply::oauth_error(401, "invalid_client", "client authentication failed"),
                    None,
                ));
            }
        };
        let reply = self.introspect_for(tx, realm, &client, params, now).await?;
        Ok((reply, Some(client)))
    }

    async fn introspect_for(
        &self,
        mut tx: <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        params: &Params,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let client = client.clone();
        let Some(token) = params.get("token") else {
            return Ok(Reply::oauth_error(
                400,
                "invalid_request",
                "token is required",
            ));
        };
        if super::authority::looks_authority(token) {
            tx.commit().await?;
            return self.introspect_authority(realm, &client, token).await;
        }
        let at = self.presented(realm, token, now).await?;
        if let Some(at) = at.as_ref().filter(|at| at.sid.is_none()) {
            // OP-149 m.31 (a)
            let reply = self
                .introspect_service(&mut tx, realm, &client, at, now)
                .await?;
            tx.commit().await?;
            return Ok(reply);
        }
        let Some((grant, at)) = self.token_grant(&mut tx, token, at).await? else {
            tx.commit().await?;
            return Ok(active_false());
        };
        let live = grant.client == client.uuid
            && self.live_grant(&mut tx, &grant.sid, now).await?.is_some();
        let sub = if live {
            Some(
                self.pairwise(&mut tx, grant.subject, client.sector())
                    .await?,
            )
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
            // OP-149 m.26 (a)
            if at.client_id != client.id || expired || at.aud != details.audience(&realm.issuer) {
                return Ok(active_false());
            }
            // OP-149 m.34 (a)
            let tenant = if details.resource.is_some() {
                Some(self.tenant_name(realm)?)
            } else {
                None
            };
            if at.access_tenant != tenant {
                return Ok(active_false());
            }
            m.insert("token_type".into(), at.binding.token_type().into());
            m.insert("scope".into(), at.scope.into());
            m.insert("exp".into(), at.exp.into());
            m.insert("iat".into(), at.iat.into());
            m.insert("aud".into(), at.aud.into());
            if let Some(t) = tenant {
                m.insert("access_tenant".into(), t.into());
            }
            if let Some(cnf) = at.binding.confirmation() {
                m.insert("cnf".into(), cnf);
            }
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
