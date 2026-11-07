//! The management read token exchange (RFC 8693, TN-130, TN-27, OP-151 m.3 (c)): an Instance
//! of the realm's governing domain trades its own `check` statement over the audience and scope
//! for a read token bound to its own key. There is no client authentication: the AIS and the
//! DPoP proof by the same key are the caller's proof, and the AIS nonce is used once. The token
//! reads one management surface for at most [`READ_TTL_MS`]; it never writes (MD-14).

use access_crypto::dpop::Role;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use serde_json::json;
use suiss_crypto::digest::context_digest;

use super::{Env, OAuth, Realm, Reply, TokenHttp};
use crate::app::dpop::DpopRequest;
use crate::domain::dpop::Failure;
use crate::domain::management::{
    ACCESS_TOKEN_TYPE, AIS_TOKEN_TYPE, READ_TTL_MS, ReadFacts, Surface, exchange_intent,
    read_token_claims, subject_token, verify_subject,
};
use crate::domain::metadata::Endpoint;
use crate::domain::request::Params;
use crate::domain::tokens::ACCESS_TYP;
use crate::ports::Unavailable;
use crate::ports::dpop::ReplayCache;
use crate::ports::oauth::{OAuthTx, TokenSigner};

/// The replay key context of an exchange's AIS nonce.
const NONCE_CONTEXT: &str = "access/management-read-nonce/v1";

const DAY_MS: u64 = 86_400_000;

/// The exchange's form, apart from the subject token: its one audience.
fn shape<'a>(params: &'a Params, http: TokenHttp<'_>) -> Result<&'a str, Reply> {
    if http.authorization.is_some() || params.get("client_assertion").is_some() {
        return Err(invalid_request(
            "the exchange takes no client authentication",
        ));
    }
    if params.get("subject_token_type") != Some(AIS_TOKEN_TYPE) {
        return Err(invalid_request("subject_token_type must be an AIS"));
    }
    if params
        .get("requested_token_type")
        .is_some_and(|t| t != ACCESS_TOKEN_TYPE)
        || params.get("actor_token").is_some()
        || params.get("resource").is_some()
    {
        return Err(invalid_request("only a read token for one audience"));
    }
    params
        .get("audience")
        .ok_or_else(|| invalid_request("audience is required"))
}

fn invalid_request(why: &str) -> Reply {
    Reply::oauth_error(400, "invalid_request", why)
}

fn invalid_grant() -> Reply {
    Reply::oauth_error(400, "invalid_grant", "the subject token is not valid")
}

fn invalid_target() -> Reply {
    Reply::oauth_error(
        400,
        "invalid_target",
        "not a management surface of this realm",
    )
}

impl<E: Env> OAuth<E> {
    /// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 §2.1) with an
    /// AIS subject token, for a management read token (TN-130).
    pub(crate) async fn exchange_read(
        &self,
        realm: &Realm,
        params: &Params,
        http: TokenHttp<'_>,
    ) -> Result<Reply, Unavailable> {
        let audience = match shape(params, http) {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let surface = match Surface::of(audience) {
            Some(Surface::Realm(slug)) if slug == realm.slug => Surface::Realm(slug),
            Some(Surface::Platform) if self.env.management().platform(realm).await? => {
                Surface::Platform
            }
            _ => return Ok(invalid_target()),
        };
        if params.get("scope").is_some_and(|s| s != surface.scope()) {
            return Ok(Reply::oauth_error(
                400,
                "invalid_scope",
                "a management read token has the surface's read scope only",
            ));
        }
        let Some((ais, kid)) = params
            .get("subject_token")
            .and_then(|t| subject_token(t).ok())
        else {
            return Ok(invalid_grant());
        };
        let token_uri = realm.issuer.endpoint(Endpoint::Token.path());
        // TN-27, IDP-11
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
                return Ok(
                    Reply::oauth_error(400, f.error(), "the DPoP proof was not accepted")
                        .with_nonce(nonce),
                );
            }
        };
        let nonce = Some(proof.nonce.clone());
        // TN-130: the token is bound to the Instance key that signed the statement
        if proof.jkt.0 != kid {
            return Ok(invalid_grant().with_nonce(nonce));
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let Some(domain) = tx.governing().await? else {
            return Ok(invalid_target().with_nonce(nonce));
        };
        let alg = tx.jose_alg().await?;
        tx.commit().await?;
        let Some(key) = self.env.management().instance_key(domain, kid).await? else {
            return Ok(invalid_grant().with_nonce(nonce));
        };
        let intent = exchange_intent(&surface.audience(), surface.scope());
        let Ok(statement) = verify_subject(&ais, kid, &key, &Digest(domain), &intent, now) else {
            return Ok(invalid_grant().with_nonce(nonce));
        };
        let day = u32::try_from(now / DAY_MS).map_err(|_| Unavailable)?;
        let replay_key = context_digest(NONCE_CONTEXT, &statement.nonce).0;
        match self
            .env
            .replay(realm.tenant, realm.realm)
            .first_use(day, replay_key)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Ok(invalid_grant().with_nonce(nonce)),
            Err(_) => return Err(Unavailable),
        }
        let token = self.issue_read(realm, &surface, kid, alg, now).await?;
        tracing::info!(
            event = "oauth.management.read_issued",
            outcome = "ok",
            "management read token issued"
        );
        Ok(Reply::json(
            200,
            &json!({
                "access_token": token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "DPoP",
                "expires_in": READ_TTL_MS / 1000,
                "scope": surface.scope(),
            }),
        )
        .with_nonce(nonce))
    }

    async fn issue_read(
        &self,
        realm: &Realm,
        surface: &Surface,
        kid: [u8; 32],
        alg: access_crypto::jose::JwsAlg,
        now: u64,
    ) -> Result<String, Unavailable> {
        let holder = b64url_encode(&kid);
        let jti = b64url_encode(&self.random::<16>()?);
        let claims = read_token_claims(
            &ReadFacts {
                issuer: realm.issuer.as_str(),
                surface,
                sub: &holder,
                client_id: &holder,
                instance: kid,
                jkt: kid,
                console_session: None,
                rev: None,
                now_ms: now,
                ttl_ms: READ_TTL_MS,
            },
            &jti,
        );
        self.env
            .signer()
            .sign(realm.realm, alg, ACCESS_TYP, &claims, now)
            .await
    }
}
