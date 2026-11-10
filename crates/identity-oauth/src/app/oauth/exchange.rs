//! RFC 8693 token exchange for agents and the RFC 7523 JWT bearer grant (§9.9 table, §11.10,
//! §11.11, §11.12.3, AG-23, AG-27…AG-29, OP-154 m.3 (m), (n), (o), (q)). An exchange is the
//! actor's own `projection.issue` Exercise: the subject token is Claim input only, the new
//! token is decided on the actor's own Grant, and its `act` is written by the authority plane
//! from the lineage record, never from a presented token (AGI-1, P53). A token is never handed
//! on: a resource server reaches its upstream with a token it exchanged for itself (L24, P48).
//! An ID-JAG or a cloud workload JWT is a carrier, never a grant (MD-18, L25).

use access_crypto::AwsLcBackend;
use access_internal_api::projections::Projections as _;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::meta::Payload;
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};
use serde_json::{Value, json};

use super::authority::{Asked, Projected, looks_authority, projected_body};
use super::{Env, OAuth, Realm, Reply};
use crate::domain::authority::{
    DETAILS_PARAM, Detail, EXERCISE_PARAM, parse_details, parse_exercise, within,
};
use crate::domain::client::{Client, ClientAuth};
use crate::domain::dpop::Jkt;
use crate::domain::exchange::{
    self, ACCESS_TOKEN, AssertionRules, ID_JAG, ID_JAG_TYP, IdJagFacts, JWT_TYP, Requested,
    SubjectKind, TXN_TOKEN, TXN_TYP, TxnFacts, act_depth, jti_slot, peek, verify_assertion,
};
use crate::domain::jwt::realm_key_set;
use crate::domain::request::Params;
use crate::domain::tokens::ID_TYP;
use crate::ports::Unavailable;
use crate::ports::dpop::ReplayCache as _;
use crate::ports::oauth::{OAuthTx as _, TokenSigner as _};

fn invalid_request(why: &str) -> Reply {
    Reply::oauth_error(400, "invalid_request", why)
}

fn invalid_grant(why: &str) -> Reply {
    Reply::oauth_error(400, "invalid_grant", why)
}

/// A subject token once verified: Claim input, never authority.
enum Subject {
    /// An active Access projection of this realm's domain.
    Projection {
        /// Its claims.
        claims: Value,
        /// Its `exp`, Unix milliseconds.
        exp_ms: u64,
    },
    /// An identity assertion: an ID token of this realm or an accepted issuer's JWT.
    Identity,
}

fn exp_ms(c: &Value) -> Option<u64> {
    c.get("exp")
        .and_then(Value::as_u64)
        .and_then(|s| s.checked_mul(1000))
}

/// The details a projection subject token carries, as the request's are read (RFC 9396).
fn subject_details(claims: &Value) -> Option<std::collections::BTreeSet<Detail>> {
    let items = claims.get(DETAILS_PARAM)?.as_array()?;
    let mut out = std::collections::BTreeSet::new();
    for d in items {
        out.insert(Detail {
            r#type: String::from(d.get("type")?.as_str()?),
            schema: String::from(d.get("schema")?.as_str()?),
            intent: d.get("intent").and_then(Value::as_str).map(String::from),
        });
    }
    Some(out)
}

/// The unverified claims of a token the authority plane just signed for this request.
fn own_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&b64url_decode(payload).ok()?).ok()
}

impl<E: Env> OAuth<E> {
    /// The governing domain of `realm`.
    async fn domain_of(&self, realm: &Realm) -> Result<Option<Digest>, Unavailable> {
        let mut tx = self.begin(realm).await?;
        let d = tx.governing().await?.map(Digest);
        tx.commit().await?;
        Ok(d)
    }

    /// An accepted issuer's assertion `token` of `typ` (AG-29): verified under each pinned key
    /// set the governing domain accepted for `iss`; `None` when none verifies it.
    async fn accepted_assertion(
        &self,
        realm: &Realm,
        token: &str,
        typ: &str,
        client: Option<&str>,
        now: u64,
    ) -> Result<Option<exchange::Assertion>, Unavailable> {
        let Some((t, iss)) = peek(token) else {
            return Ok(None);
        };
        if t != typ || (iss == realm.issuer.as_str() && typ == JWT_TYP) {
            return Ok(None);
        }
        let Some(domain) = self.domain_of(realm).await? else {
            return Ok(None);
        };
        let issuers = self.env.issuers().accepted(domain.0, iss.clone()).await?;
        let rules = AssertionRules {
            iss: &iss,
            typ,
            audience: realm.issuer.as_str(),
            client_id: client,
            now_ms: now,
        };
        for i in issuers {
            let keys = access_kernel::claim::Pinned {
                iss: iss.clone(),
                aud: i.aud.clone(),
                keys: i.keys,
            }
            .key_set();
            if let Ok(a) = verify_assertion(token, &keys, &rules) {
                return Ok(Some(a));
            }
        }
        Ok(None)
    }

    /// Verifies the subject token (RFC 8693 §2.1): an active Access projection of this realm's
    /// domain, an ID token this realm issued to `client`, or a JWT of an issuer the domain
    /// accepted for `actor-binding`. A token of another realm or tenant verifies under none of
    /// these (§12.1.3 rule 11). Its `act` is bounded and never read further (AG-25, L22).
    async fn subject(
        &self,
        realm: &Realm,
        client: &Client,
        kind: SubjectKind,
        token: &str,
        saml2: bool,
        now: u64,
    ) -> Result<Result<Subject, Reply>, Unavailable> {
        let refused = || Ok(Err(invalid_grant("the subject token is not valid")));
        match kind {
            // OP-154 m.3 (m), OP-155 m.3 (k)
            SubjectKind::Saml if !saml2 => Ok(Err(invalid_request("SAML 1.1 is not read"))),
            SubjectKind::Saml => {
                use super::client_auth::saml_bearer::SamlRefusal;
                match self.saml_subject(realm, client, token, now).await? {
                    Ok(_) => Ok(Ok(Subject::Identity)),
                    Err(SamlRefusal::NotAllowed) => Ok(Err(Reply::oauth_error(
                        400,
                        "unauthorized_client",
                        "this client may not exchange SAML assertions",
                    ))),
                    Err(SamlRefusal::Invalid) => refused(),
                }
            }
            SubjectKind::Access if looks_authority(token) => {
                let Some(domain) = self.domain_of(realm).await? else {
                    return refused();
                };
                let answer = self
                    .env()
                    .projections()
                    .introspect(domain, String::from(token))
                    .await
                    .map_err(|_| Unavailable)?;
                let claims = answer
                    .claims
                    .filter(|_| answer.active)
                    .and_then(|c| serde_json::from_str::<Value>(&c).ok())
                    .filter(|c| {
                        c.get("iss").and_then(Value::as_str) == Some(realm.issuer.as_str())
                    });
                let Some(claims) = claims else {
                    return refused();
                };
                let (Ok(_), Some(exp_ms)) = (act_depth(&claims), exp_ms(&claims)) else {
                    return refused();
                };
                Ok(Ok(Subject::Projection { claims, exp_ms }))
            }
            SubjectKind::IdToken
                if peek(token).is_some_and(|(_, iss)| iss == realm.issuer.as_str()) =>
            {
                let jwks = self.env.signer().jwks(realm.realm).await?;
                let keys = realm_key_set(jwks.as_bytes()).map_err(|_| Unavailable)?;
                let Ok(v) = verify_compact(&AwsLcBackend, token, &keys, ID_TYP, Origin::Native)
                else {
                    return refused();
                };
                let Ok(c) = json::parse(&v.payload, MAX_PAYLOAD) else {
                    return refused();
                };
                let live = c
                    .get("exp")
                    .and_then(Json::as_int)
                    .and_then(|e| u64::try_from(e).ok())
                    .and_then(|e| e.checked_mul(1000))
                    .is_some_and(|e| e > now);
                if !live
                    || c.get("iss").and_then(Json::as_str) != Some(realm.issuer.as_str())
                    || c.get("aud").and_then(Json::as_str) != Some(client.id.as_str())
                {
                    return refused();
                }
                Ok(Ok(Subject::Identity))
            }
            SubjectKind::Access | SubjectKind::IdToken => {
                match self
                    .accepted_assertion(realm, token, JWT_TYP, None, now)
                    .await?
                {
                    Some(_) => Ok(Ok(Subject::Identity)),
                    None => refused(),
                }
            }
        }
    }

    /// The agent grant of `params`: token exchange or JWT bearer.
    pub(crate) async fn agent_grant(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        if params.get("grant_type") == Some(crate::domain::metadata::TOKEN_EXCHANGE_GRANT) {
            self.agent_exchange(realm, client, params, jkt, now).await
        } else if params.get("grant_type") == Some(crate::domain::metadata::SAML2_BEARER_GRANT) {
            self.saml_bearer(realm, client, params, jkt, now).await
        } else {
            self.jwt_bearer(realm, client, params, jkt, now).await
        }
    }

    /// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` for an agent (OP-154 m.3
    /// (m)): `client` authenticated, its DPoP key `jkt` the actor Instance's.
    pub(crate) async fn agent_exchange(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(kind) = params
            .get("subject_token_type")
            .and_then(exchange::subject_kind)
        else {
            return Ok(invalid_request("subject_token_type is not supported"));
        };
        let Some(token) = params.get("subject_token") else {
            return Ok(invalid_request("subject_token is required"));
        };
        let Some(asked) = exchange::requested(params.get("requested_token_type")) else {
            return Ok(invalid_request("requested_token_type is not supported"));
        };
        let saml2 = params.get("subject_token_type") == Some(exchange::SAML2);
        let subject = match self.subject(realm, client, kind, token, saml2, now).await? {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
        Ok(match asked {
            Requested::Projection { issued } => {
                match self.exchanged(realm, client, params, &subject, jkt).await? {
                    Ok(p) => {
                        let mut body = projected_body(&p, now);
                        if let Value::Object(m) = &mut body {
                            m.insert("issued_token_type".into(), issued.into());
                        }
                        Reply::json(200, &body)
                    }
                    Err(r) => r,
                }
            }
            Requested::IdJag => self.id_jag(realm, client, params, jkt, now).await?,
            Requested::Txn => self.txn(realm, &subject, now).await?,
            Requested::IdToken | Requested::Refresh => {
                invalid_request("this token type is not issued by an exchange")
            }
        })
    }

    /// The exchanged authority token (§9.9 table, AG-23): the actor's own decision for the
    /// requested resource, never broader than a projection subject token in what it names or
    /// how long it lives (AG-26 rules 1 and 2).
    async fn exchanged(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        subject: &Subject,
        jkt: Jkt,
    ) -> Result<Result<Projected, Reply>, Unavailable> {
        if let Subject::Projection { claims, exp_ms } = subject {
            let narrower = || -> Option<bool> {
                let resource = params.get("resource")?;
                let (_, asked) = parse_details(params.get(DETAILS_PARAM)?, resource).ok()?;
                let held = subject_details(claims)?;
                let e = parse_exercise(params.get(EXERCISE_PARAM)?).ok()?;
                let Payload::ProjectionIssue { bounds, .. } = &e.payload else {
                    return Some(false);
                };
                Some(within(&asked, &held) && bounds.constraints.validity.until <= *exp_ms)
            };
            if narrower() == Some(false) {
                return Ok(Err(Reply::oauth_error(
                    400,
                    "invalid_scope",
                    "an exchange never widens the subject token",
                )));
            }
        }
        let asked = Asked {
            params,
            authorized: None,
            family: None,
        };
        self.project(realm, client, &asked, jkt).await
    }

    /// An ID-JAG (§11.11.2, MD-18, OP-154 m.3 (n)): the holder's `projection.issue` for the
    /// resource is decided first and its token is not released; what is issued is an identity
    /// assertion for the Resource AS, signed by the realm, five minutes at most, naming the
    /// decided projection's pairwise subject and no authority. A public client is refused.
    async fn id_jag(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        // §11.11.2 (e)
        if !matches!(
            client.auth,
            ClientAuth::PrivateKeyJwt { .. } | ClientAuth::PrivateKeyJwtKey { .. }
        ) {
            return Ok(Reply::oauth_error(
                400,
                "unauthorized_client",
                "an ID-JAG needs a client authenticated as strongly as for sign-in",
            ));
        }
        let (Some(audience), Some(resource)) = (params.get("audience"), params.get("resource"))
        else {
            return Ok(invalid_request("audience and resource are required"));
        };
        // AG-28, OP-154 m.3 (n)
        let mut tx = self.begin(realm).await?;
        let connected = tx
            .cross_app_connected(client.id.as_str(), audience, resource)
            .await?;
        tx.commit().await?;
        if !connected {
            return Ok(Reply::oauth_error(
                400,
                "invalid_target",
                "no cross-app connection lets this client ask for that audience and resource",
            ));
        }
        let asked = Asked {
            params,
            authorized: None,
            family: None,
        };
        let p = match self.project(realm, client, &asked, jkt).await? {
            Ok(p) => p,
            Err(r) => return Ok(r),
        };
        let decided = own_claims(&p.token.token).ok_or(Unavailable)?;
        let sub = decided
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(Unavailable)?;
        let jti = b64url_encode(&self.random::<16>()?);
        let claims = exchange::id_jag_claims(&IdJagFacts {
            issuer: realm.issuer.as_str(),
            sub,
            audience,
            client_id: client.id.as_str(),
            resource,
            scope: params.get("scope"),
            jti: &jti,
            now_ms: now,
            until_ms: p.token.expires_at,
        });
        let mut tx = self.begin(realm).await?;
        let alg = tx.jose_alg().await?;
        tx.commit().await?;
        let jag = self
            .env
            .signer()
            .sign(realm.realm, alg, ID_JAG_TYP, &claims, now)
            .await?;
        let expires = p
            .token
            .expires_at
            .min(now.saturating_add(exchange::ID_JAG_TTL_MS));
        Ok(Reply::json(
            200,
            &json!({
                "access_token": jag,
                "issued_token_type": ID_JAG,
                "token_type": "N_A",
                "expires_in": expires.saturating_sub(now) / 1000,
            }),
        ))
    }

    /// A Transaction Token (§11.12.3, OP-154 m.3 (o)): audit context of an active projection
    /// subject token for this realm's trust domain, sixty seconds, never a basis or a subject
    /// token itself.
    async fn txn(&self, realm: &Realm, subject: &Subject, now: u64) -> Result<Reply, Unavailable> {
        let Subject::Projection { claims, .. } = subject else {
            return Ok(invalid_request(
                "a transaction token names an Access projection",
            ));
        };
        let (Some(sub), Some(exercise)) = (
            claims.get("sub").and_then(Value::as_str),
            claims.get("jti").and_then(Value::as_str),
        ) else {
            return Ok(invalid_grant("the subject token is not valid"));
        };
        let intent = claims
            .get(DETAILS_PARAM)
            .and_then(Value::as_array)
            .and_then(|d| d.first())
            .and_then(|d| d.get("intent"))
            .and_then(Value::as_str);
        let txn = b64url_encode(&self.random::<16>()?);
        let body = exchange::txn_claims(&TxnFacts {
            issuer: realm.issuer.as_str(),
            audience: realm.issuer.as_str(),
            sub,
            txn: &txn,
            exercise,
            intent,
            now_ms: now,
        });
        let mut tx = self.begin(realm).await?;
        let alg = tx.jose_alg().await?;
        tx.commit().await?;
        let token = self
            .env
            .signer()
            .sign(realm.realm, alg, TXN_TYP, &body, now)
            .await?;
        Ok(Reply::json(
            200,
            &json!({
                "access_token": token,
                "issued_token_type": TXN_TOKEN,
                "token_type": "N_A",
                "expires_in": exchange::TXN_TTL_MS / 1000,
            }),
        ))
    }

    /// `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1; AG-29, OP-154
    /// m.3 (n), (q)): an ID-JAG or a cloud workload JWT of an accepted issuer, checked in five
    /// steps, its `jti` used once in the realm's replay store; without that store nothing is
    /// accepted. The assertion is Claim input only: the token is the holder's own decision, and
    /// without one there is no token (EI-6).
    pub(crate) async fn jwt_bearer(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        let Some(assertion) = params.get("assertion") else {
            return Ok(invalid_request("assertion is required"));
        };
        let typ = match peek(assertion) {
            Some((t, _)) if t == ID_JAG_TYP || t == JWT_TYP => t,
            _ => return Ok(invalid_grant("the assertion is not valid")),
        };
        let Some(a) = self
            .accepted_assertion(realm, assertion, &typ, Some(client.id.as_str()), now)
            .await?
        else {
            return Ok(invalid_grant("the assertion is not valid"));
        };
        // §11.11.4, AG-8
        if let Some(r) = &a.resource
            && params.get("resource") != Some(r.as_str())
        {
            return Ok(Reply::oauth_error(
                400,
                "invalid_target",
                "not the resource the assertion names",
            ));
        }
        // AG-29, OP-154 m.3 (n)
        let (day, key) = jti_slot(&a).ok_or(Unavailable)?;
        match self
            .env
            .replay(realm.tenant, realm.realm)
            .first_use(day, key)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Ok(invalid_grant("the assertion was already used")),
            Err(_) => return Err(Unavailable),
        }
        // EI-6, MD-18
        if params.get(EXERCISE_PARAM).is_none() || params.get(DETAILS_PARAM).is_none() {
            return Ok(invalid_grant("an assertion is not a grant"));
        }
        let asked = Asked {
            params,
            authorized: None,
            family: None,
        };
        Ok(match self.project(realm, client, &asked, jkt).await? {
            Ok(p) => {
                let mut body = projected_body(&p, now);
                if let Value::Object(m) = &mut body {
                    m.insert("issued_token_type".into(), ACCESS_TOKEN.into());
                }
                Reply::json(200, &body)
            }
            Err(r) => r,
        })
    }
}
