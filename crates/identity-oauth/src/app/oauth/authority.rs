//! Authority tokens at the token endpoint (§9.9, §10.4 (i), OP-150 m.2): a request with
//! `authorization_details` is the holder's `projection.issue` Exercise, which the authority
//! plane decides and signs; the identity plane only checks that the request and the Exercise
//! say the same thing and forwards it as PEP. No ALLOW, no token (P17). DENY answers
//! `invalid_grant` and a required action `insufficient_authorization`, never the same (§9.9.5);
//! an unreachable authority plane or signer answers 503 (K17, G50).

use access_internal_api::projections::{
    Confirmation, IssuedToken, Projections as _, TokenKind, TokenProjection, TokenProjectionRequest,
};
use access_kernel::combinator::Decision;
use access_kernel::combinator::codec::decision_value;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use serde_json::{Value, json};
use suiss_crypto::dcbor::Value as Cbor;

use super::{Env, OAuth, Realm, Reply};
use crate::domain::authority::{
    AuthorityError, DETAILS_PARAM, EXERCISE_PARAM, Kind, check, parse_details, parse_exercise,
    within,
};
use crate::domain::client::Client;
use crate::domain::dpop::Jkt;
use crate::domain::request::{AuthorityAsk, Params};
use crate::ports::Unavailable;
use crate::ports::oauth::OAuthTx;

/// What an authority token request carries.
pub(crate) struct Asked<'a> {
    /// The form.
    pub(crate) params: &'a Params,
    /// What an earlier authorization request authorized, for a code or a refresh.
    pub(crate) authorized: Option<&'a AuthorityAsk>,
    /// The family a refresh continues.
    pub(crate) family: Option<[u8; 16]>,
}

/// A signed authority token and the details it answers.
pub(crate) struct Projected {
    /// The token.
    pub(crate) token: IssuedToken,
    /// The details the token was asked with, as sent.
    pub(crate) details: Value,
    /// The domain that decided it.
    pub(crate) domain: Digest,
}

fn refused(e: AuthorityError, description: &str) -> Reply {
    Reply::oauth_error(400, e.error(), description)
}

fn texts(v: Option<&Cbor>, member: &str) -> Vec<Value> {
    let Some(Cbor::Array(items)) = v else {
        return Vec::new();
    };
    let mut out: Vec<Value> = Vec::new();
    for item in items {
        if let Some(Cbor::Text(t)) = item.get(member)
            && !out.iter().any(|o| o.as_str() == Some(t.as_str()))
        {
            out.push(Value::from(t.as_str()));
        }
    }
    out
}

/// §9.9.5: the closed blocker classes of a DENY, never free text (A-7).
fn denied(d: &Decision) -> Reply {
    let v = decision_value(d);
    Reply::json(
        400,
        &json!({
            "error": "invalid_grant",
            "error_description": "the authority decision is not allow",
            "access_blockers": texts(v.get("blockers"), "class"),
        }),
    )
}

/// §9.9.5: a required action with its remediation codes and the nonce to answer it with.
fn required(d: &Decision, domain: &Digest, nonce: &[u8]) -> Reply {
    let v = decision_value(d);
    Reply::json(
        400,
        &json!({
            "error": "insufficient_authorization",
            "error_description": "the authority decision requires an action",
            "authorization_remediation": {
                "remediation": texts(v.get("blockers"), "remediation"),
                "exercise_ref": { "domain": b64url_encode(&domain.0), "nonce": b64url_encode(nonce) },
            },
        }),
    )
}

/// A refusal of the authority plane by its stable code.
fn plane_refused(code: &str) -> Reply {
    let error = if code == "invalid-target" {
        "invalid_target"
    } else {
        "invalid_request"
    };
    Reply::json(
        400,
        &json!({
            "error": error,
            "error_description": "the token was not projected",
            "access_error": code,
        }),
    )
}

/// What a request asks once its own members are read: the resource, the details as sent and
/// parsed, and the Exercise.
struct Requested<'a> {
    resource: &'a str,
    raw: &'a str,
    kind: Kind,
    details: std::collections::BTreeSet<crate::domain::authority::Detail>,
    exercise: crate::domain::authority::TokenExercise,
}

/// Reads `asked`: one resource server, never a default one (RFC 8707, AG-8), details within
/// what was authorized (RFC 9396 §6.1), and the Exercise.
fn requested<'a>(realm: &Realm, asked: &'a Asked<'a>) -> Result<Requested<'a>, Reply> {
    let p = asked.params;
    let resource = match (p.get("resource"), asked.authorized) {
        (Some(r), Some(a)) if r != a.resource => {
            return Err(refused(
                AuthorityError::Target,
                "not the authorized resource",
            ));
        }
        (Some(r), _) => r,
        (None, Some(a)) => a.resource.as_str(),
        (None, None) => {
            return Err(refused(
                AuthorityError::Target,
                "a resource server is required",
            ));
        }
    };
    if resource == realm.issuer.as_str() {
        return Err(refused(AuthorityError::Target, "not a resource server"));
    }
    let raw = p
        .get(DETAILS_PARAM)
        .or(asked.authorized.map(|a| a.details.as_str()))
        .ok_or_else(|| refused(AuthorityError::Details, "authorization_details is required"))?;
    let (kind, details) = parse_details(raw, resource)
        .map_err(|e| refused(e, "the authorization details are not valid"))?;
    if let Some(a) = asked.authorized {
        let ok = parse_details(&a.details, &a.resource)
            .is_ok_and(|(k, granted)| k == kind && within(&details, &granted));
        if !ok {
            return Err(refused(AuthorityError::Details, "more than was authorized"));
        }
    }
    let exercise = p
        .get(EXERCISE_PARAM)
        .ok_or_else(|| refused(AuthorityError::Exercise, "access_exercise is required"))?;
    let exercise = parse_exercise(exercise).map_err(|e| refused(e, "the exercise is not valid"))?;
    Ok(Requested {
        resource,
        raw,
        kind,
        details,
        exercise,
    })
}

/// The token response of a projected token (RFC 6749 §5.1, RFC 9396 §7): DPoP-bound, its
/// lifetime the contract's horizon, the details it answers.
pub(crate) fn projected_body(p: &Projected, now: u64) -> Value {
    json!({
        "access_token": p.token.token,
        "token_type": "DPoP",
        "expires_in": p.token.expires_at.saturating_sub(now) / 1000,
        "authorization_details": p.details,
    })
}

impl<E: Env> OAuth<E> {
    /// Asks the authority plane for the token of `asked` (§9.9): the details (as sent, or as
    /// authorized when omitted), one resource, the holder's Exercise signed by the DPoP key
    /// `jkt`.
    pub(crate) async fn project(
        &self,
        realm: &Realm,
        client: &Client,
        asked: &Asked<'_>,
        jkt: Jkt,
    ) -> Result<Result<Projected, Reply>, Unavailable> {
        let r = match requested(realm, asked) {
            Ok(r) => r,
            Err(reply) => return Ok(Err(reply)),
        };
        let mut tx = self.begin(realm).await?;
        let domain = tx.governing().await?.ok_or(Unavailable)?;
        tx.commit().await?;
        let domain = Digest(domain);
        let e = r.exercise;
        let checked = match check(&e, r.kind, &r.details, r.resource, &domain, &jkt.0) {
            Ok(c) => c,
            Err(err) => return Ok(Err(refused(err, "the exercise does not match the request"))),
        };
        let nonce = e.nonce.clone();
        let request = TokenProjectionRequest {
            domain,
            nonce: e.nonce,
            intent: e.intent,
            payload: e.payload_bytes,
            basis: e.basis,
            capacity: e.capacity,
            ais: e.ais,
            pep: String::from(realm.issuer.as_str()),
            issuer: String::from(realm.issuer.as_str()),
            client_id: client.id.clone(),
            kind: match checked.kind {
                Kind::Intent => TokenKind::Intent,
                Kind::Bounds => TokenKind::Bounds,
            },
            target: checked.target,
            confirmation: Confirmation::DpopJkt(jkt.0),
            resources: vec![String::from(r.resource)],
            family: asked.family,
        };
        // K17, G50
        let answer = self
            .env()
            .projections()
            .issue(request)
            .await
            .map_err(|_| Unavailable)?;
        Ok(match answer {
            TokenProjection::Issued(token) => Ok(Projected {
                token,
                details: serde_json::from_str(r.raw).unwrap_or(Value::Null),
                domain,
            }),
            TokenProjection::Denied { decision, .. } => Err(denied(&decision)),
            TokenProjection::RequireAction { decision, .. } => {
                Err(required(&decision, &domain, &nonce))
            }
            TokenProjection::Refused { code } => Err(plane_refused(&code)),
        })
    }

    /// The authority token of a code exchange (§9.9, RFC 9396 §6.1): only what the code
    /// authorized, only as a decision; the grant then holds the family it opened.
    pub(crate) async fn code_projection(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        grant: &mut crate::domain::tokens::GrantDetails,
        jkt: Jkt,
    ) -> Result<Result<Option<Projected>, Reply>, Unavailable> {
        let Some(a) = grant.authority.clone() else {
            return Ok(if params.get(DETAILS_PARAM).is_some() {
                Err(refused(
                    AuthorityError::Details,
                    "no authority was authorized",
                ))
            } else {
                Ok(None)
            });
        };
        let asked = Asked {
            params,
            authorized: Some(&a),
            family: None,
        };
        Ok(match self.project(realm, client, &asked, jkt).await? {
            Ok(p) => {
                grant.family = Some(p.token.family);
                grant.projection = Some(p.token.exercise.0);
                Ok(Some(p))
            }
            Err(r) => Err(r),
        })
    }

    /// `client_credentials` (RFC 6749 §4.4, §10.4.1): a confidential client's own authority
    /// token, a `projection.issue` of its Instance under its own Grant (OWN, §11.21.2); no
    /// refresh token (RFC 6749 §4.4.3).
    pub(crate) async fn client_credentials(
        &self,
        realm: &Realm,
        client: &Client,
        params: &Params,
        jkt: Jkt,
        now: u64,
    ) -> Result<Reply, Unavailable> {
        if client.client_type() != crate::domain::dpop::ClientType::Confidential {
            return Ok(Reply::oauth_error(
                400,
                "unauthorized_client",
                "client credentials need a confidential client",
            ));
        }
        let asked = Asked {
            params,
            authorized: None,
            family: None,
        };
        Ok(match self.project(realm, client, &asked, jkt).await? {
            Ok(p) => Reply::json(200, &projected_body(&p, now)),
            Err(r) => r,
        })
    }
}

impl<E: Env> OAuth<E> {
    /// Ends the refresh family `family` of `domain` (§9.9.3 rule 6, P50): no refresh of it is
    /// decided again, and a `projection-invalidated` event names it, its first token's Exercise
    /// as the source. A family already ended raises no second event.
    pub(crate) async fn invalidate(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        domain: Digest,
        family: [u8; 16],
        root: &Digest,
        now: u64,
    ) -> Result<(), Unavailable> {
        let first = self
            .env()
            .projections()
            .revoke_family(domain, family)
            .await
            .map_err(|_| Unavailable)?;
        if !first {
            return Ok(());
        }
        let id = self.random::<32>()?;
        let event = json!({
            "id": b64url_encode(&id),
            "payload": {
                "domain": b64url_encode(&domain.0),
                "source": { "exercise": b64url_encode(&root.0) },
                "subject": { "kind": "projection", "id": b64url_encode(&family) },
                "at": now,
            },
        });
        let bytes = serde_json::to_vec(&event).map_err(|_| Unavailable)?;
        tx.outbox(crate::domain::tokens::INVALIDATED_OUTBOX, &bytes)
            .await
    }

    /// The token response of a grant's authority token: the token, a rotated refresh token for
    /// the next decision (RFC 6749 §6) and, for `openid`, the ID token, which carries no
    /// authority (§10.4 (ii)).
    #[expect(clippy::too_many_arguments, reason = "the facts of one issuance")]
    pub(crate) async fn authority_tokens(
        &self,
        tx: &mut <E::Db as crate::ports::oauth::OAuthDb>::Tx,
        realm: &Realm,
        client: &Client,
        grant: &access_store::oauth::GrantRow,
        details: &crate::domain::tokens::GrantDetails,
        p: &Projected,
        nonce: Option<&str>,
        now: u64,
    ) -> Result<Value, Unavailable> {
        let refresh = self.random::<32>()?;
        tx.insert_refresh(
            &super::refresh_digest(&refresh),
            grant.id,
            super::signed(now),
        )
        .await?;
        let mut body = projected_body(p, now);
        if let Value::Object(m) = &mut body {
            m.insert("refresh_token".into(), b64url_encode(&refresh).into());
            if details.openid {
                let id = self
                    .id_token(tx, realm, client, grant, details, nonce, now)
                    .await?;
                m.insert("id_token".into(), id.into());
            }
        }
        Ok(body)
    }
}

fn member(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or(Value::Null)
}

/// Whether `token` reads as an authority token: an `at+jwt` whose claims carry
/// `authorization_details`. Only routing; the authority plane verifies it.
pub(crate) fn looks_authority(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let json = |s: &str| {
        access_kernel::json::b64url_decode(s)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
    };
    json(h).is_some_and(|h| {
        h.get("typ").and_then(Value::as_str) == Some(crate::domain::tokens::ACCESS_TYP)
    }) && json(p).is_some_and(|p| p.get(DETAILS_PARAM).is_some())
}

impl<E: Env> OAuth<E> {
    /// The verified claims of an authority token of this realm that `client` holds, with the
    /// head the authority plane answered at; `None` when it is not active (MD-8, OPI-3).
    pub(crate) async fn authority_claims(
        &self,
        realm: &Realm,
        client: &Client,
        token: &str,
    ) -> Result<Option<(Value, u64, Digest)>, Unavailable> {
        let mut tx = self.begin(realm).await?;
        let domain = Digest(tx.governing().await?.ok_or(Unavailable)?);
        tx.commit().await?;
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
                member(c, "iss") == realm.issuer.as_str()
                    && member(c, "client_id") == client.id.as_str()
            });
        Ok(claims.map(|c| (c, answer.as_of, domain)))
    }

    /// RFC 7662 for an authority token (§9.9.3 rule 5, MD-8): the authority plane's state of it,
    /// `at_least` the domain's head, with the Access members (OP-150 m.2); anything it cannot
    /// prove is `active: false`, never 503 (OPI-3).
    pub(crate) async fn introspect_authority(
        &self,
        realm: &Realm,
        client: &Client,
        token: &str,
    ) -> Result<Reply, Unavailable> {
        let Some((c, as_of, _)) = self.authority_claims(realm, client, token).await? else {
            return Ok(Reply::json(200, &json!({ "active": false })));
        };
        let exercise = c
            .get("jti")
            .and_then(Value::as_str)
            .and_then(|j| j.strip_prefix("sha-256:"))
            .map(String::from);
        Ok(Reply::json(
            200,
            &json!({
                "active": true,
                "iss": member(&c, "iss"),
                "sub": member(&c, "sub"),
                "aud": member(&c, "aud"),
                "exp": member(&c, "exp"),
                "iat": member(&c, "iat"),
                "client_id": member(&c, "client_id"),
                "token_type": "DPoP",
                "cnf": member(&c, "cnf"),
                "authorization_details": member(&c, "authorization_details"),
                "exercise": exercise,
                "as_of": as_of.to_string(),
            }),
        ))
    }

    /// RFC 7009 for an authority token: a projection cleanup that ends its family and cascades
    /// nowhere else (§9.9 table, PI-10); `false` when it is not one of `client`'s.
    pub(crate) async fn revoke_authority(
        &self,
        realm: &Realm,
        client: &Client,
        token: &str,
    ) -> Result<bool, Unavailable> {
        let Some((c, _, domain)) = self.authority_claims(realm, client, token).await? else {
            return Ok(false);
        };
        let family = c
            .get("family")
            .and_then(Value::as_str)
            .and_then(|f| access_kernel::json::b64url_decode(f).ok())
            .and_then(|f| <[u8; 16]>::try_from(f).ok());
        let Some(family) = family else {
            return Ok(false);
        };
        self.env()
            .projections()
            .revoke_family(domain, family)
            .await
            .map_err(|_| Unavailable)
    }
}

/// The OAuth `error` of a reply, for the audit row of a refused token request.
pub(crate) fn error_of(r: &Reply) -> Option<String> {
    match r {
        Reply::Json { status, body, .. } if *status >= 400 => serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(String::from)),
        _ => None,
    }
}
