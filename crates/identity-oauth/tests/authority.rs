//! Authority tokens at the realm's token endpoint (§9.9, §10.4 (i), OP-150 m.2): the identity
//! plane checks the request against the holder's `projection.issue` Exercise and forwards it;
//! the authority plane (scripted here) decides. Real PostgreSQL, real identity signer.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::unnecessary_wraps,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};

use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::domain::authority::{TokenExercise, encode_exercise};
use access_identity_oauth::domain::tokens::INVALIDATED_OUTBOX;
use access_internal_api::idp::Unavailable as PlaneUnavailable;
use access_internal_api::instances::core_action;
use access_internal_api::projections::{
    Confirmation, Introspection, IssuedToken, TokenKind, TokenProjection,
};
use access_kernel::combinator::{
    Blocker, BlockerClass, Capacity, Decision, Outcome, Position, Remediation, Resolver,
};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ExerciseBasis, Payload};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, Window,
};
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_kernel::verify::cose::{KID, PublicKey};
use access_kernel::verify::key_scope::thumbprint;
use access_kernel::verify::projection::digest_text;
use access_store::identity::TenantTx;
use aws_lc_rs::signature::KeyPair as _;
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use support::{At, CB, Cluster, VERIFIER, body, location, now, query};

const RS: &str = "https://rs.shop.example";

fn read() -> ActionRef {
    ActionRef {
        namespace: String::from("shop"),
        name: String::from("read"),
        major: 1,
        schema: Digest([0x5c; 32]),
    }
}

fn details(kind: &str, action: &ActionRef, extra: &str) -> String {
    format!(
        r#"[{{"type":"{}:{}:{}","kind":"{kind}","schema":"{}"{extra}}}]"#,
        action.namespace,
        action.name,
        action.major,
        digest_text(&action.schema)
    )
}

/// A `COSE_Sign1` whose protected header names `kid`; the authority plane verifies it, the
/// identity plane only reads its `kid`.
fn ais(kid: [u8; 32]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Cbor::Map(vec![(Cbor::Unsigned(KID), Cbor::Bytes(kid.to_vec()))]),
        Limits::CEILING,
    )
    .unwrap();
    let body = dcbor::encode(
        &Cbor::Array(vec![
            Cbor::Bytes(prot),
            Cbor::Map(Vec::new()),
            Cbor::Bytes(b"statement".to_vec()),
            Cbor::Bytes(vec![0; 64]),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

fn holder_kid(at: &At<'_>) -> [u8; 32] {
    thumbprint(&PublicKey::P256(at.key.public_key().as_ref().to_vec()))
}

async fn governing(at: &At<'_>) -> Digest {
    let mut tx = TenantTx::begin(&at.c.db.app, at.f.realm.tenant, at.f.realm.realm)
        .await
        .unwrap();
    let g = access_store::idp::governance(&mut tx)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    Digest(*g.domain.as_bytes())
}

/// The holder's `projection.issue` of `actions` for `audience`, signed (by `kid`).
fn exercise(
    domain: Digest,
    actions: Vec<ActionRef>,
    audience: &str,
    kid: [u8; 32],
) -> TokenExercise {
    let payload = Payload::ProjectionIssue {
        bounds: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: actions.into_iter().collect(),
                    prefix: BTreeSet::new(),
                },
                resource: ResourceSelector::Structural(Structural {
                    namespace: String::from("shop"),
                    prefix: Vec::new(),
                    kind: None,
                    attrs: BTreeMap::new(),
                }),
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window {
                    from: now(),
                    until: now() + 300_000,
                },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 0,
                downstream_holder_class: None,
            },
            requirements: BTreeSet::new(),
        },
        audience: BTreeSet::from([String::from(audience)]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    let intent = IntentEnvelope {
        action: core_action("projection_issue"),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.projection"),
            path: vec![String::from(audience)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from("payload"), payload.digest().unwrap())]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now(),
            until: now() + 60_000,
        },
    };
    TokenExercise {
        domain,
        nonce: access_crypto::random::bytes::<16>().unwrap().to_vec(),
        intent,
        payload_bytes: access_kernel::codec::Canonical::to_bytes(&payload).unwrap(),
        payload,
        basis: ExerciseBasis::Anchor(Id([1; 16])),
        capacity: Capacity::Own,
        ais: ais(kid),
        target: None,
    }
}

fn issued(family: [u8; 16]) -> Result<TokenProjection, PlaneUnavailable> {
    Ok(TokenProjection::Issued(IssuedToken {
        token: String::from("eyJ0eXAiOiJhdCtqd3QifQ.e30.sig"),
        exercise: Digest([0xe1; 32]),
        position: 7,
        contract: Digest([0xc0; 32]),
        expires_at: now() + 300_000,
        status: None,
        family,
    }))
}

fn script(at: &At<'_>, answer: Result<TokenProjection, PlaneUnavailable>) {
    *at.c.oauth.env().plane.answer.lock().unwrap() = Some(answer);
}

fn asked(at: &At<'_>) -> Vec<access_internal_api::projections::TokenProjectionRequest> {
    std::mem::take(&mut *at.c.oauth.env().plane.asked.lock().unwrap())
}

async fn credentials(at: &At<'_>, pairs: &[(&str, &str)]) -> Reply {
    let mut all = vec![("grant_type", "client_credentials")];
    all.extend_from_slice(pairs);
    at.token(&all, Some(&at.basic())).await
}

fn error(r: &Reply) -> String {
    match r {
        Reply::Json { status, body, .. } => {
            assert!(*status >= 400, "{body}");
            let v: Value = serde_json::from_str(body).unwrap();
            String::from(v["error"].as_str().unwrap())
        }
        other => panic!("{other:?}"),
    }
}

// §9.9, P17, PI-11, §9.9.3 rules 1-3, §11.21.2, CMP-15.1, TN-27: client credentials is the
// confidential client's own projection.issue; the token is the authority plane's, DPoP-bound
// to the Exercise's own key, for one resource, with no refresh token
#[tokio::test]
async fn client_credentials_is_a_projection_issue_decision() {
    // IDP-11, AG-8, P48
    let c = Cluster::new(&["ccred"]).await;
    let at = c.at(0);
    let domain = governing(&at).await;
    let e = exercise(domain, vec![read()], RS, holder_kid(&at));
    script(&at, issued([3; 16]));
    let rar = details(
        "bounds",
        &read(),
        r#","actions":["ignored"],"locations":["https://rs.shop.example"]"#,
    );
    let r = credentials(
        &at,
        &[
            ("resource", RS),
            ("authorization_details", &rar),
            ("access_exercise", &encode_exercise(&e).unwrap()),
        ],
    )
    .await;
    let b = body(&r, 200);
    assert_eq!(b["token_type"], "DPoP");
    assert_eq!(b["access_token"], "eyJ0eXAiOiJhdCtqd3QifQ.e30.sig");
    assert!(b.get("refresh_token").is_none());
    assert_eq!(b["authorization_details"][0]["kind"], "bounds");
    let sent = asked(&at);
    assert_eq!(sent.len(), 1);
    let s = &sent[0];
    assert_eq!(s.domain, domain);
    assert_eq!(s.kind, TokenKind::Bounds);
    assert_eq!(s.resources, vec![String::from(RS)]);
    assert_eq!(s.confirmation, Confirmation::DpopJkt(holder_kid(&at)));
    assert_eq!(s.client_id, at.f.confidential);
    assert_eq!(s.pep, at.f.issuer);
    assert_eq!(s.family, None);
}

// §9.9.3 rules 1-3, §9.9.4, §9.13.5, RFC 9396, RFC 8707, AG-8, OP-39: a request that does not say
// what its Exercise says is refused before anything is decided, and every refusal is audited
#[tokio::test]
async fn a_mismatched_authority_request_is_refused_before_the_decision() {
    // P25, P48, IDP-11
    let c = Cluster::new(&["mismatch"]).await;
    let at = c.at(0);
    let domain = governing(&at).await;
    let kid = holder_kid(&at);
    let ok = encode_exercise(&exercise(domain, vec![read()], RS, kid)).unwrap();
    let rar = details("bounds", &read(), "");
    script(&at, issued([3; 16]));
    let mut other = read();
    other.name = String::from("write");
    let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
        // AG-8: no default resource
        (
            vec![
                ("authorization_details", rar.clone()),
                ("access_exercise", ok.clone()),
            ],
            "invalid_target",
        ),
        (
            vec![
                ("resource", at.f.issuer.clone()),
                ("authorization_details", rar.clone()),
                ("access_exercise", ok.clone()),
            ],
            "invalid_target",
        ),
        (
            vec![
                ("resource", String::from("https://other.example")),
                ("authorization_details", rar.clone()),
                ("access_exercise", ok.clone()),
            ],
            "invalid_target",
        ),
        // the details are what the bounds are, no more, no less
        (
            vec![
                ("resource", String::from(RS)),
                ("authorization_details", details("bounds", &other, "")),
                ("access_exercise", ok.clone()),
            ],
            "invalid_authorization_details",
        ),
        // P25: locations only as a hint consistent with the resource
        (
            vec![
                ("resource", String::from(RS)),
                (
                    "authorization_details",
                    details(
                        "bounds",
                        &read(),
                        r#","locations":["https://evil.example"]"#,
                    ),
                ),
                ("access_exercise", ok.clone()),
            ],
            "invalid_authorization_details",
        ),
        (
            vec![
                ("resource", String::from(RS)),
                ("authorization_details", String::from("{}")),
                ("access_exercise", ok.clone()),
            ],
            "invalid_authorization_details",
        ),
        (
            vec![
                ("resource", String::from(RS)),
                ("authorization_details", rar.clone()),
            ],
            "invalid_request",
        ),
        // §9.9.4: cnf is the actor Instance's key, so the Exercise is the DPoP key's
        (
            vec![
                ("resource", String::from(RS)),
                ("authorization_details", rar.clone()),
                (
                    "access_exercise",
                    encode_exercise(&exercise(domain, vec![read()], RS, [7; 32])).unwrap(),
                ),
            ],
            "invalid_dpop_proof",
        ),
        // only the realm's governing domain
        (
            vec![
                ("resource", String::from(RS)),
                ("authorization_details", rar.clone()),
                (
                    "access_exercise",
                    encode_exercise(&exercise(Digest([0xdd; 32]), vec![read()], RS, kid)).unwrap(),
                ),
            ],
            "invalid_request",
        ),
    ];
    let n = cases.len();
    for (pairs, want) in cases {
        let p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(error(&credentials(&at, &p).await), want, "{pairs:?}");
    }
    // a public client has no client credentials
    let r = at
        .token(
            &[
                ("grant_type", "client_credentials"),
                ("client_id", &at.f.public),
                ("resource", RS),
                ("authorization_details", &rar),
                ("access_exercise", &ok),
            ],
            None,
        )
        .await;
    assert_eq!(error(&r), "unauthorized_client");
    assert_eq!(asked(&at).len(), 0);
    // OP-39
    let mut tx = TenantTx::begin(&c.db.app, at.f.realm.tenant, at.f.realm.realm)
        .await
        .unwrap();
    let rows = tx.list_audit(100).await.unwrap();
    tx.commit().await.unwrap();
    let refused = rows
        .iter()
        .filter(|r| r.event_type == "oauth.token.refused")
        .count();
    assert_eq!(refused, n + 1);
}

// §9.9.5, K17, G50: DENY and REQUIRE_ACTION are told apart; no decision is a 503
#[tokio::test]
async fn the_authority_decision_is_answered_by_its_outcome() {
    // R2, A-7
    let c = Cluster::new(&["outcome"]).await;
    let at = c.at(0);
    let domain = governing(&at).await;
    let rar = details("bounds", &read(), "");
    let blocker = |class, remediation| Blocker {
        class,
        subcode: None,
        position: Position::Anchor,
        resolver: Resolver::Root,
        remediation,
    };
    let decision = |outcome, b| Decision {
        outcome,
        blockers: vec![b],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    };
    let ask = |at: &At<'_>| {
        let e = encode_exercise(&exercise(domain, vec![read()], RS, holder_kid(at))).unwrap();
        (rar.clone(), e)
    };
    script(
        &at,
        Ok(TokenProjection::Denied {
            decision: decision(
                Outcome::Deny,
                blocker(
                    BlockerClass::NoCoveringAuthority,
                    Remediation::RouteToCoordinator,
                ),
            ),
            position: Some(4),
        }),
    );
    let (r1, e1) = ask(&at);
    let r = credentials(
        &at,
        &[
            ("resource", RS),
            ("authorization_details", &r1),
            ("access_exercise", &e1),
        ],
    )
    .await;
    let b = body(&r, 400);
    assert_eq!(b["error"], "invalid_grant");
    assert_eq!(b["access_blockers"][0], "no-covering-authority");
    script(
        &at,
        Ok(TokenProjection::RequireAction {
            decision: decision(
                Outcome::RequireAction,
                blocker(BlockerClass::NoCoveringAuthority, Remediation::RefreshClaim),
            ),
            position: Some(5),
        }),
    );
    let (r2, e2) = ask(&at);
    let r = credentials(
        &at,
        &[
            ("resource", RS),
            ("authorization_details", &r2),
            ("access_exercise", &e2),
        ],
    )
    .await;
    let b = body(&r, 400);
    assert_eq!(b["error"], "insufficient_authorization");
    assert_eq!(
        b["authorization_remediation"]["remediation"][0],
        "refresh-claim"
    );
    assert_eq!(
        b["authorization_remediation"]["exercise_ref"]["domain"],
        b64url_encode(&domain.0)
    );
    // OP-150 m.3 (s)
    script(
        &at,
        Ok(TokenProjection::Refused {
            code: String::from("token-too-large"),
        }),
    );
    let (r3, e3) = ask(&at);
    let r = credentials(
        &at,
        &[
            ("resource", RS),
            ("authorization_details", &r3),
            ("access_exercise", &e3),
        ],
    )
    .await;
    assert_eq!(body(&r, 400)["access_error"], "token-too-large");
    // K17: the signer cannot be reached
    script(
        &at,
        Err(PlaneUnavailable(String::from(
            access_internal_api::projections::SIGNER_UNAVAILABLE,
        ))),
    );
    let (r4, e4) = ask(&at);
    let r = credentials(
        &at,
        &[
            ("resource", RS),
            ("authorization_details", &r4),
            ("access_exercise", &e4),
        ],
    )
    .await;
    assert_eq!(r, Reply::Unavailable);
}

// §9.9.3 rule 6, L19, P50, PI-10, RFC 9396 §6.1, §11.4.5 #22, AS-M8: authority asked at
// /authorize is decided at the token endpoint; every refresh is a new decision of the same
// family; a reused refresh token ends the family and raises projection-invalidated
#[tokio::test]
async fn authority_refresh_is_a_new_decision_and_reuse_ends_the_family() {
    // OP-10, OP-24
    let c = Cluster::new(&["refresh"]).await;
    let at = c.at(0);
    let domain = governing(&at).await;
    let rar = details("bounds", &read(), "");
    // RFC 9396 §6.1: authority is asked at /authorize with its resource
    let cookie = at.sign_in(now() - 1000).await;
    let r = at
        .authorize(
            &[("resource", RS), ("authorization_details", &rar)],
            Some(&cookie),
        )
        .await;
    let code = query(&location(&r), "code");
    let unauthorized = at
        .authorize(&[("authorization_details", &rar)], Some(&cookie))
        .await;
    assert!(location(&unauthorized).contains("error=invalid_target"));
    script(&at, issued([9; 16]));
    let first = encode_exercise(&exercise(domain, vec![read()], RS, holder_kid(&at))).unwrap();
    let r = at
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &at.f.public),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
                ("access_exercise", &first),
            ],
            None,
        )
        .await;
    let b = body(&r, 200);
    assert_eq!(b["token_type"], "DPoP");
    assert!(b["id_token"].is_string());
    let refresh = String::from(b["refresh_token"].as_str().unwrap());
    assert_eq!(asked(&at)[0].family, None);
    // L19: a refresh without a new Exercise is no decision
    let r = at.refresh(&refresh).await;
    assert_eq!(error(&r), "invalid_request");
    let second = encode_exercise(&exercise(domain, vec![read()], RS, holder_kid(&at))).unwrap();
    let r = at
        .token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &at.f.public),
                ("refresh_token", &refresh),
                ("access_exercise", &second),
            ],
            None,
        )
        .await;
    let next = body(&r, 200);
    assert_ne!(next["refresh_token"], b["refresh_token"]);
    let sent = asked(&at);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].family, Some([9; 16]));
    // AS-M8: the rotated token presented again ends the family
    let r = at
        .token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &at.f.public),
                ("refresh_token", &refresh),
                ("access_exercise", &second),
            ],
            None,
        )
        .await;
    assert_eq!(error(&r), "invalid_grant");
    assert_eq!(
        *at.c.oauth.env().plane.revoked.lock().unwrap(),
        vec![[9; 16]]
    );
    // the outbox shows a transaction once every older one in the cluster has ended
    let mut ended = Vec::new();
    for _ in 0..100 {
        ended = access_store::identity::poll(
            &c.db.reader,
            access_store::identity::Cursor::default(),
            100,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == INVALIDATED_OUTBOX)
        .collect();
        if !ended.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(ended.len(), 1);
    let v: Value = serde_json::from_slice(&ended[0].payload).unwrap();
    assert_eq!(v["payload"]["subject"]["kind"], "projection");
    assert_eq!(v["payload"]["subject"]["id"], b64url_encode(&[9; 16]));
    assert_eq!(
        v["payload"]["source"]["exercise"],
        b64url_encode(&[0xe1; 32])
    );
}

fn authority_token(at: &At<'_>, client: &str) -> (String, String) {
    let claims = serde_json::json!({
        "iss": at.f.issuer,
        "sub": "pw-1",
        "aud": RS,
        "exp": now() / 1000 + 60,
        "iat": now() / 1000,
        "jti": format!("sha-256:{}", b64url_encode(&[0xe1; 32])),
        "client_id": client,
        "cnf": { "jkt": at.jkt() },
        "authorization_details": [{ "type": "shop:read:1", "kind": "bounds" }],
        "family": b64url_encode(&[4; 16]),
    })
    .to_string();
    let token = format!(
        "{}.{}.c2ln",
        b64url_encode(br#"{"typ":"at+jwt","alg":"ES256","kid":"k"}"#),
        b64url_encode(claims.as_bytes())
    );
    (token, claims)
}

// §9.9.3 rule 5, MD-8, OPI-3, OP-45, P-ID-8, T24, OP-150 m.2: an authority token is introspected
// by the authority plane at least at its head, with the Access members; what cannot be proven
// is active=false, never 503; RFC 7009 on it ends its family (PI-10)
#[tokio::test]
async fn authority_tokens_are_introspected_and_revoked_by_the_authority_plane() {
    // §11.4.5 #16, CMP-1
    let c = Cluster::new(&["intro"]).await;
    let at = c.at(0);
    let (token, claims) = authority_token(&at, &at.f.confidential);
    *at.c.oauth.env().plane.introspection.lock().unwrap() = Some(Introspection {
        active: true,
        claims: Some(claims),
        as_of: 42,
    });
    let b = at.introspect(&token).await;
    assert_eq!(b["active"], true);
    // a ledger position is a decimal string (OP-65)
    assert_eq!(b["as_of"], "42");
    assert_eq!(b["exercise"], b64url_encode(&[0xe1; 32]));
    assert_eq!(b["authorization_details"][0]["kind"], "bounds");
    assert_eq!(b["cnf"]["jkt"], at.jkt());
    // another client's token is not this client's to read
    let (theirs, their_claims) = authority_token(&at, &at.f.public);
    *at.c.oauth.env().plane.introspection.lock().unwrap() = Some(Introspection {
        active: true,
        claims: Some(their_claims),
        as_of: 42,
    });
    assert_eq!(at.introspect(&theirs).await["active"], false);
    // inactive, and no answer at all, are both active=false
    *at.c.oauth.env().plane.introspection.lock().unwrap() = Some(Introspection {
        active: false,
        claims: None,
        as_of: 43,
    });
    assert_eq!(
        at.introspect(&token).await,
        serde_json::json!({ "active": false })
    );
    *at.c.oauth.env().plane.introspection.lock().unwrap() = None;
    assert_eq!(
        at.introspect(&token).await,
        serde_json::json!({ "active": false })
    );
    // RFC 7009: projection cleanup of the token's family
    let (_, claims) = authority_token(&at, &at.f.confidential);
    *at.c.oauth.env().plane.introspection.lock().unwrap() = Some(Introspection {
        active: true,
        claims: Some(claims),
        as_of: 44,
    });
    let p = access_identity_oauth::domain::request::Params::new(vec![(
        String::from("token"),
        token.clone(),
    )])
    .unwrap();
    let r = at.c.oauth.revoke(&at.f.realm, &p, Some(&at.basic())).await;
    assert_eq!(body(&r, 200), serde_json::json!({}));
    assert_eq!(
        *at.c.oauth.env().plane.revoked.lock().unwrap(),
        vec![[4; 16]]
    );
}
