//! The token-confusion fuzzer (§12.1.3 test 4, TN-23, OP-138): tokens signed with the realm's
//! real keys but with the wrong type, issuer, audience, binding, lifetime, session or realm,
//! and tokens with swapped algorithms or keys, are refused everywhere a token is read.

use access_crypto::jose::JwsAlg;
use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::ports::oauth::TokenSigner;
use access_kernel::json::b64url_encode;
use aws_lc_rs::hmac;
use serde_json::{Value, json};

use crate::support::{At, Cluster, body, claims, error, header, location, new_key, now, sign};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signer {
    Own,
    Other,
}

/// One point of the product of what a token can claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Point {
    signer: Signer,
    typ: usize,
    iss: usize,
    aud: usize,
    cnf: usize,
    exp: usize,
    sid: usize,
}

const TYPS: [&str; 5] = ["at+jwt", "JWT", "logout+jwt", "dpop+jwt", "secevent+jwt"];
const SIZES: [usize; 6] = [TYPS.len(), 3, 5, 3, 2, 2];
const VALID: Point = Point {
    signer: Signer::Own,
    typ: 0,
    iss: 0,
    aud: 0,
    cnf: 0,
    exp: 0,
    sid: 0,
};

struct Basis<'a> {
    a: &'a At<'a>,
    b: &'a At<'a>,
    real: Value,
    other_sid: String,
}

impl Basis<'_> {
    fn claims(&self, p: Point) -> Value {
        let (a, b) = (self.a.issuer(), self.b.issuer());
        let mut c = self.real.clone();
        let m = c.as_object_mut().unwrap();
        m.insert(
            "iss".into(),
            json!([a.to_owned(), b.to_owned(), format!("{a}/")][p.iss]),
        );
        match p.aud {
            0 => {
                m.insert("aud".into(), json!(a));
            }
            1 => {
                m.insert("aud".into(), json!(self.a.f.public));
            }
            2 => {
                m.insert("aud".into(), json!([a, "https://evil.example"]));
            }
            3 => {
                m.insert("aud".into(), json!(b));
            }
            _ => {
                m.remove("aud");
            }
        }
        match p.cnf {
            0 => {
                m.insert("cnf".into(), json!({ "jkt": self.a.jkt() }));
            }
            1 => {
                m.insert(
                    "cnf".into(),
                    json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }),
                );
            }
            _ => {
                m.remove("cnf");
            }
        }
        let t = now() / 1000;
        if p.exp == 1 {
            m.insert("iat".into(), json!(t - 7200));
            m.insert("exp".into(), json!(t - 3600));
        } else {
            m.insert("iat".into(), json!(t));
            m.insert("exp".into(), json!(t + 300));
        }
        if p.sid == 1 {
            m.insert("sid".into(), json!(self.other_sid));
        }
        c
    }

    async fn token(&self, p: Point) -> String {
        let realm = match p.signer {
            Signer::Own => self.a.realm().realm,
            Signer::Other => self.b.realm().realm,
        };
        let payload = self.claims(p).to_string();
        self.a
            .c
            .oauth
            .env()
            .signer
            .sign(realm, JwsAlg::Es256, TYPS[p.typ], payload.as_bytes(), now())
            .await
            .unwrap()
    }
}

fn next(seed: &mut u64) -> usize {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    usize::try_from(*seed >> 33).unwrap()
}

fn deviations() -> Vec<Point> {
    let mut out = vec![Point {
        signer: Signer::Other,
        ..VALID
    }];
    for (dim, size) in SIZES.iter().enumerate() {
        for v in 1..*size {
            let mut p = VALID;
            *[
                &mut p.typ, &mut p.iss, &mut p.aud, &mut p.cnf, &mut p.exp, &mut p.sid,
            ][dim] = v;
            out.push(p);
        }
    }
    out
}

fn random_points(n: usize) -> Vec<Point> {
    let mut seed = 0x70ce_c0f0_5e00_u64;
    (0..n)
        .map(|_| {
            let mut v = [0; 6];
            for (i, size) in SIZES.iter().enumerate() {
                v[i] = next(&mut seed) % size;
            }
            Point {
                signer: if next(&mut seed).is_multiple_of(2) {
                    Signer::Own
                } else {
                    Signer::Other
                },
                typ: v[0],
                iss: v[1],
                aud: v[2],
                cnf: v[3],
                exp: v[4],
                sid: v[5],
            }
        })
        .collect()
}

fn accepted(r: &Reply) -> bool {
    match r {
        Reply::Json { status: 200, .. } => true,
        Reply::Json {
            status: 401,
            challenge,
            ..
        } => {
            assert!(
                challenge.as_deref().is_some_and(|c| c.starts_with("DPoP ")),
                "{r:?}"
            );
            false
        }
        other => panic!("not a userinfo decision: {other:?}"),
    }
}

// TN-23, §12.1.3, OP-138, RFC 9068 §4, RFC 8725 §3.11, TN-8, TN-27, MD-3, CR-5, PI-11,
// Storm-0558 class (OP-119 m.2): a token is honoured only when it is this realm's access
// token: signed by this realm's key, typ at+jwt, this issuer, this audience alone, bound to
// the caller's key, unexpired and of a live grant here; every single deviation and a random
// sample of combined deviations is refused
#[tokio::test]
async fn signed_confusions_are_refused() {
    // K05
    let c = Cluster::new(&["tcf-a", "tcf-b"]).await;
    let (a, b) = (c.at(0), c.at(1));
    let real = a.tokens().await;
    let other = b.tokens().await;
    let basis = Basis {
        a: &a,
        b: &b,
        real: claims(real["access_token"].as_str().unwrap()),
        other_sid: claims(other["access_token"].as_str().unwrap())["sid"]
            .as_str()
            .unwrap()
            .to_owned(),
    };
    let baseline = basis.token(VALID).await;
    assert!(
        accepted(&a.userinfo(&baseline).await),
        "the forged baseline is a real token"
    );
    let mut points = deviations();
    points.extend(random_points(160).into_iter().filter(|p| *p != VALID));
    for p in points {
        let t = basis.token(p).await;
        assert!(!accepted(&a.userinfo(&t).await), "{p:?}");
    }
}

fn unsigned(header: &str, payload: &str) -> String {
    format!(
        "{}.{}.",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    )
}

fn hs256(header: &str, payload: &str, key: &[u8]) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), input.as_bytes());
    format!("{input}.{}", b64url_encode(tag.as_ref()))
}

// TN-23, MD-3, CR-5, RFC 8725 §2.1 and §3.1, OP-119 m.2: the algorithm and key come from the
// realm's own key set, never from the token: alg none, HS256 keyed with the public key set,
// EdDSA, an embedded jwk or jku, or an attacker key under the realm's kid are all refused; ID,
// refresh and logout tokens are not access tokens, and an access token is not a refresh token
// or a logout hint
#[tokio::test]
async fn swapped_algorithms_keys_and_token_kinds_are_refused() {
    let c = Cluster::new(&["tcs-a", "tcs-b"]).await;
    let (a, b) = (c.at(0), c.at(1));
    let real = a.tokens().await;
    let access = real["access_token"].as_str().unwrap();
    let kid = header(access)["kid"].as_str().unwrap().to_owned();
    let payload = claims(access).to_string();
    let jwks = c.oauth.env().signer.jwks(a.realm().realm).await.unwrap();
    let attacker = new_key();
    let jwk = crate::support::ec_jwk(&attacker);
    let mut forged = vec![
        (
            "alg none",
            unsigned(
                &format!(r#"{{"alg":"none","typ":"at+jwt","kid":"{kid}"}}"#),
                &payload,
            ),
        ),
        (
            "alg None",
            unsigned(
                &format!(r#"{{"alg":"None","typ":"at+jwt","kid":"{kid}"}}"#),
                &payload,
            ),
        ),
        (
            "HS256 with the key set",
            hs256(
                &format!(r#"{{"alg":"HS256","typ":"at+jwt","kid":"{kid}"}}"#),
                &payload,
                jwks.as_bytes(),
            ),
        ),
        (
            "EdDSA label",
            sign(
                &attacker,
                &format!(r#"{{"alg":"EdDSA","typ":"at+jwt","kid":"{kid}"}}"#),
                &payload,
            ),
        ),
        (
            "attacker key under the realm kid",
            sign(
                &attacker,
                &format!(r#"{{"alg":"ES256","typ":"at+jwt","kid":"{kid}"}}"#),
                &payload,
            ),
        ),
        (
            "embedded jwk",
            sign(
                &attacker,
                &format!(r#"{{"alg":"ES256","typ":"at+jwt","jwk":{jwk}}}"#),
                &payload,
            ),
        ),
        (
            "jku",
            sign(
                &attacker,
                &format!(
                    r#"{{"alg":"ES256","typ":"at+jwt","kid":"{kid}","jku":"https://evil.example/jwks"}}"#
                ),
                &payload,
            ),
        ),
        (
            "x5u",
            sign(
                &attacker,
                r#"{"alg":"ES256","typ":"at+jwt","x5u":"https://evil.example/cert"}"#,
                &payload,
            ),
        ),
        (
            "crit",
            sign(
                &attacker,
                &format!(
                    r#"{{"alg":"ES256","typ":"at+jwt","kid":"{kid}","crit":["b64"],"b64":false}}"#
                ),
                &payload,
            ),
        ),
    ];
    let parts: Vec<&str> = access.split('.').collect();
    forged.push(("signature stripped", format!("{}.{}.", parts[0], parts[1])));
    forged.push(("two dots more", format!("{access}..")));
    forged.push((
        "JWE shape",
        format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[1], parts[2]
        ),
    ));
    forged.push(("ID token", real["id_token"].as_str().unwrap().to_owned()));
    forged.push((
        "refresh token",
        real["refresh_token"].as_str().unwrap().to_owned(),
    ));
    let other = b.tokens().await;
    forged.push((
        "other realm access token",
        other["access_token"].as_str().unwrap().to_owned(),
    ));
    forged.push((
        "other realm ID token",
        other["id_token"].as_str().unwrap().to_owned(),
    ));
    for (class, token) in &forged {
        assert!(!accepted(&a.userinfo(token).await), "{class}");
        assert_eq!(a.introspect(token).await["active"], false, "{class}");
    }

    // RFC 9449 §7.1: a DPoP token as a bearer token, or with a proof that does not bind it
    let bearer = c
        .oauth
        .userinfo(a.realm(), "GET", Some(&format!("Bearer {access}")), &[])
        .await;
    assert!(!accepted(&bearer));
    let uri = format!("{}/userinfo", a.issuer());
    let unbound = a.proof("GET", &uri, None);
    let r = c
        .oauth
        .userinfo(
            a.realm(),
            "GET",
            Some(&format!("DPoP {access}")),
            &[&unbound],
        )
        .await;
    assert!(!accepted(&r));
    let wrong_ath = a.proof("GET", &uri, Some("something else"));
    let r = c
        .oauth
        .userinfo(
            a.realm(),
            "GET",
            Some(&format!("DPoP {access}")),
            &[&wrong_ath],
        )
        .await;
    assert!(!accepted(&r));
    let thief = a.with_key(new_key());
    assert!(
        !accepted(&thief.userinfo(access).await),
        "a stolen token with another key"
    );
    assert!(accepted(&a.userinfo(access).await));

    // RFC 6749 §6: only a refresh token refreshes
    for (class, token) in [
        ("access token", access),
        ("ID token", real["id_token"].as_str().unwrap()),
        (
            "other realm refresh token",
            other["refresh_token"].as_str().unwrap(),
        ),
    ] {
        assert_eq!(error(&a.refresh(token).await), "invalid_grant", "{class}");
    }

    // OIDC RP-Initiated Logout §2, Back-Channel Logout §2.4: only this realm's ID token is a
    // hint; an access, logout or foreign ID token leaves the session to the confirm page
    let logout_token = c
        .oauth
        .env()
        .signer
        .sign(
            a.realm().realm,
            JwsAlg::Es256,
            "logout+jwt",
            claims(real["id_token"].as_str().unwrap())
                .to_string()
                .as_bytes(),
            now(),
        )
        .await
        .unwrap();
    let cookie = a.sign_in(now() - 1000).await;
    for (class, hint) in [
        ("access token", access),
        ("logout token", logout_token.as_str()),
        ("other realm ID token", other["id_token"].as_str().unwrap()),
    ] {
        let r = a
            .end_session(&[("id_token_hint", hint)], Some(&cookie))
            .await;
        assert_eq!(location(&r), format!("{}/sign-out", a.issuer()), "{class}");
        assert!(a.signed_in(&cookie).await, "{class}");
    }
    assert!(
        body(
            &a.refresh(real["refresh_token"].as_str().unwrap()).await,
            200
        )["access_token"]
            .is_string()
    );
}
