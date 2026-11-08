//! Metamorphic realm and tenant isolation: the same script in
//! two realms of two tenants gives the same decisions up to the realm's own names; random
//! mutations in one realm leave the other's authentication and token decisions bit for bit the
//! same; nothing minted in one realm is honoured in the other.

use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::domain::request::Params;
use serde_json::Value;

use crate::support::{
    At, CB, Cluster, JWT_BEARER, VERIFIER, body, claims, error, header, location, now, query,
    query_opt, status,
};

/// What one realm minted, to be presented elsewhere.
struct Minted {
    cookie: String,
    code: String,
    access: String,
    refresh: String,
    id_token: String,
    request_uri: String,
    nonce: String,
    assertion: String,
    public: String,
}

async fn mint(x: &At<'_>) -> Minted {
    let cookie = x.sign_in(now() - 1000).await;
    let to = location(&x.authorize(&[], Some(&cookie)).await);
    let code = query(&to, "code");
    let t = x.tokens().await;
    let par = Params::new(
        [
            ("redirect_uri", CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", crate::support::CHALLENGE),
            ("code_challenge_method", "S256"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect(),
    )
    .unwrap();
    let pushed = body(
        &x.oauth().par(x.realm(), &par, Some(&x.basic()), &[]).await,
        201,
    );
    Minted {
        cookie,
        code,
        access: t["access_token"].as_str().unwrap().to_owned(),
        refresh: t["refresh_token"].as_str().unwrap().to_owned(),
        id_token: t["id_token"].as_str().unwrap().to_owned(),
        request_uri: pushed["request_uri"].as_str().unwrap().to_owned(),
        nonce: x.rings().authorization.issue(now()).unwrap(),
        assertion: x.assertion(x.issuer()),
        public: x.f.public.clone(),
    }
}

/// A reply with the realm's own names replaced, so two realms compare.
fn shape(x: &At<'_>, r: &Reply) -> String {
    let text = match r {
        Reply::Redirect(to) => {
            let mut keys: Vec<String> = to
                .split_once('?')
                .map(|(_, q)| Params::parse(q).unwrap())
                .map(|p| {
                    ["code", "state", "iss", "error", "return_to", "reason"]
                        .iter()
                        .filter(|k| p.get(k).is_some())
                        .map(|k| match *k {
                            "error" => format!("error={}", p.get(k).unwrap()),
                            "iss" => format!("iss={}", p.get(k).unwrap()),
                            other => String::from(other),
                        })
                        .collect()
                })
                .unwrap_or_default();
            keys.sort();
            format!(
                "303 {} {}",
                to.split('?').next().unwrap_or_default(),
                keys.join(",")
            )
        }
        Reply::Json { status, body, .. } => {
            let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let mut keys: Vec<String> = v
                .as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            keys.sort();
            let e = v["error"].as_str().unwrap_or_default();
            let active = v["active"]
                .as_bool()
                .map(|b| format!(" active={b}"))
                .unwrap_or_default();
            format!("{status} {e}{active} [{}]", keys.join(","))
        }
        Reply::Problem { status, code } => format!("{status} {code}"),
        Reply::Unavailable => String::from("503"),
        Reply::NotFound => String::from("404"),
    };
    text.replace(x.issuer(), "{issuer}")
        .replace(&x.f.public, "{public}")
        .replace(&x.f.confidential, "{confidential}")
        .replace(&x.f.keyed, "{keyed}")
}

/// The shape of issued tokens: header and claim names, and which claims name the realm.
fn token_shape(x: &At<'_>, t: &Value) -> String {
    let at = claims(t["access_token"].as_str().unwrap());
    let id = claims(t["id_token"].as_str().unwrap());
    let names = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k.join(",")
    };
    format!(
        "at[{}] {} {} {} id[{}] {} {} {} {}",
        names(&at),
        header(t["access_token"].as_str().unwrap())["typ"],
        at["iss"] == x.issuer(),
        at["aud"] == x.issuer(),
        names(&id),
        header(t["id_token"].as_str().unwrap())["typ"],
        id["iss"] == x.issuer(),
        id["aud"] == x.f.public.as_str(),
        id["sub"] == at["sub"],
    )
}

/// The decision vector of realm `x`: its own flow, and everything `other` minted presented to
/// it. Every entry is a normalised decision.
async fn vector(x: &At<'_>, other: &Minted) -> Vec<String> {
    let mut v = Vec::new();
    let cookie = x.sign_in(now() - 1000).await;
    v.push(shape(x, &x.authorize(&[], Some(&cookie)).await));
    v.push(shape(x, &x.authorize(&[("prompt", "none")], None).await));
    v.push(shape(
        x,
        &x.authorize(&[("prompt", "none")], Some(&other.cookie))
            .await,
    ));
    v.push(shape(x, &x.authorize(&[], Some(&other.cookie)).await));
    v.push(shape(
        x,
        &x.authorize(&[("client_id", &other.public)], Some(&cookie))
            .await,
    ));
    let to = location(&x.authorize(&[], Some(&cookie)).await);
    let code = query(&to, "code");
    let issued = x.exchange(&code).await;
    v.push(shape(x, &issued));
    let t = body(&issued, 200);
    v.push(token_shape(x, &t));
    let access = t["access_token"].as_str().unwrap();
    let refresh = t["refresh_token"].as_str().unwrap();
    v.push(shape(x, &x.userinfo(access).await));
    v.push(format!(
        "introspect {}",
        x.introspect(access).await["active"]
    ));
    v.push(format!(
        "introspect {}",
        x.introspect(&other.access).await["active"]
    ));
    v.push(format!(
        "introspect {}",
        x.introspect(&other.refresh).await["active"]
    ));
    v.push(shape(x, &x.exchange(&other.code).await));
    v.push(shape(x, &x.refresh(&other.refresh).await));
    v.push(shape(x, &x.userinfo(&other.access).await));
    let revoke = Params::new(vec![("token".into(), other.refresh.clone())]).unwrap();
    v.push(shape(
        x,
        &x.oauth().revoke(x.realm(), &revoke, Some(&x.basic())).await,
    ));
    let rotated = x.refresh(refresh).await;
    v.push(shape(x, &rotated));
    let stored = Params::new(vec![
        ("client_id".into(), x.f.confidential.clone()),
        ("request_uri".into(), other.request_uri.clone()),
    ])
    .unwrap();
    v.push(shape(
        x,
        &x.oauth().authorize(x.realm(), &stored, Some(&cookie)).await,
    ));
    let token_uri = format!("{}/token", x.issuer());
    let foreign_nonce = x.proof_with("POST", &token_uri, None, &other.nonce);
    let code = query(&location(&x.authorize(&[], Some(&cookie)).await), "code");
    let p = [
        ("grant_type", "authorization_code"),
        ("client_id", x.f.public.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", CB),
        ("code_verifier", VERIFIER),
    ];
    v.push(shape(x, &x.token_with(&p, None, &[&foreign_nonce]).await));
    let code = query(
        &location(
            &x.authorize(&[("client_id", &x.f.keyed)], Some(&cookie))
                .await,
        ),
        "code",
    );
    let p = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", CB),
        ("code_verifier", VERIFIER),
        ("client_id", x.f.keyed.as_str()),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", other.assertion.as_str()),
    ];
    v.push(shape(x, &x.token(&p, None).await));
    let hinted = x
        .end_session(&[("id_token_hint", &other.id_token)], Some(&cookie))
        .await;
    v.push(shape(x, &hinted));
    v.push(format!("signed in {}", x.signed_in(&cookie).await));
    v
}

/// One mutation of a realm: users, factors, clients, keys.
async fn mutate(x: &At<'_>, which: u64) -> String {
    match which % 7 {
        0 => {
            let t = x.tokens().await;
            let r = t["refresh_token"].as_str().unwrap();
            let _ = x.refresh(r).await;
            let _ = x.refresh(r).await;
            String::from("refresh reuse: grant revoked, session epoch raised")
        }
        1 => {
            let cookie = x.sign_in(now() - 1000).await;
            let to = location(&x.authorize(&[], Some(&cookie)).await);
            let t = body(&x.exchange(&query(&to, "code")).await, 200);
            let _ = x
                .end_session(
                    &[
                        ("id_token_hint", t["id_token"].as_str().unwrap()),
                        ("post_logout_redirect_uri", crate::support::BYE),
                    ],
                    Some(&cookie),
                )
                .await;
            String::from("logout")
        }
        2 => {
            let t = x.tokens().await;
            let p = Params::new(vec![(
                "token".into(),
                t["access_token"].as_str().unwrap().into(),
            )])
            .unwrap();
            let _ = x.oauth().revoke(x.realm(), &p, Some(&x.basic())).await;
            String::from("revocation")
        }
        3 => {
            let code = x.code(&x.f.public).await;
            let _ = x.exchange(&code).await;
            let _ = x.exchange(&code).await;
            String::from("code reuse")
        }
        4 => {
            for _ in 0..5 {
                let code = x.code(&x.f.confidential).await;
                let _ = x
                    .token(
                        &[
                            ("grant_type", "authorization_code"),
                            ("code", &code),
                            ("redirect_uri", CB),
                            ("code_verifier", VERIFIER),
                        ],
                        Some(&crate::support::basic(&x.f.confidential, "wrong")),
                    )
                    .await;
            }
            String::from("failed client authentications")
        }
        5 => {
            let mut tx = access_store::identity::TenantTx::begin(
                &x.c.db.app,
                x.f.realm.tenant,
                x.f.realm.realm,
            )
            .await
            .unwrap();
            let s = tx
                .insert_subject("active", "realm-kek:1", &[3; 40])
                .await
                .unwrap();
            tx.commit().await.unwrap();
            format!("new subject {}", s.len())
        }
        _ => {
            let to = location(&x.authorize(&[("prompt", "login")], Some(&x.f.cookie)).await);
            format!("prompt=login {}", to.contains("reauthenticate"))
        }
    }
}

// MR7b, SA-45, SAI-6, MD-5, TN-2, TN-7, TN-8, INV-17, TN-23, §12.1.3
#[tokio::test]
async fn realms_are_isomorphic_and_never_cross() {
    // K05, X41
    let c = Cluster::new(&["iso-a", "iso-b"]).await;
    let (a, b) = (c.at(0), c.at(1));
    assert!(a.realm().tenant != b.realm().tenant);
    let from_a = mint(&a).await;
    let from_b = mint(&b).await;
    let va = vector(&a, &from_b).await;
    let vb = vector(&b, &from_a).await;
    assert_eq!(va, vb, "the realms do not answer alike");
    for (n, line) in va.iter().enumerate() {
        assert!(!line.contains("iso-b"), "{n}: {line}");
        assert!(!line.contains(&b.f.public), "{n}: {line}");
    }

    let kept = b.tokens().await;
    let mut seed: u64 = 0x5eed_1a7e;
    for round in 0..3 {
        let mut done = Vec::new();
        for _ in 0..4 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            done.push(mutate(&a, seed >> 33).await);
        }
        let from_a = mint(&a).await;
        let again = vector(&b, &from_a).await;
        assert_eq!(
            again, vb,
            "round {round}: {done:?} in realm A changed realm B"
        );
        assert!(
            matches!(
                b.userinfo(kept["access_token"].as_str().unwrap()).await,
                Reply::Json { status: 200, .. }
            ),
            "round {round}: {done:?}"
        );
    }
    let refreshed = b.refresh(kept["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status(&refreshed), 200, "{refreshed:?}");
    assert!(b.signed_in(&b.f.cookie).await);
    let to = location(&a.authorize(&[("prompt", "none")], Some(&b.f.cookie)).await);
    assert_eq!(query(&to, "error"), "login_required");
    assert!(query_opt(&to, "code").is_none());
    let _ = error;
}
