//! The endpoint permission manifest (TN-113): the router serves exactly the manifest's rows, and
//! every row, sent without its permission, answers as the row says.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::items_after_statements,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_http::api::app::router_for;
use access_http::api::domain::Surface;
use access_http::api::manifest::{
    Access, MANIFEST, ManifestError, PLATFORM_ROOT, REALM_ROOT, Route, Verb, Visibility, check,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};

use admin::{
    Harness, MISSING, REALM, ROWS, ais, platform_domain, proof, realm_domain, send, surface,
};

fn concrete(row: &Route, slug: &str) -> String {
    row.path
        .split('/')
        .map(|s| match s {
            "{slug}" => slug,
            s if s.starts_with('{') => "k1",
            s => s,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn request(row: &Route, path: &str) -> axum::http::request::Builder {
    Request::builder().method(row.verb.method()).uri(path)
}

fn read_as(row: &Route, path: &str, token: &str) -> Request<Body> {
    request(row, path)
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", proof(row.verb.method().as_str(), path))
        .body(Body::empty())
        .unwrap()
}

fn audience(row: &Route) -> String {
    match row.surface {
        Surface::Realm => format!("access-admin:realm:{REALM}"),
        Surface::Platform => "access-admin:platform".to_owned(),
    }
}

fn other_audience(row: &Route) -> String {
    match row.surface {
        Surface::Realm => "access-admin:platform".to_owned(),
        Surface::Platform => format!("access-admin:realm:{REALM}"),
    }
}

async fn code_of(router: &axum::Router, request: Request<Body>) -> (StatusCode, String) {
    let (r, body) = send(router, request).await;
    (r.status(), body["code"].as_str().unwrap_or("").to_owned())
}

// TN-113, TN-119, TN-130, OP-151 m.3 (c)
async fn deny_matrix(h: &Harness, router: &axum::Router, rows: &[Route]) {
    for row in rows {
        h.pass(4_000);
        let path = concrete(row, REALM);
        let op = row.operation_id;
        let before = h.position();
        match row.access {
            Access::Read { scope } => {
                let none = request(row, &path).body(Body::empty()).unwrap();
                assert_eq!(
                    code_of(router, none).await,
                    (StatusCode::UNAUTHORIZED, "invalid-token".into()),
                    "{op}"
                );
                let good = h.token(&format!("{op}-good"), &audience(row), &[scope], 3_600_000);
                let bearer = request(row, &path)
                    .header("authorization", format!("Bearer {good}"))
                    .header("dpop", proof(row.verb.method().as_str(), &path))
                    .body(Body::empty())
                    .unwrap();
                assert_eq!(
                    code_of(router, bearer).await,
                    (StatusCode::UNAUTHORIZED, "invalid-token".into()),
                    "{op}: a bearer token is never a management credential"
                );
                let unbound = request(row, &path)
                    .header("authorization", format!("DPoP {good}"))
                    .body(Body::empty())
                    .unwrap();
                assert_eq!(
                    code_of(router, unbound).await.0,
                    StatusCode::UNAUTHORIZED,
                    "{op}: no proof of possession"
                );
                let other = h.token(
                    &format!("{op}-other"),
                    &other_audience(row),
                    &[scope],
                    600_000,
                );
                assert_eq!(
                    code_of(router, read_as(row, &path, &other)).await,
                    (StatusCode::UNAUTHORIZED, "wrong-audience".into()),
                    "{op}"
                );
                let unscoped = h.token(
                    &format!("{op}-unscoped"),
                    &audience(row),
                    &["realm.audit.read"],
                    600_000,
                );
                let expected = match row.visibility {
                    Visibility::Hidden => (StatusCode::NOT_FOUND, "not-found".to_owned()),
                    Visibility::Forbidden => {
                        (StatusCode::FORBIDDEN, "insufficient-scope".to_owned())
                    }
                };
                assert_eq!(
                    code_of(router, read_as(row, &path, &unscoped)).await,
                    expected,
                    "{op}"
                );
                let long = h.token(&format!("{op}-long"), &audience(row), &[scope], 3_600_001);
                assert_eq!(
                    code_of(router, read_as(row, &path, &long)).await,
                    (StatusCode::UNAUTHORIZED, "token-lifetime".into()),
                    "{op}"
                );
                if row.surface == Surface::Realm {
                    let ghost = h.token(
                        &format!("{op}-ghost"),
                        &format!("access-admin:realm:{MISSING}"),
                        &[scope],
                        600_000,
                    );
                    let missing = concrete(row, MISSING);
                    assert_eq!(
                        code_of(router, read_as(row, &missing, &ghost)).await,
                        (StatusCode::NOT_FOUND, "not-found".into()),
                        "{op}: a missing realm is 404"
                    );
                    assert_eq!(
                        code_of(router, read_as(row, &missing, &good)).await,
                        (StatusCode::UNAUTHORIZED, "wrong-audience".into()),
                        "{op}: a token never reaches another realm"
                    );
                }
                assert_eq!(
                    code_of(router, read_as(row, &path, &good)).await.0,
                    if access_http::api::realm::planned(op) {
                        StatusCode::NOT_IMPLEMENTED
                    } else if row.verb == Verb::Get {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    "{op}: a draft without an operation is refused only after its caller is"
                );
            }
            Access::Write => {
                let post = |ais: Option<String>, auth: Option<String>| {
                    let mut b = request(row, &path)
                        .header("content-type", "application/json")
                        .header("idempotency-key", "AAAAAAAAAAAAAAAAAAAAAA");
                    if let Some(a) = ais {
                        b = b.header("x-access-ais", a);
                    }
                    if let Some(a) = auth {
                        b = b
                            .header("authorization", format!("DPoP {a}"))
                            .header("dpop", proof(row.verb.method().as_str(), &path));
                    }
                    b.body(Body::from("{}")).unwrap()
                };
                assert_eq!(
                    code_of(router, post(None, None)).await,
                    (StatusCode::UNAUTHORIZED, "ais-required".into()),
                    "{op}"
                );
                let token = h.token(
                    &format!("{op}-reader"),
                    &audience(row),
                    &["realm.read", "platform.read"],
                    600_000,
                );
                assert_eq!(
                    code_of(router, post(None, Some(token))).await,
                    (StatusCode::UNAUTHORIZED, "ais-required".into()),
                    "{op}: a read token never writes"
                );
                assert_eq!(
                    code_of(router, post(Some("bm90LWNvc2U".into()), None)).await,
                    (StatusCode::UNAUTHORIZED, "ais-invalid".into()),
                    "{op}"
                );
                let (own, foreign) = match row.surface {
                    Surface::Realm => (realm_domain(), platform_domain()),
                    Surface::Platform => (platform_domain(), realm_domain()),
                };
                let stranger = suiss_crypto::signer::SoftSigner::generate_ed25519()
                    .unwrap()
                    .0;
                assert_eq!(
                    code_of(
                        router,
                        post(Some(ais(&stranger, own, [0; 16], h.now())), None)
                    )
                    .await,
                    (StatusCode::FORBIDDEN, "ais-rejected".into()),
                    "{op}: an Instance the domain does not know"
                );
                let elsewhere = h.instance(foreign);
                assert_eq!(
                    code_of(
                        router,
                        post(Some(ais(&elsewhere, own, [0; 16], h.now())), None)
                    )
                    .await,
                    (StatusCode::FORBIDDEN, "ais-rejected".into()),
                    "{op}: another surface's Instance"
                );
                let mine = h.instance(own);
                assert_eq!(
                    code_of(
                        router,
                        post(Some(ais(&mine, foreign, [0; 16], h.now())), None)
                    )
                    .await,
                    (StatusCode::FORBIDDEN, "ais-rejected".into()),
                    "{op}: a statement for another domain"
                );
            }
        }
        assert_eq!(h.position(), before, "{op}: nothing was written");
    }
}

// TN-113
#[tokio::test]
async fn every_manifest_row_refuses_a_caller_without_its_permission() {
    let h = Harness::new();
    deny_matrix(&h, &h.router(), MANIFEST).await;
}

// TN-113
#[tokio::test]
async fn the_router_serves_only_manifest_rows() {
    let h = Harness::new();
    let router = h.router();
    for path in [
        "/admin/v1",
        "/admin/v1/realms",
        "/admin/v1/realms/acme/users",
        "/admin/v1/platform/realms",
        "/admin/v1/platform/tenants/t1/accounts",
        "/admin/v2/platform",
        "/console/login",
        "/healthz",
        "/.well-known/openid-configuration",
    ] {
        let (r, body) = send(&router, Request::get(path).body(Body::empty()).unwrap()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body["code"], "not-found");
    }
    let (r, body) = send(
        &router,
        Request::delete("/admin/v1/platform")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["code"], "method-not-allowed");
}

// TN-113
#[test]
fn the_builder_holds_the_router_to_the_manifest() {
    let h = Harness::new();
    let missing = router_for(&h.api, ROWS, |b| b.handle("getPlatformSurface", surface));
    assert!(matches!(missing, Err(ManifestError::Missing(_))));
    let unlisted = router_for(&h.api, MANIFEST, |b| {
        b.handle("getPlatformSurface", surface)?
            .handle("getRealmSurface", surface)?
            .handle("setCredential", surface)
    });
    assert!(matches!(
        unlisted,
        Err(ManifestError::Unlisted("setCredential"))
    ));
    let twice = router_for(&h.api, MANIFEST, |b| {
        b.handle("getPlatformSurface", surface)?
            .handle("getPlatformSurface", surface)
    });
    assert!(matches!(twice, Err(ManifestError::Duplicate(_))));
    check(MANIFEST).unwrap();
}

// TN-113, OP-151 m.3 (a)
#[test]
fn manifest_rows_stay_on_their_surface() {
    static CROSS: &[Route] = &[Route {
        access: Access::Read {
            scope: "platform.read",
        },
        ..REALM_ROOT
    }];
    assert!(matches!(check(CROSS), Err(ManifestError::Surface(_))));
    static ESCAPE: &[Route] = &[Route {
        path: "/admin/v1/realmsx",
        ..REALM_ROOT
    }];
    assert!(matches!(check(ESCAPE), Err(ManifestError::Surface(_))));
    static TOKEN_WRITE: &[Route] = &[Route {
        verb: Verb::Post,
        ..PLATFORM_ROOT
    }];
    assert!(matches!(check(TOKEN_WRITE), Err(ManifestError::Surface(_))));
}
