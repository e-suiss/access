//! The authorization server over HTTP: routes at the host root and under a path issuer,
//! form-only bodies, `no-store`, and `503 + Retry-After` when the realm's rows cannot be read.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    reason = "test code with fakes of async ports; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::sync::Arc;

use access_crypto::dpop::{NonceRing, Role};
use access_http::oauth::router;
use access_identity_oauth::adapters::SignerKeys;
use access_identity_oauth::adapters::oauth::{HostedPages, OsRandom, PgOAuthTx};
use access_identity_oauth::app::oauth::{Env, OAuth};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::dpop::{CacheUnavailable, Clock, ClockUnavailable, ReplayCache};
use access_identity_oauth::ports::oauth::{ClientKeys, OAuthDb};
use access_identity_oauth::ports::{Directory, RealmEntry, Unavailable};
use access_store::identity::{RealmId, TenantId};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

struct Rows;

fn entry(n: u8, slug: &str, issuer: &str) -> RealmEntry {
    RealmEntry {
        tenant: TenantId::from_bytes([n; 16]),
        realm: RealmId::from_bytes([n; 16]),
        slug: slug.to_owned(),
        issuer: Issuer::parse(issuer).unwrap(),
    }
}

impl Directory for Rows {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((host == "acme.id.test").then(|| entry(1, "acme", "https://acme.id.test")))
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((slug == "beta").then(|| entry(2, "beta", "https://id.test/realms/beta")))
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(Vec::new())
    }
}

struct NoKeys;

impl ClientKeys for NoKeys {
    async fn fetch(&self, _: &str) -> Result<Vec<u8>, Unavailable> {
        Err(Unavailable)
    }
}

struct Now;

impl Clock for Now {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(1_800_000_000_000)
    }
}

/// A database that does not answer.
struct NoDb;

impl OAuthDb for NoDb {
    type Tx = PgOAuthTx;

    async fn begin(&self, _: TenantId, _: RealmId) -> Result<PgOAuthTx, Unavailable> {
        Err(Unavailable)
    }

    async fn platform_product(&self, _: &str) -> Result<Option<String>, Unavailable> {
        Err(Unavailable)
    }
}

struct NoCache;

impl ReplayCache for NoCache {
    async fn first_use(&self, _: u32, _: [u8; 32]) -> Result<bool, CacheUnavailable> {
        Err(CacheUnavailable)
    }
}

/// Realm rows behind a database nobody answers at.
struct Down {
    signer: SignerKeys,
    profile: DpopProfile,
}

impl Env for Down {
    type Db = NoDb;
    type Signer = SignerKeys;
    type ClientKeys = NoKeys;
    type Pages = HostedPages;
    type Clock = Now;
    type Random = OsRandom;
    type Directory = Rows;
    type Replay = NoCache;
    type Projections = access_internal_api::projections::Unserved;

    fn db(&self) -> &NoDb {
        &NoDb
    }
    fn signer(&self) -> &SignerKeys {
        &self.signer
    }
    fn client_keys(&self) -> &NoKeys {
        &NoKeys
    }
    fn pages(&self) -> &HostedPages {
        &HostedPages
    }
    fn clock(&self) -> &Now {
        &Now
    }
    fn random(&self) -> &OsRandom {
        &OsRandom
    }
    fn directory(&self) -> &Rows {
        &Rows
    }
    fn replay(&self, _: TenantId, _: RealmId) -> NoCache {
        NoCache
    }
    fn nonces(&self, _: RealmId, _: Role) -> Option<Arc<NonceRing>> {
        None
    }
    fn dpop(&self) -> &DpopProfile {
        &self.profile
    }
    fn projections(&self) -> &access_internal_api::projections::Unserved {
        &access_internal_api::projections::Unserved
    }
}

fn app() -> axum::Router {
    router(OAuth::new(Down {
        signer: SignerKeys::new(PathBuf::from("/nonexistent/s.sock")),
        profile: DpopProfile::default(),
    }))
}

async fn send(req: Request<Body>) -> axum::response::Response {
    app().oneshot(req).await.unwrap()
}

// §11.4.5 #19, G50, EP-2, TN-10: the endpoints answer at the host root and under the path
// issuer; a body that is not a form is refused before anything is read; when the realm's rows
// cannot be read the answer is 503 with Retry-After and no-store, never invalid_grant; an
// unknown host gets 404
#[tokio::test]
async fn routes_forms_and_outages() {
    let json = send(
        Request::post("/token")
            .header(header::HOST, "acme.id.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(json.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json.headers()[header::CACHE_CONTROL], "no-store");
    for (path, host) in [
        ("/token", "acme.id.test"),
        ("/realms/beta/token", "id.test"),
        ("/par", "acme.id.test"),
        ("/revoke", "acme.id.test"),
    ] {
        let down = send(
            Request::post(path)
                .header(header::HOST, host)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=refresh_token&client_id=cli_x&refresh_token=x",
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(down.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(down.headers()[header::RETRY_AFTER], "1");
        assert_eq!(down.headers()[header::CACHE_CONTROL], "no-store");
    }
    let authorize = send(
        Request::get("/authorize?client_id=cli_x")
            .header(header::HOST, "acme.id.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(authorize.status(), StatusCode::SERVICE_UNAVAILABLE);
    // MD-8: introspection never answers 503
    let introspect = send(
        Request::post("/introspect")
            .header(header::HOST, "acme.id.test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("token=x"))
            .unwrap(),
    )
    .await;
    assert_eq!(introspect.status(), StatusCode::OK);
    let elsewhere = send(
        Request::get("/authorize")
            .header(header::HOST, "evil.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(elsewhere.status(), StatusCode::NOT_FOUND);
    let userinfo = send(
        Request::get("/userinfo")
            .header(header::HOST, "acme.id.test")
            .header(header::AUTHORIZATION, "Bearer abc")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(userinfo.status(), StatusCode::UNAUTHORIZED);
    assert!(
        userinfo.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("DPoP ")
    );
}
