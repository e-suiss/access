//! OP-149 m.7, SSF 1.0 §7.1, §8, RFC 8936, RFC 6750: the realm's SSF transmitter over HTTP on
//! a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    reason = "test code with fakes of async ports; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};

use access_crypto::jose::JwsAlg;
use access_http::ssf::router;
use access_identity_events::adapters::{KekSealer, RealmKek};
use access_identity_events::app::Db;
use access_identity_events::app::ssf::Transmitter;
use access_identity_events::app::streams::Streams;
use access_identity_events::domain::stream::parse_stream;
use access_identity_oauth::adapters::oauth::OsRandom;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::dpop::{Clock, ClockUnavailable};
use access_identity_oauth::ports::oauth::TokenSigner;
use access_identity_oauth::ports::{Directory, RealmEntry, Unavailable};
use access_kernel::json::b64url_encode;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::create_settings;
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant, set_issuer};
use access_store::testing::fresh;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use suiss_crypto::envelope::{Kek, SoftKek};
use tower::ServiceExt;

const ISSUER: &str = "https://id.test/realms/shop";

struct One(Mutex<Option<RealmEntry>>);

impl Directory for One {
    async fn by_host(&self, _: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok(None)
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok(self.0.lock().unwrap().clone().filter(|e| e.slug == slug))
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(Vec::new())
    }
}

struct Kek1(Arc<SoftKek>);

impl RealmKek for Kek1 {
    fn kek(&self, _: TenantId, _: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

struct Clear;

impl TokenSigner for Clear {
    async fn sign(
        &self,
        _: RealmId,
        _: JwsAlg,
        _: &str,
        payload: &[u8],
        _: u64,
    ) -> Result<String, Unavailable> {
        Ok(format!("e30.{}.c2ln", b64url_encode(payload)))
    }

    async fn jwks(&self, _: RealmId) -> Result<String, Unavailable> {
        Ok(String::from("{}"))
    }
}

struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(1_793_750_400_000)
    }
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "id.test");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = if method == "POST" || method == "PATCH" {
        Body::from(
            r#"{"events_requested":["urn:suiss:access:event:party.disabled"],"status":"paused"}"#,
        )
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json, cache)
}

// OP-149 m.7, SSF §7.1, §8.1.1, RFC 8936 §2.4, RFC 6750
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one stream through its whole life")]
async fn the_transmitter_serves_metadata_streams_and_poll() {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let domain = DomainId::from_bytes([7; 32]);
    let genesis = access_store::authority::LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [7; 32],
        envelope: vec![0xa0],
    };
    access_store::authority::create_domain(
        &db.sequencer,
        &domain,
        *tenant.as_bytes(),
        &genesis,
        &[],
    )
    .await
    .unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let realm = create_realm(&mut t, &domain, "shop", "pool-default")
        .await
        .unwrap();
    t.enter_realm(realm).await.unwrap();
    assert!(set_issuer(&mut t, ISSUER).await.unwrap());
    create_settings(&mut t).await.unwrap();
    t.commit().await.unwrap();

    let pools = Db {
        app: db.app.clone(),
        reader: db.reader.clone(),
        ids: Arc::new(access_crypto::opaque_id::IdKey::new(
            access_crypto::secret::Secret::new([4; 32]),
        )),
    };
    let sealer = || KekSealer(Kek1(Arc::new(SoftKek::new("k1", [9; 32]))));
    let created = Streams::new(pools.clone(), sealer(), OsRandom)
        .create(
            tenant,
            realm,
            &parse_stream(br#"{"delivery":{"method":"urn:ietf:rfc:8936"},"aud":"work","events_requested":["urn:suiss:access:event:party.compromised"]}"#).unwrap(),
        )
        .await
        .unwrap();
    let token = created.token.unwrap();
    let directory = One(Mutex::new(Some(RealmEntry {
        tenant,
        realm,
        slug: String::from("shop"),
        issuer: Issuer::parse(ISSUER).unwrap(),
    })));
    let app = router(Transmitter::new(
        directory,
        Streams::new(pools, sealer(), OsRandom),
        Clear,
        Fixed,
    ));

    let (status, meta, _) = call(
        &app,
        "GET",
        "/.well-known/ssf-configuration/realms/shop",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(meta["issuer"], ISSUER);
    assert_eq!(
        meta["configuration_endpoint"],
        format!("{ISSUER}/ssf/streams")
    );
    let (status, same, _) = call(
        &app,
        "GET",
        "/realms/shop/.well-known/ssf-configuration",
        None,
    )
    .await;
    assert_eq!((status, &same), (StatusCode::OK, &meta));
    assert_eq!(
        call(
            &app,
            "GET",
            "/realms/other/.well-known/ssf-configuration",
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let (status, stream, cache) = call(&app, "GET", "/realms/shop/ssf/streams", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(
        stream["delivery"]["endpoint_url"],
        format!("{ISSUER}/ssf/poll")
    );
    assert_eq!(
        call(&app, "GET", "/realms/shop/ssf/streams", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/realms/shop/ssf/streams", Some("other"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let (status, polled, _) = call(&app, "POST", "/realms/shop/ssf/poll", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(polled["moreAvailable"], false);
    assert_eq!(
        call(&app, "POST", "/realms/shop/ssf/poll", None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let (status, updated, _) = call(&app, "PATCH", "/realms/shop/ssf/streams", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["status"], "paused");
    assert_eq!(
        updated["events_requested"][0],
        "urn:suiss:access:event:party.disabled"
    );

    // SSF §8.1.2, §8.1.4
    assert_eq!(same["status_endpoint"], format!("{ISSUER}/ssf/status"));
    assert_eq!(
        meta["verification_endpoint"],
        format!("{ISSUER}/ssf/verify")
    );
    let id = updated["stream_id"].as_str().unwrap();
    let (status, state, cache) = call(
        &app,
        "GET",
        &format!("/realms/shop/ssf/status?stream_id={id}"),
        Some(&token),
    )
    .await;
    assert_eq!(
        (status, cache.as_deref()),
        (StatusCode::OK, Some("no-store"))
    );
    assert_eq!(
        state,
        serde_json::json!({ "stream_id": id, "status": "paused" })
    );
    for (method, path, token, want) in [
        (
            "GET",
            "/realms/shop/ssf/status",
            Some(token.as_str()),
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            "/realms/shop/ssf/status",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/realms/shop/ssf/verify",
            Some(token.as_str()),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/realms/shop/ssf/verify",
            None,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        assert_eq!(
            call(&app, method, path, token).await.0,
            want,
            "{method} {path}"
        );
    }

    assert_eq!(
        call(&app, "DELETE", "/realms/shop/ssf/streams", Some(&token))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "GET", "/realms/shop/ssf/streams", Some(&token))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
