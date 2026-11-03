//! The realm runtime against real PostgreSQL and a real identity signer on a Unix socket:
//! Host → realm through the router role, the stored issuer, and the realm's JWKS.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::{Discovery, Reply, StartupError};
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_identity_oauth::domain::metadata::Document;
use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
use access_identity_signer::service::Service;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::TenantTx;
use access_store::scope::DomainId;
use access_store::tenancy::{HostKind, add_hostname, create_realm, create_tenant, set_issuer};
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;
use tokio::net::UnixListener;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aio-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn signer(dir: &Path) -> PathBuf {
    let service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek", [7; 32])),
        DirVault::new(dir),
        Policy::REALM,
    )
    .unwrap();
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

async fn realm(db: &TestDb, seed: u8, slug: &str, style: IssuerStyle) -> String {
    let base = RealmBase::parse("https://id.test").unwrap();
    let issuer = base.issuer(slug, style).unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    if style == IssuerStyle::Subdomain {
        add_hostname(&mut tx, issuer.authority(), HostKind::Subdomain)
            .await
            .unwrap();
    }
    assert!(set_issuer(&mut tx, issuer.as_str()).await.unwrap());
    tx.commit().await.unwrap();
    issuer.as_str().to_owned()
}

fn metadata(reply: Reply) -> serde_json::Value {
    let Reply::Metadata(doc) = reply else {
        panic!("{reply:?}");
    };
    serde_json::from_str(&doc).unwrap()
}

// TN-10, §17.9.6, OP-132 m.3, CMP-22b, CR-19, OP-138: a subdomain realm and a path realm are
// served from their stored issuers, each with its own JWKS from the signer; unknown hosts get
// nothing; start-up checks pass with the signer up and fail without it
#[tokio::test]
async fn realms_are_served_from_their_rows_and_the_signer() {
    let db = fresh().await.unwrap();
    let dir = temp("realm");
    let socket = signer(&dir);
    let acme = realm(&db, 31, "acme", IssuerStyle::Subdomain).await;
    let beta = realm(&db, 32, "beta", IssuerStyle::Path).await;
    let base = RealmBase::parse("https://id.test").unwrap();
    let s = Discovery::new(
        PgDirectory::new(db.router.clone()),
        SignerKeys::new(socket.clone()),
    );
    let m = metadata(
        s.serve(Document::OpenIdConfiguration, "ACME.id.test", None)
            .await,
    );
    assert_eq!(m["issuer"], acme.as_str());
    let m = metadata(
        s.serve(Document::AuthorizationServer, "id.test", Some("beta"))
            .await,
    );
    assert_eq!(m["issuer"], beta.as_str());
    assert_eq!(m["jwks_uri"], "https://id.test/realms/beta/jwks.json");
    let Reply::Jwks(a) = s.serve(Document::Jwks, "acme.id.test", None).await else {
        panic!("jwks");
    };
    let Reply::Jwks(b) = s.serve(Document::Jwks, "id.test", Some("beta")).await else {
        panic!("jwks");
    };
    assert!(a.contains(r#""kty":"EC""#), "{a}");
    assert_ne!(a, b);
    assert_eq!(
        s.serve(Document::Jwks, "evil.test", None).await,
        Reply::NotFound
    );
    assert_eq!(
        s.serve(Document::Jwks, "id.test", Some("acme")).await,
        Reply::NotFound
    );
    assert_eq!(s.check(&base).await, Ok(2));
    let gone = Discovery::new(
        PgDirectory::new(db.router.clone()),
        SignerKeys::new(dir.join("missing.sock")),
    );
    assert_eq!(gone.check(&base).await, Err(StartupError::Signer));
    assert_eq!(
        gone.serve(Document::Jwks, "acme.id.test", None).await,
        Reply::Unavailable
    );
}
