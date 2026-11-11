#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_authority_core::status::adapters::{PgLists, SignerSocket, open_family};
use access_authority_core::status::{Publisher, list_uri, set_entries};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::status::CWT_CONTENT_TYPE;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, acquire_lease, commit_batch, create_domain,
};
use access_store::projections::{Family, revoke_family};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;

use super::*;

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 9];
const NOW: u64 = 10_000;
const API: &str = "https://api.example";

/// Appends one record to `d`, moving its head to `pos`.
async fn append(db: &TestDb, d: &DomainId, pos: u64) {
    let (lease, head) = acquire_lease(&db.sequencer, d, "a", Duration::from_secs(10))
        .await
        .unwrap();
    let leaf = [0x80 + u8::try_from(pos).unwrap(); 32];
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos,
            kind: "claim",
            recorded_at: NOW + pos * 1_000,
            leaf_hash: leaf,
            envelope: vec![0xa1, u8::try_from(pos).unwrap()],
        }],
        head: HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: NOW + pos * 1_000,
            frontier: vec![leaf],
        },
        nonces: vec![],
        outbox: vec![],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        beside: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, d, TENANT, &batch)
        .await
        .unwrap();
}

/// A domain whose head is at position 1.
async fn domain(db: &TestDb, seed: u8) -> Digest {
    let d = DomainId::from_bytes([seed; 32]);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: NOW,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, TENANT, &genesis, &[])
        .await
        .unwrap();
    append(db, &d, 1).await;
    Digest([seed; 32])
}

/// The in-process signer's clock: `NOW` until a test moves it.
static SIGNER_NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NOW);

fn signer_now() -> u64 {
    SIGNER_NOW.load(std::sync::atomic::Ordering::Relaxed)
}

struct SoftBinding;

impl access_authority_signer::ports::Bindings for SoftBinding {
    fn binding(
        &mut self,
        _: &Digest,
    ) -> Result<Box<dyn suiss_crypto::signer::Signer + Send>, suiss_crypto::signer::SignError> {
        static DOC: std::sync::OnceLock<suiss_crypto::secret::Secret<Vec<u8>>> =
            std::sync::OnceLock::new();
        let doc = DOC.get_or_init(|| {
            suiss_crypto::signer::SoftSigner::generate_ed25519()
                .unwrap()
                .1
        });
        Ok(Box::new(
            suiss_crypto::signer::SoftSigner::ed25519_from_pkcs8(doc)?,
        ))
    }
}

/// An in-process authority signer on a socket of its own, with `d`'s keyring open and its
/// first key active.
async fn start_signer(name: &str, d: Digest) -> std::path::PathBuf {
    use access_authority_signer::adapters::{DirVault, SealedFactory, call, serve};
    use access_authority_signer::protocol::{Request, Response};
    let dir = std::env::temp_dir().join(format!("access-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = suiss_crypto::rotation::Policy {
        publish_lead_ms: 0,
        ..suiss_crypto::rotation::Policy::AUTHORITY
    };
    let service = std::sync::Arc::new(std::sync::Mutex::new(
        access_authority_signer::service::Service::start(
            SealedFactory::new(suiss_crypto::envelope::SoftKek::new("kek", [4; 32])),
            SoftBinding,
            DirVault::new(&dir),
            policy,
            NOW,
        )
        .unwrap(),
    ));
    let socket = dir.join("signer.sock");
    let _ = std::fs::remove_file(&socket);
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&socket).unwrap(),
        std::sync::Arc::clone(&service),
        vec![uid],
        signer_now,
    ));
    let open = Request::Open(Box::new(access_authority_signer::domain::default_template(
        d,
    )));
    assert_eq!(call(&socket, &open).await.unwrap(), Response::Opened);
    for _ in 0..2 {
        service.lock().unwrap().tick(NOW, 1);
    }
    socket
}

async fn get(app: &Pool, d: Digest, if_none_match: Option<&str>) -> axum::response::Response {
    let path = format!(
        "/access/v1/status-lists/0?domain=sha-256:{}",
        b64url_encode(&d.0)
    );
    let mut req = Request::get(path);
    if let Some(tag) = if_none_match {
        req = req.header(header::IF_NONE_MATCH, tag);
    }
    routes(app.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

// OP-150 m.3 (a), (s), m.10 (a), (d), (e), T24, G43, PI-9
#[tokio::test]
async fn the_served_list_shows_a_revocation() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 41).await;
    let scope = DomainId::from_bytes(d.0);
    let socket = start_signer("served-status", d).await;
    assert_eq!(get(&db.app, d, None).await.status(), StatusCode::NOT_FOUND);

    let family = Family {
        family: [7; 16],
        client_id: String::from("cli_x"),
        holder: [4; 16],
        root_exercise: [7; 32],
        status: None,
        revoked_pos: None,
    };
    let entry = open_family(&db.sequencer, API, d, &family)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry, (list_uri(API, &d, 0), 0));
    let publisher = Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket),
    );
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let r = get(&db.app, d, None).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CONTENT_TYPE], CWT_CONTENT_TYPE);
    assert_eq!(r.headers()[header::ETAG], "\"1.0\"");
    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    assert_eq!(set_entries(&body), Some(0));

    assert!(
        revoke_family(&db.sequencer, &scope, &family.family, 1)
            .await
            .unwrap()
    );
    append(&db, &scope, 2).await;
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    assert_eq!(
        get(&db.app, d, Some("\"1.0\"")).await.status(),
        StatusCode::OK
    );
    let r = get(&db.app, d, None).await;
    assert_eq!(r.headers()[header::ETAG], "\"2.1\"");
    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    assert_eq!(set_entries(&body), Some(1));
    let payload = access_kernel::verify::cose::parse_sign1(&body)
        .unwrap()
        .payload
        .unwrap();
    let t = access_kernel::status::ListToken::from_bytes(&payload).unwrap();
    assert_eq!((t.as_of, t.iat), (2, (NOW + 2_000) / 1_000));
    assert_eq!(
        get(&db.app, d, Some("\"2.1\"")).await.status(),
        StatusCode::NOT_MODIFIED
    );
}

// E13, T16, §9.16, T24, OP-150 m.10 (d)
#[tokio::test]
async fn an_idle_domains_list_stays_fresh() {
    use access_authority_core::status::{HEARTBEAT_MS, TTL_S};
    let db = fresh().await.unwrap();
    let d = domain(&db, 43).await;
    let socket = start_signer("idle-status", d).await;
    let family = Family {
        family: [8; 16],
        client_id: String::from("cli_y"),
        holder: [5; 16],
        root_exercise: [8; 32],
        status: None,
        revoked_pos: None,
    };
    open_family(&db.sequencer, API, d, &family)
        .await
        .unwrap()
        .unwrap();
    let publisher = Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket),
    );
    let token = |body: &[u8]| {
        let payload = access_kernel::verify::cose::parse_sign1(body)
            .unwrap()
            .payload
            .unwrap();
        access_kernel::status::ListToken::from_bytes(&payload).unwrap()
    };
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let first = to_bytes(get(&db.app, d, None).await.into_body(), 1 << 20)
        .await
        .unwrap();
    let first = token(&first);
    assert_eq!((first.as_of, first.iat), (1, (NOW + 1_000) / 1_000));
    let quiet = NOW + 1_000 + HEARTBEAT_MS;
    assert_eq!(publisher.publish(d, quiet - 1).await.unwrap().len(), 0);
    SIGNER_NOW.store(quiet, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(publisher.publish(d, quiet).await.unwrap().len(), 1);
    let r = get(&db.app, d, None).await;
    assert_eq!(r.headers()[header::ETAG], "\"1.1\"");
    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let again = token(&body);
    assert_eq!((again.as_of, again.iat), (1, quiet / 1_000));
    assert_eq!(again.lst, first.lst);
    assert!(quiet / 1_000 + 60 < first.iat + TTL_S + HEARTBEAT_MS / 1_000);
    assert_eq!(
        get(&db.app, d, Some("\"1.0\"")).await.status(),
        StatusCode::OK
    );
}
