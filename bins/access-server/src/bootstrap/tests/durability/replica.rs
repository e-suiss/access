//! A real `access-replica` process against this server's mirror, on real Postgres, the real
//! sequencer, `SoftHSM` and a real authority signer (OP-158 m.5, OP-153 m.3 (gg)): the run an
//! allowed audit export Exercise starts, the replica's verified, durable copy and its signed
//! acks, the fail-closed path when the replica is killed, its own files when it starts again,
//! the redaction it applies to its copy and its advisory reads.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use access_authority_core::app::mirror::{Replica as Declared, replicas};
use access_authority_sequencer::adapters::{PgHeads, SocketSigner};
use access_http::adp::adapters::{Discovery, Pep, router as adp_router};
use access_http::adp::app::Service;
use access_http::{Limits, harden};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, ParamValue};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::ResourceRef;
use access_kernel::verify::key_scope::DomainMetadata;
use access_product_twin::replica::{Follows, Replica};
use access_store::scope::DomainId;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value as Json;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer as _, SoftSigner};
use suiss_ledger::replica::mirror::{ReplicaAck, SignedReplicaAck};
use tower::ServiceExt as _;

use super::super::authzen::{PEP, Pdp, pdp};

/// How long a replica may take to ack what it was sent.
const ACK_WAIT: Duration = Duration::from_secs(60);

/// A binary of this target directory, built when it is missing.
pub(super) fn bin(package: &str, name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    let bin = dir.join(name);
    if !bin.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", package, "--bin", name])
            .status()
            .unwrap();
        assert!(status.success(), "{name} did not build");
    }
    assert!(bin.exists(), "no {name} at {}", bin.display());
    bin
}

pub(super) fn signer_socket(label: &str) -> PathBuf {
    std::env::temp_dir()
        .join(format!("abs-auth-{label}-{}", std::process::id()))
        .join("a.sock")
}

/// The public router this test serves on a TCP port: ADP and the mirror routes, hardened as
/// served, with every caller authenticated as [`PEP`] by the stand-in of the TLS layer.
pub(super) fn public(p: &Pdp) -> axum::Router {
    let limits = Limits::default();
    let routes = adp_router(
        Service::new(p.w.domains.clone(), limits.max_body_bytes),
        Discovery {
            issuer: String::from("https://access.test"),
        },
    )
    .merge(access_http::mirror::router(
        p.w.domains.clone(),
        limits.max_body_bytes,
    ));
    harden(routes, limits)
}

pub(super) fn as_pep(router: axum::Router, pep: &'static str) -> axum::Router {
    router.layer(axum::middleware::from_fn(
        move |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
            req.extensions_mut().insert(Pep(String::from(pep)));
            next.run(req).await
        },
    ))
}

pub(super) async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr.to_string()
}

pub(super) async fn call(router: &axum::Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let r = router.clone().oneshot(req).await.unwrap();
    let status = r.status();
    (
        status,
        to_bytes(r.into_body(), 1 << 26).await.unwrap().to_vec(),
    )
}

/// The root's `access.audit_export` intent on the domain's record with `params`.
pub(super) async fn export_intent(p: &Pdp, params: &[(&str, ParamValue)]) -> IntentEnvelope {
    let mut i = p
        .idp_intent(access_internal_api::idp::IdpAction::ClientRegister, "x")
        .await;
    i.action = meta::core_action("audit_export");
    i.resources = vec![ResourceRef {
        namespace: String::from("access.audit"),
        path: vec![String::from("authzen")],
        incarnation: 0,
    }];
    i.params = params
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect::<BTreeMap<_, _>>();
    i
}

/// Commits the root's export Exercise with `params` through ADP; its body.
pub(super) async fn commit_export(
    p: &Pdp,
    router: &axum::Router,
    params: &[(&str, ParamValue)],
) -> Json {
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let intent = export_intent(p, params).await;
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&p.domain));
    let body = p.body(Mode::Commit, &nonce, &intent, basis, PEP).await;
    let (status, answer) = call(
        router,
        Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    let v: Json = serde_json::from_slice(&answer).unwrap();
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true, "{v}");
    body
}

pub(super) fn domain_path(d: &Digest) -> String {
    b64url_encode(&d.0)
}

/// Starts the mirror run of the root's committed export Exercise; its id.
async fn start_mirror(p: &Pdp, router: &axum::Router) -> [u8; 32] {
    let body = commit_export(
        p,
        router,
        &[
            ("stream", ParamValue::Enum(String::from("mirror"))),
            ("disclosure", ParamValue::Enum(String::from("full"))),
        ],
    )
    .await;
    let (status, answer) = call(
        router,
        Request::post(format!(
            "/access/v1/domains/{}/exports",
            domain_path(&p.domain)
        ))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap(),
    )
    .await;
    let v: Json = serde_json::from_slice(&answer).unwrap();
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["kind"], "mirror");
    b64url_decode(v["export"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The domain's Ed25519 binding keys, from its binding-signed Domain Metadata.
async fn bindings(p: &Pdp) -> Vec<[u8; 32]> {
    let signed = p.w.domains.metadata(p.domain).await.unwrap();
    let msg = access_kernel::verify::cose::parse_sign1(&signed).unwrap();
    let m = DomainMetadata::from_bytes(msg.payload.as_deref().unwrap()).unwrap();
    m.binding
        .values()
        .map(|b| match b.key {
            PublicKey::Ed25519(k) => k,
            ref other => panic!("{other:?}"),
        })
        .collect()
}

/// Signs and keeps the checkpoint of the domain's head now, as the checkpointer does; its size.
pub(super) async fn checkpoint(p: &Pdp, label: &str) -> u64 {
    let now = access_authority_signer::adapters::now_ms();
    let row = crate::checkpoints::domain_checkpoint(
        (
            &PgHeads(p.w.db.app.clone()),
            &SocketSigner::new(signer_socket(label)),
        ),
        (&p.w.db.app, &p.w.db.sequencer),
        p.domain,
        now,
    )
    .await
    .unwrap();
    row.size
}

async fn stored_ack(p: &Pdp, name: &str) -> u64 {
    access_store::mirror::acked(
        &p.w.db.app,
        &DomainId::from_bytes(p.domain.0),
        &[String::from(name)],
    )
    .await
    .unwrap()[0]
        .1
}

fn declare(p: &Pdp, r: &Replica) {
    replicas().declare(
        p.domain,
        vec![Declared {
            name: r.name.clone(),
            key: r.key,
            operator: String::from("Acme Replica Ltd"),
            independent: true,
        }],
    );
}

pub(super) fn json(body: &str) -> Json {
    serde_json::from_str(body).unwrap()
}

// T21, CMP-21, TI-13, SEC23, P43, U22, N-11, OP-158 m.3 (f)
#[tokio::test(flavor = "multi_thread")]
async fn a_real_replica_follows_acks_fails_closed_when_killed_and_redacts_its_own_copy() {
    let label = "w3-replica";
    let p = pdp(label).await;
    let router = public(&p);
    let server = serve(as_pep(router.clone(), PEP)).await;
    let export = start_mirror(&p, &as_pep(router.clone(), PEP)).await;
    let root = std::env::temp_dir().join(format!("w3-replica-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let follows = Follows {
        server,
        domain: p.domain.0,
        export,
        bindings: bindings(&p).await,
    };
    let bin = bin("access-replica", "access-replica");
    let mut replica = Replica::start(&bin, &root, "acme-replica", &follows).unwrap();
    declare(&p, &replica);
    // TI-13
    let first = checkpoint(&p, label).await;
    assert_eq!(replica.acked(first, ACK_WAIT), Some(first));
    assert_eq!(stored_ack(&p, "acme-replica").await, first);
    assert!(replicas().acked(&p.domain) >= first);
    // P43
    let (status, head) = replica.read("/v1/head").unwrap();
    assert_eq!(status, 200, "{head}");
    let head = json(&head);
    assert_eq!(head["advisory"], true);
    assert_eq!(head["checkpoint"]["size"], first.to_string());
    // TI-RT11
    let signed =
        access_store::authority_checkpoint::latest(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(head["checkpoint"]["root"], b64url_encode(&signed.root));
    let (_, zero) = replica.read("/v1/records/0").unwrap();
    let zero = json(&zero);
    assert_eq!(zero["advisory"], true);
    assert!(zero["record"].is_string(), "{zero}");
    assert_eq!(zero.get("decision"), None);
    // SEC23
    replica.kill().unwrap();
    let _ = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    let second = checkpoint(&p, label).await;
    assert!(second > first);
    let id = DomainId::from_bytes(p.domain.0);
    let app = p.w.db.app.clone();
    let looked = replicas()
        .wait(
            p.domain,
            second,
            (Duration::from_secs(2), Duration::from_millis(100)),
            || {
                let app = app.clone();
                async move {
                    access_store::mirror::acked(&app, &id, &[String::from("acme-replica")])
                        .await
                        .map_or(0, |a| a[0].1)
                }
            },
        )
        .await;
    assert_eq!(looked, Err(first));
    replica.restart().unwrap();
    assert_eq!(replica.acked(second, ACK_WAIT), Some(second));
    assert_eq!(replica.kept_acks(p.domain.0).unwrap().len(), 2);
    // U22, N-11
    let report = replica.apply_redactions(&[1]).unwrap();
    assert_eq!(report.trim(), "applied 1");
    let (_, one) = replica.read("/v1/records/1").unwrap();
    let one = json(&one);
    assert_eq!(one["redacted"], true, "{one}");
    assert!(one.get("record").is_none());
    assert!(json(&replica.read("/v1/records/0").unwrap().1)["record"].is_string());
    let _ = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    let third = checkpoint(&p, label).await;
    assert_eq!(replica.acked(third, ACK_WAIT), Some(third));
    replica.kill().unwrap();
    let _ = std::fs::remove_dir_all(&root);
    p.w.domains.release().await;
}

fn signed_ack(
    key: &SoftSigner,
    domain: Digest,
    name: &str,
    (size, root): (u64, [u8; 32]),
) -> Vec<u8> {
    let ack = ReplicaAck {
        domain: domain.0,
        replica: String::from(name),
        size,
        root,
        at: access_authority_signer::adapters::now_ms(),
    };
    let sig = key.sign(&ack.message().unwrap()).unwrap();
    SignedReplicaAck {
        ack,
        sig: sig.try_into().unwrap(),
    }
    .to_bytes()
    .unwrap()
}

// TI-13, SEC23, G28
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_counts_only_under_the_declared_key_for_a_signed_checkpoint_and_a_run_reads_only_for_its_pep()
 {
    let label = "w3-ack";
    let p = pdp(label).await;
    let router = as_pep(public(&p), PEP);
    let export = start_mirror(&p, &router).await;
    let size = checkpoint(&p, label).await;
    let cp =
        access_store::authority_checkpoint::latest(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
            .await
            .unwrap()
            .unwrap();
    let (key, _) = SoftSigner::generate_ed25519().unwrap();
    let (other, _) = SoftSigner::generate_ed25519().unwrap();
    let PublicKey::Ed25519(pk) = key.public_key() else {
        panic!("ed25519");
    };
    let path = format!("/access/v1/domains/{}/mirror", domain_path(&p.domain));
    let post = |body: Vec<u8>| {
        Request::post(path.clone())
            .header("content-type", "application/cbor")
            .body(Body::from(body))
            .unwrap()
    };
    let code = |b: &[u8]| serde_json::from_slice::<Json>(b).unwrap()["code"].clone();
    let (s, b) = call(
        &router,
        post(signed_ack(&key, p.domain, "r1", (size, cp.root))),
    )
    .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::FORBIDDEN, Json::from("replica-unknown"))
    );
    replicas().declare(
        p.domain,
        vec![Declared {
            name: String::from("r1"),
            key: pk,
            operator: String::from("Acme Replica Ltd"),
            independent: true,
        }],
    );
    let (s, b) = call(
        &router,
        post(signed_ack(&other, p.domain, "r1", (size, cp.root))),
    )
    .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::FORBIDDEN, Json::from("replica-ack-signature"))
    );
    let mut wrong = cp.root;
    wrong[0] ^= 1;
    let (s, b) = call(
        &router,
        post(signed_ack(&key, p.domain, "r1", (size, wrong))),
    )
    .await;
    assert_eq!(
        (s, code(&b)),
        (StatusCode::FORBIDDEN, Json::from("replica-ack-checkpoint"))
    );
    assert_eq!(stored_ack(&p, "r1").await, 0);
    let (s, _) = call(
        &router,
        post(signed_ack(&key, p.domain, "r1", (size, cp.root))),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(stored_ack(&p, "r1").await, size);
    // G28
    let mirror = format!(
        "/access/v1/domains/{}/mirror?export={}&from=0",
        domain_path(&p.domain),
        b64url_encode(&export)
    );
    let elsewhere = as_pep(public(&p), "another-pep");
    let (s, b) = call(
        &elsewhere,
        Request::get(mirror.clone()).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&b)
    );
    let (s, b) = call(&router, Request::get(mirror).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let frames = suiss_ledger::replica::mirror::read_all(&b).unwrap();
    assert!(matches!(
        frames[0],
        suiss_ledger::replica::mirror::Frame::Record { position: 0, .. }
    ));
    p.w.domains.release().await;
}
