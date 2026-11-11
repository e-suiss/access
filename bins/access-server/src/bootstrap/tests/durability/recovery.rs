//! Forced recovery between two `access-server` installs, R* and the post-recovery quarantine (OP-158 m.3 (m)). Lane W6 fills it.
//!
//! The recovering side plans from real processes: two `access-witness` processes cosign the
//! domain's checkpoints, the honest export package carries the records, and `access-cli domain
//! recover` reads both itself (FR-1…FR-3) and lists the lost suffix's revocations (PR-2).

use std::path::PathBuf;
use std::process::Command;

use access_authority_sequencer::adapters::{PgHeads, SocketSigner};
use access_authority_sequencer::witness::{Target, board};
use access_authority_signer::adapters::call as sign_call;
use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
use access_kernel::combinator::Mode;
use access_kernel::intent::ParamValue;
use access_kernel::json::b64url_encode;
use access_kernel::verify::key_scope::Declarations;
use access_product_twin::witness::Witness;
use access_store::authority::read_head;
use access_store::scope::DomainId;
use axum::http::StatusCode;
use suiss_ledger::checkpoint::cadence::Cadence;

use super::super::authzen::pdp;
use super::export::{routes, start};
use super::replica::{bin, bindings, commit_export, signer_socket};
use crate::checkpoints::domain_step;
use crate::checkpoints::publish::Publisher;

const PROVIDER: &str = "Suiss";
const INDEPENDENT: &str = "Example Witness Ltd";

fn now() -> u64 {
    access_authority_signer::adapters::now_ms()
}

fn declared(witnesses: &[(&Witness, &str, bool)]) -> Declarations {
    let mut d = access_authority_signer::domain::declared_default();
    for (w, operator, independent) in witnesses {
        let (name, rest) = w.vkey.split_once('+').unwrap();
        let b64 = rest.split_once('+').unwrap().1;
        let raw = suiss_crypto::note::base64_decode(b64).unwrap();
        let key: [u8; 32] = raw[1..].try_into().unwrap();
        d.witnesses
            .push(access_kernel::verify::key_scope::Witness::new(
                name.to_owned(),
                suiss_crypto::cose::PublicKey::Ed25519(key),
                suiss_crypto::cose::Algorithm::Ed25519,
                (*operator).to_owned(),
                *independent,
            ));
    }
    d
}

async fn evaluate(router: &axum::Router, body: &serde_json::Value) -> StatusCode {
    let r = tower::ServiceExt::oneshot(
        router.clone(),
        axum::http::Request::post("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap();
    r.status()
}

/// Runs `access-cli domain recover` with `args`; its exit status and the JSON it printed.
fn recover(args: &[String]) -> (bool, serde_json::Value, String) {
    let out = Command::new(bin("access-cli", "access-cli"))
        .arg("domain")
        .arg("recover")
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    (
        out.status.success(),
        serde_json::from_str(&text).unwrap_or_default(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// §13.6, §16.6 FR-0…FR-3, PR-2, SEC21, SEC22, U24, OP-158 m.3 (m), Ek B 5764, 6022, 6023, 6025
#[tokio::test(flavor = "multi_thread")]
async fn the_recovering_side_plans_from_real_witnesses_and_the_exported_records() {
    let label = "w6-rec";
    let p = pdp(label).await;
    let socket = signer_socket(label);
    let d = p.domain;
    let id = DomainId::from_bytes(d.0);
    let router = routes(&p, 512);
    for _ in 0..3 {
        assert_eq!(
            evaluate(&router, &p.allowed(Mode::Commit).await).await,
            StatusCode::OK
        );
    }
    let key = bindings(&p).await[0];
    let dir = std::env::temp_dir().join(format!("w6-rec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let witness_bin = bin("access-witness", "access-witness");
    let independent = Witness::start(
        &witness_bin,
        &dir,
        ("w6-independent", INDEPENDENT),
        d.0,
        key,
    )
    .unwrap();
    let mut own = Witness::start(&witness_bin, &dir, ("w6-own", PROVIDER), d.0, key).unwrap();
    let answer = sign_call(
        &socket,
        &SignRequest::Declare {
            domain: d,
            declared: Box::new(declared(&[
                (&independent, INDEPENDENT, true),
                (&own, PROVIDER, false),
            ])),
        },
    )
    .await
    .unwrap();
    assert_eq!(answer, SignResponse::Opened);
    let publisher = Publisher {
        targets: vec![
            Target::new(&independent.url, &independent.vkey, INDEPENDENT, PROVIDER).unwrap(),
            Target::new(&own.url, &own.vkey, PROVIDER, PROVIDER).unwrap(),
        ],
        sinks: Vec::new(),
    };
    let size = read_head(&p.w.db.app, &id).await.unwrap().pos + 1;
    board().want(d, size);
    let (row, out) = domain_step(
        (
            &PgHeads(p.w.db.app.clone()),
            &SocketSigner::new(socket.clone()),
            &publisher,
        ),
        (&p.w.db.app, &p.w.db.sequencer),
        (d, &mut Cadence::default()),
        now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((row.size, out.independent), (size, 1), "{out:?}");

    // FR-1: the honest provider's export, past the witnessed checkpoint
    let body = commit_export(
        &p,
        &router,
        &[("disclosure", ParamValue::Enum(String::from("full")))],
    )
    .await;
    let (status, package, _) = start(&p, &router, &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&package)
    );
    let file: PathBuf = dir.join("package.cbor");
    std::fs::write(&file, &package).unwrap();
    let named = [
        format!("{}={}", independent.url, independent.vkey),
        format!("{}={}", own.url, own.vkey),
    ];
    let args = |extra: &[&str]| {
        let mut a = vec![
            String::from("--domain"),
            b64url_encode(&d.0),
            String::from("--witness"),
            named[0].clone(),
            String::from("--witness"),
            named[1].clone(),
            String::from("--export"),
            file.display().to_string(),
        ];
        a.extend(extra.iter().map(|s| (*s).to_owned()));
        a
    };

    // FR-2, FR-3, arm (i): the replica reproduces the witnesses' highest checkpoint
    let (ok, plan, err) = recover(&args(&["--replica"]));
    assert!(ok, "{err}");
    assert_eq!(plan["n"], row.size.to_string(), "{plan}");
    assert_eq!(plan["cited_checkpoint"]["root"], b64url_encode(&row.root));
    assert_eq!(plan["arm"], "i");
    assert_eq!(plan["quorum"], "complete");

    // U24, FR-0: no replica, the recovery still plans (arm ii)
    let (ok, plan, err) = recover(&args(&[]));
    assert!(ok, "{err}");
    assert_eq!(
        (plan["arm"].as_str(), plan["n"].as_str()),
        (Some("ii"), Some(row.size.to_string().as_str()))
    );

    // FR-2: a witness that does not answer leaves the quorum incomplete, never guessed
    own.kill().unwrap();
    let (ok, plan, err) = recover(&args(&["--replica", "--discover"]));
    assert!(ok, "{err}");
    assert_eq!(plan["quorum"], "incomplete");
    assert_eq!(plan["arm"], "ii");
    assert!(plan["lost"].is_array());
    assert!(
        plan["redo"]
            .as_str()
            .unwrap()
            .contains("own revoke Exercise")
    );
}
