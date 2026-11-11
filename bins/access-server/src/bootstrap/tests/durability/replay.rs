//! Replay, rebuild-diff, divergence and quarantine on the real router, sequencer, store and
//! signer (OP-158 m.3 (h), (i), m.5, OP-153 m.3 (gg)): a streamed export verifies with the open
//! `access-verify` alone, a decision a faulty evaluator recorded is found and comes out as a
//! signed divergence set, and a redacted export declares digest coverage.

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

use access_authority_sequencer::adapters::PgLog;
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::domain::{Draft, Item, NonceUse};
use access_crypto::event_id::EventKey;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::ParamValue;
use access_kernel::meta::{self, ExerciseBasis, HoldingRef};
use access_kernel::model::Id;
use access_kernel::record::{Opened, RecordEnvelope, RecordKind};
use access_store::scope::DomainId;
use access_verifier::replay::{Kind, SignedSet};
use axum::http::StatusCode;
use suiss_crypto::dcbor::Value;
use suiss_crypto::secret::Secret;
use suiss_crypto::sig::PureBackend;

use super::super::authzen::{Pdp, pdp};
use super::checkpoint::log_vkey;
use super::export::{routes, start};
use super::replica::{bin, checkpoint, commit_export};

fn opened(fields: Vec<(&str, Value)>) -> BTreeMap<String, Opened> {
    fields
        .into_iter()
        .map(|(k, value)| {
            (
                k.to_owned(),
                Opened {
                    value,
                    salt: access_crypto::random::bytes::<32>().unwrap(),
                },
            )
        })
        .collect()
}

fn item(kind: RecordKind, fields: Vec<(&str, Value)>, nonce: Option<NonceUse>) -> Item {
    Item {
        draft: Draft {
            kind,
            fields: opened(fields),
        },
        nonce,
        events: Vec::new(),
        proofs: Vec::new(),
        reads: Vec::new(),
        writes: Vec::new(),
        draws: Vec::new(),
        single_use: Vec::new(),
    }
}

/// The first committed opening record of the domain: its actor.
async fn an_actor(p: &Pdp) -> Value {
    let id = DomainId::from_bytes(p.domain.0);
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    for r in access_store::authority::read_log(&p.w.db.app, &id, 0, head)
        .await
        .unwrap()
    {
        let e = RecordEnvelope::from_bytes(&r.envelope).unwrap();
        if e.header.kind == RecordKind::Opening {
            return e.fields["actor"].value.clone();
        }
    }
    panic!("no opening");
}

/// A faulty evaluator: commits, with the sequencer directly, an ALLOW on a holding of a Grant
/// the domain never issued. The record is sealed, chained and stored like any other; only
/// replay can tell. Its position.
pub(super) async fn faulty_allow(p: &Pdp) -> u64 {
    let actor = an_actor(p).await;
    p.w.domains.release().await;
    let id = DomainId::from_bytes(p.domain.0);
    let tenant = access_store::authority::domain_tenant(&p.w.db.app, &id)
        .await
        .unwrap()
        .unwrap();
    let log = PgLog::new(
        p.w.db.sequencer.clone(),
        p.domain,
        tenant,
        String::from("w4-faulty"),
        Duration::from_secs(5),
    );
    let key = EventKey::new(Secret::new(access_crypto::random::bytes::<32>().unwrap()));
    let mut leader = Leader::acquire(log, p.domain, key).await.unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let intent = Digest(access_crypto::random::bytes::<32>().unwrap());
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: Id(access_crypto::random::bytes::<16>().unwrap()),
        holder: p.party,
        since: 1,
    });
    let opening = item(
        RecordKind::Opening,
        vec![
            ("nonce", Value::Bytes(nonce.clone())),
            ("actor", actor.clone()),
            ("basis", meta::basis_value(&basis)),
            ("capacity", meta::capacity_value(Capacity::Own)),
            ("intent", intent.to_value()),
        ],
        None,
    );
    let decision = item(
        RecordKind::Decision,
        vec![
            (
                "outcome",
                Value::Map(vec![(Value::text("outcome"), Value::text("allow"))]),
            ),
            (
                "state_basis",
                Value::Map(vec![
                    (Value::text("at"), Value::Unsigned(0)),
                    (Value::text("reads"), Value::Array(Vec::new())),
                ]),
            ),
            (
                "versions",
                Value::Map(vec![
                    (Value::text("core"), Value::Unsigned(1)),
                    (Value::text("meta_schema"), Value::Unsigned(1)),
                ]),
            ),
            ("nonce", Value::Bytes(nonce.clone())),
            ("intent", intent.to_value()),
        ],
        Some(NonceUse {
            nonce,
            actor: match actor {
                Value::Bytes(b) => b,
                _ => b"anonymous".to_vec(),
            },
            intent_digest: intent.0,
            outcome: String::from("allow"),
            render_digest: None,
            tier: Some(1),
        }),
    );
    let now = p.now().await;
    let out = leader.commit(now, &[opening, decision]).await.unwrap();
    leader.release().await.unwrap();
    let access_authority_sequencer::domain::Outcome::Appended(at) = out else {
        panic!("{out:?}");
    };
    at[1]
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin("esuiss-access-verify", "access-verify"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn line<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} in {text}"))
}

/// The domain's log vkey, from its latest stored checkpoint.
pub(super) async fn vkey(p: &Pdp) -> String {
    let row =
        access_store::authority_checkpoint::latest(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
            .await
            .unwrap()
            .unwrap();
    let origin = format!(
        "sha-256:{}",
        access_kernel::json::b64url_encode(&p.domain.0)
    );
    log_vkey(&origin, &row.excerpt)
}

/// A fresh Ed25519 key in a PKCS #8 file of `dir`.
pub(super) fn key_file(dir: &Path) -> PathBuf {
    let (_, doc) = suiss_crypto::signer::SoftSigner::generate_ed25519().unwrap();
    write(dir, "replayer.p8", doc.expose())
}

// INV-27, PI-6, U13, T34, CMP-17, TI-RT1, G32, OP-158 m.3 (h), Ek B 5811, 5874, 5876
#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "one export from a faulty provider through the open verifier"
)]
async fn an_export_verifies_without_suiss_and_a_decision_a_faulty_evaluator_recorded_is_found() {
    let label = "w4-verify";
    let p = pdp(label).await;
    let router = routes(&p, 4);
    for _ in 0..3 {
        let a = p
            .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
            .await;
        assert_eq!(a.status, StatusCode::OK);
    }
    let d = p
        .post("/access/v1/evaluation", &p.denied(Mode::Commit).await)
        .await;
    assert_eq!(d.status, StatusCode::OK);
    let faulty = faulty_allow(&p).await;
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK);
    checkpoint(&p, label).await;
    let body = commit_export(
        &p,
        &router,
        &[("disclosure", ParamValue::Enum(String::from("full")))],
    )
    .await;
    let (status, package, _) = start(&p, &router, &body).await;
    assert_eq!(status, StatusCode::OK);
    let dir = std::env::temp_dir().join(format!("w4-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = write(&dir, "package.cbor", &package);
    let log = vkey(&p).await;
    let key = key_file(&dir);
    let set = dir.join("set.cbor");
    let now = p.now().await.to_string();
    let (code, text) = run(&[
        "export",
        "--package",
        file.to_str().unwrap(),
        "--log",
        &log,
        "--now",
        &now,
        "--sign",
        key.to_str().unwrap(),
        "--out",
        set.to_str().unwrap(),
    ]);
    assert_eq!(code, 3, "{text}");
    assert!(text.starts_with("diverged\n"), "{text}");
    assert_eq!(line(&text, "replay_coverage"), "full", "{text}");
    assert_eq!(line(&text, "divergent"), "1", "{text}");
    assert!(
        line(&text, "items").starts_with(&format!("{faulty}:re-evaluation:basis-not-live:")),
        "{text}"
    );
    assert!(line(&text, "checkpoints").parse::<u64>().unwrap() >= 1);
    let decisions: u64 = line(&text, "decisions").parse().unwrap();
    assert_eq!(line(&text, "reevaluated"), decisions.to_string());
    // G32
    let signed = SignedSet::verify(&PureBackend, &std::fs::read(&set).unwrap()).unwrap();
    assert_eq!(signed.set.domain, p.domain);
    assert_eq!(signed.set.items.len(), 1);
    assert_eq!(signed.set.items[0].position, faulty);
    assert_eq!(signed.set.items[0].kind, Kind::ReEvaluation);
    assert!(signed.set.evaluator.starts_with("access-verify/"));
    // TI-19, INV-27
    let mut forged = package.clone();
    let at = forged.len() / 2;
    forged[at] ^= 0x01;
    let forged = write(&dir, "forged.cbor", &forged);
    let (code, text) = run(&[
        "export",
        "--package",
        forged.to_str().unwrap(),
        "--log",
        &log,
        "--now",
        &now,
    ]);
    assert_eq!(code, 1, "{text}");
    assert!(text.starts_with("reject: "), "{text}");
    // T19, Ek B 5875
    let redacted = commit_export(&p, &router, &[]).await;
    let (status, digest, _) = start(&p, &router, &redacted).await;
    assert_eq!(status, StatusCode::OK);
    let file = write(&dir, "digest.cbor", &digest);
    let (code, text) = run(&[
        "export",
        "--package",
        file.to_str().unwrap(),
        "--log",
        &log,
        "--now",
        &now,
    ]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(line(&text, "replay_coverage"), "digest", "{text}");
    assert_eq!(line(&text, "reevaluated"), "0", "{text}");
    assert_eq!(line(&text, "divergent"), "0", "{text}");
    p.w.domains.release().await;
    let _ = std::fs::remove_dir_all(&dir);
}
