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
        beside: Vec::new(),
    }
}

/// The actor of the domain's latest opening record: the root's Instance.
async fn an_actor(p: &Pdp) -> Value {
    let id = DomainId::from_bytes(p.domain.0);
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    access_store::authority::read_log(&p.w.db.app, &id, 0, head)
        .await
        .unwrap()
        .into_iter()
        .rev()
        .find_map(|r| {
            let e = RecordEnvelope::from_bytes(&r.envelope).unwrap();
            (e.header.kind == RecordKind::Opening).then(|| e.fields["actor"].value.clone())
        })
        .unwrap()
}

/// A faulty evaluator: commits, with the sequencer directly, an ALLOW on a holding of a Grant
/// the domain never issued. The record is sealed, chained and stored like any other; only
/// replay can tell. Its position.
pub(super) async fn faulty_allow(p: &Pdp) -> u64 {
    faulty(p, |_| Vec::new()).await
}

/// [`faulty_allow`] with the effects `effects` gives for the decision's position.
async fn faulty(p: &Pdp, effects: impl FnOnce(u64) -> Vec<Value>) -> u64 {
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let intent = Digest(access_crypto::random::bytes::<32>().unwrap());
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: Id(access_crypto::random::bytes::<16>().unwrap()),
        holder: p.party,
        since: 1,
    });
    faulty_as(p, (nonce, intent, basis), effects).await
}

/// An ALLOW a faulty evaluator records for the request `(nonce, intent, basis)` of the root.
async fn faulty_as(
    p: &Pdp,
    (nonce, intent, basis): (Vec<u8>, Digest, ExerciseBasis),
    effects: impl FnOnce(u64) -> Vec<Value>,
) -> u64 {
    let actor = an_actor(p).await;
    p.w.domains.release().await;
    let id = DomainId::from_bytes(p.domain.0);
    let tenant = access_store::authority::domain_tenant(&p.w.db.app, &id)
        .await
        .unwrap()
        .unwrap();
    // T6: the released domain's lease may still be live for a moment; wait for it to end
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut leader = loop {
        let log = PgLog::new(
            p.w.db.sequencer.clone(),
            p.domain,
            tenant,
            String::from("w4-faulty"),
            Duration::from_secs(5),
        );
        let key = EventKey::new(Secret::new(access_crypto::random::bytes::<32>().unwrap()));
        match Leader::acquire(log, p.domain, key).await {
            Ok(leader) => break leader,
            Err(access_authority_sequencer::SequencerError::Store(
                access_store::StoreError::LeaseHeld,
            )) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("{error:?}"),
        }
    };
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
    let at = access_store::authority::read_head(&p.w.db.app, &id)
        .await
        .unwrap()
        .pos
        + 2;
    let effects = effects(at);
    let mut fields = vec![
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
    ];
    if !effects.is_empty() {
        fields.push(("effects", Value::Array(effects)));
    }
    let decision = item(
        RecordKind::Decision,
        fields,
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
    let out = leader
        .commit(
            access_authority_sequencer::permit::WritePermit::for_tests(),
            now,
            &[opening, decision],
        )
        .await
        .unwrap();
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

fn stepper(p: &Pdp, label: &str) -> access_authority_sequencer::adapters::SocketSigner {
    let _ = p;
    access_authority_sequencer::adapters::SocketSigner::new(super::replica::signer_socket(label))
}

async fn live(p: &Pdp) -> Vec<access_store::authority::StateRow> {
    access_store::authority::state(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
        .await
        .unwrap()
}

/// Rewrites one live row, as a corrupted store would: the log is untouched.
async fn corrupt(p: &Pdp, key: &[u8]) {
    let id = DomainId::from_bytes(p.domain.0);
    let tenant = access_store::authority::domain_tenant(&p.w.db.app, &id)
        .await
        .unwrap()
        .unwrap();
    let rows: Vec<access_store::divergence::FoldedRow> = live(p)
        .await
        .into_iter()
        .map(|r| access_store::divergence::FoldedRow {
            value: if r.key == key {
                Some(
                    suiss_crypto::dcbor::encode(
                        &Value::Unsigned(7),
                        suiss_crypto::dcbor::Limits::CEILING,
                    )
                    .unwrap(),
                )
            } else {
                r.value
            },
            key: r.key,
            version: r.version,
        })
        .collect();
    access_store::divergence::rebuild_state(&p.w.db.sequencer, &id, tenant, &rows)
        .await
        .unwrap();
}

// TI-1, TI-16, TI-RT1, G33, RT9, FA-14, §16.5, OP-158 m.3 (i), Ek B 5756, 5835, 6011, 6015
#[tokio::test(flavor = "multi_thread")]
async fn a_fold_difference_stops_commits_until_the_log_rebuilds_the_live_state() {
    let label = "w4-fold";
    let p = pdp(label).await;
    for _ in 0..2 {
        let a = p
            .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
            .await;
        assert_eq!(a.status, StatusCode::OK);
    }
    let signer = stepper(&p, label);
    let mut replayers = std::collections::HashMap::new();
    let now = p.now().await;
    let clean = crate::divergence::step(
        &p.w.domains,
        (&p.w.db.app, &signer),
        &mut replayers,
        p.domain,
        now,
    )
    .await
    .unwrap();
    assert!(!clean.fold && clean.declared == 0, "{clean:?}");
    assert!(clean.replayed > 0);
    let before = live(&p).await;
    let key = before
        .iter()
        .find(|r| r.value.is_some() && r.version > 0)
        .unwrap()
        .key
        .clone();
    corrupt(&p, &key).await;
    let diff = access_authority_core::app::divergence::rebuild_diff(&p.w.db.app, p.domain)
        .await
        .unwrap();
    assert_eq!(diff.differing, vec![key.clone()]);
    // RT9
    let stopped = crate::divergence::step(
        &p.w.domains,
        (&p.w.db.app, &signer),
        &mut replayers,
        p.domain,
        now,
    )
    .await
    .unwrap();
    assert!(stopped.fold, "{stopped:?}");
    let notices = access_store::divergence::notices(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
        .await
        .unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(
        (notices[0].kind.as_str(), notices[0].source.as_str()),
        ("fold", "rebuild-diff")
    );
    assert!(!notices[0].resolved);
    let refused = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{:?}",
        refused.json()
    );
    assert!(
        access_authority_core::app::divergence::halted(&p.w.db.app, p.domain)
            .await
            .unwrap()
    );
    // TI-1, G33
    let changed =
        access_authority_core::app::divergence::rebuild(&p.w.db.app, &p.w.db.sequencer, p.domain)
            .await
            .unwrap();
    assert_eq!(changed, 1);
    assert_eq!(live(&p).await, before);
    access_authority_sequencer::adapters::fold_check(&p.w.db.sequencer, p.domain)
        .await
        .unwrap();
    assert!(
        !access_authority_core::app::divergence::halted(&p.w.db.app, p.domain)
            .await
            .unwrap()
    );
    let again = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.json());
    // TI-RT11, FA-14
    p.w.domains.release().await;
    checkpoint(&p, label).await;
    access_authority_core::app::divergence::commitments(
        &p.w.db.app,
        p.domain,
        p.w.domains.head(p.domain).await.unwrap().0,
    )
    .await
    .unwrap();
    p.w.domains.release().await;
    let size = access_store::authority::read_head(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
        .await
        .unwrap()
        .pos
        + 1;
    let mut forged =
        access_store::authority_checkpoint::latest(&p.w.db.app, &DomainId::from_bytes(p.domain.0))
            .await
            .unwrap()
            .unwrap();
    forged.size = size;
    forged.root = access_crypto::random::bytes::<32>().unwrap();
    forged.issued_at += 1;
    access_store::authority_checkpoint::append(
        &p.w.db.sequencer,
        &DomainId::from_bytes(p.domain.0),
        &forged,
    )
    .await
    .unwrap();
    assert!(matches!(
        access_authority_core::app::divergence::commitments(&p.w.db.app, p.domain, size - 1).await,
        Err(access_authority_core::CoreError::Protocol("commitment"))
    ));
    corrupt(&p, &key).await;
    assert!(matches!(
        access_authority_core::app::divergence::rebuild(&p.w.db.app, &p.w.db.sequencer, p.domain)
            .await,
        Err(access_authority_core::CoreError::Protocol("commitment"))
    ));
    let mut fresh = std::collections::HashMap::new();
    let refused = crate::divergence::step(
        &p.w.domains,
        (&p.w.db.app, &signer),
        &mut fresh,
        p.domain,
        now,
    )
    .await
    .unwrap();
    assert!(refused.fold, "{refused:?}");
    p.w.domains.release().await;
}

/// The stored state of the root's audit Grant, and a fresh Grant id.
async fn audit_state(p: &Pdp) -> (Id, Vec<u8>) {
    let id = DomainId::from_bytes(p.domain.0);
    let audit = meta::key(meta::kind::GRANT, &p.audit.grant);
    let stored = access_store::authority::state_of(&p.w.db.app, &id, std::slice::from_ref(&audit))
        .await
        .unwrap()
        .remove(0)
        .value
        .unwrap();
    (Id(access_crypto::random::bytes::<16>().unwrap()), stored)
}

/// The effect that issues `copy` with the audit Grant's content `stored` at position `at`: a
/// widening a faulty evaluator records.
fn grant_effect(copy: &Id, stored: &[u8], at: u64) -> Vec<Value> {
    let Value::Map(mut m) =
        suiss_crypto::dcbor::decode(stored, suiss_crypto::dcbor::Limits::CEILING).unwrap()
    else {
        panic!("a grant state is a map");
    };
    for (k, v) in &mut m {
        if *k == Value::text("since") {
            *v = Value::Unsigned(at);
        }
    }
    vec![Value::Array(vec![
        Value::Bytes(meta::key(meta::kind::GRANT, copy)),
        Value::Map(m),
    ])]
}

async fn commit_meta(p: &Pdp, nonce: &[u8], payload: meta::Payload) -> Result<u64, String> {
    let declared = access_identity_oauth::adapters::outbound::DeclaredTargets::default();
    let b = crate::bootstrap::Bootstrap {
        app: &p.w.db.app,
        router: &p.w.db.router,
        plane: &p.w.plane,
        realm_keys: &p.w.keyring,
        hsm: &p.w.keys,
        base: &p.w.base,
        declared: &declared,
        console: None,
    };
    b.commit_meta(p.domain, &p.root, nonce, payload, p.party)
        .await
        .map_err(|e| e.to_string())
}

/// The root's check of `access.read` on the audit stream on `basis`: whether it is allowed.
async fn reads(p: &Pdp, basis: ExerciseBasis) -> bool {
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let mut intent = super::replica::export_intent(p, &[]).await;
    intent.action = meta::core_action("read");
    let body = p
        .body(
            Mode::Check,
            &nonce,
            &intent,
            basis,
            super::super::authzen::PEP,
        )
        .await;
    let a = p.post("/access/v1/evaluation", &body).await;
    assert_eq!(a.status, StatusCode::OK, "{:?}", a.json());
    a.json()["decision"] == true
}

// TI-RT1, RT3, RT9, G32, SEC22, §9.15, §13.6, OP-158 m.3 (b), (i), Ek B 5756, 5801, 5878, 5943, 6027
#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "one divergence from its declaration through the quarantine and its lifting"
)]
async fn a_declared_divergence_stops_nothing_and_the_roots_quarantine_denies_what_it_widened() {
    use access_authority_core::restrict::patterns::{Widened, divergence_quarantine};
    let label = "w4-quarantine";
    let p = pdp(label).await;
    let id = DomainId::from_bytes(p.domain.0);
    let (copy, stored) = audit_state(&p).await;
    let mut since = 0;
    let pos = faulty(&p, |at| {
        since = at;
        grant_effect(&copy, &stored, at)
    })
    .await;
    assert_eq!(pos, since);
    let widened = ExerciseBasis::Holding(HoldingRef {
        grant: copy,
        holder: p.party,
        since,
    });
    assert!(reads(&p, widened).await, "the divergent record widened");
    assert!(reads(&p, ExerciseBasis::Holding(p.audit)).await);
    // G32
    let signer = stepper(&p, label);
    let mut replayers = std::collections::HashMap::new();
    let now = p.now().await;
    let found = crate::divergence::step(
        &p.w.domains,
        (&p.w.db.app, &signer),
        &mut replayers,
        p.domain,
        now,
    )
    .await
    .unwrap();
    assert!(!found.fold && found.declared == 1, "{found:?}");
    let notices = access_store::divergence::notices(&p.w.db.app, &id)
        .await
        .unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, "re-evaluation");
    assert_eq!(notices[0].first_position, pos);
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK, "commits go on");
    // RT3, Ek B 5801
    let policies = access_store::authority::state(&p.w.db.app, &id)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.key
                .starts_with(&meta::key(meta::kind::POLICY, &Id([0; 16]))[..9])
        })
        .count();
    assert_eq!(policies, 0);
    assert!(
        reads(&p, widened).await,
        "no quarantine until the root sets one"
    );
    // TI-RT1
    let record = access_store::authority::read_log(&p.w.db.app, &id, pos, pos)
        .await
        .unwrap()
        .remove(0);
    let effects =
        access_kernel::fold::effects(&RecordEnvelope::from_bytes(&record.envelope).unwrap())
            .unwrap();
    let mut w = Widened::default();
    w.add(&effects);
    let content = divergence_quarantine(&w).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    commit_meta(
        &p,
        &nonce,
        meta::Payload::PolicySet {
            policy: None,
            content,
            defaults: None,
        },
    )
    .await
    .unwrap();
    assert!(
        !reads(&p, widened).await,
        "a widening effect is denied under quarantine"
    );
    assert!(
        reads(&p, ExerciseBasis::Holding(p.audit)).await,
        "what the record did not widen is untouched"
    );
    // RT9
    let policy = meta::object_id(
        &meta::exercise_id(&p.domain, &nonce).unwrap(),
        meta::kind::POLICY,
        0,
    );
    let lift = access_crypto::random::bytes::<16>().unwrap();
    let _ = commit_meta(&p, &lift, meta::Payload::PolicyRetire { policy }).await;
    let row = access_store::authority::find_nonce(&p.w.db.app, &id, &lift)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.tier, Some(3), "{row:?}");
    p.w.domains.release().await;
}

// TI-RT4, TI-16, OP-142, OP-158 m.3 (i), Ek B 6135
#[tokio::test(flavor = "multi_thread")]
async fn a_cold_start_uses_only_a_verified_snapshot_and_otherwise_folds_from_genesis() {
    use access_authority_core::app::snapshot::state_bytes;
    use access_authority_core::app::{divergence, snapshot};
    let label = "w4-snapshot";
    let p = pdp(label).await;
    let id = DomainId::from_bytes(p.domain.0);
    for _ in 0..2 {
        let a = p
            .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
            .await;
        assert_eq!(a.status, StatusCode::OK);
    }
    p.w.domains.release().await;
    checkpoint(&p, label).await;
    let signer = stepper(&p, label);
    let now = p.now().await;
    let taken = snapshot::take(&p.w.db.app, &signer, p.domain, now)
        .await
        .unwrap();
    let head = access_store::authority::read_head(&p.w.db.app, &id)
        .await
        .unwrap()
        .pos;
    assert_eq!(taken.pos, head);
    assert!(
        access_store::mirror::checkpoint_exists(&p.w.db.app, &id, head + 1, &taken.root)
            .await
            .unwrap(),
        "the snapshot's root is a signed checkpoint's"
    );
    let origin = format!(
        "sha-256:{}",
        access_kernel::json::b64url_encode(&p.domain.0)
    );
    let key = suiss_crypto::note::Verifier::parse(&vkey(&p).await).unwrap();
    let (cp, _) =
        suiss_crypto::note::verify_checkpoint(&PureBackend, &taken.note, &origin, &key, &[])
            .unwrap_or_else(|e| panic!("{e:?}: {}", taken.note));
    assert_eq!((cp.size, cp.root), (head + 1, taken.root));
    let (state, from) = snapshot::cold_start(&p.w.db.app, p.domain, head)
        .await
        .unwrap();
    assert_eq!(from, snapshot::Start::Snapshot(head));
    let genesis = divergence::fold_to(&p.w.db.app, p.domain, None, 0, head)
        .await
        .unwrap();
    assert_eq!(state_bytes(&state).unwrap(), state_bytes(&genesis).unwrap());
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK);
    p.w.domains.release().await;
    let later = access_store::authority::read_head(&p.w.db.app, &id)
        .await
        .unwrap()
        .pos;
    let (state, from) = snapshot::cold_start(&p.w.db.app, p.domain, later)
        .await
        .unwrap();
    assert_eq!(from, snapshot::Start::Snapshot(head));
    let full = divergence::fold_to(&p.w.db.app, p.domain, None, 0, later)
        .await
        .unwrap();
    assert_eq!(state_bytes(&state).unwrap(), state_bytes(&full).unwrap());
    // TI-RT4
    let tenant = access_store::authority::domain_tenant(&p.w.db.app, &id)
        .await
        .unwrap()
        .unwrap();
    let forged = access_store::divergence::Snapshot {
        pos: later,
        root: access_crypto::random::bytes::<32>().unwrap(),
        ..taken.clone()
    };
    assert!(
        access_store::divergence::keep_snapshot(&p.w.db.app, &id, tenant, &forged)
            .await
            .unwrap()
    );
    let (state, from) = snapshot::cold_start(&p.w.db.app, p.domain, later)
        .await
        .unwrap();
    assert_eq!(from, snapshot::Start::Genesis);
    assert_eq!(state_bytes(&state).unwrap(), state_bytes(&full).unwrap());
}

// U13, G32, FM-16, F-9, SA-40, §13.3, §17.6.13, OP-158 m.3 (h), Ek B 5876, 5877, 6068
#[tokio::test(flavor = "multi_thread")]
async fn the_replica_operators_own_build_replays_its_copy_and_declares_what_does_not_replay() {
    use access_product_twin::replica::{Follows, Replica};
    let label = "w4-agent";
    let p = pdp(label).await;
    let router = super::replica::public(&p).merge(access_http::divergence::router(
        crate::divergence::Declarations {
            domains: p.w.domains.clone(),
            app: p.w.db.app.clone(),
        },
    ));
    let pep = super::replica::as_pep(router, super::super::authzen::PEP);
    let server = super::replica::serve(pep.clone()).await;
    let export = super::replica::start_mirror(&p, &pep).await;
    let root = std::env::temp_dir().join(format!("w4-agent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let follows = Follows {
        server,
        domain: p.domain.0,
        export,
        bindings: super::replica::bindings(&p).await,
    };
    let exe = bin("access-replica", "access-replica");
    let mut replica = Replica::start(&exe, &root, "acme-replica", &follows).unwrap();
    super::replica::declare(&p, label, &replica.name, replica.key).await;
    for _ in 0..2 {
        let a = p
            .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
            .await;
        assert_eq!(a.status, StatusCode::OK);
    }
    let (copy, stored) = audit_state(&p).await;
    let faulty = faulty(&p, |at| grant_effect(&copy, &stored, at)).await;
    let size = checkpoint(&p, label).await;
    assert_eq!(replica.acked(size, Duration::from_secs(60)), Some(size));
    replica.kill().unwrap();
    let out = Command::new(&exe)
        .args(["--replay", replica.config.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("divergent 1"), "{text}");
    assert!(text.contains("declared "), "{text}");
    let id = DomainId::from_bytes(p.domain.0);
    let notices = access_store::divergence::notices(&p.w.db.app, &id)
        .await
        .unwrap();
    assert_eq!(notices.len(), 1);
    let n = &notices[0];
    assert_eq!(
        (n.kind.as_str(), n.source.as_str(), n.declared_by.as_deref()),
        ("re-evaluation", "replica", Some("acme-replica"))
    );
    assert_eq!(n.first_position, faulty);
    let signed = SignedSet::verify(&PureBackend, &n.set).unwrap();
    assert_eq!(signed.key, replica.key);
    assert!(signed.set.evaluator.starts_with("access-replica/"));
    let kept = std::fs::read_dir(
        replica
            .state
            .join(access_kernel::json::b64url_encode(&p.domain.0))
            .join("divergence"),
    )
    .unwrap()
    .count();
    assert_eq!(kept, 1);
    // G32
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK);
    let again = Command::new(&exe)
        .args(["--replay", replica.config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(again.status.success());
    assert_eq!(
        access_store::divergence::notices(&p.w.db.app, &id)
            .await
            .unwrap()
            .len(),
        1
    );
    let _ = std::fs::remove_dir_all(&root);
    p.w.domains.release().await;
}

// INV-27, X25, §8.17.10.4, OP-158 m.3 (h), Ek B 5807
#[tokio::test(flavor = "multi_thread")]
async fn the_decision_lab_replays_a_recorded_decision_and_a_mismatch_is_an_evaluator_finding() {
    let label = "w4-lab";
    let p = pdp(label).await;
    let honest = p.allowed(Mode::Commit).await;
    let a = p.post("/access/v1/evaluation", &honest).await;
    assert_eq!(a.status, StatusCode::OK);
    let decoded = |body: &serde_json::Value| {
        access_http::adp::domain::decode(body.to_string().as_bytes(), 1 << 20).unwrap()
    };
    let incoming = |d: access_http::adp::domain::Decoded| access_authority_core::app::Incoming {
        request: d.request,
        ais: d.ais,
        pep: String::from(super::super::authzen::PEP),
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    let id = DomainId::from_bytes(p.domain.0);
    let nonce_of = |b: &serde_json::Value| {
        access_kernel::json::b64url_decode(b["context"]["nonce"].as_str().unwrap()).unwrap()
    };
    let record = access_store::authority::find_nonce(&p.w.db.app, &id, &nonce_of(&honest))
        .await
        .unwrap()
        .unwrap()
        .decision_pos;
    let replay =
        p.w.domains
            .lab_replay(&incoming(decoded(&honest)), record)
            .await
            .unwrap();
    assert!(replay.matches && replay.finding.is_none(), "{replay:?}");
    let body = p.denied(Mode::Commit).await;
    let d = decoded(&body);
    let intent = access_kernel::intent::intent_digest(&d.request.intent).unwrap();
    let pos = faulty_as(&p, (nonce_of(&body), intent, d.request.basis), |_| {
        Vec::new()
    })
    .await;
    let replay =
        p.w.domains
            .lab_replay(&incoming(decoded(&body)), pos)
            .await
            .unwrap();
    assert!(!replay.matches, "{replay:?}");
    assert_eq!(
        replay.finding,
        Some(access_authority_core::app::lab::EVALUATOR_MISMATCH)
    );
    assert!(replay.differing.contains(&String::from("outcome")));
    p.w.domains.release().await;
}
