//! The operator break-glass path end to end (OP-46, CMP-25, G63, OP-157 m.3 (j), (k), OP-153
//! m.3 (gg)): the real `access-breakglass` process, with no database reachable, verifies a 2-of-3
//! document and leaves signed directives; this server reads them and ends every session issued
//! before the floor and stands its leader down, writes one `operator.directive` row per
//! directive, and makes no authority record or decision.

#![allow(
    clippy::too_many_lines,
    reason = "test code; the walkthrough reads in order"
)]

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use access_authority_core::CoreError;
use access_crypto::breakglass::{Directive, Op, OperatorKey};
use access_store::scope::DomainId;
use axum::http::{Method, StatusCode};

use super::management::{console, now};
use super::recovery::{Page, Recording, account, hosted, session};
use crate::config::Breakglass;
use crate::directives::{Applied, Reader, tick};

/// The tool next to this test binary, built first when the run did not build it.
fn tool_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    let bin = profile.join("access-breakglass");
    if !bin.is_file() {
        let target = profile.parent().unwrap();
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--locked",
                "-p",
                "access-breakglass",
                "--target-dir",
            ])
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success());
    }
    bin
}

fn tool(args: &[&str]) -> Output {
    let out = Command::new(tool_path())
        .args(args)
        // G63
        .env("DATABASE_URL", "postgres://nobody@127.0.0.1:1/down")
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {out:?}");
    out
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn public(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .strip_prefix("ed25519 ")
        .unwrap()
        .to_owned()
}

/// A cell directory with three approvers, a directive key and an alarm hook.
fn cell(root: &Path) -> (PathBuf, PathBuf, Vec<PathBuf>, String) {
    let _ = std::fs::remove_dir_all(root);
    let dir = root.join("eu-1");
    let ops = root.join("ops");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&ops).unwrap();
    let mut keys = String::from("generation 1\nthreshold 2\n");
    let mut seeds = Vec::new();
    for i in 0..3 {
        let seed = root.join(format!("op{i}.seed"));
        let p = public(&tool(&["keygen", s(&seed)]));
        let _ = writeln!(keys, "ed25519 op{i} {p}");
        seeds.push(seed);
    }
    std::fs::write(dir.join("keys"), keys).unwrap();
    let directive = public(&tool(&["keygen", s(&dir.join("directive.key"))]));
    let alarm = root.join("alarm.sh");
    std::fs::write(
        &alarm,
        format!("#!/bin/sh\necho \"$@\" >> {}\n", s(&root.join("alarms"))),
    )
    .unwrap();
    std::fs::set_permissions(&alarm, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        dir.join("cell"),
        format!(
            "name eu-1\nops {}\nalarm {}\nsyslog udp:127.0.0.1:9\n",
            s(&ops),
            s(&alarm)
        ),
    )
    .unwrap();
    (dir, ops, seeds, directive)
}

// G63, OP-46, CMP-25, SI-22, OP-157 m.3 (j), (k), Ek B 5546, 5547, 5548, 5551, 5608
#[tokio::test(flavor = "multi_thread")]
async fn g63_operator_directives_end_sessions_and_stand_the_leader_down_without_a_decision() {
    let c = Box::pin(console("op-breakglass", false)).await;
    let app = hosted(&c, Recording::default());
    let mia = account(&c, "mia@example.com", true).await;
    let mut before = Page::default();
    before.jar.insert(
        String::from("__Host-access-session"),
        session(&c, mia).await,
    );
    let path = "/v1/account/recovery-contacts";
    assert_eq!(
        before.call(&app, &Method::GET, path, None).await.status,
        StatusCode::OK
    );
    c.w.domains.take_over(c.domain).await.unwrap();
    assert!(c.w.domains.led().contains(&c.domain));
    let id = DomainId::from_bytes(c.domain.0);
    let head = access_store::authority::read_head(&c.w.db.sequencer, &id)
        .await
        .unwrap();

    let root = std::env::temp_dir().join(format!("abs-breakglass-{}", std::process::id()));
    let (dir, ops, seeds, directive_key) = cell(&root);
    let doc = root.join("incident.cbor");
    tool(&[
        "document",
        "eu-1",
        "epoch.floor,leader.unhealthy",
        "15",
        s(&doc),
    ]);
    for i in [0, 2] {
        tool(&["approve", s(&doc), &format!("op{i}"), s(&seeds[i])]);
    }
    let run = tool(&["run", s(&dir), s(&doc)]);
    assert!(String::from_utf8_lossy(&run.stdout).contains("directive"));
    let (stranger, _) = OperatorKey::generate().unwrap();
    let forged = Directive {
        cell: String::from("eu-1"),
        seq: 99,
        op: Op::LeaderHealthy,
        at_ms: now(),
        document: [1; 32],
    }
    .sign(&stranger)
    .unwrap();
    std::fs::write(ops.join("directives/forged.cbor"), forged).unwrap();

    let reader = Reader::new(&Breakglass {
        cell: String::from("eu-1"),
        directives: ops.join("directives"),
        directive_key: directive_key.clone(),
    })
    .unwrap();
    let mut applied = Applied::default();
    let state = tick(
        &reader,
        &c.w.domains,
        &c.w.db.app,
        &c.w.db.router,
        &mut applied,
    )
    .await;
    assert!(state.leader_unhealthy && state.epoch_floor_ms.is_some());
    assert_eq!(reader.read().1, 1);

    // MD-7, TN-50
    assert_eq!(
        before.call(&app, &Method::GET, path, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    // TI-2
    assert!(matches!(
        c.w.domains.take_over(c.domain).await,
        Err(CoreError::Unavailable("leader-unhealthy"))
    ));
    let (other, _) = c.w.other_process("after-breakglass");
    other.take_over(c.domain).await.unwrap();
    let fenced = access_store::authority::read_head(&c.w.db.sequencer, &id)
        .await
        .unwrap();
    // G63, SI-22
    assert_eq!(fenced.pos, head.pos);
    assert_eq!(fenced.leaf_hash, head.leaf_hash);
    assert!(fenced.epoch > head.epoch);
    other.release().await;

    let mut after = Page::default();
    after.jar.insert(
        String::from("__Host-access-session"),
        session(&c, mia).await,
    );
    tick(
        &reader,
        &c.w.domains,
        &c.w.db.app,
        &c.w.db.router,
        &mut applied,
    )
    .await;
    assert_eq!(
        after.call(&app, &Method::GET, path, None).await.status,
        StatusCode::OK
    );

    // OP-157 m.3 (k), SA-51, TI-18
    let rows = access_store::operational::operational_rows(&c.w.db.checkpointer, 1000)
        .await
        .unwrap();
    let directed: Vec<_> = rows
        .iter()
        .filter(|r| r.event_type == "operator.directive")
        .collect();
    assert_eq!(
        directed
            .iter()
            .map(|r| r.reason.as_str())
            .collect::<Vec<_>>(),
        ["epoch.floor", "leader.unhealthy"]
    );
    assert!(directed.iter().all(|r| r.actor == "operator:eu-1"
        && r.tenant.is_none()
        && r.domain.is_none()
        && r.correlation.len() == 64));
    let alarms = std::fs::read_to_string(root.join("alarms")).unwrap();
    assert!(alarms.starts_with("used eu-1 "), "{alarms}");
}

// SEC19, SA-51, OP-157 m.3 (k), Ek B 5551
#[tokio::test(flavor = "multi_thread")]
async fn sec19_operator_database_sessions_are_recorded_once() {
    let db = access_store::testing::fresh().await.unwrap();
    let mut seen = std::collections::HashSet::new();
    let role = "access_test_app";
    assert!(crate::directives::sessions_tick(&db.app, role, &mut seen).await >= 1);
    crate::directives::sessions_tick(&db.app, role, &mut seen).await;
    let rows = access_store::operational::operational_rows(&db.checkpointer, 1000)
        .await
        .unwrap();
    let sessions: Vec<_> = rows
        .iter()
        .filter(|r| r.event_type == "operator.db_session")
        .collect();
    let backends: std::collections::BTreeSet<&str> =
        sessions.iter().map(|r| r.correlation.as_str()).collect();
    assert_ne!(sessions.len(), 0);
    assert_eq!(backends.len(), sessions.len());
    assert!(
        sessions
            .iter()
            .all(|r| r.actor == "db:access_test_app" && r.target.starts_with("backend:"))
    );
}
