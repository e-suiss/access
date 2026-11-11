//! Failover, cell seal and acceptance, upgrade and restore on `scripts/pg-ha.sh` (OP-158 m.3 (n), (q), (r)).
//!
//! The restore drill runs on a real point-in-time restore of the replicated cell: a base backup
//! and the WAL archive of `scripts/pg-ha.sh`, replayed to a target before later writes. These
//! tests need the lane's cell (`ACCESS_PG_HA_PORT`, `ACCESS_PG_HA_DIR`) and run in the `pg-ha`
//! test group.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::process::Command;
use std::time::{Duration, Instant};

use access_store::testing::{
    archived_wal, attach_at, authority_events, clock_text, fresh_at, superuser, switch_wal,
};

use super::super::*;
use crate::drill::{self, Status};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/pg-ha.sh");

fn base_port() -> u16 {
    std::env::var("ACCESS_PG_HA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55_440)
}

fn url(port: u16) -> String {
    format!("postgres://postgres:local-only-not-a-secret@127.0.0.1:{port}/postgres")
}

/// Runs `scripts/pg-ha.sh` with `args`, off the runtime and bounded.
async fn sh(args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let shown = args.join(" ");
    let out = tokio::time::timeout(
        Duration::from_secs(240),
        tokio::task::spawn_blocking(move || Command::new("bash").arg(SCRIPT).args(&args).output()),
    )
    .await
    .unwrap_or_else(|_| panic!("pg-ha.sh {shown} did not finish"))
    .unwrap()
    .unwrap();
    assert!(
        out.status.success(),
        "pg-ha.sh {shown}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

async fn run_drill(
    w: &World,
    db: &TestDb,
    base: Option<&drill::Baseline>,
) -> (Option<drill::Baseline>, Option<drill::Report>) {
    let migrator = superuser(db).await.unwrap();
    let keys = w.keys.clone();
    let event_key =
        move |d: &Digest| access_authority_core::ports::Keys::event_key(&*keys, d).is_ok();
    let env = drill::Env {
        app: &db.app,
        router: &db.router,
        sequencer: &db.sequencer,
        migrator: Some(&migrator),
        realm_keys: &w.keyring,
        event_key: &event_key,
        cold: None,
        breakglass: None,
    };
    match base {
        None => {
            let now = server_time(&db.app).await.unwrap();
            (Some(drill::baseline(&env, now).await.unwrap()), None)
        }
        Some(b) => (None, Some(drill::restore(&env, b).await.unwrap())),
    }
}

// OP-57, §17.10.3, OP-158 m.3 (r), Ek B 6017, 5711, 6009
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the replicated cell of scripts/pg-ha.sh (OP-158 m.3 (n))"]
async fn pg_ha_op_57_the_restore_drill_runs_its_nine_items_on_a_point_in_time_restore() {
    sh(&["up"]).await;
    let db = fresh_at(&url(base_port())).await.unwrap();
    let name = db.name.clone();
    let (w, _) = World::open_on("drill-pitr", false, None, db);
    w.run(&plan()).await;
    sh(&["base"]).await;
    let (baseline, _) = run_drill(&w, &w.db, None).await;
    let baseline = baseline.unwrap();
    assert_eq!(
        baseline.kids.keys().map(String::as_str).collect::<Vec<_>>(),
        ["acme", "platform"]
    );
    assert!(baseline.kids.values().all(|k| !k.is_empty()));
    let target = clock_text(&w.db).await.unwrap();
    w.admin_realm("later").await;
    w.domains.release().await;
    let wal = switch_wal(&w.db).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let archived = archived_wal(&w.db).await.unwrap();
        if archived >= wal {
            break;
        }
        assert!(Instant::now() < deadline, "{wal} was not archived");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pitr = sh(&["pitr", &target, &(base_port() + 3).to_string()]).await;
    let restored = attach_at(&pitr, &name).await.unwrap();
    let (_, report) = run_drill(&w, &restored, Some(&baseline)).await;
    let report = report.unwrap();
    let statuses: Vec<(u8, Status)> = report.items.iter().map(|i| (i.n, i.status)).collect();
    assert_eq!(
        statuses,
        vec![
            (1, Status::Pass),
            (2, Status::Pass),
            (3, Status::Pass),
            (4, Status::Pass),
            (5, Status::NotRun),
            (6, Status::NotRun),
            (7, Status::Pass),
            (8, Status::Pass),
            (9, Status::NotRun),
        ],
        "{:#?}",
        report.items
    );
    assert!(report.passed);
    let target_row = format!("report:{}", report.digest);
    assert_eq!(
        authority_events(&restored, "drill.restore", Some(&target_row))
            .await
            .unwrap(),
        1
    );
    let (_, live) = run_drill(&w, &w.db, Some(&baseline)).await;
    let live = live.unwrap();
    assert!(!live.passed);
    assert_eq!(live.items[2].status, Status::Fail, "{:#?}", live.items);
    sh(&["down"]).await;
}
