//! OP-156 m.3 (q), OP-73: the connector's run history on real Postgres, in its own database.
//! A run is inserted once; no row changes.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_hr_connector::app::Report;
use access_hr_connector::store::Run;
use access_hr_connector::testing::store;

// OP-156 m.3 (q), OP-73
#[tokio::test]
async fn runs_are_recorded_once_newest_first() {
    let (s, _) = store().await.unwrap();
    assert!(s.healthy().await);
    let first = Run {
        run: [1; 16],
        connector: String::from("personio-1"),
        started_ms: 10,
        ended_ms: 20,
        outcome: String::from("done"),
        report: Report {
            read: 3,
            left_out: 1,
            pushed: 2,
            refused: 0,
            batches: 1,
        },
        reason: None,
    };
    let second = Run {
        run: [2; 16],
        started_ms: 30,
        ended_ms: 40,
        outcome: String::from("failed"),
        report: Report::default(),
        reason: Some(String::from("unreachable")),
        ..first.clone()
    };
    s.record(&first).await.unwrap();
    s.record(&second).await.unwrap();
    assert!(s.record(&first).await.is_err());
    let runs = s.runs("personio-1", 10).await.unwrap();
    assert_eq!(runs, vec![second.clone(), first.clone()]);
    assert_eq!(s.run("personio-1", [1; 16]).await.unwrap(), Some(first));
    assert_eq!(s.run("other", [1; 16]).await.unwrap(), None);
}
