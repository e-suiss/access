//! SL2 risk at sign-in (§12.2.4, TN-46, IDP-39, §4.4, MD-8, CI-2) on the real flow.

use std::sync::Arc;
use std::time::Duration;

use access_identity_risk::app::settings::{CANARY_ACTION, apply_mode, mark_canary};
use access_identity_risk::domain::geo::{GeoAnswer, Place, Point};
use access_identity_risk::domain::mode::{PROTECTION_MODE_ACTION, ProtectionMode};
use access_identity_risk::ports::{GeoResolver, GeoStatus};
use access_store::authority::{CommitBatch, HeadRow, NonceRow, acquire_lease, commit_batch};
use access_store::idp::{Bound, Decision, bind};

use super::*;

/// 10.0.0.1 is in Istanbul, 10.0.0.2 in New York, both AS 64500; nothing else is known.
struct Atlas;

impl GeoResolver for Atlas {
    fn locate(&self, ip: IpAddr) -> GeoAnswer {
        let at = |lat, lon| Place {
            country: None,
            asn: Some(64_500),
            point: Point::from_degrees(lat, lon),
        };
        match ip {
            IpAddr::V4(v4) if v4.octets() == [10, 0, 0, 1] => GeoAnswer::Found(at(41.0, 29.0)),
            IpAddr::V4(v4) if v4.octets() == [10, 0, 0, 2] => GeoAnswer::Found(at(40.7, -74.0)),
            _ => GeoAnswer::Unavailable,
        }
    }

    fn status(&self) -> GeoStatus {
        GeoStatus::Ready {
            database_type: String::from("test"),
            build_epoch: 0,
        }
    }
}

fn with_atlas(mut e: Env) -> Env {
    e.risk.geo = Arc::new(Atlas);
    e
}

/// Commits one ALLOW of `action` in the realm's domain and binds it in `tx`.
async fn allow(e: &Env, tx: &mut TenantTx, n: u8, action: &str) -> Bound {
    let (lease, head) = acquire_lease(&e.db.sequencer, &e.domain, "t", Duration::from_secs(10))
        .await
        .unwrap();
    let pos = head.pos + 1;
    let leaf = [n; 32];
    let next = HeadRow {
        pos,
        epoch: lease.epoch,
        leaf_hash: leaf,
        recorded_at: 2,
        frontier: vec![leaf],
    };
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos,
            kind: "decision",
            recorded_at: 2,
            leaf_hash: leaf,
            envelope: vec![0xa1, n],
        }],
        head: next,
        nonces: vec![NonceRow {
            nonce: vec![n; 16],
            actor: vec![1],
            intent_digest: [9; 32],
            decision_pos: pos,
            outcome: String::from("allow"),
            render_digest: None,
            tier: None,
        }],
        outbox: vec![],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        effects: vec![],
    };
    commit_batch(&e.db.sequencer, &e.domain, *e.tenant.as_bytes(), &batch)
        .await
        .unwrap();
    let nonce = vec![n; 16];
    bind(
        tx,
        &Decision {
            domain: &e.domain,
            position: pos,
            nonce: &nonce,
            intent: [9; 32],
            change: [5; 32],
            action,
        },
    )
    .await
    .unwrap()
    .unwrap()
}

async fn set_mode(e: &Env, n: u8, m: &ProtectionMode) {
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let bound = allow(e, &mut tx, n, PROTECTION_MODE_ACTION).await;
    apply_mode(&mut tx, &bound, m).await.unwrap();
    tx.commit().await.unwrap();
}

async fn reviews(e: &Env) -> Vec<access_store::risk::ReviewRow> {
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let r = tx.open_reviews(100).await.unwrap();
    tx.commit().await.unwrap();
    r
}

async fn status_of(e: &Env, s: [u8; 16]) -> String {
    use access_identity_account::ports::{AccountDb, AccountTx};
    let pg = PgAccounts(e.db.app.clone());
    let mut tx = pg.begin(e.tenant, e.realm).await.unwrap();
    let status = tx.subject(s, false).await.unwrap().unwrap().status;
    tx.commit().await.unwrap();
    status
}

async fn login_from(e: &mut Env, who: &str, client: u8) -> Step {
    e.client = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, client)));
    let flow = start(e, Some(who), None).await;
    password(e, &flow, who, PW).await
}

// MD-8: with no source the level is unavailable; it neither blocks a sign-in SL1 lets through
// nor drops a second step SL1 asks for
#[tokio::test]
async fn unavailable_risk_neither_blocks_nor_allows() {
    let mut e = env(0x61, "sl2-md8").await;
    e.account("alice@example.com").await;
    signed_in(login_from(&mut e, "alice@example.com", 1).await);
    e.policy = AuthPolicy {
        mfa: MfaPolicy::Required,
        ..AuthPolicy::DEFAULT
    };
    match login_from(&mut e, "alice@example.com", 1).await {
        Step::Continue { needs, .. } => assert_eq!(needs, [Requirement::EnrollSecondFactor]),
        other => panic!("{other:?}"),
    }
    let orders = claim_orders(&e, |o| o.iter().any(|x| x.class == "risk.level")).await;
    let level = orders.iter().find(|o| o.class == "risk.level").unwrap();
    assert!(matches!(
        &level.content,
        access_identity_account::domain::claims::Content::Scalar(
            access_kernel::model::EqValue::Text(t)
        ) if t == "unavailable"
    ));
    assert!(level.assurance.is_empty());
    assert_eq!(reviews(&e).await.len(), 0);
}

// TN-46, IDP-39, OP-151 m.3 (o): impossible travel in the default shadow mode asks nothing of
// the user, opens a review item and never locks the account
#[tokio::test]
async fn shadow_reviews_but_asks_nothing() {
    let mut e = with_atlas(env(0x62, "sl2-shadow").await);
    let alice = e.account("alice@example.com").await;
    signed_in(login_from(&mut e, "alice@example.com", 1).await);
    e.advance(3_600_000);
    signed_in(login_from(&mut e, "alice@example.com", 2).await);
    let r = reviews(&e).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].subject, alice);
    assert_eq!(r[0].reason, "shadow_step_up");
    assert_eq!(r[0].level, "high");
    assert!(r[0].signals.contains(&String::from("impossible_travel")));
    assert_eq!(status_of(&e, alice).await, "active");
}

// TN-46, OP-151 m.3 (o), m.7 (h): in step-up mode a high level asks a second step the account
// is not offered to enrol, goes out as CAEP risk-level-change in step-up+CAEP mode, and is never
// a lock
#[tokio::test]
async fn stepup_asks_a_second_step_and_signals_caep() {
    let mut e = with_atlas(env(0x63, "sl2-stepup").await);
    let alice = e.account("alice@example.com").await;
    let m = ProtectionMode::parse(&[], "stepup_caep", &[]).unwrap();
    set_mode(&e, 1, &m).await;
    signed_in(login_from(&mut e, "alice@example.com", 1).await);
    e.advance(3_600_000);
    match login_from(&mut e, "alice@example.com", 2).await {
        Step::Continue { needs, .. } => assert_eq!(needs, [Requirement::SecondFactor]),
        other => panic!("{other:?}"),
    }
    let r = reviews(&e).await;
    assert_eq!(r.len(), 1);
    assert_eq!(
        (r[0].reason.as_str(), r[0].mode.as_str()),
        ("step_up", "stepup_caep")
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rows = access_store::identity::poll(
            &e.db.reader,
            access_store::identity::Cursor::default(),
            1000,
        )
        .await
        .unwrap();
        if rows.iter().any(|o| o.kind == "signal.risk_level_change") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no risk-level-change");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status_of(&e, alice).await, "active");
}

// §4.4: a canary credential that matches never obtains a session; the flow ends with the
// generic failure and a review item is opened
#[tokio::test]
async fn a_canary_never_gets_a_session() {
    let mut e = env(0x64, "sl2-canary").await;
    let bait = e.account("admin-backup@example.com").await;
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let bound = allow(&e, &mut tx, 1, CANARY_ACTION).await;
    assert!(mark_canary(&mut tx, &bound, bait).await.unwrap());
    tx.commit().await.unwrap();
    match login_from(&mut e, "admin-backup@example.com", 1).await {
        Step::Rejected(Refusal { problem, .. }) => assert_eq!(problem, REJECTED),
        other => panic!("{other:?}"),
    }
    let r = reviews(&e).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].reason, "canary_hit");
    assert!(r[0].signals.contains(&String::from("canary_hit")));
}

// EI-25, TN-110: the protection mode is written only against a committed ALLOW of its own
// action
#[tokio::test]
async fn protection_mode_needs_its_own_committed_allow() {
    let e = env(0x65, "sl2-mode").await;
    let mut tx = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let bound = allow(&e, &mut tx, 1, "idp.realm.branding").await;
    let m = ProtectionMode::parse(&[], "stepup", &[]).unwrap();
    assert!(apply_mode(&mut tx, &bound, &m).await.is_err());
}
