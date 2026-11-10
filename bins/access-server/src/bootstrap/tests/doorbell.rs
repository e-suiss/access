//! The doorbell on the real path (OP-23, T26, OP-156 m.3 (j)): the bootstrap's Exercises commit
//! through the real sequencer on PostgreSQL with `SoftHSM`, each leader rings the NATS twin after
//! its durable commit, and every ring names a committed outbox event by its id. With the server
//! down nothing waits for it, and the fan-out still consumes every event from its cursor.

use std::time::{Duration, Instant};

use access_identity_events::app::Db;
use access_identity_events::app::fanout::Fanout;
use access_identity_oauth::adapters::dpop::SystemClock;
use access_store::scope::DomainId;
use suiss_ledger::doorbell::testing::{Pki, Twin};
use suiss_ledger::doorbell::{Ring, Topic};

use super::*;
use crate::doorbell::Doorbell;

fn acme_domain(summary: &Summary) -> DomainId {
    let acme = summary.realms.iter().find(|r| r.slug == "acme").unwrap();
    DomainId::from_bytes(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&acme.domain).unwrap()).unwrap(),
    )
}

/// Bootstraps the local plan and has its compromise declarant declare one, through Claim
/// Ingest on the domain's leader: the record carries a `party.compromised` event (OP-149 m.7).
async fn bootstrap_with_an_event(w: &World) -> DomainId {
    use access_internal_api::claims::{Carrier, ClaimIngest as _, ClaimSubmission, ClaimVerdict};
    use access_kernel::claim::Channel;
    let summary = w.run(&local_plan()).await;
    let compromise = summary.compromise.clone().unwrap();
    let domain = Digest(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&compromise.domain).unwrap())
            .unwrap(),
    );
    let issuer = Id(<[u8; 16]>::try_from(
        access_kernel::json::b64url_decode(&compromise.issuer).unwrap(),
    )
    .unwrap());
    let now = server_time(&w.db.app).await.unwrap();
    for day in [now / 86_400_000 - 1, now / 86_400_000, now / 86_400_000 + 1] {
        access_store::claims::open_claim_ingest_day(&w.db.archive, u32::try_from(day).unwrap())
            .await
            .unwrap();
    }
    let channel = Channel::Pep([0x5a; 32]);
    let claim = access_kernel::claim::Unsigned {
        statement: access_kernel::claim::Statement {
            domain,
            issuer,
            subject: Id([0x77; 16]),
            class: String::from(access_kernel::claim::PARTY_COMPROMISE),
            value: None,
            issued_at: now,
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        channel,
    }
    .to_bytes()
    .unwrap();
    let ingest = access_authority_ingest::app::Ingest::new(
        w.domains.clone(),
        crate::ingest::PgSubmissions(w.db.app.clone()),
        Now,
    );
    let verdict = ingest
        .ingest(ClaimSubmission {
            domain,
            carrier: Carrier::Unsigned(channel),
            claim,
            body: None,
            evidence: None,
        })
        .await
        .unwrap();
    assert!(
        matches!(verdict, ClaimVerdict::Admitted { .. }),
        "{verdict:?}"
    );
    w.domains.release().await;
    assert_eq!(acme_domain(&summary).as_bytes(), &domain.0);
    DomainId::from_bytes(domain.0)
}

// TI-6, T26, OP-156 m.3 (j)
#[tokio::test(flavor = "multi_thread")]
async fn each_ring_names_a_committed_event_by_its_id() {
    let pki = Pki::new().unwrap();
    let twin = Twin::start(pki.server.clone()).await.unwrap();
    let bell = Doorbell::start(&pki.client(&twin.addr(), "rung").unwrap());
    let (w, _) = World::open_rung("doorbell-rung", false, Some(bell.bell.clone())).await;
    let domain = bootstrap_with_an_event(&w).await;
    let events = access_store::authority::read_outbox(&w.db.app, &domain, (0, 0), 1_000)
        .await
        .unwrap()
        .len();
    assert!(events > 0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let stored = loop {
        let stored = twin.stored(Topic::ACCESS.stream);
        if stored
            .iter()
            .any(|s| Ring::read(&s.payload).is_ok_and(|(d, _)| d == *domain.as_bytes()))
        {
            break stored;
        }
        assert!(Instant::now() < deadline, "no ring in 20 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    for s in &stored {
        let (d, at) = Ring::read(&s.payload).unwrap();
        let rows = access_store::authority::read_outbox(
            &w.db.app,
            &DomainId::from_bytes(d),
            (0, 0),
            1_000,
        )
        .await
        .unwrap();
        let row = rows
            .iter()
            .find(|r| (r.pos, r.idx) == (at.pos, at.idx))
            .unwrap_or_else(|| panic!("a ring for {at:?} names no committed event"));
        let named = Ring {
            domain: d,
            at,
            id: row.event_id,
        };
        assert_eq!(s.msg_id.as_deref(), Some(named.msg_id().as_str()));
        assert_eq!(s.subject, Topic::ACCESS.subject(&d));
    }
    bell.stop().await;
}

// OP-23, INV-24
#[tokio::test(flavor = "multi_thread")]
async fn with_the_server_down_commits_and_the_fan_out_go_on() {
    let pki = Pki::new().unwrap();
    let twin = Twin::start(pki.server.clone()).await.unwrap();
    let addr = twin.addr();
    twin.stop();
    drop(twin);
    let bell = Doorbell::start(&pki.client(&addr, "down").unwrap());
    let (w, _) = World::open_rung("doorbell-down", false, Some(bell.bell.clone())).await;
    let domain = bootstrap_with_an_event(&w).await;
    let rows = access_store::authority::read_outbox(&w.db.app, &domain, (0, 0), 1_000)
        .await
        .unwrap();
    let last = rows.last().map(|r| (r.pos, r.idx)).unwrap();
    let fanout = Fanout::new(
        Db {
            app: w.db.app.clone(),
            reader: w.db.reader.clone(),
            ids: Arc::new(crate::ids::CellIds::new(w.keys.clone())),
        },
        SystemClock,
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while access_store::events::domain_cursor(&w.db.app, &domain)
        .await
        .unwrap()
        < last
    {
        assert!(
            Instant::now() < deadline,
            "the fan-out did not reach {last:?}"
        );
        fanout.domain_step(&domain).await.unwrap();
    }
    bell.stop().await;
}
