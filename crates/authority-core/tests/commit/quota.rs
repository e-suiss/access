//! Commit quotas, billing hold and the hot domain on the real store (OP-158 m.3 (v), T27, TN-1,
//! TN-24, B3, B10, B18, B19, D7, SI-20, §16.7): over a quota a widening commit is a protocol
//! rejection with no record and an unspent nonce; narrowing never draws and is never refused.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use access_authority_core::app::quota::{Quotas, Rate, Refusal};
use access_authority_core::app::{BUSY, MAX_RETRIES};
use access_authority_sequencer::ports::DomainLog;
use access_store::StoreError;
use access_store::authority::{CommitBatch, HeadRow, Lease, LogRecord, NonceRow, Renewal};
use access_store::identity::TenantId;

use super::*;

/// Quotas wide enough that a test clock stepping an hour back is not refused: the burst spans
/// more than an hour.
pub(super) const CLOCK_STEPS: Quotas = Quotas {
    tenant: Rate {
        per_second: 1_000_000,
        burst: u32::MAX,
    },
    domain: Rate {
        per_second: 1_000_000,
        burst: u32::MAX,
    },
};

/// One unit a second, `burst` at once: a fixed clock never refills it.
const fn tight(burst: u32) -> Quotas {
    Quotas {
        tenant: Rate {
            per_second: 1_000,
            burst: 1_000,
        },
        domain: Rate {
            per_second: 1,
            burst,
        },
    }
}

async fn core_of(db: &TestDb, tenant: [u8; 16], at: u64, quotas: Quotas) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, tenant, genesis(), at)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, tenant, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0)).with_quotas(quotas);
    (Authority::new(leader, reader, binding(), Counter(0), d), d)
}

fn refused(r: Result<Response, CoreError>) -> Refusal {
    match r {
        Err(CoreError::Quota(refusal)) => refusal,
        other => panic!("{other:?}"),
    }
}

/// ROOT and ALICE onboarded and ALICE granted `shop.read`: five widening commits.
async fn granted(core: &mut Core, d: Digest) -> ExerciseBasis {
    onboard(core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let issued = send(
        core,
        meta_request(
            d,
            5,
            ExerciseBasis::Anchor(shop),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(shop),
                holder: SubjectSelector::Party(ALICE),
                authority: authority(vec![action("shop", "read")], selector("shop")),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    })
}

// T27, SI-20, B3, B19, D7
#[tokio::test]
async fn a_full_domain_refuses_widening_commits_and_still_revokes() {
    let db = fresh().await.unwrap();
    let (mut core, d) = core_of(&db, TENANT, 1_000, tight(6)).await;
    let holding = granted(&mut core, d).await;
    allowed(
        &send(
            &mut core,
            shop_request(d, 6, Mode::Commit, holding),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let head = core.head();
    assert_eq!(
        refused(
            send(
                &mut core,
                shop_request(d, 7, Mode::Commit, holding),
                ALICE_KEY
            )
            .await
        ),
        Refusal::Domain
    );
    assert_eq!(core.head(), head, "a refused commit records nothing");
    allowed(
        &send(
            &mut core,
            shop_request(d, 8, Mode::Check, holding),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );

    let ExerciseBasis::Holding(h) = holding else {
        panic!("a holding")
    };
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                9,
                ExerciseBasis::Anchor(shop),
                Payload::GrantRevoke { grant: h.grant },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let terminate = Payload::InstanceTerminate {
        instance: alice_instance(d),
    };
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let r = send(
        &mut core,
        meta_request(d, 10, public_basis, terminate),
        ALICE_KEY,
    )
    .await;
    assert!(
        !matches!(r, Err(CoreError::Quota(_))),
        "termination draws no quota: {r:?}"
    );

    // SI-20
    let later = send_at(
        &mut core,
        shop_request(d, 7, Mode::Commit, holding),
        ALICE_KEY,
        NOW + 5_000,
    )
    .await
    .unwrap();
    assert!(!later.replayed);
    fold_check(&db.sequencer, d).await.unwrap();
}

// TN-24, §12.1.3
#[tokio::test]
async fn one_domain_over_its_quota_leaves_another_domain_alone() {
    let db = fresh().await.unwrap();
    let (mut hot, a) = core_of(&db, TENANT, 1_000, tight(5)).await;
    let (mut quiet, b) = core_of(&db, TENANT, 1_001, tight(5)).await;
    let holding = granted(&mut hot, a).await;
    assert_eq!(
        refused(
            send(
                &mut hot,
                shop_request(a, 6, Mode::Commit, holding),
                ALICE_KEY
            )
            .await
        ),
        Refusal::Domain
    );
    let other = granted(&mut quiet, b).await;
    assert_eq!(
        refused(
            send(
                &mut quiet,
                shop_request(b, 6, Mode::Commit, other),
                ALICE_KEY
            )
            .await
        ),
        Refusal::Domain,
        "the second domain spent its own five, untouched by the first"
    );
}

// TN-1, B10, B18
#[tokio::test]
async fn a_billing_hold_is_only_a_protocol_rejection_of_widening_commits() {
    let db = fresh().await.unwrap();
    let tenant = access_store::tenancy::create_tenant(&db.app, "pool-default")
        .await
        .unwrap();
    let (mut core, d) = core_of(&db, *tenant.as_bytes(), 1_000, Quotas::default()).await;
    let holding = granted(&mut core, d).await;
    let hold = |on| {
        access_store::quota::set_billing_hold(&db.app, TenantId::from_bytes(*tenant.as_bytes()), on)
    };
    assert!(hold(true).await.unwrap());
    let head = core.head();
    assert_eq!(
        refused(
            send(
                &mut core,
                shop_request(d, 6, Mode::Commit, holding),
                ALICE_KEY
            )
            .await
        ),
        Refusal::Suspended
    );
    assert_eq!(core.head(), head);
    allowed(
        &send(
            &mut core,
            shop_request(d, 7, Mode::Check, holding),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let ExerciseBasis::Holding(h) = holding else {
        panic!("a holding")
    };
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                8,
                ExerciseBasis::Anchor(shop),
                Payload::GrantRevoke { grant: h.grant },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert!(hold(false).await.unwrap());
    let after = send(
        &mut core,
        shop_request(d, 6, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(after.decision.outcome, Outcome::Deny, "revoked while held");
    fold_check(&db.sequencer, d).await.unwrap();
}

/// A log whose every commit loses the head compare-and-set, as on a hot domain.
struct Contended {
    log: PgLog,
    commits: Arc<AtomicUsize>,
}

impl DomainLog for Contended {
    fn acquire(&self) -> impl Future<Output = Result<(Lease, HeadRow), SequencerError>> + Send {
        self.log.acquire()
    }

    fn renew(&self, lease: Lease) -> impl Future<Output = Result<Renewal, SequencerError>> + Send {
        self.log.renew(lease)
    }

    fn release(&self, lease: Lease) -> impl Future<Output = Result<(), SequencerError>> + Send {
        self.log.release(lease)
    }

    fn record(
        &self,
        pos: u64,
    ) -> impl Future<Output = Result<Option<LogRecord>, SequencerError>> + Send {
        self.log.record(pos)
    }

    fn nonce(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<NonceRow>, SequencerError>> + Send {
        self.log.nonce(nonce)
    }

    fn commit(&self, _: &CommitBatch) -> impl Future<Output = Result<(), SequencerError>> + Send {
        self.commits.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Err(SequencerError::Store(StoreError::Stale)))
    }
}

// §16.7, OP-36, MD-8
#[tokio::test]
async fn a_hot_domain_is_busy_after_bounded_retries_and_never_allows() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let commits = Arc::new(AtomicUsize::new(0));
    let log = Contended {
        log: PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL),
        commits: commits.clone(),
    };
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut core = Authority::new(leader, reader, binding(), Counter(0), d);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party: ROOT,
        root: Root::Sole(ROOT),
        actor_kind: ActorKind::Human,
    };
    let r = core
        .exercise(
            &incoming(meta_request(d, 1, public_basis, register), ROOT_KEY),
            NOW,
        )
        .await;
    match r {
        Err(CoreError::Unavailable(why)) => assert_eq!(why, BUSY),
        other => panic!("{other:?}"),
    }
    assert_eq!(commits.load(Ordering::SeqCst), MAX_RETRIES);
    assert_eq!(
        core.head(),
        0,
        "nothing was recorded and nothing was allowed"
    );
}
