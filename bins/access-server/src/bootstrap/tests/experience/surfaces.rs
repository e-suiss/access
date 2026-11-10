//! The experience surfaces of Stage 11 on the real decision point (OP-156 m.3 (v), OP-153 m.3
//! (gg)): a merchant's budgeted Grant read through ADP's public search shows Access's authority
//! limit and Pay's financial limit as two rows with two owners (XI-14); Relay's delay, read from
//! the server's own `relay-status` route, is a notice that changes no row (§8.13, INV-24); and a
//! hub whose Access does not answer says authority can't be changed right now.

use access_authority_core::domain::Request as CoreRequest;
use access_kernel::meta::{self as kmeta, GrantBasis, GrantContent};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, BudgetDimension, BudgetTerm, BudgetWindow,
    CanonicalAuthority, ConstraintSet, DelegationTerms, Id, ResourceSelector, Structural,
    SubjectSelector,
};

use super::*;

/// The merchant the customer lets charge their card.
const MERCHANT: Id = Id([0x4d; 16]);

/// ADP in this process and the server's own `relay-status` route, or a fixed status body.
#[derive(Clone)]
struct WithRelay {
    inner: InProcess,
    relay: axum::Router,
}

impl Upstream for WithRelay {
    async fn search(&self, domain: &str, kind: Kind, body: Vec<u8>) -> Answer {
        self.inner.search(domain, kind, body).await
    }

    async fn relay_status(&self) -> Answer {
        let r = self
            .relay
            .clone()
            .oneshot(
                Request::get("/access/v1/relay-status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = r.status().as_u16();
        let body = to_bytes(r.into_body(), 1 << 16).await.unwrap().to_vec();
        Answer::Response(Answered::new(status, body))
    }
}

/// "Let *M* charge your card: up to 500 TRY per order" as the Grant the root gives the merchant
/// from the domain's meta-anchor (§8.17.5.11, §7.9.9.3).
fn card_authority() -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([ActionRef {
                    namespace: String::from("work"),
                    name: String::from("read"),
                    major: 1,
                    schema: Digest([3; 32]),
                }]),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from("work"),
                prefix: Vec::new(),
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::from([BudgetTerm {
                dimension: BudgetDimension::Amount(String::from("try")),
                capacity: 50_000,
                window: BudgetWindow::Total,
            }]),
        },
        delegation: DelegationTerms {
            depth: 0,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    }
}

/// The root's `grant.issue` to the merchant, committed on the real sequencer; the Grant's id.
async fn give_merchant(c: &Console) -> Id {
    let root = root_key(&c.w.keys).unwrap();
    let at = server_time(&c.w.db.app).await.unwrap();
    let payload = kmeta::Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(kmeta::meta_anchor(&c.domain)),
        holder: SubjectSelector::Party(MERCHANT),
        authority: card_authority(),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let intent = access_internal_api::instances::self_signed_intent(
        &payload,
        c.root,
        Window {
            from: at - 60_000,
            until: at + 600_000,
        },
    )
    .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta_anchor(&c.domain));
    let ais = sign(
        &root,
        &Statement {
            domain: c.domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: at,
            exercise: None,
        },
    )
    .unwrap();
    MetaExercises::lead(&c.w.plane, c.domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &c.w.plane,
        CoreRequest {
            domain: c.domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais,
        String::from(IDENTITY_PEP),
    )
    .await
    .unwrap();
    let Verdict::Committed(done) = verdict else {
        panic!("{verdict:?}");
    };
    kmeta::object_id(&done.exercise, kmeta::kind::GRANT, 0)
}

/// The hub of the root over `domains`, with `financial` as the device read it from Pay.
async fn read(c: &Console, app: &axum::Router, domains: &[&str], financial: &Value) -> Hub {
    let viewer = b64url_encode(&c.root.0);
    let (status, plan) = call(
        app,
        "/experience/v1/hub/plan",
        &json!({
            "viewer": viewer,
            "domains": domains.iter().map(|d| json!({ "domain": d })).collect::<Vec<_>>(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    let plan: Plan = serde_json::from_value(plan).unwrap();
    let reads = signed(c, &plan, &BTreeMap::new());
    let (status, hub) = call(
        app,
        "/experience/v1/hub",
        &json!({ "viewer": viewer, "reads": reads, "financial": financial }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hub}");
    serde_json::from_value(hub).unwrap()
}

fn app(upstream: impl Upstream + 'static) -> axum::Router {
    experience_router(
        Experience::new(
            upstream,
            SystemTime,
            SystemTime,
            String::from(EXPERIENCE_PEP),
        ),
        Beacon::default(),
    )
}

// XI-14, E21, F9, §8.13, INV-24, E30, OP-156 m.3 (u), (v), m.11 (e), OP-153 m.3 (gg)
#[tokio::test]
async fn two_limits_are_two_rows_and_a_relay_delay_changes_no_row() {
    let c = console_with("exp-surfaces", false, &sample_plan()).await;
    let acme = b64url_encode(&c.domain.0);
    let grant = give_merchant(&c).await;
    let inner = InProcess {
        adp: adp_router(
            Service::new(c.w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        ),
        domain: acme.clone(),
    };
    let live = app(WithRelay {
        inner: inner.clone(),
        relay: crate::relay::routes(c.w.db.reader.clone(), c.w.db.app.clone()),
    });
    let pay =
        json!({ "currency": "TRY", "limit_minor": 500_000, "period": "day", "held_minor": 12_000 });
    let seen = read(
        &c,
        &live,
        &[&acme],
        &json!([{ "grant": b64url_encode(&grant.0), "pay_limit": pay, "as_of": 5 }]),
    )
    .await;
    let row = seen
        .shared_from_you
        .iter()
        .find(|r| r.grant == b64url_encode(&grant.0))
        .unwrap();
    assert_eq!(
        row.who.party.as_deref(),
        Some(b64url_encode(&MERCHANT.0).as_str())
    );
    let owners: Vec<(&str, Owner)> = row
        .limits
        .iter()
        .map(|l| (l.kind.as_str(), l.owner))
        .collect();
    assert_eq!(
        owners,
        [("authority", Owner::Access), ("financial", Owner::Pay)],
        "two limits, two rows, two owners"
    );
    assert_eq!(
        row.limits[0].term["capacity"], 50_000,
        "{:?}",
        row.limits[0]
    );
    assert_eq!(row.limits[0].as_of, None);
    assert_eq!(row.limits[1].term, pay);
    assert_eq!(row.limits[1].as_of, Some(5));
    let plain = read(&c, &live, &[&acme], &json!([])).await;
    let alone = plain
        .shared_from_you
        .iter()
        .find(|r| r.grant == b64url_encode(&grant.0))
        .unwrap();
    assert_eq!(
        alone.limits.len(),
        1,
        "without Pay's statement no financial row is derived from the authority limit"
    );
    let delivery = plain.delivery.unwrap();
    assert_eq!((delivery.owner, delivery.delayed), (Owner::Relay, false));
    assert!(
        !plain
            .notices
            .contains(&String::from("status.notifications_delayed"))
    );

    let behind = axum::Router::new().route(
        "/access/v1/relay-status",
        axum::routing::get(|| async { axum::Json(crate::relay::body(Some(61_000))) }),
    );
    let delayed = read(
        &c,
        &app(WithRelay {
            inner,
            relay: behind,
        }),
        &[&acme],
        &json!([]),
    )
    .await;
    assert!(
        delayed
            .notices
            .contains(&String::from("status.notifications_delayed"))
    );
    assert_eq!(delayed.delivery.unwrap().lag_ms, Some(61_000));
    let unread = |rows: &[access_experience::contract::Row]| {
        rows.iter()
            .map(|r| {
                let mut r = r.clone();
                r.as_of = 0;
                r
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        unread(&delayed.shared_from_you),
        unread(&plain.shared_from_you),
        "no row changes"
    );
    assert_eq!(delayed.changes, plain.changes);
    c.w.domains.release().await;
}

// §8.13, OP-156 m.6 (d), E25
#[tokio::test]
async fn a_hub_without_access_says_authority_cant_be_changed_right_now() {
    let c = console_with("exp-unavailable", false, &sample_plan()).await;
    let gone = b64url_encode(&[0x42; 32]);
    let upstream = InProcess {
        adp: adp_router(
            Service::new(c.w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        ),
        domain: b64url_encode(&c.domain.0),
    };
    let seen = read(&c, &app(upstream), &[&gone], &json!([])).await;
    assert!(
        seen.notices
            .contains(&String::from("status.access_unavailable"))
    );
    assert!(
        seen.domains
            .iter()
            .all(|d| d.freshness == Freshness::Unknown)
    );
    assert!(seen.shared_from_you.is_empty() && seen.delivery.is_none());
    c.w.domains.release().await;
}
