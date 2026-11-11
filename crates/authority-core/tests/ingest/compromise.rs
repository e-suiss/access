//! A compromise declared without `occurred_at` on the real store (TN-48, SI-9, §12.2.4,
//! OP-157 m.3 (i)): its window reaches 72 hours back from the declaration, the Party's Instances
//! set up inside it end and stop acting, those set up before it keep acting.

use access_internal_api::events::{COMPROMISE_LOOKBACK_MS, Detail, Event, Kind, Subject};

use super::*;

const LONG: u64 = 1 << 42;

/// The declaration: 300 hours after the domain's start.
const DECLARED: u64 = 300 * 3_600_000;

fn long_grant(holder: &SubjectSelector, actions: &[&str], namespace: &str) -> Value {
    let Value::Map(mut m) = grant(holder, actions, namespace) else {
        panic!("a grant is a map");
    };
    for (k, v) in &mut m {
        if *k == Value::text("authority") {
            let mut a = CanonicalAuthority::from_value(v).unwrap();
            a.constraints.validity.until = LONG;
            *v = a.to_value();
        }
    }
    Value::Map(m)
}

fn long_regime_acceptance() -> Value {
    let Value::Map(mut m) = regime_acceptance() else {
        panic!("an acceptance is a map");
    };
    for (k, v) in &mut m {
        if *k == Value::text("validity") {
            *v = Value::Array(vec![Value::Unsigned(0), Value::Unsigned(LONG)]);
        }
    }
    Value::Map(m)
}

async fn long_lived(db: &TestDb) -> (Core, Digest) {
    let mut g = genesis_with(vec![long_regime_acceptance()], Vec::new());
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(vec![
                long_grant(
                    &SubjectSelector::Public,
                    &["party_register", "instance_create"],
                    "access.party",
                ),
                long_grant(&SubjectSelector::Party(ALICE), &["read"], "access.party"),
            ]),
            salt: [3; 32],
        },
    );
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut core = Authority::new(leader, reader, binding(), Counter(0), d);
    for (party, key, nonces) in [(ALICE, ALICE_KEY, (1, 2)), (REGIME, REGIME_KEY, (5, 6))] {
        onboard(&mut core, d, party, key, nonces).await;
    }
    (core, d)
}

fn at(mut r: Request, now: u64) -> Request {
    r.intent.validity = Window {
        from: now.saturating_sub(1_000),
        until: now.saturating_add(60_000),
    };
    r
}

/// ALICE adds an Instance with key `new` at `now`.
async fn add_key_at(core: &mut Core, d: Digest, (new, nonce): (u8, u8), now: u64) -> Outcome {
    let basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let create = Payload::InstanceCreate {
        party: ALICE,
        key: public(new),
        mandate: None,
    };
    send_at(
        core,
        at(request(d, nonce, basis, create), now),
        ALICE_KEY,
        now,
    )
    .await
    .unwrap()
    .decision
    .outcome
}

/// ALICE, by key `seed`, reads under her Grant at `now`.
async fn act_at(core: &mut Core, d: Digest, seed: u8, nonce: u8, now: u64) -> Outcome {
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&d, kind::GRANT, 1),
        holder: ALICE,
        since: 0,
    });
    let mut r = request(
        d,
        nonce,
        basis,
        Payload::InstanceTerminate { instance: ALICE },
    );
    r.intent.action = action("read");
    r.intent.opaque = BTreeMap::new();
    r.payload = None;
    match send_at(core, at(r, now), seed, now).await {
        Ok(r) => r.decision.outcome,
        Err(_) => Outcome::Deny,
    }
}

// TN-48, SI-9, §12.2.4, OP-149 m.17 (d), OP-157 m.3 (i), Ek B 5582
#[tokio::test]
async fn a_compromise_without_occurred_at_reaches_back_72_hours() {
    let db = fresh().await.unwrap();
    let (mut core, d) = long_lived(&db).await;
    let before = DECLARED - 80 * 3_600_000;
    let inside = DECLARED - 48 * 3_600_000;
    assert_eq!(
        add_key_at(&mut core, d, (50, 40), before).await,
        Outcome::Allow
    );
    assert_eq!(
        add_key_at(&mut core, d, (51, 41), inside).await,
        Outcome::Allow
    );
    let declared = Statement {
        value: None,
        issued_at: DECLARED,
        validity: Window {
            from: 0,
            until: LONG,
        },
        ..statement(d, REGIME, ALICE, "party_compromise", EqValue::Bool(true))
    };
    let admitted = core
        .ingest(&signed(&declared, REGIME_KEY), DECLARED)
        .await
        .unwrap();
    let ClaimVerdict::Admitted { position, .. } = admitted.verdict else {
        panic!("admitted: {:?}", admitted.verdict);
    };

    let event =
        access_store::authority::read_outbox(&db.app, &DomainId::from_bytes(d.0), (0, 0), 1_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|o| o.pos == position)
            .filter_map(|o| Event::from_bytes(&o.event).ok())
            .find(|e| e.kind == Kind::PartyCompromised)
            .unwrap();
    assert_eq!(event.subject, Subject::Party(ALICE));
    let Detail::Compromised {
        keys,
        occurred_at,
        window_from,
        ..
    } = event.detail
    else {
        panic!("a compromise: {event:?}");
    };
    assert_eq!(occurred_at, None);
    assert_eq!(window_from, DECLARED - COMPROMISE_LOOKBACK_MS);
    let covered: BTreeSet<[u8; 32]> = keys.iter().map(|(_, k)| *k).collect();
    assert!(covered.contains(&thumbprint(&public(51))));
    assert!(!covered.contains(&thumbprint(&public(50))));
    assert!(!covered.contains(&thumbprint(&public(ALICE_KEY))));

    assert_ne!(act_at(&mut core, d, 51, 42, DECLARED).await, Outcome::Allow);
    assert_eq!(act_at(&mut core, d, 50, 43, DECLARED).await, Outcome::Allow);
    assert_eq!(
        act_at(&mut core, d, ALICE_KEY, 44, DECLARED).await,
        Outcome::Allow
    );
}
