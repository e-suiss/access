//! Joiner, mover and leaver end to end on the real commit path (OP-157 m.3 (v), OP-153 m.3
//! (gg), IDP-29, IDP-35, C13, TN-75, TN-109, INV-31, AG-41, XI-15, §2.4, §7.9.13 rows 13–15,
//! §8.17.9.6, Ek B 5446, 5447, 5484, 5570, 5571, 5573): an HR source's record selects a joiner
//! into a baseline Grant over `hr_department`; a mover leaves that selection at once, and the
//! administrator's preview shows the role ended with its source; a rejoin waits out the cooling
//! and is a new episode that never revives the old one, whose Mandate pin does not carry over; a
//! leaver is suspended in the import's own transaction with their sessions and agents, and an
//! offboarding that blocks re-entry keeps the account from being reactivated.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one person's joiner, mover and leaver life read in order"
)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use access_authority_core::app::offboarding::{HR_DEPARTMENT, baseline_holder};
use access_authority_ingest::app::Ingest;
use access_identity_account::app::hr as records;
use access_identity_admin::app::hr::HrJob;
use access_identity_admin::app::offboarding::Departure;
use access_identity_admin::app::rest::{Kind, Op, compile};
use access_identity_admin::domain::Invalid;
use access_identity_admin::domain::hr::HrChange;
use access_internal_api::idp::Verdict;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{GrantBasis, GrantContent, HoldingRef, MandateEnvelope};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, ResourceSelector,
    Structural,
};

use super::hr::{Moving, TestVaults, establish, import, import_body, kinds, selection, status_of};
use super::*;
use crate::ingest::PgSubmissions;

const SLUG: &str = "jml";

/// A meta-action write by the key `seed` on `basis`, valid for an hour from `from`.
fn meta_write(
    (d, from): (Digest, u64),
    nonce: u8,
    payload: Payload,
    basis: ExerciseBasis,
    seed: u8,
) -> access_internal_api::idp::Submission {
    let intent = access_kernel::intent::IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: meta::core_action(payload.action()),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::from([(
            String::from(meta::PAYLOAD_PARAM),
            payload.digest().unwrap(),
        )]),
        recipient: None,
        purpose: None,
        context: access_kernel::intent::ContextRefs::default(),
        validity: Window {
            from,
            until: from + HOUR,
        },
    };
    let digest = intent_digest(&intent).unwrap();
    access_internal_api::idp::Submission {
        domain: d,
        nonce: vec![nonce; 16],
        intent,
        payload: Some(Box::new(payload)),
        basis,
        capacity: Capacity::Own,
        ais: sign(&statement(d, &[nonce; 16], digest, basis), seed),
        contributions: Vec::new(),
        pep: String::from(PEP),
        actor: None,
    }
}

/// A proposal of `change` valid for an hour from `from`.
fn proposal_at(
    at: (TenantId, RealmId),
    change: Change,
    nonce: u8,
    basis: ExerciseBasis,
    from: u64,
) -> Proposal {
    let mut p = proposal(at, change, nonce, basis, 1);
    p.validity = Window {
        from,
        until: from + HOUR,
    };
    p
}

/// An `idp.hr.import` of `content` by the root, valid for an hour from `from`.
async fn import_late(
    w: &World,
    (at, d): ((TenantId, RealmId), Digest),
    content: &str,
    nonce: u8,
    from: u64,
) {
    let n = u64::try_from(records::parse_jsonl(content).unwrap().len()).unwrap();
    let change =
        HrChange::import("workday", records::Format::Jsonl, &import_body(content, n)).unwrap();
    written(
        &exercise(
            w,
            &proposal_at(at, Change::Hr(change), nonce, idp_anchor(d), from),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
}

/// The group `name` as the joiner's write: what the baseline Grant lets its holders do.
fn group(name: &str, w: &World) -> Change {
    compile(
        Op::PutGroup,
        Some(name),
        &serde_json::json!({ "display_name": name }),
        &w.ids,
    )
    .unwrap()
}

/// The baseline authority: creating groups in the realm, for good.
fn baseline(w: &World) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([group("probe", w).action().action_ref()]),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
                prefix: vec![String::from(SLUG)],
                kind: None,
                attrs: std::collections::BTreeMap::new(),
            }),
            params: std::collections::BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements: BTreeSet::new(),
    }
}

/// Where the joiner stands in the baseline Grant now: the open episode's first position, or
/// `None` once it ended.
async fn episode(w: &World, d: Digest, grant: Id, at: u64) -> Option<u64> {
    let c = w
        .plane
        .domains
        .offboarding(d, ALICE, at)
        .await
        .unwrap()
        .unwrap();
    c.holdings
        .iter()
        .find(|h| h.grant == grant)
        .map(|h| h.since)
}

// OP-157 m.3 (v), IDP-35, C13, TN-75, TN-109, INV-31, AG-41, XI-15, OP-153 m.3 (gg),
// Ek B 5446, 5447, 5484, 5570, 5571, 5573
#[tokio::test]
async fn a_joiner_mover_and_leaver_move_through_rule_shaped_authority_and_offboarding() {
    let w = World::new().await;
    let (t, r, d) = w.realm_with(SLUG, Some(0)).await;
    let at = (t, r);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let RegistrationVerdict::Registered(alice) =
        Instances::register(&w.plane, registration(d, device(), ALICE, ALICE_KEY, true))
            .await
            .unwrap()
    else {
        panic!("alice");
    };
    let register = HrChange::register_source(&serde_json::json!({"name": "workday"})).unwrap();
    written(
        &exercise(
            &w,
            &proposal(at, Change::Hr(register), 0x51, idp_anchor(d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let source = tx.hr_source("workday").await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let v = establish(&w, d, 0x52, selection(source.issuer)).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");

    // IDP-35 (2), C13, Ek B 5484
    let idp = meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR);
    let Applied::Written { exercise: ex, .. } = w
        .admin()
        .meta(
            at,
            meta_write(
                (d, NOW),
                0x53,
                Payload::GrantIssue(GrantContent {
                    basis: GrantBasis::Anchor(idp),
                    holder: baseline_holder(Some("Finance"), None).unwrap(),
                    authority: baseline(&w),
                    agency: BTreeSet::from([Capacity::Own]),
                    named: None,
                }),
                ExerciseBasis::Anchor(idp),
                ROOT_KEY,
            ),
        )
        .await
        .unwrap()
    else {
        panic!("baseline");
    };
    let finance = meta::object_id(&ex, kind::GRANT, 0);
    let held = |since| {
        ExerciseBasis::Holding(HoldingRef {
            grant: finance,
            holder: ALICE,
            since,
        })
    };

    // §2.4, IDP-35 (2): the joiner
    let joiner = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"Finance","#,
        r#""start_date":"1970-01-01"}"#,
    );
    import(&w, at, d, joiner, 0x54).await;
    let vault = w.keys.vault(r).unwrap();
    let mut tx = access_identity_account::adapters::pg::PgTx(
        TenantTx::begin(&w.db.app, t, r).await.unwrap(),
        Some(vault),
    );
    let ada = access_identity_account::ports::AccountTx::subject_by_identifier(
        &mut tx,
        "ada@acme.example",
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx.0, &ada, &ALICE.0)
            .await
            .unwrap()
    );
    tx.0.commit().await.unwrap();
    let clock = Arc::new(AtomicU64::new(NOW));
    let ingest = Ingest::new(
        w.plane.domains.clone(),
        PgSubmissions(w.db.app.clone()),
        Moving(Arc::clone(&clock)),
    );
    let vaults = TestVaults(&w.keys);
    let job = HrJob {
        app: &w.db.app,
        reader: &w.db.reader,
        ingest: &ingest,
        vaults: &vaults,
        ids: &w.ids,
    };
    for day in 0..6_u32 {
        access_store::claims::open_claim_ingest_day(&w.db.archive, day)
            .await
            .unwrap();
    }
    job.run_once(NOW).await.unwrap();
    assert_eq!(status_of(&w, at, ada).await.0, "active");
    let first = episode(&w, d, finance, NOW)
        .await
        .expect("the joiner is selected");
    written(
        &exercise(
            &w,
            &proposal(at, group("g-1", &w), 0x60, held(first), 1),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );

    // INV-31, C14: a pin names a holding by name; a rule-shaped episode is never pinned
    let pinned = |pin| Payload::MandateBind {
        instance: alice.instance,
        envelope: MandateEnvelope {
            authority: baseline(&w).authority,
            constraints: baseline(&w).constraints,
            requirements: BTreeSet::new(),
            pin,
            origins: access_kernel::combinator::Origins::default(),
        },
    };
    let public = access_internal_api::instances::bootstrap_basis(&d);

    // §12.3.5 (2), TN-75, Ek B 5447, 5571: the mover
    let mover = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"R&D","#,
        r#""start_date":"1970-01-01"}"#,
    );
    import(&w, at, d, mover, 0x55).await;
    job.run_once(NOW).await.unwrap();
    let moved = NOW + 1;
    w.clock.0.store(moved, Ordering::SeqCst);
    clock.store(moved, Ordering::SeqCst);
    assert_eq!(
        episode(&w, d, finance, moved).await,
        None,
        "the episode closed"
    );
    let c = w
        .plane
        .domains
        .offboarding(d, ALICE, moved)
        .await
        .unwrap()
        .unwrap();
    let ended = c.ended.iter().find(|e| e.grant == finance).unwrap();
    assert_eq!(ended.issuer, Some(Id(source.issuer)));
    // INV-31
    assert!(matches!(
        exercise(
            &w,
            &proposal(at, group("g-2", &w), 0x61, held(first), 1),
            ALICE_KEY
        )
        .await
        .unwrap(),
        Applied::NotAllowed { .. }
    ));
    // §8.17.9.6: "E's Finance role ended (HR, …)", and nothing given by name is touched
    let party = b64url_encode(&ALICE.0);
    let view = w
        .admin()
        .read(t, r, Kind::OffboardingPreviews, Some(&party), None, 1)
        .await
        .unwrap();
    let (p, _) = &view.items[0];
    assert_eq!(p["status"], "active", "{p}");
    assert_eq!(p["survive"], 0);
    let role = p["ended"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["grant"] == b64url_encode(&finance.0))
        .unwrap();
    assert_eq!(role["source"], "workday", "{p}");
    assert_eq!(role["selects"][0]["class"], HR_DEPARTMENT);
    assert_eq!(role["selects"][0]["value"], "Finance");
    assert!(role["at"].is_string(), "{p}");

    // TN-109, INV-31, XI-15: the rejoin waits out the cooling and is a new episode
    import(&w, at, d, joiner, 0x56).await;
    job.run_once(moved).await.unwrap();
    assert_eq!(episode(&w, d, finance, moved).await, None, "still cooling");
    let later = moved + records::COOLING_MS;
    w.clock.0.store(later, Ordering::SeqCst);
    clock.store(later, Ordering::SeqCst);
    job.run_once(later).await.unwrap();
    let again = episode(&w, d, finance, later)
        .await
        .expect("the rejoin is selected");
    assert!(again > first, "{again} > {first}");
    assert!(matches!(
        exercise(
            &w,
            &proposal_at(at, group("g-3", &w), 0x62, held(first), later),
            ALICE_KEY
        )
        .await
        .unwrap(),
        Applied::NotAllowed { .. }
    ));
    written(
        &exercise(
            &w,
            &proposal_at(at, group("g-4", &w), 0x63, held(again), later),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    // INV-31, C14, §7.9.13 row 15: a Mandate pin names a holding by name only, so neither the
    // old episode nor the new one is ever pinned; nothing carries over and binding is explicit
    for (nonce, since) in [(0x64, first), (0x65, again)] {
        let pin = HoldingRef {
            grant: finance,
            holder: ALICE,
            since,
        };
        assert!(!matches!(
            w.admin()
                .meta(
                    at,
                    meta_write((d, later), nonce, pinned(Some(pin)), public, ALICE_KEY)
                )
                .await,
            Ok(Applied::Written { .. })
        ));
    }

    // AG-41, Ek B 5573
    let agent = [0x7d; 16];
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    tx.insert_agent(&access_store::agents::NewAgent {
        party: agent,
        operator: ALICE.0,
        kind: "cloud",
        display_name: "Helper",
        description: None,
        exercise: &[0x7e; 32],
    })
    .await
    .unwrap();
    tx.open_sponsorship(agent, ada, &[0x7f; 32]).await.unwrap();
    tx.commit().await.unwrap();
    let (_, epoch) = status_of(&w, at, ada).await;

    // IDP-35 (4), TN-H5, Ek B 5446: the leaver, without waiting for the job
    let leaver = concat!(
        r#"{"employee_id":"E1","email":"ada@acme.example","department":"Finance","#,
        r#""start_date":"1970-01-01","employment_status":"terminated"}"#,
    );
    import_late(&w, (at, d), leaver, 0x57, later).await;
    let (status, after) = status_of(&w, at, ada).await;
    assert_eq!(status, "suspended");
    assert!(after > epoch, "{after} > {epoch}");
    kinds(&w, "signal.session_revoked").await;
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    assert_eq!(tx.agent(agent).await.unwrap().unwrap().status, "suspended");
    let vault = w.keys.vault(r).unwrap();
    let person = records::person(&vault, (t.as_bytes(), r.as_bytes()), "workday", "E1").unwrap();
    assert!(
        !tx.hr_record_versions("workday", &person)
            .await
            .unwrap()
            .is_empty(),
        "nothing of the record is deleted"
    );
    tx.commit().await.unwrap();
    // INV-2: a suspended account's Party no longer acts through the identity plane
    assert!(
        exercise(
            &w,
            &proposal_at(at, group("g-5", &w), 0x66, held(again), later),
            ALICE_KEY
        )
        .await
        .is_err()
    );

    // §8.17.9.6, OP-157 m.3 (v): the departure, re-entry blocked
    let departure = Departure {
        party: ALICE.0,
        choices: String::from(r#"{"reentry":"blocked","self_anchor":"retire"}"#),
        reentry_blocked: true,
        actor: [0x42; 32],
    };
    written(
        &w.admin()
            .offboard(
                at,
                &departure,
                meta_write(
                    (d, later),
                    0x58,
                    Payload::PartyDepart {
                        party: ALICE,
                        disposition: std::collections::BTreeMap::new(),
                    },
                    ExerciseBasis::Anchor(meta::meta_anchor(&d)),
                    ROOT_KEY,
                ),
            )
            .await
            .unwrap(),
    );
    let view = w
        .admin()
        .read(t, r, Kind::OffboardingPreviews, Some(&party), None, 1)
        .await
        .unwrap();
    assert_eq!(view.items[0].0["status"], "offboarded");
    assert!(matches!(
        w.admin()
            .prepare(&proposal_at(
                at,
                Change::AccountReactivate(ada),
                0x59,
                idp_anchor(d),
                later
            ))
            .await,
        Err(AdminError::Invalid(Invalid::AccountState))
    ));
}
