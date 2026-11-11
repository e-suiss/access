//! Access review on the real commit path (OP-157 m.3 (w), m.6 (a), (f), OP-153 m.3 (gg),
//! IDP-39 (3), LFP-18, §8.17.9.8, Ek B 5563, 5564, 5565): a campaign is scheduled and closed
//! with `idp.review.*`; each manager's items are the live Grants of its own team and never
//! another manager's; a keep records `review.kept` and writes no authority; a removal takes
//! effect only as the manager's own `grant.revoke`, one item at a time.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one campaign read in order"
)]

use std::collections::BTreeSet;

use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::review::ReviewChange;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{GrantBasis, GrantContent, HoldingRef};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, ResourceSelector,
    Structural, SubjectSelector,
};
use access_store::authority::read_head;
use access_store::scope::DomainId;

use super::*;

const SLUG: &str = "reviews";
const BOB: Id = Id([3; 16]);
const BOB_KEY: u8 = 13;
const XAVI: Id = Id([4; 16]);
const XAVI_KEY: u8 = 14;
const YARA: Id = Id([5; 16]);
const YARA_KEY: u8 = 15;

/// A meta-action write by the key `seed` on `basis`.
fn meta_write(
    d: Digest,
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
            from: NOW,
            until: NOW + HOUR,
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

/// Creating groups in the realm, passed on `depth` more times.
fn authority(w: &World, depth: u64) -> CanonicalAuthority {
    let put = compile(
        Op::PutGroup,
        Some("probe"),
        &serde_json::json!({ "display_name": "probe" }),
        &w.ids,
    )
    .unwrap();
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([put.action().action_ref()]),
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
        delegation: DelegationTerms {
            depth,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    }
}

/// `seed`'s Grant to `holder` on `basis`, and the holding it opens.
async fn issue(
    w: &World,
    (at, d): ((TenantId, RealmId), Digest),
    nonce: u8,
    (basis, from): (ExerciseBasis, GrantBasis),
    (holder, depth, seed): (Id, u64, u8),
) -> HoldingRef {
    let Applied::Written {
        exercise, position, ..
    } = w
        .admin()
        .meta(
            at,
            meta_write(
                d,
                nonce,
                Payload::GrantIssue(GrantContent {
                    basis: from,
                    holder: SubjectSelector::Party(holder),
                    authority: authority(w, depth),
                    agency: BTreeSet::from([Capacity::Own]),
                    named: None,
                }),
                basis,
                seed,
            ),
        )
        .await
        .unwrap()
    else {
        panic!("issue");
    };
    HoldingRef {
        grant: meta::object_id(&exercise, kind::GRANT, 0),
        holder,
        since: position,
    }
}

async fn items(w: &World, at: (TenantId, RealmId), review: &str, who: Id) -> Vec<Id> {
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let out = w
        .admin()
        .review_items(&mut t, review, who)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.grant)
        .collect();
    t.commit().await.unwrap();
    out
}

async fn head(w: &World, d: Digest) -> u64 {
    read_head(&w.db.sequencer, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .pos
}

async fn kept(w: &World, at: (TenantId, RealmId)) -> Vec<access_store::audit::AuditRow> {
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let rows = t.list_audit(500).await.unwrap();
    t.commit().await.unwrap();
    rows.into_iter()
        .filter(|r| r.event_type == "review.kept")
        .collect()
}

// IDP-39 (3), LFP-18, OP-157 m.3 (w), m.6 (a), (f), OP-153 m.3 (gg), Ek B 5563, 5564, 5565
#[tokio::test]
async fn a_campaign_shows_each_manager_its_own_team_and_writes_no_authority() {
    let w = World::new().await;
    let (t, r, d) = w.realm(SLUG).await;
    let at = (t, r);
    for (party, seed) in [
        (ROOT, ROOT_KEY),
        (ALICE, ALICE_KEY),
        (BOB, BOB_KEY),
        (XAVI, XAVI_KEY),
        (YARA, YARA_KEY),
    ] {
        onboard(&w.plane, d, party, seed).await;
    }

    // OP-157 m.6 (f)
    let schedule = |name: &str, days: u64| {
        ReviewChange::schedule(&serde_json::json!({
            "name": name, "period_days": days, "scope": "manager_team",
        }))
        .unwrap()
    };
    assert!(schedule("q4", 6).check().is_err());
    assert!(schedule("q4", 367).check().is_err());
    written(
        &exercise(
            &w,
            &proposal(
                at,
                Change::Review(schedule("q4", 90)),
                0x40,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert!(matches!(
        w.admin()
            .prepare(&proposal(
                at,
                Change::Review(schedule("q4", 30)),
                0x41,
                idp_anchor(d),
                1
            ))
            .await,
        Err(access_identity_admin::AdminError::Conflict)
    ));
    let listed = w
        .admin()
        .read(
            t,
            r,
            access_identity_admin::app::rest::Kind::Reviews,
            Some("q4"),
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].0["status"], "live");
    assert_eq!(listed.items[0].0["period_days"], 90);
    assert!(listed.items[0].0["next_run"].is_string());

    let idp = meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR);
    let from_root = (ExerciseBasis::Anchor(idp), GrantBasis::Anchor(idp));
    let alice = issue(&w, (at, d), 0x50, from_root, (ALICE, 1, ROOT_KEY)).await;
    let bob = issue(&w, (at, d), 0x51, from_root, (BOB, 1, ROOT_KEY)).await;
    let xavi = issue(
        &w,
        (at, d),
        0x52,
        (ExerciseBasis::Holding(alice), GrantBasis::Holding(alice)),
        (XAVI, 0, ALICE_KEY),
    )
    .await;
    let yara = issue(
        &w,
        (at, d),
        0x53,
        (ExerciseBasis::Holding(bob), GrantBasis::Holding(bob)),
        (YARA, 0, BOB_KEY),
    )
    .await;

    // IDP-39 (3)
    assert_eq!(items(&w, at, "q4", ALICE).await, [xavi.grant]);
    assert_eq!(items(&w, at, "q4", BOB).await, [yara.grant]);
    assert_eq!(items(&w, at, "q4", XAVI).await, Vec::<Id>::new());
    let everyone = items(&w, at, "q4", ROOT).await;
    for g in [alice.grant, bob.grant, xavi.grant, yara.grant] {
        assert!(everyone.contains(&g), "the root roots the anchor");
    }
    assert!(
        items(&w, at, "q5", ALICE).await.is_empty(),
        "no such campaign"
    );
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let shown = w.admin().review_items(&mut tx, "q4", ALICE).await.unwrap();
    tx.commit().await.unwrap();
    let view = access_identity_admin::app::review::item_view("q4", &shown[0]);
    assert_eq!(view["remove"]["operation"], "revokeGrant");
    assert_eq!(
        view["remove"]["basis"]["holding"]["grant"],
        b64url_encode(&alice.grant.0)
    );
    assert_eq!(view["derived"], 0);

    // OP-157 m.3 (w), m.6 (a), LFP-18
    let before = head(&w, d).await;
    let alice_kid = thumbprint(&public(ALICE_KEY));
    assert!(
        w.admin()
            .keep_review(at, "q4", &b64url_encode(&xavi.grant.0), alice_kid)
            .await
            .unwrap()
    );
    assert!(
        !w.admin()
            .keep_review(at, "q4", &b64url_encode(&yara.grant.0), alice_kid)
            .await
            .unwrap(),
        "another manager's item"
    );
    assert!(
        !w.admin()
            .keep_review(at, "q5", &b64url_encode(&xavi.grant.0), alice_kid)
            .await
            .unwrap()
    );
    assert_eq!(head(&w, d).await, before, "a keep writes no authority");
    let rows = kept(&w, at).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, b64url_encode(&ALICE.0));
    assert_eq!(rows[0].target, b64url_encode(&xavi.grant.0));
    assert_eq!(rows[0].correlation, "q4");
    assert_eq!(items(&w, at, "q4", ALICE).await, [xavi.grant], "kept stays");

    // §8.17.9.8, LFP-18
    let by_bob = w
        .admin()
        .meta(
            at,
            meta_write(
                d,
                0x60,
                Payload::GrantRevoke { grant: xavi.grant },
                ExerciseBasis::Holding(bob),
                BOB_KEY,
            ),
        )
        .await;
    assert!(!matches!(by_bob, Ok(Applied::Written { .. })), "{by_bob:?}");
    assert_eq!(items(&w, at, "q4", ALICE).await, [xavi.grant]);
    written(
        &w.admin()
            .meta(
                at,
                meta_write(
                    d,
                    0x61,
                    Payload::GrantRevoke { grant: xavi.grant },
                    ExerciseBasis::Holding(alice),
                    ALICE_KEY,
                ),
            )
            .await
            .unwrap(),
    );
    assert_eq!(items(&w, at, "q4", ALICE).await, Vec::<Id>::new());
    assert_eq!(items(&w, at, "q4", BOB).await, [yara.grant]);

    // OP-157 m.3 (w)
    written(
        &exercise(
            &w,
            &proposal(
                at,
                Change::Review(ReviewChange::close("q4", &serde_json::json!({})).unwrap()),
                0x42,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert!(
        items(&w, at, "q4", BOB).await.is_empty(),
        "a closed campaign"
    );
    assert!(matches!(
        w.admin()
            .prepare(&proposal(
                at,
                Change::Review(ReviewChange::close("q4", &serde_json::json!({})).unwrap()),
                0x43,
                idp_anchor(d),
                1,
            ))
            .await,
        Err(access_identity_admin::AdminError::Conflict)
    ));
    assert!(
        matches!(
            w.admin()
                .prepare(&proposal(
                    at,
                    Change::Review(schedule("q4", 90)),
                    0x44,
                    idp_anchor(d),
                    1
                ))
                .await,
            Err(access_identity_admin::AdminError::Conflict)
        ),
        "a closed name is never reused"
    );
}
