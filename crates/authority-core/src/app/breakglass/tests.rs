use std::collections::BTreeSet;

use access_kernel::combinator::{Capacity, Mode};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{GrantBasis, GrantState, HoldingRef};
use access_kernel::model::{ActionRef, Id, ResourceRef, Structural};

use super::*;

fn action(name: &str) -> ActionRef {
    ActionRef {
        namespace: String::from("access"),
        name: String::from(name),
        major: 1,
        schema: Digest([3; 32]),
    }
}

fn setup(holders: &[u8]) -> Setup {
    Setup {
        basis: GrantBasis::Anchor(Id([9; 16])),
        holders: holders.iter().map(|h| Id([*h; 16])).collect(),
        actions: BTreeSet::from([action("instance_terminate")]),
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("access.instance"),
            prefix: Vec::new(),
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        approvals: 2,
        approvers: None,
    }
}

fn request(grant: Id, purpose: Option<&str>) -> Request {
    Request {
        domain: Digest([1; 32]),
        mode: Mode::Commit,
        nonce: vec![1],
        intent: IntentEnvelope {
            action: action("instance_terminate"),
            resources: vec![ResourceRef {
                namespace: String::from("access.instance"),
                path: vec![String::from("x")],
                incarnation: 0,
            }],
            params: std::collections::BTreeMap::new(),
            opaque: std::collections::BTreeMap::new(),
            recipient: None,
            purpose: purpose.map(|p| PurposeRef::Code(String::from(p))),
            context: ContextRefs::default(),
            provenance: std::collections::BTreeMap::new(),
            validity: Window { from: 0, until: 10 },
        },
        payload: None,
        basis: ExerciseBasis::Holding(HoldingRef {
            grant,
            holder: Id([2; 16]),
            since: 1,
        }),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

fn state(content: GrantContent) -> GrantState {
    GrantState {
        content,
        since: 1,
        revision: 0,
        ended: None,
    }
}

// G29, TN-93, §12.3.8 (1), Ek B 5534
#[test]
fn a_setup_installs_two_grants_or_none() {
    assert_eq!(setup(&[2]).grants(), Err(Refusal::MinimumTwo));
    assert_eq!(Refusal::MinimumTwo.code(), "breakglass-minimum-two");
    let mut one_approval = setup(&[2, 3]);
    one_approval.approvals = 1;
    assert_eq!(one_approval.grants(), Err(Refusal::MinimumTwo));
    let mut nothing = setup(&[2, 3]);
    nothing.actions.clear();
    assert_eq!(nothing.grants(), Err(Refusal::Actions));
    let grants = setup(&[2, 3]).grants().unwrap();
    assert_eq!(grants.len(), 2);
    let holders: BTreeSet<_> = grants.iter().map(|g| g.holder.clone()).collect();
    assert_eq!(holders.len(), 2);
    for g in &grants {
        assert!(well_formed(g));
        assert!(is_breakglass(&g.authority.authority));
        let term = g.authority.requirements.first().unwrap();
        assert_eq!(term.count, 2);
        assert_eq!(term.independence, Independence::DistinctParty);
        assert_eq!(term.freshness_ms, Some(USE_MAX_MS));
        assert_eq!(g.authority.delegation.depth, 0);
    }
}

// G29, INV-28
#[test]
fn a_breakglass_grant_without_its_approvals_is_not_well_formed() {
    let mut g = setup(&[2, 3]).grants().unwrap().remove(0);
    g.authority.requirements.clear();
    assert!(!well_formed(&g));
    let mut wide = setup(&[2, 3]).grants().unwrap().remove(0);
    wide.authority
        .authority
        .actions
        .prefix
        .insert((String::from("access"), Digest([0; 32])));
    assert!(!well_formed(&wide));
    let mut public = setup(&[2, 3]).grants().unwrap().remove(0);
    public.holder = SubjectSelector::Public;
    assert!(!well_formed(&public));
    let mut passed_on = setup(&[2, 3]).grants().unwrap().remove(0);
    passed_on.authority.delegation.depth = 1;
    assert!(!well_formed(&passed_on));
}

// G29, INV-28, Ek B 5653
#[test]
fn only_a_breakglass_grant_makes_a_use() {
    let g = Id([5; 16]);
    let bg = state(setup(&[2, 3]).grants().unwrap().remove(0));
    let used = of(&request(g, Some(PURPOSE)), Some(&bg)).unwrap();
    assert!(!used.drill);
    assert_eq!(used.approvals, 2);
    assert!(of(&request(g, Some(DRILL)), Some(&bg)).unwrap().drill);
    assert_eq!(of(&request(g, None), Some(&bg)), None);
    assert_eq!(of(&request(g, Some("support")), Some(&bg)), None);
    let mut plain = bg.clone();
    plain.content.authority.authority.purpose = None;
    assert_eq!(of(&request(g, Some(PURPOSE)), Some(&plain)), None);
    let mut wider = bg.clone();
    wider
        .content
        .authority
        .authority
        .purpose
        .as_mut()
        .unwrap()
        .insert(PurposeRef::Code(String::from("support")));
    assert_eq!(of(&request(g, Some(PURPOSE)), Some(&wider)), None);
    let mut ended = bg.clone();
    ended.ended = Some(access_kernel::meta::Ended {
        at: 9,
        how: access_kernel::meta::EndedHow::Revoked,
    });
    assert_eq!(of(&request(g, Some(PURPOSE)), Some(&ended)), None);
    assert_eq!(of(&request(g, Some(PURPOSE)), None), None);
    let mut anchored = request(g, Some(PURPOSE));
    anchored.basis = ExerciseBasis::Anchor(Id([9; 16]));
    assert_eq!(of(&anchored, Some(&bg)), None);
}

// §12.3.8 (4), (5), OP-157 m.3 (h), Ek B 5535, 5537
#[test]
fn reviews_and_drills_fall_due() {
    let h = 3_600_000;
    let uses = [
        (Digest([1; 32]), 0),
        (Digest([2; 32]), 0),
        (Digest([3; 32]), 10 * h),
    ];
    let reviewed = BTreeSet::from([Digest([2; 32])]);
    assert_eq!(review_due(0, REVIEW_WITHIN_H), 72 * h);
    assert_eq!(
        overdue(&uses, &reviewed, 72 * h, REVIEW_WITHIN_H),
        Vec::<Digest>::new()
    );
    assert_eq!(
        overdue(&uses, &reviewed, 72 * h + 1, REVIEW_WITHIN_H),
        vec![Digest([1; 32])]
    );
    assert_eq!(
        overdue(&uses, &reviewed, 83 * h, REVIEW_WITHIN_H),
        vec![Digest([1; 32]), Digest([3; 32])]
    );
    assert!(!drill_overdue(None, 0, DRILL_EVERY_MS));
    assert!(drill_overdue(None, 0, DRILL_EVERY_MS + 1));
    assert!(!drill_overdue(Some(DRILL_EVERY_MS), 0, DRILL_EVERY_MS + 2));
    for c in Classification::ALL {
        assert_eq!(Classification::parse(c.name()), Some(c));
    }
    assert_eq!(Classification::parse("routine"), None);
}

// TN-71, §12.6, OP-157 m.3 (h)
#[test]
fn an_exemption_on_the_subjects_own_restriction_does_not_count() {
    let anchor = Id([4; 16]);
    let on = |target: Value| Value::Map(vec![(Value::text("target"), target)]);
    let own = on(Value::Map(vec![(Value::text("anchor"), anchor.to_value())]));
    let domain = on(Value::text("domain"));
    let facts = crate::restrict::Facts {
        breakglass: true,
        self_anchor: Some(anchor),
        ..crate::restrict::Facts::default()
    };
    assert!(facts.exempt_under(&domain));
    assert!(!facts.exempt_under(&own));
    let ordinary = crate::restrict::Facts {
        self_anchor: Some(anchor),
        ..crate::restrict::Facts::default()
    };
    assert!(!ordinary.exempt_under(&domain));
}
