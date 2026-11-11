#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

fn setup() -> Setup {
    Setup {
        basis: GrantBasis::Anchor(Id([1; 16])),
        holder: Id([2; 16]),
        actions: BTreeSet::from([access_kernel::meta::core_action("read")]),
        resource: ResourceSelector::Exact(access_kernel::model::ResourceRef {
            namespace: String::from("idp.account"),
            path: vec![String::from("p")],
            incarnation: 0,
        }),
        validity: Window {
            from: 0,
            until: 1_000,
        },
        approvals: 2,
        approvers: None,
        acceptance: Digest([3; 32]),
    }
}

// CI-13, §7.9.12.7, OP-157 m.3 (i), Ek B 5668
#[test]
fn a_legal_process_grant_is_held_under_a_court_order_and_two_approvals() {
    let g = setup().grant().unwrap();
    assert!(is_legal(&g.authority));
    assert!(well_formed(&g));
    assert_eq!(g.authority.delegation.depth, 0);
    assert!(
        g.authority
            .constraints
            .conditions
            .contains(&condition(Id([2; 16]), Digest([3; 32])))
    );

    assert_eq!(
        Setup {
            approvals: 1,
            ..setup()
        }
        .grant(),
        Err(Refusal::Shape)
    );
    assert_eq!(
        Setup {
            actions: BTreeSet::new(),
            ..setup()
        }
        .grant(),
        Err(Refusal::Shape)
    );
    assert_eq!(Refusal::Shape.code(), "legal-process-grant");

    let mut unconditioned = g.clone();
    unconditioned.authority.constraints.conditions.clear();
    assert!(is_legal(&unconditioned.authority) && !well_formed(&unconditioned));
    let mut elsewhere = g.clone();
    elsewhere.authority.constraints.conditions =
        BTreeSet::from([condition(Id([9; 16]), Digest([3; 32]))]);
    assert!(!well_formed(&elsewhere));
    let mut unbound = g.clone();
    unbound.authority.requirements = BTreeSet::from([RequirementTerm {
        binding: Binding::None,
        ..approval_term(2, None)
    }]);
    assert!(!well_formed(&unbound));
    let mut passed_on = g.clone();
    passed_on.authority.delegation.depth = 1;
    assert!(!well_formed(&passed_on));
    let mut wider = g;
    wider.authority.authority.purpose = None;
    assert!(is_legal(&wider.authority) && !well_formed(&wider));
}

#[test]
fn the_court_order_value_is_the_digest_of_its_body() {
    let b = body(
        &Digest([4; 32]),
        "TR",
        &BTreeSet::from([String::from("idp.account:export")]),
        9,
    );
    assert_eq!(value_digest(&b), value_digest(&b.clone()));
    let other = body(
        &Digest([4; 32]),
        "DE",
        &BTreeSet::from([String::from("idp.account:export")]),
        9,
    );
    assert_ne!(value_digest(&b), value_digest(&other));
}
