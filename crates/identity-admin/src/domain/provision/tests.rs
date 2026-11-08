#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;

use access_internal_api::idp::NAMESPACES;

use super::*;

fn order(root: Root, ack: bool) -> RealmOrder {
    RealmOrder {
        tenant: [1; 16],
        slug: String::from("acme"),
        style: IssuerStyle::Subdomain,
        placement: String::from(DEFAULT_PLACEMENT),
        root,
        ct3_delay_s: None,
        causal_binding: false,
        acknowledge_no_recovery: ack,
    }
}

fn joint(k: u64, n: u8) -> Root {
    Root::Joint {
        parties: (1..=n).map(|i| Id([i; 16])).collect::<BTreeSet<_>>(),
        k,
    }
}

// TN-111, §13.7.7, TN-60
#[test]
fn a_sole_root_needs_the_no_recovery_acknowledgement() {
    assert_eq!(
        order(Root::Sole(Id([1; 16])), false).check(),
        Err(ProvisionInvalid::RecoveryNotAcknowledged)
    );
    assert_eq!(order(Root::Sole(Id([1; 16])), true).check(), Ok(()));
}

// TN-111, §13.7.7
#[test]
fn a_joint_root_needs_two_of_its_parties_at_least() {
    assert_eq!(order(joint(2, 3), false).check(), Ok(()));
    assert_eq!(order(joint(3, 3), false).check(), Ok(()));
    assert_eq!(
        order(joint(1, 3), true).check(),
        Err(ProvisionInvalid::Root)
    );
    assert_eq!(
        order(joint(4, 3), true).check(),
        Err(ProvisionInvalid::Root)
    );
    assert_eq!(
        order(joint(2, 1), true).check(),
        Err(ProvisionInvalid::Root)
    );
}

// TN-111, §13.7.7, N-14
#[test]
fn recovery_is_declared_not_available() {
    for root in [Root::Sole(Id([1; 16])), joint(2, 3)] {
        assert_eq!(recovery(&root), Recovery::NotAvailable);
        assert_eq!(recovery(&root).name(), "not_available");
    }
}

// TN-16, OP-40
#[test]
fn orders_are_checked_before_a_decision() {
    let mut o = order(joint(2, 2), false);
    o.slug = String::from("A");
    assert_eq!(o.check(), Err(ProvisionInvalid::Slug));
    let mut o = order(joint(2, 2), false);
    o.placement = String::from("Pool");
    assert_eq!(o.check(), Err(ProvisionInvalid::Placement));
    let mut o = order(joint(2, 2), false);
    o.ct3_delay_s = Some(60);
    assert_eq!(o.check(), Err(ProvisionInvalid::TimeLock));
    let t = PlatformChange::Tenant {
        tenant: [2; 16],
        placement: String::from("-x"),
    };
    assert_eq!(t.check(), Err(ProvisionInvalid::Placement));
}

// EI-25
#[test]
fn the_intent_binds_the_change() {
    let w = Window { from: 1, until: 2 };
    let a = PlatformChange::Realm(order(joint(2, 3), false));
    let b = PlatformChange::Realm(order(joint(3, 3), false));
    let s = PlatformChange::Sandbox(order(joint(2, 3), false));
    let ia = a.intent("platform", w).unwrap();
    assert_eq!(ia.action.namespace, NAMESPACE);
    assert_eq!(ia.action.name, "realm_create");
    assert_eq!(
        ia.resources[0].path,
        ["platform", "platform", "realm", "acme"]
    );
    assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    assert_ne!(a.digest().unwrap(), s.digest().unwrap());
    assert_eq!(
        s.intent("platform", w).unwrap().action.name,
        "sandbox_create"
    );
}

// OP-151 m.3 (m), X21
#[test]
fn nothing_flows_across_the_sandbox_line() {
    assert!(flows(Regime::Production, Regime::Production));
    assert!(flows(Regime::Sandbox, Regime::Sandbox));
    assert!(!flows(Regime::Production, Regime::Sandbox));
    assert!(!flows(Regime::Sandbox, Regime::Production));
}

// OP-141 m.35 (c), INV-29
#[test]
fn only_the_platform_realm_publishes_the_platform_catalog() {
    assert!(!NAMESPACES.contains(&NAMESPACE));
    let spp = catalog(Id([5; 16]));
    assert_eq!(spp.namespace, NAMESPACE);
    assert_eq!(spp.actions.len(), PlatformAction::ALL.len());
    assert!(
        spp.actions
            .iter()
            .all(|a| !a.reserved && a.effect == EffectClass::Irreversible)
    );
}
