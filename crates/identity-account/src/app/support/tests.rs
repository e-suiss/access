#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code"
)]

use super::*;

fn id(b: u8) -> Id {
    Id([b; 16])
}

fn draft(scope: Scope, minutes: u64) -> Draft {
    Draft {
        person: id(1),
        anchor: id(2),
        operator: id(3),
        case: Digest([4; 32]),
        acceptance: Digest([5; 32]),
        scope,
        validity: Window {
            from: 1_000_000,
            until: 1_000_000 + minutes * 60_000,
        },
    }
}

// §8.16, TN-137 (2), OP-157 m.3 (c)
#[test]
fn each_scope_has_its_ceiling_and_only_reading_stands_for_a_day() {
    assert!(Scope::Read.fits(24 * 60));
    assert!(!Scope::Read.fits(24 * 60 + 1));
    assert!(Scope::Profile.fits(60));
    assert!(!Scope::Profile.fits(61));
    assert!(!Scope::Artifacts.fits(61));
    assert!(!Scope::Read.fits(0));
    assert_eq!(Scope::Read.template(60).0, "support.session");
    assert_eq!(
        Scope::Read.template(61),
        ("support.standing", vec![IdpAction::AccountRead])
    );
    assert_eq!(
        Scope::Artifacts.template(30),
        ("support.artifacts", vec![IdpAction::AccountArtifactRead])
    );
    assert_eq!(Scope::parse("artifacts"), Some(Scope::Artifacts));
    assert_eq!(Scope::parse("impersonate"), None);
}

// §8.16, MD-9, OP-157 m.3 (c)
#[test]
fn the_draft_is_the_persons_own_grant_for_them_alone_on_one_case() {
    let g = draft(Scope::Profile, 30).grant();
    assert_eq!(g.basis, GrantBasis::Anchor(id(2)));
    assert_eq!(g.holder, SubjectSelector::Party(id(3)));
    assert_eq!(g.agency, BTreeSet::from([Capacity::For(id(1))]));
    assert_eq!(g.authority.delegation.depth, 0);
    assert_eq!(
        g.authority.authority.purpose,
        Some(BTreeSet::from([PurposeRef::Case(Digest([4; 32]))]))
    );
    assert_eq!(g.authority.authority.actions.exact.len(), 2);
}

// §8.16, XI-7
#[test]
fn only_the_drafted_grant_within_the_asked_minutes_is_taken() {
    let d = draft(Scope::Read, 30);
    let now = 1_000_000;
    assert!(d.signed_as(&d.grant(), 30, now));
    assert!(!d.signed_as(&d.grant(), 29, now), "longer than asked");
    let mut wider = d.grant();
    wider
        .authority
        .authority
        .actions
        .exact
        .insert(IdpAction::AccountProfileUpdate.action_ref());
    assert!(!d.signed_as(&wider, 30, now));
    let mut other = d.grant();
    other.holder = SubjectSelector::Party(id(9));
    assert!(!d.signed_as(&other, 30, now));
    assert!(!d.signed_as(&d.grant(), 30, now + 10 * 60_000), "stale");
}
