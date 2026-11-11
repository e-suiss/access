#![allow(
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const MIN: u64 = 60_000;

fn give(template: Template, actions: &[IdpAction], minutes: u64) -> Give {
    Give {
        template,
        subject: Id([1; 16]),
        anchor: Id([2; 16]),
        holder: SubjectSelector::Party(Id([3; 16])),
        case: access_kernel::digest::case_ref("acme-desk", "4411").unwrap(),
        acceptance: Digest([4; 32]),
        actions: actions.iter().copied().collect(),
        validity: Window {
            from: NOW,
            until: NOW + minutes * MIN,
        },
    }
}

// U57, MD-9, TN-70, TN-71, §8.16, OP-157 m.3 (c), Ek B 5505, 5507, 5508, 5516
#[test]
fn a_session_acts_for_the_person_on_their_own_account_and_passes_on_to_no_one() {
    let g = give(
        Template::Session,
        &[IdpAction::AccountRead, IdpAction::AccountProfileUpdate],
        60,
    )
    .grant()
    .unwrap();
    assert_eq!(g.agency, BTreeSet::from([Capacity::For(Id([1; 16]))]));
    assert_eq!(g.authority.delegation, DelegationTerms::default());
    assert_eq!(g.basis, GrantBasis::Anchor(Id([2; 16])));
    assert!(is_support(&g.authority, &g.agency));
    let ResourceSelector::Structural(s) = &g.authority.authority.resource else {
        panic!("structural");
    };
    assert_eq!(s.namespace, RESOURCES);
    assert_eq!(s.prefix, [hex(&Id([1; 16]))]);
    assert!(
        g.authority
            .authority
            .actions
            .exact
            .iter()
            .all(|a| a.namespace == NAMESPACE)
    );

    let mut deeper = g.clone();
    deeper.authority.delegation.depth = 1;
    assert_eq!(shape(&deeper, NOW, None), Err(PASSES_ON));
}

// U57, TN-73, §5.3, §8.16, OP-157 m.3 (c), (e), Ek B 5511
#[test]
fn a_support_grant_names_one_case_and_holds_while_it_is_open() {
    let g = give(Template::Session, &[IdpAction::AccountRead], 30)
        .grant()
        .unwrap();
    let (party, acceptance, case) = parts(&g.authority).unwrap();
    assert_eq!(party, Id([1; 16]));
    assert_eq!(acceptance, Digest([4; 32]));
    assert_eq!(
        case,
        access_kernel::digest::case_ref("acme-desk", "4411").unwrap()
    );

    let mut caseless = g.clone();
    caseless.authority.authority.purpose = None;
    assert_eq!(shape(&caseless, NOW, None), Err(CASE_REQUIRED));
    let mut coded = g.clone();
    coded.authority.authority.purpose = Some(BTreeSet::from([PurposeRef::Code(String::from(
        "customer cannot log in",
    ))]));
    assert_eq!(shape(&coded, NOW, None), Err(CASE_REQUIRED));
    let mut unheld = g.clone();
    unheld.authority.constraints.conditions.clear();
    assert!(
        is_support(&unheld.authority, &unheld.agency),
        "acting for someone with idp.account is support access"
    );
    assert_eq!(shape(&unheld, NOW, None), Err(CASE_REQUIRED));
    let mut two = g;
    two.authority
        .authority
        .purpose
        .as_mut()
        .unwrap()
        .insert(PurposeRef::Case(Digest([9; 32])));
    assert_eq!(shape(&two, NOW, None), Err(CASE_REQUIRED));

    assert_ne!(
        value_digest(&case, &party, true),
        value_digest(&case, &party, false)
    );
    assert_ne!(
        value_digest(&case, &party, true),
        value_digest(&Digest([9; 32]), &party, true)
    );
}

// U57, §8.16, TN-137 (2), OP-157 m.3 (c), (n), Ek B 5512
#[test]
fn writing_support_lasts_an_hour_and_read_only_a_day() {
    assert!(
        give(Template::Session, &[IdpAction::AccountProfileUpdate], 60)
            .grant()
            .is_ok()
    );
    assert_eq!(
        give(Template::Session, &[IdpAction::AccountProfileUpdate], 61).grant(),
        Err(TOO_LONG)
    );
    assert!(
        give(
            Template::Standing,
            &[IdpAction::AccountProfileUpdate],
            24 * 60
        )
        .grant()
        .is_ok_and(|g| g.authority.authority.actions.exact
            == BTreeSet::from([IdpAction::AccountRead.action_ref()]))
    );
    assert_eq!(
        give(Template::Standing, &[], 24 * 60 + 1).grant(),
        Err(TOO_LONG)
    );
    let g = give(Template::Session, &[IdpAction::AccountProfileUpdate], 45)
        .grant()
        .unwrap();
    assert_eq!(shape(&g, NOW, Some(30)), Err(TOO_LONG));
    assert!(shape(&g, NOW, Some(50)).is_ok());
    let mut later = g;
    later.authority.constraints.validity = Window {
        from: 0,
        until: NOW + 30 * MIN,
    };
    assert_eq!(shape(&later, NOW, None), Err(TOO_LONG));
}

// §8.16, E34, MD-9, OP-157 m.3 (a), (c), Ek B 5508, 5510
#[test]
fn no_protected_or_reserved_action_is_ever_in_support_access() {
    for p in PROTECTED {
        assert_eq!(
            give(Template::Session, &[IdpAction::AccountRead, p], 30).grant(),
            Err(PROTECTED_ACTION),
            "{}",
            p.name()
        );
    }
    for a in IdpAction::ALL {
        if a.namespace() == NAMESPACE && a.reserved() {
            assert!(PROTECTED.contains(&a), "{}", a.name());
        }
    }
    assert!(
        ELIGIBLE
            .iter()
            .all(|e| !e.reserved() && !PROTECTED.contains(e))
    );
    assert_eq!(
        give(Template::Session, &[IdpAction::AccountSuspend], 30).grant(),
        Err(OUT_OF_SCOPE)
    );
    assert_eq!(give(Template::Session, &[], 30).grant(), Err(OUT_OF_SCOPE));
}

// INV-4, TN-72, §5.7, §12.3.4, OP-157 m.3 (c), Ek B 5509, 5520
#[test]
fn support_acts_only_for_the_one_it_is_for_and_only_on_their_resources() {
    let g = give(Template::Org, &[IdpAction::AccountRead], 30)
        .grant()
        .unwrap();
    let mut own = g.clone();
    own.agency = BTreeSet::from([Capacity::Own]);
    assert_eq!(shape(&own, NOW, None), Err(OUT_OF_SCOPE));
    let mut both = g.clone();
    both.agency.insert(Capacity::Own);
    assert_eq!(shape(&both, NOW, None), Err(OUT_OF_SCOPE));
    let mut other = g.clone();
    other.agency = BTreeSet::from([Capacity::For(Id([8; 16]))]);
    assert_eq!(shape(&other, NOW, None), Err(OUT_OF_SCOPE));
    let mut employee = g.clone();
    employee.authority.authority.resource = ResourceSelector::Structural(Structural {
        namespace: String::from(RESOURCES),
        prefix: vec![hex(&Id([8; 16]))],
        kind: None,
        attrs: std::collections::BTreeMap::new(),
    });
    assert_eq!(shape(&employee, NOW, None), Err(OUT_OF_SCOPE));
    let mut to_self = g.clone();
    to_self.holder = SubjectSelector::Party(Id([1; 16]));
    assert_eq!(shape(&to_self, NOW, None), Err(OUT_OF_SCOPE));
    let mut public = g;
    public.holder = SubjectSelector::Public;
    assert_eq!(shape(&public, NOW, None), Err(OUT_OF_SCOPE));
}

// MD-9, OP-157 m.3 (c)
#[test]
fn an_admin_role_on_accounts_is_not_support_access() {
    let mut g = give(Template::Session, &[IdpAction::AccountRead], 30)
        .grant()
        .unwrap();
    g.authority.constraints.conditions.clear();
    g.agency = BTreeSet::from([Capacity::Own]);
    assert!(!is_support(&g.authority, &g.agency));
}
