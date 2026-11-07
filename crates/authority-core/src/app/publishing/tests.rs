#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;
use access_kernel::schema::EffectClass;

const PUBLISHER: Id = Id([9; 16]);

fn schema(name: &str, params: &[(&str, &str)], reserved: bool) -> ActionSchema {
    ActionSchema {
        name: name.to_owned(),
        major: 1,
        effect: EffectClass::Irreversible,
        reserved,
        consumption_bearing: false,
        params: params
            .iter()
            .map(|(p, t)| ((*p).to_owned(), (*t).to_owned()))
            .collect(),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

fn draft(version: u64, actions: Vec<ActionSchema>, classes: &[(&str, &str, ParamClass)]) -> Draft {
    Draft {
        namespace: "commerce".to_owned(),
        catalog_version: version,
        actions,
        classes: classes
            .iter()
            .map(|(a, p, c)| (((*a).to_owned(), (*p).to_owned()), *c))
            .collect(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
        compatibility: None,
    }
}

fn refund_v1() -> Draft {
    draft(
        1,
        vec![schema(
            "refund",
            &[("amount", "amount"), ("note", "text")],
            false,
        )],
        &[
            ("refund", "amount", ParamClass::Relevant(Affects::Amount)),
            ("refund", "note", ParamClass::Opaque),
        ],
    )
}

// E12, §8.17.10.2: an authority-relevant parameter without a closed type is refused, with the
// structured warning the console shows before publishing
#[test]
fn an_unmappable_relevant_parameter_is_refused_with_its_warning() {
    let d = draft(
        1,
        vec![schema(
            "refund",
            &[("amount", "amount"), ("note", "text")],
            false,
        )],
        &[
            ("refund", "amount", ParamClass::Relevant(Affects::Amount)),
            ("refund", "note", ParamClass::Relevant(Affects::Recipient)),
        ],
    );
    let want = vec![Warning {
        action: "refund".to_owned(),
        parameter: "note".to_owned(),
        reason: "affects_recipient",
        suggestion: "id",
    }];
    assert_eq!(warnings(&d), want);
    assert_eq!(
        publish(PUBLISHER, d, None, 1),
        Err(PublishError::Unmappable(want))
    );
    let opaque = draft(
        1,
        vec![schema("refund", &[("blob", "opaque")], false)],
        &[("refund", "blob", ParamClass::Relevant(Affects::Choice))],
    );
    assert!(matches!(
        publish(PUBLISHER, opaque, None, 1),
        Err(PublishError::Unmappable(_))
    ));
}

// E12: every declared parameter has a class, and no class names an undeclared one
#[test]
fn every_parameter_is_classified_once() {
    let mut d = refund_v1();
    d.classes.remove(&("refund".to_owned(), "note".to_owned()));
    assert!(matches!(
        publish(PUBLISHER, d, None, 1),
        Err(PublishError::Unclassified { .. })
    ));
    let mut d = refund_v1();
    d.classes.insert(
        ("refund".to_owned(), "ghost".to_owned()),
        ParamClass::Opaque,
    );
    assert!(matches!(
        publish(PUBLISHER, d, None, 1),
        Err(PublishError::Undeclared { .. })
    ));
}

// E10: a published version is immutable, the next one follows it, and every answer says the
// existing delegations are unchanged
#[test]
fn versions_only_move_forward_and_existing_grants_stay() {
    let v1 = publish(PUBLISHER, refund_v1(), None, 1).unwrap();
    assert!(v1.notes.existing_grants_unchanged);
    assert_eq!(v1.notes.text[0], EXISTING_GRANTS_UNCHANGED);
    assert_eq!(v1.fingerprint, fingerprint(&v1.publication.spp));
    let mut again = refund_v1();
    again.catalog_version = 1;
    assert_eq!(
        publish(PUBLISHER, again, Some(&v1.publication), 2),
        Err(PublishError::Version { latest: 1 })
    );
    let mut wrong = refund_v1();
    wrong.catalog_version = 2;
    wrong.compatibility = Some(Compatibility {
        from: 7,
        relation: Relation::Narrowing,
    });
    assert_eq!(
        publish(PUBLISHER, wrong, Some(&v1.publication), 2),
        Err(PublishError::Compatibility)
    );
}

// E11: actions new in a version are named as not included in pinned catalogs
#[test]
fn new_actions_are_noted_as_not_included() {
    let v1 = publish(PUBLISHER, refund_v1(), None, 1).unwrap();
    assert_eq!(v1.notes.new_actions, Vec::<String>::new());
    let mut d2 = refund_v1();
    d2.catalog_version = 2;
    d2.actions.push(schema("void", &[], true));
    d2.compatibility = Some(Compatibility {
        from: 1,
        relation: Relation::Broadening,
    });
    let v2 = publish(PUBLISHER, d2, Some(&v1.publication), 2).unwrap();
    assert_eq!(v2.notes.new_actions, ["void"]);
    assert!(v2.notes.text.contains(&NEW_ACTIONS_NOT_INCLUDED));
    assert!(v2.notes.existing_grants_unchanged);
    let d = diff(Some(&v1.publication.spp), &v2.publication.spp);
    assert_eq!(d.added, ["void"]);
    assert!(d.removed.is_empty() && d.reserved_removed.is_empty());
}

// E10: the kept bytes round-trip exactly, so the fingerprint a domain pins is the published one
#[test]
fn a_publication_round_trips_its_bytes() {
    let mut d = refund_v1();
    d.catalog_version = 2;
    d.compatibility = Some(Compatibility {
        from: 1,
        relation: Relation::RepresentationEquivalent,
    });
    let v1 = publish(PUBLISHER, refund_v1(), None, 1).unwrap();
    let p = publish(PUBLISHER, d, Some(&v1.publication), 5)
        .unwrap()
        .publication;
    let back = Publication::from_bytes(&p.to_bytes().unwrap()).unwrap();
    assert_eq!(back, p);
    assert_eq!(back.fingerprint(), p.fingerprint());
}

// E11: dropping a reserved flag is shown as broadening
#[test]
fn a_dropped_reserved_flag_is_shown() {
    let v1 = publish(
        PUBLISHER,
        draft(1, vec![schema("void", &[], true)], &[]),
        None,
        1,
    )
    .unwrap();
    let v2 = publish(
        PUBLISHER,
        draft(2, vec![schema("void", &[], false)], &[]),
        Some(&v1.publication),
        2,
    )
    .unwrap();
    let d = diff(Some(&v1.publication.spp), &v2.publication.spp);
    assert_eq!(d.reserved_removed, ["void"]);
    assert_eq!(d.changed, ["void"]);
}
