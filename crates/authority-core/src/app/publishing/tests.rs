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
        reversibility: None,
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

// E12, §8.17.10.2
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

// E12
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

// E10
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
        mappings: Vec::new(),
    });
    assert_eq!(
        publish(PUBLISHER, wrong, Some(&v1.publication), 2),
        Err(PublishError::Compatibility)
    );
}

// E11
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
        mappings: Vec::new(),
    });
    let v2 = publish(PUBLISHER, d2, Some(&v1.publication), 2).unwrap();
    assert_eq!(v2.notes.new_actions, ["void"]);
    assert!(v2.notes.text.contains(&NEW_ACTIONS_NOT_INCLUDED));
    assert!(v2.notes.existing_grants_unchanged);
    let d = diff(Some(&v1.publication.spp), &v2.publication.spp);
    assert_eq!(d.added, ["void"]);
    assert!(d.removed.is_empty() && d.reserved_removed.is_empty());
}

// E10
#[test]
fn a_publication_round_trips_its_bytes() {
    let mut d = refund_v1();
    d.catalog_version = 2;
    d.compatibility = Some(Compatibility {
        from: 1,
        relation: Relation::RepresentationEquivalent,
        mappings: Vec::new(),
    });
    let v1 = publish(PUBLISHER, refund_v1(), None, 1).unwrap();
    let p = publish(PUBLISHER, d, Some(&v1.publication), 5)
        .unwrap()
        .publication;
    let back = Publication::from_bytes(&p.to_bytes().unwrap()).unwrap();
    assert_eq!(back, p);
    assert_eq!(back.fingerprint(), p.fingerprint());
}

// E11
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

fn mapping_v1_to_v2(
    v1: &Publication,
    v2: &Draft,
    relation: access_kernel::compat::Relation,
    ops: Vec<access_kernel::compat::MappingOp>,
) -> access_kernel::compat::Mapping {
    let to_spp = Spp {
        publisher: PUBLISHER,
        namespace: v2.namespace.clone(),
        catalog_version: v2.catalog_version,
        actions: v2.actions.clone(),
        retirements: v2.retirements.clone(),
        core_spec_min: v2.core_spec_min,
    };
    access_kernel::compat::Mapping {
        from: v1.spp.refs()[0].0.clone(),
        to: to_spp.refs()[0].0.clone(),
        relation,
        ops,
    }
}

// E10, PI-19, OP-157 m.3 (r), Ek B 5665
#[test]
fn a_mapping_must_fit_its_declaration_and_round_trips() {
    use access_kernel::compat::{MappingOp, Relation as K};
    let v1 = publish(PUBLISHER, refund_v1(), None, 1)
        .unwrap()
        .publication;
    let mut v2 = refund_v1();
    v2.catalog_version = 2;
    v2.actions[0].major = 2;
    let ok = mapping_v1_to_v2(&v1, &v2, K::Narrowing, Vec::new());
    let with = |relation: Relation, mappings| {
        let mut d = v2.clone();
        d.compatibility = Some(Compatibility {
            from: 1,
            relation,
            mappings,
        });
        publish(PUBLISHER, d, Some(&v1), 2)
    };
    let p = with(Relation::Narrowing, vec![ok.clone()])
        .unwrap()
        .publication;
    let back = Publication::from_bytes(&p.to_bytes().unwrap()).unwrap();
    assert_eq!(back, p);
    assert_eq!(
        with(Relation::RepresentationEquivalent, vec![ok.clone()]),
        Err(PublishError::Mapping)
    );
    let incompatible = mapping_v1_to_v2(&v1, &v2, K::Incompatible, Vec::new());
    assert_eq!(
        with(Relation::Incompatible, vec![incompatible]),
        Err(PublishError::Mapping)
    );
    assert_eq!(
        with(Relation::Narrowing, vec![ok.clone(), ok.clone()]),
        Err(PublishError::Mapping)
    );
    let mut stray = ok.clone();
    stray.to.major = 9;
    assert_eq!(
        with(Relation::Narrowing, vec![stray]),
        Err(PublishError::Mapping)
    );
    let relevant = v2
        .classes
        .iter()
        .find(|(_, c)| matches!(c, ParamClass::Relevant(_)))
        .map(|((_, p), _)| p.clone())
        .unwrap();
    let dropped = mapping_v1_to_v2(
        &v1,
        &v2,
        K::Narrowing,
        vec![MappingOp::Drop { field: relevant }],
    );
    assert_eq!(
        with(Relation::Narrowing, vec![dropped]),
        Err(PublishError::Mapping)
    );
}
