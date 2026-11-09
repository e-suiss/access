use super::*;

fn action(namespace: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: String::from(namespace),
        name: String::from(name),
        major: 1,
        schema: access_kernel::digest::Digest([7; 32]),
    }
}

fn template() -> AgentTemplate {
    AgentTemplate {
        name: Name::parse("mail-helper").unwrap(),
        actions: BTreeSet::from([action("shop", "buy")]),
        namespace: String::from("shop"),
        prefix: Vec::new(),
        consumption: true,
        spend: Some(Spend {
            param: String::from("amount"),
            unit: String::from("EUR"),
            per_intent: 50,
            daily: 200,
        }),
        count: 20,
        window_s: 3_600,
        depth: 1,
        ttl_ms: 3_600_000,
    }
}

// X10, §13.7.6, OP-154 m.3 (g), Ek B 4267, 4336
#[test]
fn a_template_without_its_budget_is_refused_when_defined() {
    template().check().unwrap();
    let mut no_spend = template();
    no_spend.spend = None;
    assert_eq!(no_spend.check(), Err(Invalid::AgentTemplate));
    let mut no_count = template();
    no_count.count = 0;
    assert_eq!(no_count.check(), Err(Invalid::AgentTemplate));
    let mut over = template();
    over.spend = Some(Spend {
        daily: 10,
        ..over.spend.clone().unwrap()
    });
    assert_eq!(over.check(), Err(Invalid::AgentTemplate));
    let mut plain = template();
    plain.consumption = false;
    plain.spend = None;
    plain.check().unwrap();
}

// C15, OP-154 m.3 (g), Ek B 4335
#[test]
fn a_template_delegates_one_hop_at_most_and_only_to_the_same_operator() {
    let mut deep = template();
    deep.depth = 2;
    assert_eq!(deep.check(), Err(Invalid::AgentTemplate));
    let g = template().grant(&Placement {
        basis: GrantBasis::Anchor(Id([1; 16])),
        agent: Id([2; 16]),
        operator: Id([3; 16]),
        issuer: Id([4; 16]),
        from: 1_000,
    });
    assert_eq!(g.authority.delegation.depth, 1);
    let Some(SubjectSelector::Pred(p)) = &g.authority.delegation.downstream_holder_class else {
        panic!("downstream holder class");
    };
    assert_eq!(
        p.iter().next().unwrap(),
        &Conjunct {
            claim_class: String::from("operated_by"),
            value: Some(EqValue::Bytes(vec![3; 16])),
        }
    );
    let mut none = template();
    none.depth = 0;
    let g = none.grant(&Placement {
        basis: GrantBasis::Anchor(Id([1; 16])),
        agent: Id([2; 16]),
        operator: Id([3; 16]),
        issuer: Id([4; 16]),
        from: 1_000,
    });
    assert!(g.authority.delegation.downstream_holder_class.is_none());
}

// RR-12, AG-19, OP-154 m.3 (g), Ek B 4334, 4375
#[test]
fn a_template_never_covers_a_core_meta_action() {
    let mut meta = template();
    meta.namespace = String::from("access");
    meta.actions = BTreeSet::from([action("access", "grant_issue")]);
    assert_eq!(meta.check(), Err(Invalid::AgentTemplate));
    let mut mixed = template();
    mixed.actions.insert(action("access", "mandate_rebind"));
    assert_eq!(mixed.check(), Err(Invalid::AgentTemplate));
    let mut on_meta = template();
    on_meta.namespace = String::from("access");
    assert_eq!(on_meta.check(), Err(Invalid::AgentTemplate));
}

// AG-41, OP-154 m.3 (e), (g)
#[test]
fn every_grant_from_a_template_needs_a_live_sponsor_and_carries_its_budget() {
    let g = template().grant(&Placement {
        basis: GrantBasis::Anchor(Id([1; 16])),
        agent: Id([2; 16]),
        operator: Id([3; 16]),
        issuer: Id([4; 16]),
        from: 1_000,
    });
    assert_eq!(g.holder, SubjectSelector::Party(Id([2; 16])));
    let [term] = g.authority.requirements.iter().collect::<Vec<_>>()[..] else {
        panic!("one requirement");
    };
    assert_eq!(term.class, "sponsored_by");
    assert_eq!(term.source, Some(SubjectSelector::Party(Id([4; 16]))));
    assert_eq!(g.authority.constraints.budget.len(), 2);
    assert!(g.authority.authority.params.contains_key("amount"));
    assert_eq!(g.authority.constraints.validity.until, 1_000 + 3_600_000);
}

#[test]
fn a_template_round_trips_through_its_stored_form() {
    let t = template();
    let bytes = dcbor::encode(&t.to_value(), Limits::CEILING).unwrap();
    assert_eq!(AgentTemplate::from_bytes(&bytes).unwrap(), t);
}

// AG-41
#[test]
fn a_registration_names_at_least_one_distinct_sponsor() {
    let r = AgentRegister {
        party: [1; 16],
        operator: [2; 16],
        kind: AgentKind::Cloud,
        display_name: String::from("Helper"),
        description: None,
        sponsors: vec![[3; 16]],
    };
    r.check().unwrap();
    for bad in [
        AgentRegister {
            sponsors: Vec::new(),
            ..r.clone()
        },
        AgentRegister {
            sponsors: vec![[3; 16], [3; 16]],
            ..r.clone()
        },
        AgentRegister {
            operator: [1; 16],
            ..r.clone()
        },
        AgentRegister {
            display_name: String::from("a\u{7}"),
            ..r.clone()
        },
    ] {
        assert_eq!(bad.check(), Err(Invalid::Agent));
    }
    assert_eq!(AgentKind::parse("robot"), Ok(AgentKind::Robot));
    assert_eq!(AgentKind::parse("human"), Err(Invalid::Agent));
}
