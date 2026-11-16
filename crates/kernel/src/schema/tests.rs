use alloc::string::ToString;

use super::*;

pub(crate) fn refund() -> ActionSchema {
    ActionSchema {
        reversibility: None,
        name: "refund".to_string(),
        major: 1,
        effect: EffectClass::Irreversible,
        reserved: false,
        consumption_bearing: true,
        params: BTreeMap::from([("amount".to_string(), "amount".to_string())]),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

fn spp(actions: Vec<ActionSchema>) -> Spp {
    Spp {
        publisher: Id([1; 16]),
        namespace: "shop".to_string(),
        catalog_version: 1,
        actions,
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

// OP-141 m.35 (b), (c)
#[test]
fn digests_pin_schemas_and_catalogs() {
    let one = spp(alloc::vec![refund()]);
    assert_eq!(Spp::from_value(&one.to_value()).unwrap(), one);
    let (r, _) = &one.refs()[0];
    assert_eq!(r.schema, action_digest(&refund()));
    let mut read = refund();
    read.name = "read".to_string();
    read.effect = EffectClass::None;
    let two = spp(alloc::vec![refund(), read]);
    assert_ne!(one.catalog_digest(), two.catalog_digest());
    let mut bad = one.to_value();
    if let Value::Map(m) = &mut bad {
        m.retain(|(k, _)| k != &Value::text("actions"));
        m.push((Value::text("actions"), Value::Array(alloc::vec![])));
    }
    assert!(Spp::from_value(&bad).is_err());
}

// L0-ENC-13, OP-141 m.35 (e), OP-159 m.47 (h)
#[test]
fn retirements_round_trip_in_canonical_order() {
    let mut retiring = spp(alloc::vec![refund()]);
    for name in ["sandbox_create", "environment_create", "a"] {
        let mut s = refund();
        s.name = name.to_string();
        retiring.retirements.insert(ActionRef {
            namespace: "shop".to_string(),
            name: name.to_string(),
            major: 1,
            schema: action_digest(&s),
        });
    }
    assert_eq!(Spp::from_value(&retiring.to_value()).unwrap(), retiring);
}

// E47 (1), OP-154 m.3 (b)
#[test]
fn an_undeclared_reversibility_is_irreversible_and_keeps_the_digest() {
    let plain = refund();
    assert_eq!(plain.reversibility(), Reversibility::Irreversible);
    let mut declared = refund();
    declared.reversibility = Some(Reversibility::Compensable);
    assert_ne!(action_digest(&declared), action_digest(&plain));
    assert_eq!(
        ActionSchema::from_value(&declared.to_value()).unwrap(),
        declared
    );
    assert_eq!(declared.reversibility(), Reversibility::Compensable);
    assert!(!Reversibility::Compensable.offers_undo());
    assert!(Reversibility::Reversible.offers_undo());
    let mut unknown = plain.to_value();
    if let Value::Map(m) = &mut unknown {
        m.push((Value::text("reversibility"), Value::text("maybe")));
        m.sort_by_key(|(k, _)| dcbor::encode(k, Limits::CEILING).unwrap());
    }
    assert!(ActionSchema::from_value(&unknown).is_err());
}
