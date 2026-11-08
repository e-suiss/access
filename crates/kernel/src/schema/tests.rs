use alloc::string::ToString;

use super::*;

pub(crate) fn refund() -> ActionSchema {
    ActionSchema {
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
