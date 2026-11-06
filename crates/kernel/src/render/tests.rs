use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec;

use super::*;
use crate::model::{ActionRef, Id, Window};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn schema(effect: EffectClass, render: Option<&str>) -> ActionSchema {
    ActionSchema {
        name: "refund".to_string(),
        major: 1,
        effect,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::from([("amount".to_string(), "amount".to_string())]),
        resource_types: alloc::collections::BTreeSet::new(),
        render: render.map(String::from),
    }
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        action: ActionRef {
            namespace: "pay".to_string(),
            name: "refund".to_string(),
            major: 1,
            schema: d(9),
        },
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["orders".to_string(), "o1".to_string()],
            incarnation: 0,
        }],
        params: BTreeMap::from([
            (
                "amount".to_string(),
                ParamValue::Amount {
                    value: 12_000,
                    unit: "try".to_string(),
                },
            ),
            ("urgent".to_string(), ParamValue::Flag(true)),
        ]),
        opaque: BTreeMap::from([("note".to_string(), d(7))]),
        recipient: Some(Id([1; 16])),
        purpose: None,
        context: crate::intent::ContextRefs::default(),
        validity: Window {
            from: 10,
            until: 20,
        },
    }
}

// §9.13.3 render, §9.14.5 WYSIWYS, XI-8: the render is a function of the accepted schema and
// the intent alone, so both sides compute the same digest
#[test]
fn the_render_is_deterministic_and_names_every_field() {
    let s = schema(
        EffectClass::Irreversible,
        Some("Refund {amount} on {resource}"),
    );
    let a = of(Some(&s), &intent(), DEFAULT_LOCALE).unwrap();
    let b = of(Some(&s), &intent(), DEFAULT_LOCALE).unwrap();
    assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
    let names: alloc::vec::Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [ACTION, RESOURCE, "amount", "urgent", RECIPIENT, VALIDITY]
    );
    assert_eq!(a.fields[0].text, "pay/refund@1");
    assert_eq!(a.fields[1].text, "shop/orders/o1");
    assert_eq!(a.fields[2].text, "12000 try");
    assert_eq!(a.fields[3].text, "true");
    assert_eq!(a.fields[5].text, "10..20");
    assert_eq!(a.template.as_deref(), Some("Refund {amount} on {resource}"));
    assert_eq!(a.intent, intent_digest(&intent()).unwrap());
    assert_eq!(a.schema, d(9));
}

// §9.14.2, XI-7: "The request changed…": any change of the intent, the schema's render
// definition or the locale changes the render digest
#[test]
fn a_changed_request_has_another_render_digest() {
    let s = schema(EffectClass::Irreversible, Some("Refund {amount}"));
    let base = digest(&of(Some(&s), &intent(), DEFAULT_LOCALE).unwrap()).unwrap();
    let mut more = intent();
    more.params.insert(
        "amount".to_string(),
        ParamValue::Amount {
            value: 12_001,
            unit: "try".to_string(),
        },
    );
    assert_ne!(
        digest(&of(Some(&s), &more, DEFAULT_LOCALE).unwrap()).unwrap(),
        base
    );
    let other_template = schema(EffectClass::Irreversible, Some("Pay {amount}"));
    assert_ne!(
        digest(&of(Some(&other_template), &intent(), DEFAULT_LOCALE).unwrap()).unwrap(),
        base
    );
    assert_ne!(
        digest(&of(Some(&s), &intent(), "tr").unwrap()).unwrap(),
        base
    );
    let mut recipient = intent();
    recipient.recipient = Some(Id([2; 16]));
    assert_ne!(
        digest(&of(Some(&s), &recipient, DEFAULT_LOCALE).unwrap()).unwrap(),
        base
    );
}

// §9.13.3 effect_class, §9.14.5 material_fields: parameters are material unless the action has
// no effect; the resource, action and recipient always are, the validity never is
#[test]
fn material_fields_follow_the_effect_class() {
    let irreversible = of(
        Some(&schema(EffectClass::Irreversible, None)),
        &intent(),
        DEFAULT_LOCALE,
    )
    .unwrap();
    let m: alloc::vec::Vec<String> = material_fields(&irreversible).into_iter().collect();
    assert_eq!(m, ["action", "amount", "recipient", "resource", "urgent"]);
    let none = of(
        Some(&schema(EffectClass::None, None)),
        &intent(),
        DEFAULT_LOCALE,
    )
    .unwrap();
    let m: alloc::vec::Vec<String> = material_fields(&none).into_iter().collect();
    assert_eq!(m, ["action", "recipient", "resource"]);
    let unknown = of(None, &intent(), DEFAULT_LOCALE).unwrap();
    assert!(material_fields(&unknown).contains("amount"));
    assert!(unknown.template.is_none());
}

// §9.13.3: parameter values render as canonical text, closed types only
#[test]
fn parameter_values_render_canonically() {
    assert_eq!(param_text(&ParamValue::Count(42)), "42");
    assert_eq!(param_text(&ParamValue::Enum("gold".to_string())), "gold");
    assert_eq!(
        param_text(&ParamValue::Amount {
            value: -5,
            unit: "eur".to_string()
        }),
        "-5 eur"
    );
    assert_eq!(
        param_text(&ParamValue::Eq(EqValue::Bytes(vec![0xde, 0xad]))),
        "dead"
    );
    assert_eq!(param_text(&ParamValue::Eq(EqValue::Int(0))), "0");
    assert_eq!(
        param_text(&ParamValue::Interval(Window { from: 1, until: 2 })),
        "1..2"
    );
    assert_eq!(
        param_text(&ParamValue::Subject(Id([0xab; 16]))),
        "ab".repeat(16)
    );
    assert_eq!(
        param_text(&ParamValue::Purpose(PurposeRef::Code("care".to_string()))),
        "care"
    );
    assert_eq!(
        param_text(&ParamValue::Resource(ResourceRef {
            namespace: "a".to_string(),
            path: vec!["b".to_string()],
            incarnation: 3,
        })),
        "a/b@3"
    );
}
