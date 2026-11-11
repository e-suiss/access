use std::collections::BTreeMap;

use access_internal_api::signals::{Posture, RiskLevel};
use access_kernel::intent::ContextRefs;
use access_kernel::model::{ActionRef, ResourceRef, Window};

use super::*;

fn policy(source: &str) -> (Id, ContentState) {
    (
        Id([7; 16]),
        ContentState {
            content: Value::Map(vec![
                (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
                (Value::text("source"), Value::text(source)),
                (Value::text("target"), Value::text("domain")),
            ]),
            since: 1,
            widened: None,
            ended: None,
        },
    )
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: ActionRef {
            namespace: String::from("shop"),
            name: String::from("disclose"),
            major: 1,
            schema: Digest([0; 32]),
        },
        resources: vec![ResourceRef {
            namespace: String::from("shop.file"),
            path: vec![String::from("f-1")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 10 },
    }
}

fn outcome(source: &str, signals: Signals) -> RestrictionOutcome {
    let actor = Actor {
        party: Id([1; 16]),
        instance: Id([2; 16]),
    };
    let facts = Facts {
        agent: false,
        tier: 1,
        signals,
        derived: derived::Derived::empty(),
    };
    results_with(
        &[policy(source)],
        &intent(),
        (Some(&actor), Capacity::Own),
        &facts,
        5,
        &Cache::default(),
    )
    .unwrap()
    .remove(0)
    .outcome
}

// CI-2, E38, OP-156 m.3 (r)
#[test]
fn an_external_signal_reaches_only_a_forbid_policy() {
    let deny_high = r#"@id("risk") forbid(principal, action, resource) when { context.risk == "high" || context.risk == "critical" };"#;
    let risk = |level| Signals {
        risk: level,
        ..Signals::default()
    };
    assert!(matches!(
        outcome(deny_high, risk(Some(RiskLevel::High))),
        RestrictionOutcome::Deny(_)
    ));
    assert_eq!(
        outcome(deny_high, risk(Some(RiskLevel::Low))),
        RestrictionOutcome::NoObjection
    );
    assert_eq!(
        outcome(deny_high, risk(None)),
        RestrictionOutcome::NoObjection
    );
    let posture = r#"@id("mdm") forbid(principal, action, resource) unless { context.posture == "compliant" };"#;
    assert!(matches!(
        outcome(posture, Signals::default()),
        RestrictionOutcome::Deny(_)
    ));
    assert_eq!(
        outcome(
            posture,
            Signals {
                posture: Posture::Compliant,
                ..Signals::default()
            }
        ),
        RestrictionOutcome::NoObjection
    );
    let label = r#"@id("dlp") forbid(principal, action, resource) when { context.labels.contains("acme-dlp:confidential") };"#;
    assert!(matches!(
        outcome(
            label,
            Signals {
                labels: BTreeSet::from([String::from("acme-dlp:confidential")]),
                ..Signals::default()
            }
        ),
        RestrictionOutcome::Deny(_)
    ));
    assert_eq!(
        outcome(label, Signals::default()),
        RestrictionOutcome::NoObjection
    );
}

// INV-36, RT26, OP-157 m.3 (o)
#[test]
fn only_whitelisted_derived_values_compile() {
    let policy = |condition: &str| {
        Value::Map(vec![
            (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
            (
                Value::text("source"),
                Value::text(&format!(
                    "@id(\"t\") forbid(principal, action, resource) when {{ {condition} }};"
                )),
            ),
            (Value::text("target"), Value::text("domain")),
        ])
    };
    for name in derived::NAMES {
        let c = compile(&policy(&format!("context.derived.{name} > 0")));
        assert!(c.is_ok(), "{name} {:?}", c.err());
    }
    assert!(compile(&policy("context.derived.reputation > 0")).is_err());
    assert!(compile(&policy("context.trust_score > 0")).is_err());
}
