use alloc::vec;

use super::*;
use crate::codec::map;

fn content(source: &str) -> Value {
    map([
        ("schema", Some(Value::text("access/restriction/v1"))),
        ("source", Some(Value::text(source))),
        ("target", Some(Value::text("domain"))),
    ])
}

const BASE: &str = "@id(\"a\")\nforbid (principal, action, resource) when { context.tier > 2 };";

#[test]
fn statements_split_at_top_level_semicolons_only() {
    assert_eq!(
        statements(
            "forbid (principal, action, resource) when { context.action == \"a;b\" }; // x; y\nforbid (principal, action, resource);"
        ),
        vec![
            "forbid (principal, action, resource) when { context.action == \"a;b\" };",
            "// x; y\nforbid (principal, action, resource);",
        ]
    );
    assert_eq!(statements("  \n"), Vec::<&str>::new());
    assert_eq!(
        statements("forbid (principal, action, resource)"),
        vec!["forbid (principal, action, resource)"]
    );
}

#[test]
fn the_effect_is_read_after_annotations() {
    assert!(is_forbid(
        "@id(\"x\") @require(\"r)\")\nforbid (principal, action, resource);"
    ));
    assert!(is_forbid(
        "@breakglass_exempt\nforbid(principal, action, resource);"
    ));
    assert!(!is_forbid(
        "@id(\"x\") permit (principal, action, resource);"
    ));
    assert!(!is_forbid("forbidden (principal, action, resource);"));
}

// SI-18, INV-36, OP-157 m.3 (b)
#[test]
fn adding_a_forbid_narrows_and_removing_one_widens() {
    let more = alloc::format!(
        "{BASE}\nforbid (principal, action, resource) when {{ context.actor == \"agent\" }};"
    );
    assert!(policy_narrows(&content(BASE), &content(&more)));
    assert!(policy_narrows(&content(BASE), &content(BASE)));
    assert!(!policy_narrows(&content(&more), &content(BASE)));
}

// SI-18, OP-157 m.3 (b)
#[test]
fn a_changed_statement_or_annotation_widens() {
    let looser = "@id(\"a\")\nforbid (principal, action, resource) when { context.tier > 3 };";
    assert!(!policy_narrows(&content(BASE), &content(looser)));
    let exempt = "@id(\"a\") @breakglass_exempt\nforbid (principal, action, resource) when { context.tier > 2 };";
    assert!(!policy_narrows(&content(BASE), &content(exempt)));
    let required = "@id(\"a\") @require(\"step\")\nforbid (principal, action, resource) when { context.tier > 2 };";
    assert!(!policy_narrows(&content(BASE), &content(required)));
    let permit = alloc::format!("{BASE}\npermit (principal, action, resource);");
    assert!(!policy_narrows(&content(BASE), &content(&permit)));
}

// OP-157 m.3 (b)
#[test]
fn schema_target_and_requirement_sets_must_stay() {
    let mut moved = content(BASE);
    if let Value::Map(entries) = &mut moved {
        for (k, v) in entries.iter_mut() {
            if *k == Value::text("target") {
                *v = Value::text("elsewhere");
            }
        }
    }
    assert!(!policy_narrows(&content(BASE), &moved));
    let with = |terms: u64| {
        map([
            (
                "requirements",
                Some(Value::Map(vec![(
                    Value::text("step"),
                    Value::Unsigned(terms),
                )])),
            ),
            ("schema", Some(Value::text("access/restriction/v1"))),
            ("source", Some(Value::text(BASE))),
            ("target", Some(Value::text("domain"))),
        ])
    };
    assert!(policy_narrows(&with(1), &with(1)));
    assert!(!policy_narrows(&with(1), &with(2)));
    assert!(!policy_narrows(&with(1), &content(BASE)));
    assert!(policy_narrows(&content(BASE), &with(1)));
}
