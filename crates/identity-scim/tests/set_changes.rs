//! SA-T7, GHSA-xxwr-vvr3-2g9f: a stateful property test of SCIM PATCH, the identity plane's
//! "Set" change. Random request sequences run against a model of what each request may touch:
//! a read-only attribute never changes, a request changes only the attributes its operations
//! name, and a refused request changes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;

use access_identity_scim::domain::patch::{self, PATCH_SCHEMA};
use access_identity_scim::domain::schema::{ENTERPRISE, Kind, USER};
use access_identity_scim::domain::tolerance::Profile;
use proptest::prelude::*;
use serde_json::{Value, json};

const READ_ONLY: [&str; 3] = ["id", "meta", "groups"];

fn user() -> Value {
    json!({
        "schemas": [USER],
        "id": "2819c223-7f76-453a-919d-413861904646",
        "meta": { "resourceType": "User", "created": "2026-01-01T00:00:00Z", "version": "W/\"1\"" },
        "userName": "ada@contoso.example",
        "displayName": "Ada",
        "active": true,
        "groups": [{ "value": "g-1", "display": "Engineering" }],
        "emails": [{ "value": "ada@contoso.example", "type": "work", "primary": true }]
    })
}

/// The paths a generated operation may name, read-only ones among them.
const PATHS: [&str; 12] = [
    "displayName",
    "title",
    "nickName",
    "active",
    "userName",
    "id",
    "meta.created",
    "groups",
    "emails",
    "emails[type eq \"work\"].value",
    "password",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
];

#[derive(Clone, Debug)]
struct Step {
    op: &'static str,
    path: Option<&'static str>,
    value: Value,
}

fn value_for(path: Option<&str>, n: u8, flag: bool) -> Value {
    match path {
        Some("active") => Value::Bool(flag),
        Some("groups") => json!([{ "value": format!("g-{n}") }]),
        Some("emails") => json!([{ "value": format!("u{n}@contoso.example"), "type": "home" }]),
        Some("id" | "meta.created" | "displayName" | "title" | "nickName" | "userName") => {
            Value::String(format!("v{n}"))
        }
        Some(_) => Value::String(format!("v{n}@contoso.example")),
        None => json!({
            "displayName": format!("Whole {n}"),
            "id": format!("forged-{n}"),
            "groups": [{ "value": "g-admins" }],
            "meta": { "created": "1970-01-01T00:00:00Z" }
        }),
    }
}

fn step() -> impl Strategy<Value = Step> {
    (
        prop_oneof![Just("add"), Just("replace"), Just("remove")],
        prop::option::weighted(0.9, 0..PATHS.len()),
        any::<u8>(),
        any::<bool>(),
    )
        .prop_map(|(op, at, n, flag)| {
            let path = at.map(|i| PATHS[i]);
            Step {
                op,
                path,
                value: value_for(path, n, flag),
            }
        })
}

fn body(steps: &[Step]) -> Value {
    let ops: Vec<Value> = steps
        .iter()
        .map(|s| {
            let mut o = json!({ "op": s.op });
            if let Some(p) = s.path {
                o["path"] = Value::String(p.to_owned());
            }
            if s.op != "remove" {
                o["value"] = s.value.clone();
            }
            o
        })
        .collect();
    json!({ "schemas": [PATCH_SCHEMA], "Operations": ops })
}

/// The top-level members a request may change: each path's attribute, and for an operation
/// without a path the members of its value.
fn named(steps: &[Step]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in steps {
        match s.path {
            Some(p) if p.starts_with("urn:") => {
                out.insert(ENTERPRISE.to_owned());
            }
            Some(p) => {
                let head = p.split(['.', '[']).next().unwrap_or(p);
                out.insert(head.to_owned());
            }
            None => {
                if let Some(o) = s.value.as_object() {
                    out.extend(o.keys().cloned());
                }
            }
        }
    }
    out.insert(String::from("schemas"));
    out
}

fn changed(before: &Value, after: &Value) -> BTreeSet<String> {
    let empty = serde_json::Map::new();
    let a = before.as_object().unwrap_or(&empty);
    let b = after.as_object().unwrap_or(&empty);
    a.keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // GHSA-xxwr-vvr3-2g9f, SA-T7
    #[test]
    fn ghsa_xxwr_a_set_change_writes_only_the_attributes_it_may(
        requests in prop::collection::vec(prop::collection::vec(step(), 1..4), 1..6),
    ) {
        let profile = Profile::strict();
        let mut state = user();
        for steps in &requests {
            let b = body(steps);
            let result = patch::parse(&b, &profile)
                .and_then(|ops| patch::apply(Kind::User, &state, &ops, &profile));
            let Ok(next) = result else {
                continue;
            };
            for attr in READ_ONLY {
                prop_assert_eq!(state.get(attr), next.get(attr), "{} changed by {}", attr, b);
            }
            let allowed = named(steps);
            for k in changed(&state, &next) {
                prop_assert!(allowed.contains(&k), "{} changed by {}", k, b);
            }
            prop_assert_eq!(next.get("password"), None, "a never-returned value is held in the resource");
            state = next;
        }
    }
}

// GHSA-xxwr-vvr3-2g9f
#[test]
fn ghsa_xxwr_a_refused_request_leaves_the_resource_as_it_was() {
    let profile = Profile::strict();
    let before = user();
    let b = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "replace", "path": "displayName", "value": "Changed" },
        { "op": "replace", "path": "id", "value": "forged" },
    ]});
    let refused = patch::parse(&b, &profile)
        .and_then(|ops| patch::apply(Kind::User, &before, &ops, &profile));
    assert!(refused.is_err());
    assert_eq!(before, user());
}

// GHSA-xxwr-vvr3-2g9f
#[test]
fn ghsa_xxwr_a_whole_object_replace_cannot_write_read_only_members() {
    let profile = Profile::strict();
    let b = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "replace", "value": { "displayName": "Whole", "groups": [{ "value": "g-admins" }], "id": "forged" } },
    ]});
    let out = patch::parse(&b, &profile)
        .and_then(|ops| patch::apply(Kind::User, &user(), &ops, &profile));
    if let Ok(after) = out {
        assert_eq!(after["groups"], user()["groups"]);
        assert_eq!(after["id"], user()["id"]);
    }
}

// GHSA-xxwr-vvr3-2g9f, SA-59
#[test]
fn ghsa_xxwr_the_generated_requests_are_mostly_applied_not_refused() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let profile = Profile::strict();
    let mut runner = TestRunner::deterministic();
    let (mut applied, mut total) = (0_u32, 0_u32);
    for _ in 0..400 {
        let steps = prop::collection::vec(step(), 1..3)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        total += 1;
        let ok = patch::parse(&body(&steps), &profile)
            .and_then(|ops| patch::apply(Kind::User, &user(), &ops, &profile))
            .is_ok();
        applied += u32::from(ok);
    }
    assert!(applied * 5 > total, "{applied} of {total} applied");
}
