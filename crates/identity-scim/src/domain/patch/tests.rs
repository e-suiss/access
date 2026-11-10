#![allow(clippy::unwrap_used, reason = "test code")]

use serde_json::{Value, json};

use super::*;
use crate::domain::schema::{ENTERPRISE, GROUP, USER};

fn ops(v: &Value) -> Vec<Operation> {
    parse(
        &json!({ "schemas": [PATCH_SCHEMA], "Operations": v }),
        &Profile::strict(),
    )
    .unwrap()
}

fn user() -> Value {
    json!({
        "schemas": [USER],
        "userName": "bjensen",
        "active": true,
        "emails": [{ "value": "b@work.example", "type": "work" }],
        "name": { "givenName": "Barbara" },
    })
}

fn group() -> Value {
    json!({
        "schemas": [GROUP],
        "displayName": "Tour Guides",
        "members": [{ "value": "u1" }, { "value": "u2" }],
    })
}

#[expect(clippy::needless_pass_by_value, reason = "each case passes its json! literal")]
fn run(kind: Kind, r: &Value, o: Value) -> Result<Value, ScimError> {
    apply(kind, r, &ops(&o), &Profile::strict())
}

// IDP-23, Ek B 4808: add rules 1 and 2 (no path: each member added; a new attribute is added)
#[test]
fn add_without_path_adds_each_member() {
    let r = run(
        Kind::User,
        &user(),
        json!([{ "op": "add", "value": { "title": "Tour Guide", "nickName": "Babs" } }]),
    )
    .unwrap();
    assert_eq!(r["title"], "Tour Guide");
    assert_eq!(r["nickName"], "Babs");
}

// add rule 3: a complex attribute's sub-attributes are merged
#[test]
fn add_to_a_complex_attribute_merges() {
    let r = run(
        Kind::User,
        &user(),
        json!([{ "op": "add", "path": "name", "value": { "familyName": "Jensen" } }]),
    )
    .unwrap();
    assert_eq!(
        r["name"],
        json!({ "givenName": "Barbara", "familyName": "Jensen" })
    );
}

// add rule 4: a multi-valued attribute gains the new values
#[test]
fn add_to_a_multi_valued_attribute_appends() {
    let r = run(
        Kind::Group,
        &group(),
        json!([{ "op": "add", "path": "members", "value": [{ "value": "u3" }] }]),
    )
    .unwrap();
    assert_eq!(r["members"].as_array().unwrap().len(), 3);
}

// add rules 5 and 6: a single-valued attribute is replaced or set
#[test]
fn add_to_a_single_valued_attribute_replaces() {
    let r = run(
        Kind::User,
        &user(),
        json!([{ "op": "add", "path": "active", "value": false }, { "op": "add", "path": "title", "value": "x" }]),
    )
    .unwrap();
    assert_eq!(r["active"], false);
    assert_eq!(r["title"], "x");
}

// add rule 7: the same value again changes nothing (so meta.lastModified stays)
#[test]
fn adding_a_value_already_there_is_a_no_op() {
    let g = group();
    let r = run(
        Kind::Group,
        &g,
        json!([{ "op": "add", "path": "members", "value": [{ "value": "u1" }] }]),
    )
    .unwrap();
    assert_eq!(r, g);
    let u = user();
    let r = run(
        Kind::User,
        &u,
        json!([{ "op": "add", "path": "active", "value": true }]),
    )
    .unwrap();
    assert_eq!(r, u);
}

// IDP-23: remove without a target is noTarget; removing a non-member succeeds
#[test]
fn remove_targets() {
    let e = run(Kind::Group, &group(), json!([{ "op": "remove" }])).unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::NoTarget));
    let g = group();
    let r = run(
        Kind::Group,
        &g,
        json!([{ "op": "remove", "path": "members[value eq \"nobody\"]" }]),
    )
    .unwrap();
    assert_eq!(r, g);
    let r = run(
        Kind::Group,
        &g,
        json!([{ "op": "remove", "path": "members[value eq \"u1\"]" }]),
    )
    .unwrap();
    assert_eq!(r["members"], json!([{ "value": "u2" }]));
    let e = run(
        Kind::User,
        &user(),
        json!([{ "op": "remove", "path": "userName" }]),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::InvalidValue));
}

// IDP-23: replace with a filter that matches nothing is noTarget
#[test]
fn replace_targets() {
    let e = run(
        Kind::User,
        &user(),
        json!([{ "op": "replace", "path": "emails[type eq \"home\"].value", "value": "x@home" }]),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::NoTarget));
    let r = run(
        Kind::User,
        &user(),
        json!([{ "op": "replace", "path": "emails[type eq \"work\"].value", "value": "new@work" }]),
    )
    .unwrap();
    assert_eq!(r["emails"][0]["value"], "new@work");
    let r = run(
        Kind::User,
        &user(),
        json!([{ "op": "replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Ops" }]),
    )
    .unwrap();
    assert_eq!(r[ENTERPRISE]["department"], "Ops");
    assert_eq!(r["schemas"], json!([USER, ENTERPRISE]));
}

// IDP-23, Ek B 4808: one failing operation fails the request; the input is untouched
#[test]
fn a_failing_operation_fails_the_whole_request() {
    let u = user();
    let e = run(
        Kind::User,
        &u,
        json!([
            { "op": "replace", "path": "title", "value": "changed" },
            { "op": "replace", "path": "id", "value": "mine" },
        ]),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::Mutability));
    assert!(u.get("title").is_none());
}

// IDP-23: paths outside the schema and passwords
#[test]
fn bad_paths() {
    let e = run(
        Kind::User,
        &user(),
        json!([{ "op": "add", "path": "colour", "value": "x" }]),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::InvalidPath));
    let e = run(
        Kind::User,
        &user(),
        json!([{ "op": "replace", "path": "password", "value": "x" }]),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::InvalidValue));
    let e = parse(
        &json!({ "schemas": [PATCH_SCHEMA], "Operations": [{ "op": "Add", "path": "title", "value": "x" }] }),
        &Profile::strict(),
    )
    .unwrap_err();
    assert_eq!(e.scim_type, Some(ScimType::InvalidSyntax));
}
