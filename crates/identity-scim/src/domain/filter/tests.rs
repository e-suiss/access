#![allow(clippy::unwrap_used, reason = "test code")]

use serde_json::json;

use super::*;

fn strict() -> Profile {
    Profile::strict()
}

fn user() -> Value {
    json!({
        "userName": "bjensen",
        "active": true,
        "title": "Tour Guide",
        "emails": [{ "value": "b@work.example", "type": "work" }, { "value": "b@home.example", "type": "home" }],
        "meta": { "lastModified": "2026-11-01T10:00:00Z" },
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Ops" },
    })
}

fn eval_text(f: &str) -> bool {
    let e = protocol::parse(f).unwrap();
    check(Kind::User, &e, Use::Patch, &strict()).unwrap();
    eval(Kind::User, &e, &user())
}

// IDP-23, Ek B 4809
#[test]
fn filters_evaluate_over_the_schema() {
    assert!(eval_text(r#"userName eq "BJENSEN""#));
    assert!(eval_text(r#"title co "guide""#));
    assert!(eval_text(
        r#"emails[type eq "work" and value ew "@work.example"]"#
    ));
    assert!(!eval_text(r#"emails[type eq "other"]"#));
    assert!(eval_text(r#"emails.value co "home""#));
    assert!(eval_text(r#"meta.lastModified gt "2026-10-01T00:00:00Z""#));
    assert!(!eval_text(r#"meta.lastModified lt "2026-10-01T00:00:00Z""#));
    assert!(eval_text("active eq true and not (title eq \"x\")"));
    assert!(eval_text(
        r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "ops""#
    ));
    assert!(eval_text(r#"nickName ne "x""#));
    assert!(!eval_text("nickName pr"));
}

// CR-10, CR-40, Ek B 4810: an attribute the client may not filter on is refused, not ignored
#[test]
fn unauthorised_and_unknown_attributes_are_refused() {
    for f in [
        r#"password eq "x""#,
        "password pr",
        r#"colour eq "blue""#,
        r#"title co "guide""#,
        "active gt true",
        r#"meta.lastModified co "2026""#,
    ] {
        let e = parse(Kind::User, f, &strict()).unwrap_err();
        assert_eq!(e.scim_type, Some(ScimType::InvalidFilter), "{f}");
    }
    assert!(parse(Kind::User, r#"userName co "jen""#, &strict()).is_ok());
    assert!(parse(Kind::Group, r#"displayName sw "Tour""#, &strict()).is_ok());
}

// IDP-23
#[test]
fn an_index_equality_is_recognised() {
    let e = parse(Kind::User, r#"userName eq "bjensen""#, &strict()).unwrap();
    assert_eq!(equality(&e, "userName"), Some("bjensen"));
    let e = parse(
        Kind::User,
        r#"userName eq "a" or userName eq "b""#,
        &strict(),
    )
    .unwrap();
    assert_eq!(equality(&e, "userName"), None);
}
