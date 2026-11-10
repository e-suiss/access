#![allow(clippy::unwrap_used, reason = "test code")]

use serde_json::json;

use super::*;
use crate::domain::schema::{ENTERPRISE, USER};

fn strict() -> Profile {
    Profile::strict()
}

// IDP-23
#[test]
fn a_user_is_stored_in_the_schemas_spelling_without_read_only_values() {
    let body = json!({
        "schemas": [USER, ENTERPRISE],
        "USERNAME": "bjensen@example.com",
        "id": "client-chosen",
        "meta": { "version": "x" },
        "groups": [{ "value": "g" }],
        "name": { "givenName": "Barbara", "familyName": "Jensen" },
        "emails": [{ "value": "b@example.com", "type": "work", "primary": true }],
        "active": true,
        ENTERPRISE: { "department": "Tour Operations", "manager": { "value": "26118915", "displayName": "x" } },
    });
    let c = canonical(Kind::User, &body, &strict()).unwrap();
    assert_eq!(c["userName"], "bjensen@example.com");
    assert!(c.get("id").is_none() && c.get("meta").is_none() && c.get("groups").is_none());
    assert_eq!(c[ENTERPRISE]["department"], "Tour Operations");
    assert!(c[ENTERPRISE]["manager"].get("displayName").is_none());
    assert_eq!(c["schemas"], json!([USER, ENTERPRISE]));
}

// IDP-23, TN-61
#[test]
fn a_password_and_unknown_or_missing_attributes_are_refused() {
    let base = json!({ "schemas": [USER], "userName": "a" });
    let mut pw = base.clone();
    pw["password"] = json!("t1me");
    assert_eq!(
        canonical(Kind::User, &pw, &strict()).unwrap_err().scim_type,
        Some(ScimType::InvalidValue)
    );
    let mut extra = base.clone();
    extra["favouriteColour"] = json!("blue");
    assert_eq!(
        canonical(Kind::User, &extra, &strict())
            .unwrap_err()
            .scim_type,
        Some(ScimType::InvalidSyntax)
    );
    assert!(canonical(Kind::User, &json!({ "schemas": [USER] }), &strict()).is_err());
    assert!(canonical(Kind::User, &json!({ "userName": "a" }), &strict()).is_err());
    let two_primaries = json!({
        "schemas": [USER], "userName": "a",
        "emails": [{ "value": "a@x", "primary": true }, { "value": "b@x", "primary": true }],
    });
    assert!(canonical(Kind::User, &two_primaries, &strict()).is_err());
}

// IDP-23
#[test]
fn values_are_typed() {
    let bad = json!({ "schemas": [USER], "userName": "a", "active": "true" });
    assert!(canonical(Kind::User, &bad, &strict()).is_err());
    let hr = json!({
        "schemas": [USER, crate::domain::schema::HR], "userName": "a",
        crate::domain::schema::HR: { "startDate": "2026-12-01T00:00:00Z", "employmentStatus": "ACTIVE" },
    });
    let c = canonical(Kind::User, &hr, &strict()).unwrap();
    assert_eq!(c[crate::domain::schema::HR]["employmentStatus"], "active");
    let bad_date = json!({
        "schemas": [USER, crate::domain::schema::HR], "userName": "a",
        crate::domain::schema::HR: { "startDate": "tomorrow" },
    });
    assert!(canonical(Kind::User, &bad_date, &strict()).is_err());
}

// IDP-23
#[test]
fn date_times_round_trip() {
    let ms = datetime_ms("2011-05-13T04:42:34Z").unwrap();
    assert_eq!(rfc3339(ms), "2011-05-13T04:42:34Z");
    assert_eq!(datetime_ms("2011-05-13T06:42:34+02:00"), Some(ms));
    assert_eq!(datetime_ms("2011-05-13T04:42:34.5Z"), Some(ms + 500));
    assert_eq!(datetime_ms("2011-13-13T04:42:34Z"), None);
    assert_eq!(datetime_ms("tomorrow"), None);
}
