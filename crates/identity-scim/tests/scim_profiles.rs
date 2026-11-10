//! The shipped tolerance profiles, one test per tolerance (IDP-23, IDP-40, OP-155 m.3 (g), (q)):
//! each case is a recorded vendor request, scrubbed of tenant names and secrets, that the strict
//! server refuses and the client's profile accepts. No profile relaxes authentication or a limit.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use access_identity_scim::domain::filter;
use access_identity_scim::domain::patch::{self, PATCH_SCHEMA};
use access_identity_scim::domain::resource::canonical;
use access_identity_scim::domain::schema::{ENTERPRISE, GROUP, Kind, USER};
use access_identity_scim::domain::tolerance::{Profile, Rule, shipped};
use serde_json::{Value, json};

fn profile(name: &str) -> Profile {
    shipped(name).unwrap()
}

fn patch_ok(kind: Kind, r: &Value, body: &Value, p: &Profile) -> Value {
    let ops = patch::parse(body, p).unwrap();
    patch::apply(kind, r, &ops, p).unwrap()
}

fn strict_refuses_patch(kind: Kind, r: &Value, body: &Value) {
    let s = Profile::strict();
    let refused = patch::parse(body, &s).and_then(|ops| patch::apply(kind, r, &ops, &s));
    assert!(refused.is_err(), "{body}");
}

fn user() -> Value {
    json!({ "schemas": [USER], "userName": "ada@contoso.example", "active": true,
            "emails": [{ "value": "ada@contoso.example", "type": "work", "primary": true }] })
}

fn group() -> Value {
    json!({ "schemas": [GROUP], "displayName": "Engineering",
            "members": [{ "value": "u-1" }, { "value": "u-2" }] })
}

mod entra {
    use super::*;

    const P: &str = "scim.entra";

    // IDP-23: Entra's aadOptscim062020 flag
    #[test]
    fn opt_flag() {
        assert!(profile(P).has(Rule::AadOptScim062020));
        assert!(!Profile::strict().has(Rule::AadOptScim062020));
    }

    // IDP-23: a recorded Entra user PATCH
    #[test]
    fn ops_in_title_case() {
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "Replace", "path": "displayName", "value": "Ada Lovelace" },
            { "op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Research" },
        ]});
        strict_refuses_patch(Kind::User, &user(), &body);
        let r = patch_ok(Kind::User, &user(), &body, &profile(P));
        assert_eq!(r["displayName"], "Ada Lovelace");
        assert_eq!(r[ENTERPRISE]["department"], "Research");
    }

    // IDP-23: Entra disables a user with "False"
    #[test]
    fn active_false_as_text() {
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "Replace", "path": "active", "value": "False" },
        ]});
        strict_refuses_patch(Kind::User, &user(), &body);
        assert_eq!(
            patch_ok(Kind::User, &user(), &body, &profile(P))["active"],
            false
        );
    }

    // IDP-23: Entra removes members by value list
    #[test]
    fn remove_member_by_value() {
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "Remove", "path": "members", "value": [{ "value": "u-1" }] },
        ]});
        let r = patch_ok(Kind::Group, &group(), &body, &profile(P));
        assert_eq!(r["members"], json!([{ "value": "u-2" }]));
        let lower = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "remove", "path": "members", "value": [{ "value": "u-1" }] },
        ]});
        let s = Profile::strict();
        let strict = patch::apply(
            Kind::Group,
            &group(),
            &patch::parse(&lower, &s).unwrap(),
            &s,
        )
        .unwrap();
        assert!(
            strict.get("members").is_none(),
            "strict remove drops the whole attribute"
        );
    }

    // IDP-23: Entra clears an attribute with an empty value
    #[test]
    fn empty_value_clears() {
        let mut u = user();
        u["title"] = json!("Engineer");
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "Replace", "path": "title", "value": "" },
        ]});
        assert!(
            patch_ok(Kind::User, &u, &body, &profile(P))
                .get("title")
                .is_none()
        );
    }

    // IDP-23
    #[test]
    fn group_list_without_members() {
        assert!(profile(P).has(Rule::GroupMembersOmitted));
    }

    // IDP-23
    #[test]
    fn no_etag() {
        assert!(profile(P).has(Rule::NoEtag));
    }
}

mod okta {
    use super::*;

    const P: &str = "scim.okta";

    // IDP-23: Okta posts application/json
    #[test]
    fn plain_json_body() {
        assert!(profile(P).has(Rule::ContentTypeJson));
        assert!(!Profile::strict().has(Rule::ContentTypeJson));
    }

    // IDP-23: a recorded Okta user creation with an app profile attribute
    #[test]
    fn custom_attributes_dropped() {
        let body = json!({
            "schemas": [USER], "userName": "grace@okta.example",
            "name": { "givenName": "Grace", "familyName": "Hopper" },
            "emails": [{ "primary": true, "value": "grace@okta.example", "type": "work" }],
            "displayName": "Grace Hopper", "locale": "en-US", "externalId": "00u1abcd",
            "groups": [], "active": true, "favoriteShip": "USS Hopper",
        });
        assert!(canonical(Kind::User, &body, &Profile::strict()).is_err());
        let c = canonical(Kind::User, &body, &profile(P)).unwrap();
        assert!(c.get("favoriteShip").is_none());
        assert_eq!(c["externalId"], "00u1abcd");
    }

    // IDP-23
    #[test]
    fn user_name_filter_ignores_case() {
        let e = filter::parse(
            Kind::User,
            r#"userName eq "GRACE@okta.example""#,
            &profile(P),
        )
        .unwrap();
        assert!(filter::eval(
            Kind::User,
            &e,
            &json!({ "userName": "grace@okta.example" })
        ));
    }

    // IDP-23
    #[test]
    fn no_etag() {
        assert!(profile(P).has(Rule::NoEtag));
    }
}

mod google_workspace {
    use super::*;

    const P: &str = "scim.google-workspace";

    // IDP-23
    #[test]
    fn plain_json_body() {
        assert!(profile(P).has(Rule::ContentTypeJson));
    }

    // IDP-23
    #[test]
    fn cursor_page_without_total() {
        assert!(profile(P).has(Rule::ListWithoutTotal));
    }

    // IDP-23
    #[test]
    fn no_etag() {
        assert!(profile(P).has(Rule::NoEtag));
    }
}

mod onelogin {
    use super::*;

    const P: &str = "scim.onelogin";

    // IDP-23
    #[test]
    fn single_value_array() {
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "replace", "path": "title", "value": ["Engineer"] },
        ]});
        strict_refuses_patch(Kind::User, &user(), &body);
        assert_eq!(
            patch_ok(Kind::User, &user(), &body, &profile(P))["title"],
            "Engineer"
        );
    }

    // IDP-23
    #[test]
    fn active_as_text() {
        let body = json!({ "schemas": [USER], "userName": "a@onelogin.example", "active": "true" });
        assert!(canonical(Kind::User, &body, &Profile::strict()).is_err());
        assert_eq!(
            canonical(Kind::User, &body, &profile(P)).unwrap()["active"],
            true
        );
    }

    // IDP-23
    #[test]
    fn body_without_schemas() {
        let body = json!({ "userName": "a@onelogin.example" });
        assert!(canonical(Kind::User, &body, &Profile::strict()).is_err());
        assert!(canonical(Kind::User, &body, &profile(P)).is_ok());
    }

    // IDP-23
    #[test]
    fn no_etag() {
        assert!(profile(P).has(Rule::NoEtag));
    }
}

mod jumpcloud {
    use super::*;

    const P: &str = "scim.jumpcloud";

    // IDP-23
    #[test]
    fn urn_path_case() {
        let body = json!({ "schemas": [PATCH_SCHEMA], "Operations": [
            { "op": "replace", "path": "URN:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Ops" },
        ]});
        strict_refuses_patch(Kind::User, &user(), &body);
        assert_eq!(
            patch_ok(Kind::User, &user(), &body, &profile(P))[ENTERPRISE]["department"],
            "Ops"
        );
    }

    // IDP-23
    #[test]
    fn urn_filter_case() {
        let f = r#"URN:ietf:params:scim:schemas:core:2.0:User:userName eq "a""#;
        assert!(filter::parse(Kind::User, f, &Profile::strict()).is_err());
        assert!(filter::parse(Kind::User, f, &profile(P)).is_ok());
    }

    // IDP-23
    #[test]
    fn flat_enterprise_attributes() {
        let body = json!({ "schemas": [USER, ENTERPRISE], "userName": "a@jc.example",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber": "42" });
        assert!(canonical(Kind::User, &body, &Profile::strict()).is_err());
        let c = canonical(Kind::User, &body, &profile(P)).unwrap();
        assert_eq!(c[ENTERPRISE]["employeeNumber"], "42");
    }

    // IDP-23
    #[test]
    fn no_etag() {
        assert!(profile(P).has(Rule::NoEtag));
    }
}

// IDP-40 (5): no profile names a rule outside format tolerance; the strict server keeps every
// limit under every profile
#[test]
fn no_profile_widens_a_limit() {
    let deep = format!("{}userName pr{}", "(".repeat(33), ")".repeat(33));
    for (name, _) in access_identity_scim::domain::tolerance::SHIPPED {
        let p = profile(name);
        let e = filter::parse(Kind::User, &deep, &p).unwrap_err();
        assert_eq!(e.status, 400, "{name}");
        assert_eq!(e.scim_type.unwrap().name(), "invalidFilter", "{name}");
    }
}
