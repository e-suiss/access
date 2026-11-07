#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

// TN-112 item 8: the command line knows the realm surface from the generated contract
#[test]
fn the_contract_names_the_realm_resources_and_their_operations() {
    let c = contract();
    let resources = c.resources();
    for r in [
        "clients",
        "groups",
        "upstream-idps",
        "accounts",
        "settings",
        "mappers",
    ] {
        assert!(resources.contains(r), "{r}");
    }
    let put = c.find("clients", Method::Put, true, "").unwrap();
    assert_eq!(put.id, "putClient");
    assert!(put.writes());
    assert_eq!(
        put.url_path("acme", Some("c 1")),
        "/admin/v1/realms/acme/clients/c%201"
    );
    let retire = c.find("groups", Method::Post, true, "/retire").unwrap();
    assert_eq!(
        retire.url_path("acme", Some("ops")),
        "/admin/v1/realms/acme/groups/ops/retire"
    );
    let branding = c
        .find("settings/branding", Method::Patch, false, "")
        .unwrap();
    assert_eq!(branding.id, "patchBranding");
    let list = c.find("clients", Method::Get, false, "").unwrap();
    assert_eq!(list.scope.as_deref(), Some("realm.read"));
    assert!(c.find("tokens", Method::Get, false, "").is_none());
    assert!(c.read_only("Client", "status"));
    assert!(!c.read_only("Client", "display_name"));
}

// TN-122, E11: reserved writes are known by their idp.* action; an unknown one is reserved
#[test]
fn reserved_operations_follow_the_idp_catalog_and_unknown_ones_fail_closed() {
    assert!(reserved("putUpstreamIdp", false));
    assert!(reserved("putUpstreamIdp", true));
    assert!(reserved("patchUpstreamIdp", true));
    assert!(reserved("putRpId", true));
    assert!(!reserved("putBranding", true));
    assert!(!reserved("createClient", false));
    assert!(!reserved("retireUpstreamIdp", true));
    assert!(reserved("deleteEverything", true));
    for op in &contract().operations {
        if op.writes() {
            assert!(
                action_of(&op.id, true).is_some(),
                "{} has no idp.* action",
                op.id
            );
        }
    }
}
