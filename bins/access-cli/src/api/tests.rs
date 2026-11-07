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
    // OP-150 m.11 (b): routes declared but answered 501 are reserved
    for op in ["deleteAccount", "rehomeRealm", "createResetIntent"] {
        assert!(reserved(op, true), "{op}");
    }
    assert!(!reserved("markCanaryAccount", true));
    assert!(!reserved("putJoseAlg", true));
    assert!(!reserved("patchCimdPolicy", true));
    assert!(!reserved("putProtectionMode", true));
    for op in &contract().operations {
        if op.writes()
            && !DECLARED_RESERVED.contains(&op.id.as_str())
            && !UNSUPPORTED.contains(&op.id.as_str())
        {
            assert!(
                action_of(&op.id, true).is_some(),
                "{} has no idp.* action",
                op.id
            );
        }
    }
}

// OP-151 m.3 (o): tightening the protection mode is protection_mode (CT1), loosening
// protection_mode_loosen (CT2), as the server's tier rule decides
#[test]
fn the_protection_mode_action_follows_the_tier_rule() {
    use serde_json::json;
    let base = json!({"bot": "monitor", "suspicious_ip": "monitor", "breached_password": "monitor",
        "brute_force": "enforce", "sl2": "shadow", "denied_asns": []});
    let tight = json!({"bot": "monitor", "suspicious_ip": "enforce", "breached_password": "monitor",
        "brute_force": "enforce", "sl2": "stepup", "denied_asns": [64496]});
    assert_eq!(
        protection_action(&base, &tight),
        IdpAction::RealmProtectionMode
    );
    assert_eq!(
        protection_action(&tight, &base),
        IdpAction::RealmProtectionModeLoosen
    );
    assert_eq!(
        protection_action(&base, &json!({"sl2": "nonsense"})),
        IdpAction::RealmProtectionModeLoosen
    );
    assert_eq!(
        action_of("patchProtectionMode", true),
        Some(IdpAction::RealmProtectionModeLoosen)
    );
}

// TN-125: a bulk job is refused by `access admin`; every listed write is placed
#[test]
fn every_contract_write_is_placed_or_refused_explicitly() {
    for op in &contract().operations {
        if !op.writes() {
            continue;
        }
        let placed = action_of(&op.id, true).is_some();
        let listed =
            DECLARED_RESERVED.contains(&op.id.as_str()) || UNSUPPORTED.contains(&op.id.as_str());
        assert!(placed ^ listed, "{}", op.id);
    }
}
