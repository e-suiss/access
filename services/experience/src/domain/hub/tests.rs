#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use serde_json::{Value, json};

use super::*;

const ME: &str = "bWU";
const ALICE: &str = "YWxpY2U";
const ANCHOR: &str = "YW5jaG9y";

fn holding(groups: &[&str], source: &Value, extra: &Value) -> Value {
    let mut v = json!({
        "type": "holding",
        "grant": "Z3JhbnQ",
        "groups": groups,
        "holder": { "party": ALICE },
        "source": source,
        "capacities": ["own"],
        "actions": [{ "namespace": "shop", "name": "read", "major": 1, "schema": "cw" }],
        "resource": {},
        "validity": { "from": 0, "until": 99 },
        "budget": [],
        "conditions": 0,
        "since": 3,
        "revision": 0,
    });
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e.clone());
    }
    v
}

fn domain(name: &str, label: &str, reads: Vec<(Kind, Read)>) -> DomainReads {
    DomainReads {
        domain: DomainRef {
            domain: name.to_owned(),
            label: Some(label.to_owned()),
        },
        reads,
    }
}

fn one(results: Vec<Value>) -> Vec<DomainReads> {
    vec![domain(
        "ZA",
        "Personal",
        vec![(Kind::Inventory, Read::Answered(results))],
    )]
}

// XI-10, X6
#[test]
fn capacity_is_always_shown_apart_from_provenance() {
    let shared = holding(
        &["shared_from_you"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "capacities": [{ "for": "YWNtZQ" }] }),
    );
    let no_agency = holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "capacities": [] }),
    );
    let hub = assemble(ME, Depth::Default, 10, &one(vec![shared, no_agency]));
    let s = &hub.shared_from_you[0];
    assert_eq!(s.capacity[0].text, texts::CAPACITY_ON_BEHALF);
    assert_eq!(s.capacity[0].party.as_deref(), Some("YWNtZQ"));
    let y = &hub.your_authority[0];
    assert_eq!(y.capacity.len(), 1, "an absent agency is own (INV-4)");
    assert_eq!(y.capacity[0].text, texts::CAPACITY_AS_YOURSELF);
}

// XI-11, XI-5, §8.17.7.1
#[test]
fn offered_actions_follow_the_readers_authority_and_name_who_can() {
    let root = json!({ "type": "root", "anchor": ANCHOR, "sole": true, "quorum": 1, "since": 1 });
    let given = holding(
        &["shared_from_you"],
        &json!({ "anchor": ANCHOR }),
        &json!({}),
    );
    let held = holding(
        &["your_authority"],
        &json!({ "anchor": "b3RoZXI" }),
        &json!({}),
    );
    let hub = assemble(ME, Depth::Default, 10, &one(vec![root, given, held]));
    let offers = &hub.shared_from_you[0].offers;
    let names: Vec<&str> = offers.iter().map(|o| o.action.as_str()).collect();
    assert_eq!(names, ["revoke", "narrow", "suspend"]);
    assert!(offers.iter().all(|o| o.available && o.steps <= 2));
    let held = &hub.your_authority[0].offers;
    assert!(held.iter().all(|o| !o.available));
    assert!(
        held.iter()
            .all(|o| o.who_can.as_deref() == Some(texts::WHO_CAN_GRANTOR)),
        "an action the reader cannot take is shown with who can"
    );
    assert!(!held.iter().any(|o| o.action == "suspend"));
    assert_eq!(hub.roots[0].confirm, texts::ROOT_SOLE_CONFIRM);
}

// XI-14
#[test]
fn two_limits_are_two_rows_with_owners() {
    let limited = holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "budget": [
            { "dimension": "count", "capacity": 3, "window": "day" },
            { "dimension": "amount", "capacity": 2000, "window": "day" },
        ] }),
    );
    let hub = assemble(ME, Depth::Default, 10, &one(vec![limited]));
    let limits = &hub.your_authority[0].limits;
    assert_eq!(limits.len(), 2);
    assert!(
        limits
            .iter()
            .all(|l| l.kind == "authority" && l.owner == Owner::Access)
    );
    assert_ne!(limits[0].term, limits[1].term);
}

// XI-15, X16
#[test]
fn a_lapsed_selection_needs_refresh_and_is_not_removed() {
    let rule = holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "holder": { "group": ["employee"] }, "member": false }),
    );
    let hub = assemble(ME, Depth::Default, 10, &one(vec![rule]));
    let r = &hub.your_authority[0];
    assert_eq!(r.freshness, Freshness::NeedsRefresh);
    assert_eq!(r.status, texts::STATUS_NEEDS_REFRESH);
    assert_eq!(r.who.classes, ["employee"]);
}

// XI-16, §8.17.7.2, E25, IA-6
#[test]
fn rows_carry_as_of_and_an_unreachable_domain_is_unknown() {
    let rows = vec![holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({}),
    )];
    let hub = assemble(
        ME,
        Depth::Default,
        1_234,
        &[
            domain(
                "ZA",
                "Personal",
                vec![(Kind::Inventory, Read::Answered(rows))],
            ),
            domain("ZB", "Acme", vec![(Kind::Inventory, Read::Unknown)]),
        ],
    );
    assert!(hub.show_domains);
    assert_eq!(hub.your_authority[0].as_of, 1_234);
    assert_eq!(hub.your_authority[0].label.as_deref(), Some("Personal"));
    let acme = hub.domains.iter().find(|d| d.domain == "ZB").unwrap();
    assert_eq!(acme.freshness, Freshness::Unknown);
    assert_eq!(acme.as_of, None);
    assert_eq!(acme.text, texts::DOMAIN_UNREACHABLE);
    assert!(hub.notices.contains(&texts::NOT_SHOWN.to_owned()));
    assert!(hub.notices.contains(&texts::SOME_UNKNOWN.to_owned()));
    let single = assemble(ME, Depth::Default, 1, &one(Vec::new()));
    assert!(!single.show_domains, "one domain shows no domain concept");
    assert_eq!(single.notices, [texts::NOT_SHOWN]);
}

// XI-22, XI-9, S6, §8.17.12
#[test]
fn nothing_about_others_or_from_elsewhere_is_surfaced() {
    let foreign = json!({ "type": "memory", "text": "private" });
    let groupless = holding(&[], &json!({ "anchor": ANCHOR }), &json!({}));
    let others_use = json!({
        "type": "use", "pos": 9, "intent": "aQ", "basis": { "grant": "Zw" },
        "capacity": { "for": ALICE }, "instance": "aW4", "by_viewer": false,
    });
    let my_use = json!({
        "type": "use", "pos": 8, "at": 80, "intent": "aQ", "basis": { "grant": "Zw" },
        "capacity": "own", "instance": "aW4", "by_viewer": true,
    });
    let for_me = json!({
        "type": "use", "pos": 7, "at": 70, "intent": "aQ", "basis": { "grant": "Zw" },
        "capacity": { "for": ME }, "instance": "aW4", "by_viewer": false,
    });
    let hub = assemble(
        ME,
        Depth::Default,
        10,
        &[domain(
            "ZA",
            "Personal",
            vec![
                (
                    Kind::Inventory,
                    Read::Answered(vec![foreign.clone(), groupless]),
                ),
                (
                    Kind::Activity,
                    Read::Answered(vec![others_use, my_use, for_me]),
                ),
                (Kind::Changes, Read::Answered(vec![foreign])),
            ],
        )],
    );
    assert!(hub.your_authority.is_empty() && hub.shared_from_you.is_empty());
    assert!(hub.acting_for_you.is_empty() && hub.changes.is_empty());
    let texts: Vec<&str> = hub.activity.iter().map(|a| a.text.as_str()).collect();
    assert_eq!(texts, [texts::ACTIVITY_BY_YOU, texts::ACTIVITY_FOR_YOU]);
    assert!(hub.activity.iter().all(|a| a.instance.is_none()));
}

// IA-2, SI-21, U26, SI-13, X27
#[test]
fn changes_are_information_only() {
    let key = json!({
        "type": "change", "position": "5", "at": 50, "kind": "key_event", "id": "Y2xhaW0",
        "class": "party_key_state", "issuer": "Y3VzdG9kaWFu", "ended": false, "own": false,
    });
    let grant = json!({ "type": "change", "position": "6", "at": 60, "kind": "grant", "id": "Zw", "ended": true, "own": false });
    let hub = assemble(
        ME,
        Depth::Default,
        10,
        &[domain(
            "ZA",
            "P",
            vec![(Kind::Changes, Read::Answered(vec![key, grant]))],
        )],
    );
    assert_eq!(hub.changes.len(), 2);
    assert_eq!(hub.changes[0].kind, "grant", "newest first");
    assert_eq!(hub.changes[0].text, "change.grant_ended");
    let k = &hub.changes[1];
    assert_eq!(k.key_event.as_ref().unwrap()["class"], "party_key_state");
    assert!(hub.changes.iter().all(|c| c.derived));
    let text = serde_json::to_string(&hub).unwrap();
    assert!(!text.contains("action_required") && !text.contains("requests"));
}

// §8.12, X25, Ek B 3687, 3889
#[test]
fn deeper_explains_and_never_hides_capacity_or_status() {
    let rows = vec![holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "named": { "name": "clerk", "version": 2 } }),
    )];
    let default = assemble(ME, Depth::Default, 1, &one(rows.clone()));
    let expert = assemble(ME, Depth::Expert, 1, &one(rows));
    let (d, e) = (&default.your_authority[0], &expert.your_authority[0]);
    assert!(d.expert.is_none());
    let x = e.expert.as_ref().unwrap();
    assert_eq!(x.role.as_ref().unwrap()["name"], "clerk");
    assert_eq!(d.capacity, e.capacity);
    assert_eq!(d.status, e.status);
    assert_eq!(d.what, e.what);
}
