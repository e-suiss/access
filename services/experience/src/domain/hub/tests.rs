#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
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

// XI-15, X16, C13, INV-31
#[test]
fn stale_is_not_removed_and_a_rejoin_is_a_new_episode() {
    let rule = |selection: Value| {
        holding(
            &["your_authority"],
            &json!({ "anchor": ANCHOR }),
            &json!({ "holder": { "group": ["employee"] }, "selection": selection }),
        )
    };
    let rows = vec![
        rule(json!({ "state": "stale", "since": 4, "by": "hr", "stated_at": 3 })),
        rule(json!({ "state": "ended", "pos": 9, "at": 1_700, "by": "hr", "stated_at": 8 })),
        rule(json!({ "state": "ended" })),
        rule(json!({ "state": "current", "since": 12, "by": "hr", "stated_at": 11 })),
    ];
    let hub = assemble(ME, Depth::Default, 10, &one(rows));
    let [stale, ended, undated, rejoined] = &hub.your_authority[..] else {
        panic!("{:?}", hub.your_authority);
    };
    assert_eq!(stale.status, texts::STATUS_STALE);
    assert_eq!(stale.freshness, Freshness::Current);
    assert_eq!(
        stale.selection.as_ref().map(|s| (s.state, s.since)),
        Some((SelectionState::Stale, Some(4)))
    );
    // XI-15, §8.17.5.7, Ek B 3704
    let said = |r: &crate::contract::Row| {
        r.selection
            .as_ref()
            .map(|s| (s.by.clone(), s.stated_at, s.reason.clone()))
    };
    let because = Some(String::from(texts::SELECTION_BECAUSE));
    assert_eq!(
        said(stale),
        Some((Some(String::from("hr")), Some(3), because.clone()))
    );
    assert_eq!(
        said(ended),
        Some((
            Some(String::from("hr")),
            Some(8),
            Some(String::from(texts::SELECTION_NO_LONGER))
        ))
    );
    assert_eq!(said(undated), Some((None, None, None)));
    assert_eq!(
        said(rejoined),
        Some((Some(String::from("hr")), Some(11), because))
    );
    assert_eq!(stale.who.classes, ["employee"]);
    assert_eq!(ended.status, texts::STATUS_ENDED);
    assert_eq!(
        ended
            .selection
            .as_ref()
            .map(|s| (s.state, s.pos, s.at, s.since)),
        Some((SelectionState::Ended, Some(9), Some(1_700), None))
    );
    assert_eq!(undated.status, texts::STATUS_ENDED_UNDATED);
    assert_ne!(stale.status, ended.status);
    assert_eq!(rejoined.status, texts::STATUS_CURRENT);
    assert_eq!(
        rejoined.selection.as_ref().map(|s| (s.state, s.since)),
        Some((SelectionState::Current, Some(12)))
    );
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

fn financial(grant: &str, body: Value) -> Financial {
    Financial {
        grant: grant.to_owned(),
        pay_limit: body,
        as_of: 77,
    }
}

// XI-14, E21, F9
#[test]
fn a_financial_limit_is_pays_own_row_and_never_derived_from_the_authority_limit() {
    let budget = json!({ "dimension": "amount", "capacity": 50_000, "window": "transaction" });
    let limited = holding(
        &["shared_from_you"],
        &json!({ "anchor": ANCHOR }),
        &json!({ "budget": [budget] }),
    );
    let mut hub = assemble(ME, Depth::Default, 10, &one(vec![limited]));
    let pay =
        json!({ "currency": "TRY", "limit_minor": 500_000, "period": "day", "held_minor": 12_000 });
    place_financial(
        &mut hub,
        &[
            financial("Z3JhbnQ", pay.clone()),
            financial("b3RoZXI", pay.clone()),
        ],
    )
    .unwrap();
    let limits = &hub.shared_from_you[0].limits;
    assert_eq!(limits.len(), 2, "one row per limit and owner");
    assert_eq!(
        (
            limits[0].kind.as_str(),
            limits[0].owner,
            &limits[0].term,
            limits[0].as_of
        ),
        ("authority", Owner::Access, &budget, None)
    );
    assert_eq!(
        (
            limits[1].kind.as_str(),
            limits[1].owner,
            &limits[1].term,
            limits[1].as_of
        ),
        ("financial", Owner::Pay, &pay, Some(77))
    );

    let mut without = assemble(
        ME,
        Depth::Default,
        10,
        &one(vec![holding(
            &["shared_from_you"],
            &json!({ "anchor": ANCHOR }),
            &json!({ "budget": [budget] }),
        )]),
    );
    place_financial(&mut without, &[]).unwrap();
    assert_eq!(
        without.shared_from_you[0].limits.len(),
        1,
        "no financial row is made up from the authority limit"
    );
    let unlimited = holding(
        &["shared_from_you"],
        &json!({ "anchor": ANCHOR }),
        &json!({}),
    );
    let mut pay_only = assemble(ME, Depth::Default, 10, &one(vec![unlimited]));
    place_financial(&mut pay_only, &[financial("Z3JhbnQ", pay.clone())]).unwrap();
    assert!(
        pay_only.shared_from_you[0]
            .limits
            .iter()
            .all(|l| l.owner == Owner::Pay),
        "no authority row is made up from Pay's figure"
    );

    for bad in [
        json!({ "currency": "try", "limit_minor": 1, "period": "day" }),
        json!({ "currency": "TRY", "limit_minor": -1, "period": "day" }),
        json!({ "currency": "TRY", "limit_minor": 1, "period": "week" }),
        json!({ "currency": "TRY", "limit_minor": 1, "period": "day", "remaining": 3 }),
    ] {
        let mut h = assemble(ME, Depth::Default, 10, &one(Vec::new()));
        assert_eq!(
            place_financial(&mut h, &[financial("Z3JhbnQ", bad)]),
            Err(Malformed("financial"))
        );
    }
}

// §8.13, INV-24, E30, OP-156 m.11 (e)
#[test]
fn a_relay_delay_is_a_notice_and_never_makes_a_revocation_pending() {
    let results = vec![holding(
        &["your_authority"],
        &json!({ "anchor": ANCHOR }),
        &json!({}),
    )];
    let changes = vec![json!({
        "type": "change", "kind": "grant", "id": "Z29uZQ", "position": "9", "ended": true, "own": true, "at": 5,
    })];
    let reads = vec![domain(
        "ZA",
        "Personal",
        vec![
            (Kind::Inventory, Read::Answered(results)),
            (Kind::Activity, Read::Answered(Vec::new())),
            (Kind::Changes, Read::Answered(changes)),
        ],
    )];
    let before = assemble(ME, Depth::Default, 10, &reads);
    let mut after = before.clone();
    let d = delivery(&json!({ "relay_lag_ms": 61_000, "notifications_delayed": true })).unwrap();
    assert_eq!(d.owner, Owner::Relay);
    show_delivery(&mut after, d);
    assert_eq!(after.your_authority, before.your_authority);
    assert_eq!(after.changes, before.changes);
    assert_eq!(after.changes[0].text, "change.grant_ended");
    assert!(
        after
            .notices
            .contains(&texts::NOTIFICATIONS_DELAYED.to_owned())
    );
    let mut on_time = before.clone();
    show_delivery(
        &mut on_time,
        delivery(&json!({ "relay_lag_ms": null, "notifications_delayed": false })).unwrap(),
    );
    assert_eq!(on_time.notices, before.notices);
    assert_eq!(delivery(&json!({ "relay_lag_ms": "soon" })), None);
}

// §8.13, OP-156 m.6 (d)
#[test]
fn access_unavailable_says_authority_cant_change_and_points_to_the_runtime() {
    let hub = assemble(
        ME,
        Depth::Default,
        1,
        &[domain(
            "ZA",
            "Personal",
            vec![(Kind::Inventory, Read::Unknown)],
        )],
    );
    assert!(hub.notices.contains(&texts::ACCESS_UNAVAILABLE.to_owned()));
    assert!(hub.your_authority.is_empty() && hub.acting_for_you.is_empty());
    let partly = assemble(
        ME,
        Depth::Default,
        1,
        &[
            domain("ZA", "Personal", vec![(Kind::Inventory, Read::Unknown)]),
            domain(
                "ZB",
                "Acme",
                vec![(Kind::Inventory, Read::Answered(Vec::new()))],
            ),
        ],
    );
    assert!(
        !partly
            .notices
            .contains(&texts::ACCESS_UNAVAILABLE.to_owned())
    );
}

// §8.17.9.8, INV-16, Ek B 5287
#[test]
fn an_hr_selection_shows_sync_from_hr_with_its_issuer() {
    let hr = |classes: Value, by: Option<&str>| {
        holding(
            &["your_authority"],
            &json!({ "anchor": ANCHOR }),
            &json!({
                "holder": { "group": classes },
                "selection": { "state": "current", "since": 4, "by": by, "stated_at": 3 },
            }),
        )
    };
    let hub = assemble(
        ME,
        Depth::Default,
        1,
        &one(vec![
            hr(json!(["hr_department"]), Some("aHI")),
            hr(json!(["hr_department", "staff"]), Some("aHI")),
            hr(json!(["hr_title"]), None),
        ]),
    );
    let rows = &hub.your_authority;
    assert_eq!(
        rows[0].source,
        Some(SourceLabel {
            text: texts::SOURCE_SYNC_FROM_HR.to_owned(),
            issuer: "aHI".to_owned()
        })
    );
    assert_eq!(rows[1].source, None, "not only HR classes");
    assert_eq!(rows[2].source, None, "no statement said so");
}
