//! The developer search kinds (L1-ADP-16, §8.17.10, X21, §5.4, SEC15): their queries and the
//! reports they answer with.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_authority_core::app::impact::{
    Acknowledged, Aftermath, Compromised, Exposure, RevocationImpact, Revoked,
};
use access_authority_core::app::publishing::{Diff, Notes, Offer, Standing};
use access_authority_core::query::{Change, Hit, Query, Report};
use access_http::adp::domain::{decode_search, encode_search};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::{Id, Window};

fn body(kind: &str, query: &str) -> Vec<u8> {
    let b = |bytes: &[u8]| b64url_encode(bytes);
    format!(
        r#"{{"context": {{
                "domain": "{d}", "mode": "check", "nonce": "{n}",
                "basis": {{"public": "{a}"}}, "capacity": "own",
                "intent": {{
                    "action": {{"namespace": "access", "name": "read", "major": 1, "schema": "{s}"}},
                    "resources": [{{"namespace": "access.search", "path": ["{kind}"]}}],
                    "validity": {{"from": 0, "until": 100000}}
                }},
                "query": {query}
            }}}}"#,
        d = b(&[1; 32]),
        n = b(&[2; 16]),
        a = b(&[3; 16]),
        s = b(&[5; 32]),
    )
    .into_bytes()
}

fn decode(kind: &str, query: &str) -> Result<Query, &'static str> {
    decode_search(&body(kind, query), 65_536, kind)
        .map(|(_, q, _)| q)
        .map_err(|e| e.0)
}

// L1-ADP-16, §8.17.10
#[test]
fn developer_kinds_decode_their_queries() {
    let id = b64url_encode(&[7; 16]);
    assert_eq!(
        decode("schema-publications", r#"{"namespace": "commerce"}"#),
        Ok(Query::SchemaPublications {
            namespace: "commerce".to_owned()
        })
    );
    assert_eq!(
        decode("change-impact", r#"{"role": "clerk", "from": 1, "to": 2}"#),
        Ok(Query::ChangeImpact(Change::Role {
            name: "clerk".to_owned(),
            from: 1,
            to: 2
        }))
    );
    assert_eq!(
        decode(
            "change-impact",
            &format!(r#"{{"policy": "{id}", "candidate": "oA"}}"#)
        ),
        Ok(Query::ChangeImpact(Change::Policy {
            policy: Some(Id([7; 16])),
            candidate: vec![0xa0]
        }))
    );
    assert_eq!(
        decode(
            "revocation-impact",
            &format!(r#"{{"grant": "{id}", "at": 5}}"#)
        ),
        Ok(Query::RevocationImpact {
            revoked: Revoked::Grant(Id([7; 16])),
            at: Some(5)
        })
    );
    assert_eq!(
        decode(
            "compromise-impact",
            &format!(r#"{{"issuer": "{id}", "window": {{"from": 1, "until": 2}}}}"#)
        ),
        Ok(Query::CompromiseImpact {
            compromised: Compromised::Issuer(Id([7; 16])),
            window: Window { from: 1, until: 2 }
        })
    );
}

// SEC15, §5.4
#[test]
fn ambiguous_or_unknown_queries_are_refused() {
    let id = b64url_encode(&[7; 16]);
    assert_eq!(
        decode(
            "revocation-impact",
            &format!(r#"{{"grant": "{id}", "instance": "{id}"}}"#)
        ),
        Err("query")
    );
    assert_eq!(
        decode(
            "compromise-impact",
            r#"{"window": {"from": 1, "until": 2}}"#
        ),
        Err("query")
    );
    assert_eq!(
        decode(
            "schema-publications",
            r#"{"namespace": "a", "accept": true}"#
        ),
        Err("unknown-member")
    );
}

// X21, E10, E11
#[test]
fn a_publication_report_has_no_accept() {
    let offer = Offer {
        fingerprint: Digest([9; 32]),
        publisher: Id([1; 16]),
        namespace: "commerce".to_owned(),
        catalog_version: 3,
        standing: Standing::Pending {
            accepted_version: Some(2),
        },
        diff: Diff {
            added: vec!["void".to_owned()],
            ..Diff::default()
        },
        reserved: Vec::new(),
        classes: Vec::new(),
        compatibility: None,
        notes: Notes {
            existing_grants_unchanged: true,
            new_actions: vec!["void".to_owned()],
            text: vec!["publish.existing_grants_unchanged"],
        },
    };
    let out = encode_search(
        &[Hit::Report(Box::new(Report::Publication(offer)))],
        None,
        true,
    );
    let r = &out["results"][0];
    assert_eq!(r["standing"], "pending_acceptance");
    assert_eq!(r["accepted_version"], 2);
    assert_eq!(r["existing_grants_unchanged"], true);
    assert_eq!(r["new_actions"][0], "void");
    assert_eq!(r["advisory"], true);
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert!(
        keys.iter()
            .all(|k| !k.contains("accept_") && *k != "accept")
    );
}

// §5.4, XI-3
#[test]
fn a_revocation_report_carries_exposure_and_aftermath() {
    let report = RevocationImpact {
        revoked: Revoked::Instance(Id([4; 16])),
        at: 100,
        subtree: Vec::new(),
        exposed: vec![Exposure {
            exercise: Digest([5; 32]),
            holder: Id([6; 16]),
            class: "offline".to_owned(),
            horizon_ms: 900,
            window_ms: 800,
            pep: "pos-7".to_owned(),
            applied_at: Some(150),
        }],
        max_exposure_ms: 800,
        index_lag: 2,
        orphan_tuples: 1,
        acknowledged: vec![Acknowledged {
            pep: "pos-7".to_owned(),
            applied_at: 150,
            basis: 12,
        }],
        aftermath: Aftermath {
            running_copies: 3,
            confirmed_applied: 1,
            ..Aftermath::default()
        },
    };
    let out = encode_search(
        &[Hit::Report(Box::new(Report::Revocation(report)))],
        None,
        true,
    );
    let r = &out["results"][0];
    assert_eq!(r["orphan_tuples"], 1);
    assert_eq!(r["index_lag"], 2);
    assert_eq!(r["aftermath"]["running_copies"], 3);
    // E15, E30
    assert_eq!(r["exposed"][0]["pep"], "pos-7");
    assert_eq!(r["exposed"][0]["applied_at"], 150);
    assert_eq!(r["acknowledged"][0]["basis"], 12);
    assert_eq!(r["aftermath"]["confirmed_applied"], 1);
    assert_eq!(r["revoked"]["instance"], b64url_encode(&[4; 16]));
}

// §8.17.7.1, S6, IA-2, XI-9
#[test]
fn hub_kinds_name_the_viewer_and_nothing_else() {
    let id = b64url_encode(&[7; 16]);
    for (kind, expected) in [
        ("inventory", Query::Inventory { party: Id([7; 16]) }),
        ("activity", Query::Activity { party: Id([7; 16]) }),
    ] {
        assert_eq!(
            decode(kind, &format!(r#"{{"party": "{id}"}}"#)),
            Ok(expected)
        );
        assert_eq!(
            decode(kind, &format!(r#"{{"party": "{id}", "all": true}}"#)),
            Err("unknown-member")
        );
    }
}

// §8.17.7.1, XI-10, IA-2
#[test]
fn hub_entries_carry_capacity_and_no_action() {
    use access_authority_core::app::hub::{Entry, Group, Holder, Holding, Source};
    use access_kernel::combinator::Capacity;
    use access_kernel::model::{ResourceSelector, Structural};
    let holding = Holding {
        grant: Id([1; 16]),
        groups: vec![Group::SharedFromYou],
        holder: Holder::Party(Id([2; 16])),
        source: Source::Anchor(Id([3; 16])),
        capacities: vec![Capacity::For(Id([4; 16]))],
        actions: Vec::new(),
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_owned(),
            prefix: Vec::new(),
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        validity: Window { from: 0, until: 9 },
        budget: Vec::new(),
        conditions: 0,
        named: None,
        since: 5,
        revision: 0,
        selection: None,
        said: None,
        agent: None,
        commitment: None,
    };
    let change = access_authority_core::app::management::Change {
        position: 7,
        at: 70,
        kind: access_authority_core::app::management::ChangeKind::KeyEvent,
        changed: access_authority_core::app::management::Changed::KeyEvent {
            claim: Id([6; 16]),
            class: "party_key_state".to_owned(),
            issuer: Id([5; 16]),
            subject: Id([7; 16]),
        },
        ended: false,
        own: false,
    };
    let out = encode_search(
        &[
            Hit::Entry(Box::new(Entry::Holding(Box::new(holding)))),
            Hit::Report(Box::new(Report::Change(change))),
        ],
        None,
        true,
    );
    let r = &out["results"][0];
    assert_eq!(r["type"], "holding");
    assert_eq!(r["groups"][0], "shared_from_you");
    assert_eq!(r["capacities"][0]["for"], b64url_encode(&[4; 16]));
    let c = &out["results"][1];
    assert_eq!(c["kind"], "key_event");
    assert_eq!(c["class"], "party_key_state");
    assert_eq!(c["id"], b64url_encode(&[6; 16]));
    for row in out["results"].as_array().unwrap() {
        let keys: Vec<&String> = row.as_object().unwrap().keys().collect();
        assert!(
            keys.iter()
                .all(|k| !k.contains("action_required") && *k != "revoke")
        );
    }
}

// XI-15, OP-153 m.25 (d), (h), Ek B 3704
#[test]
fn a_rule_shaped_row_carries_its_selection_state() {
    use access_authority_core::app::hub::{Entry, Group, Holder, Holding, Said, Selection, Source};
    use access_kernel::model::{ResourceSelector, Structural};
    let row = |selection: Option<Selection>| {
        Hit::Entry(Box::new(Entry::Holding(Box::new(Holding {
            grant: Id([1; 16]),
            groups: vec![Group::YourAuthority],
            holder: Holder::Group(vec!["staff".to_owned()]),
            source: Source::Anchor(Id([3; 16])),
            capacities: Vec::new(),
            actions: Vec::new(),
            resource: ResourceSelector::Structural(Structural {
                namespace: "shop".to_owned(),
                prefix: Vec::new(),
                kind: None,
                attrs: std::collections::BTreeMap::new(),
            }),
            validity: Window { from: 0, until: 9 },
            budget: Vec::new(),
            conditions: 0,
            named: None,
            since: 5,
            revision: 0,
            said: selection.map(|_| Said {
                issuer: Id([9; 16]),
                at: 70,
            }),
            selection,
            agent: None,
            commitment: None,
        }))))
    };
    let out = encode_search(
        &[
            row(Some(Selection::Stale { since: 4 })),
            row(Some(Selection::Ended {
                pos: Some(8),
                at: Some(80),
            })),
            row(Some(Selection::Ended {
                pos: None,
                at: None,
            })),
            row(None),
        ],
        None,
        true,
    );
    let r = &out["results"];
    let by = b64url_encode(&[9; 16]);
    assert_eq!(
        r[0]["selection"],
        serde_json::json!({ "state": "stale", "since": 4, "by": by, "stated_at": 70 })
    );
    assert_eq!(
        r[1]["selection"],
        serde_json::json!({ "state": "ended", "pos": 8, "at": 80, "by": by, "stated_at": 70 })
    );
    assert_eq!(
        r[2]["selection"],
        serde_json::json!({ "state": "ended", "by": by, "stated_at": 70 })
    );
    assert!(r[3].get("selection").is_none());
    assert!(r[0].get("member").is_none());
}

// OP-156 m.3 (k), INV-32
#[test]
fn the_incarnation_kind_decodes_and_reports() {
    assert_eq!(
        decode(
            "resource-incarnation",
            r#"{"namespace": "ride", "path": ["vehicles", "34-abc-12"]}"#
        ),
        Ok(Query::ResourceIncarnation {
            namespace: "ride".to_owned(),
            path: vec!["vehicles".to_owned(), "34-abc-12".to_owned()],
        })
    );
    for bad in [
        r#"{"namespace": "ride", "path": []}"#,
        r#"{"namespace": "ride"}"#,
        r#"{"namespace": "ride", "path": [1]}"#,
        r#"{"namespace": "ride", "path": ["v"], "extra": 1}"#,
    ] {
        assert!(decode("resource-incarnation", bad).is_err(), "{bad}");
    }
    let report = access_authority_core::app::resources::Incarnations {
        namespace: "ride".to_owned(),
        path: vec!["v".to_owned()],
        highest: Some(1),
        facts: vec![access_authority_core::app::resources::Fact {
            incarnation: 1,
            event: "reincarnate".to_owned(),
            claim: Id([4; 16]),
            issuer: Id([5; 16]),
            pos: 9,
        }],
    };
    let json = access_http::adp::report::encode(&Report::Incarnations(report));
    assert_eq!(json["type"], "resource-incarnation");
    assert_eq!(json["highest"], 1);
    assert_eq!(json["facts"][0]["event"], "reincarnate");
    assert_eq!(json["facts"][0]["position"], 9);
    assert_eq!(json["advisory"], true);
}
