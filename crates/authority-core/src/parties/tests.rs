#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_kernel::meta::{Ended, EndedHow};

use super::*;

fn state(kind: ActorKind, since: u64, ended: Option<u64>) -> PartyState {
    PartyState {
        anchor: Id([5; 16]),
        actor_kind: kind,
        since,
        ended: ended.map(|at| Ended {
            at,
            how: EndedHow::Departed,
        }),
    }
}

// OP-149 m.28 (c)
#[test]
fn a_party_is_read_at_a_ledger_position() {
    let s = state(ActorKind::System, 5, Some(9));
    let party = Id([3; 16]);
    assert!(entry(party, &s, 4, 5_000, Some(9_000)).is_none());
    let live = entry(party, &s, 8, 5_000, Some(9_000)).unwrap();
    assert_eq!(
        (live.actor_kind, live.since),
        (ActorKind::System, Point { pos: 5, at: 5_000 })
    );
    assert!(live.ended.is_none());
    let ended = entry(party, &s, 9, 5_000, Some(9_000)).unwrap();
    assert_eq!(ended.ended, Some(Point { pos: 9, at: 9_000 }));
    let human = state(ActorKind::Human, 2, None);
    assert!(
        entry(party, &human, 20, 2_000, None)
            .unwrap()
            .ended
            .is_none()
    );
}

fn committed(id: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/cddl/examples/party-lookup.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap();
    let hex = case["cbor"].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i.saturating_add(2)], 16).unwrap())
        .collect()
}

// OP-149 m.28 (c), m.8
#[test]
fn the_payload_is_the_committed_example() {
    let human = Lookup {
        domain: Digest([1; 32]),
        pos: 9,
        iat: 9_500,
        parties: vec![
            entry(
                Id([3; 16]),
                &state(ActorKind::Human, 5, None),
                9,
                5_000,
                None,
            )
            .unwrap(),
        ],
        unknown: vec![Id([8; 16])],
    };
    assert_eq!(payload(&human), committed("human-party-admitted"));
    let ended = Lookup {
        domain: Digest([1; 32]),
        pos: 12,
        iat: 12_500,
        parties: vec![
            entry(
                Id([3; 16]),
                &state(ActorKind::System, 5, Some(9)),
                12,
                5_000,
                Some(9_000),
            )
            .unwrap(),
        ],
        unknown: Vec::new(),
    };
    assert_eq!(payload(&ended), committed("system-party-departed"));
    let nothing = Lookup {
        domain: Digest([1; 32]),
        pos: 3,
        iat: 3_500,
        parties: Vec::new(),
        unknown: vec![Id([8; 16])],
    };
    assert_eq!(payload(&nothing), committed("nothing-known"));
}
