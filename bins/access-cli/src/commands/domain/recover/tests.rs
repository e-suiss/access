#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use std::collections::BTreeSet;

use access_authority_core::app::forced::{Arm, Plan};
use access_kernel::digest::Digest;
use access_kernel::recovery::{CheckpointRef, LostSuffix};
use serde_json::json;

use super::{discover, plan_view, targets};

// PR-2, PR-3, XI-19, §13.6, Ek B 6025
#[test]
fn discovery_lists_only_revocations_from_n_on() {
    let receipts = [
        json!({ "position": "4", "action": "grant_revoke", "exercise": "a" }),
        json!({ "position": "9", "action": "grant_revoke", "exercise": "b" }),
        json!({ "position": "10", "action": "instance_terminate", "exercise": "c" }),
        json!({ "position": "11", "action": "grant_issue", "exercise": "d" }),
    ];
    let found = discover(9, None, &receipts);
    let positions: Vec<&str> = found
        .iter()
        .map(|f| f["position"].as_str().unwrap())
        .collect();
    assert_eq!(positions, ["9", "10"]);
    assert!(found.iter().all(|f| f["source"] == "receipt"));
}

// FR-3, SEC22, §13.6
#[test]
fn the_plan_names_n_its_checkpoint_the_arm_and_the_lost_suffix() {
    let p = Plan {
        n: 3,
        cited: CheckpointRef::new(3, Digest([1; 32])),
        replica_head: Some(CheckpointRef::new(3, Digest([1; 32]))),
        lost_suffix: Some(LostSuffix::new(3, 5)),
        fork: BTreeSet::new(),
        arm: Arm::Lossy,
    };
    let v = plan_view(&p);
    assert_eq!(v["n"], "3");
    assert_eq!(v["arm"], "ii");
    assert_eq!(v["lost_suffix"]["to"], "5");
    assert_eq!(v["replica_head"]["size"], "3");
    assert!(targets(&[String::from("http://127.0.0.1:1")]).is_err());
}
