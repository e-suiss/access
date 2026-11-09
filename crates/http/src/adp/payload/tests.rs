#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::format_collect,
    reason = "test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use access_kernel::combinator::Capacity;
use access_kernel::meta::{
    ActorKind, AnchorScope, Disposition, GrantBasis, GrantContent, HoldingRef, MandateEnvelope,
    Root, authority_set_digest, core_action,
};
use access_kernel::model::{
    ActionSet, Binding, Bound, BudgetDimension, BudgetTerm, BudgetWindow, Conjunct, ConstraintSet,
    Consumption, DelegationTerms, EqValue, Id, Independence, ProofKind, PurposeRef,
    RequirementTerm, ResourceRef, ResourceSelector, Structural, SubjectSelector, Window,
};
use serde_json::json;

use super::*;

fn id(b: u8) -> Id {
    Id([b; 16])
}

fn set() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([core_action("grant_revoke"), core_action("grant_amend")]),
            prefix: BTreeSet::from([(String::from("commerce"), Digest([7; 32]))]),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("commerce"),
            prefix: vec![String::from("eu")],
            kind: Some(String::from("order")),
            attrs: BTreeMap::from([(String::from("tier"), EqValue::Int(-2))]),
        }),
        params: BTreeMap::from([
            (
                String::from("amount"),
                Bound::Range {
                    min: None,
                    max: Some(5_000),
                    unit: String::from("try"),
                },
            ),
            (
                String::from("channel"),
                Bound::Enum(BTreeSet::from([String::from("web"), String::from("app")])),
            ),
            (String::from("note"), Bound::Eq(EqValue::Bytes(vec![1, 2]))),
        ]),
        recipient: Some(SubjectSelector::Pred(BTreeSet::from([Conjunct {
            claim_class: String::from("member"),
            value: Some(EqValue::Text(String::from("finance"))),
        }]))),
        purpose: Some(BTreeSet::from([PurposeRef::Code(String::from("refund"))])),
    }
}

fn canonical() -> CanonicalAuthority {
    CanonicalAuthority {
        authority: set(),
        constraints: ConstraintSet {
            validity: Window {
                from: 1_000,
                until: 9_000_000,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::from([BudgetTerm {
                dimension: BudgetDimension::Amount(String::from("try")),
                capacity: 50_000,
                window: BudgetWindow::RollingSeconds(86_400),
            }]),
        },
        delegation: DelegationTerms {
            depth: 1,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::from([RequirementTerm {
            proof_kind: ProofKind::Contribution,
            class: String::from("approval"),
            count: 2,
            binding: Binding::IntentDigest,
            freshness_ms: Some(600_000),
            independence: Independence::DistinctParty,
            consumption: Consumption::SingleUse,
            source: None,
            assurance: BTreeMap::from([(String::from("aal"), 2)]),
        }]),
    }
}

fn cases() -> Vec<(&'static str, Payload)> {
    let role = set();
    vec![
        (
            "authority_set_define",
            Payload::AuthoritySetDefine {
                name: String::from("finance_approver"),
                authority: role.clone(),
            },
        ),
        (
            "grant_issue",
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(id(1)),
                holder: SubjectSelector::Party(id(2)),
                authority: canonical(),
                agency: BTreeSet::from([Capacity::Own, Capacity::For(id(3))]),
                named: Some((
                    String::from("finance_approver"),
                    1,
                    authority_set_digest(&role),
                )),
            }),
        ),
        (
            "grant_issue_from_holding",
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Holding(HoldingRef {
                    grant: id(4),
                    holder: id(2),
                    since: 17,
                }),
                holder: SubjectSelector::Public,
                authority: canonical(),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        (
            "grant_amend",
            Payload::GrantAmend {
                grant: id(5),
                authority: canonical(),
                agency: BTreeSet::from([Capacity::Own]),
                named: Some((String::from("finance_approver"), 2, Digest([9; 32]))),
            },
        ),
        ("grant_revoke", Payload::GrantRevoke { grant: id(5) }),
        (
            "instance_terminate",
            Payload::InstanceTerminate { instance: id(6) },
        ),
        (
            "party_depart",
            Payload::PartyDepart {
                party: id(2),
                disposition: BTreeMap::from([
                    (id(5), Disposition::Revoke),
                    (id(8), Disposition::Keep),
                ]),
            },
        ),
        (
            "acceptance_amend",
            Payload::AcceptanceAmend {
                acceptance: id(9),
                content: json_value(&json!({
                    "issuer": b64url_encode(&[2; 16]),
                    "use": "predicate-input",
                    "classes": ["member"],
                    "subject": "public",
                    "validity": { "from": 0, "until": 9_000_000 },
                })),
            },
        ),
        (
            "policy_set",
            Payload::PolicySet {
                policy: None,
                content: json_value(&json!({
                    "schema": "access/restriction/v1",
                    "source": "forbid (principal, action, resource) when { context.amount > 9000 };",
                    "target": "domain",
                })),
            },
        ),
        (
            "anchor_create",
            Payload::AnchorCreate {
                scope: AnchorScope::Resource(ResourceSelector::Exact(ResourceRef {
                    namespace: String::from("commerce"),
                    path: vec![String::from("eu")],
                    incarnation: 0,
                })),
                root: Root::Joint {
                    parties: BTreeSet::from([id(2), id(3)]),
                    k: 2,
                },
                root_terms: BTreeSet::new(),
            },
        ),
        (
            "mandate_bind",
            Payload::MandateBind {
                instance: id(6),
                envelope: MandateEnvelope {
                    origins: access_kernel::combinator::Origins::default(),
                    authority: role,
                    constraints: canonical().constraints,
                    requirements: BTreeSet::new(),
                    pin: Some(HoldingRef {
                        grant: id(4),
                        holder: id(2),
                        since: 17,
                    }),
                },
            },
        ),
        (
            "party_register",
            Payload::PartyRegister {
                party: id(10),
                root: Root::Sole(id(10)),
                actor_kind: ActorKind::Agent,
            },
        ),
    ]
}

fn json_value(j: &Json) -> Value {
    to_value(&ACCEPTANCE, j, "", 0)
        .or_else(|_| to_value(&POLICY, j, "", 0))
        .map(|v| {
            dcbor::decode(
                &dcbor::encode(&v, Limits::CEILING).unwrap(),
                Limits::CEILING,
            )
        })
        .unwrap()
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/management/1/meta-payload-json.json")
}

// L1-ADP-17, OP-152 m.7 (d)
#[test]
fn the_json_form_round_trips_through_the_kernel_codec() {
    let built: Vec<Json> = cases()
        .into_iter()
        .map(|(name, p)| {
            json!({
                "name": name,
                "json": to_json_value(&p).unwrap(),
                "cbor": hex(&p.to_bytes().unwrap()),
                "digest": hex(&p.digest().unwrap().0),
            })
        })
        .collect();
    let doc = json!({
        "track": "management",
        "version": "1",
        "operation": "meta_payload.json",
        "rule": "L1-ADP-17",
        "cases": built,
    });
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        let path = vectors();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
        )
        .unwrap();
    }
    let committed: Json =
        serde_json::from_str(&std::fs::read_to_string(vectors()).unwrap()).unwrap();
    assert_eq!(
        committed, doc,
        "vectors are stale; run with ACCESS_UPDATE_VECTORS=1"
    );
    for case in committed["cases"].as_array().unwrap() {
        let p = from_json(&case["json"]).unwrap();
        assert_eq!(
            hex(&p.to_bytes().unwrap()),
            case["cbor"],
            "{}",
            case["name"]
        );
        assert_eq!(
            hex(&p.digest().unwrap().0),
            case["digest"],
            "{}",
            case["name"]
        );
        assert_eq!(to_json_value(&p).unwrap(), case["json"], "{}", case["name"]);
    }
}

// L1-ADP-17
#[test]
fn a_set_is_sorted_and_may_not_repeat() {
    let p = Payload::PartyDepart {
        party: id(2),
        disposition: BTreeMap::from([(id(5), Disposition::Revoke), (id(8), Disposition::Keep)]),
    };
    let mut j = to_json_value(&p).unwrap();
    let items = j["party_depart"]["disposition"].as_array_mut().unwrap();
    items.reverse();
    assert_eq!(from_json(&j).unwrap(), p);
    let first = j["party_depart"]["disposition"][0].clone();
    j["party_depart"]["disposition"]
        .as_array_mut()
        .unwrap()
        .push(first);
    assert_eq!(from_json(&j).unwrap_err().at, "/party_depart/disposition");
}

// L1-ADP-9, L1-ADP-17
#[test]
fn an_unknown_or_malformed_member_is_refused_at_its_pointer() {
    let ok = json!({ "grant_revoke": { "grant": b64url_encode(&[5; 16]) } });
    assert_eq!(
        from_json(&ok).unwrap(),
        Payload::GrantRevoke { grant: id(5) }
    );
    let refused = [
        (
            json!({ "grant_revoke": { "grant": b64url_encode(&[5; 16]), "x": 1 } }),
            "/grant_revoke/x",
        ),
        (
            json!({ "grant_revoke": { "grant": "!!" } }),
            "/grant_revoke/grant",
        ),
        (json!({ "grant_revoke": {} }), "/grant_revoke/grant"),
        (
            json!({ "grant_burn": { "grant": b64url_encode(&[5; 16]) } }),
            "/grant_burn",
        ),
        (
            json!({ "grant_revoke": { "grant": b64url_encode(&[5; 15]) } }),
            "",
        ),
        (
            json!({ "grant_revoke": { "grant": b64url_encode(&[5; 16]) }, "grant_renounce": {} }),
            "",
        ),
        (json!([]), ""),
    ];
    for (j, at) in refused {
        assert_eq!(from_json(&j).unwrap_err().at, at, "{j}");
    }
}

// L1-ADP-17
#[test]
fn an_authority_set_and_a_canonical_authority_round_trip() {
    let a = set();
    assert_eq!(
        authority_set_from_json(&authority_set_to_json(&a).unwrap()).unwrap(),
        a
    );
    let c = canonical();
    let j = canonical_authority_to_json(&c).unwrap();
    assert_eq!(
        j["authority"]["params"]["note"]["eq"]["bytes"],
        b64url_encode(&[1, 2])
    );
    assert_eq!(j["constraints"]["validity"]["from"], 1_000);
    assert_eq!(canonical_authority_from_json(&j).unwrap(), c);
}

// OP-3
#[test]
fn a_deep_value_is_refused() {
    let mut j = json!("x");
    for _ in 0..64 {
        j = json!({ "exact": j });
    }
    assert!(authority_set_from_json(&json!({ "actions": {}, "resource": j })).is_err());
}
