#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_crypto::secret::Secret;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{
    Blocker, Capacity, Outcome, Position, Remediation, Resolver, Unmet,
};
use access_kernel::fold::Entry;
use access_kernel::meta::{AnchorScope, GrantContent, HoldingRef, key};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Independence,
    RequirementTerm, ResourceSelector, Window,
};
use access_kernel::record::{Header, Opened, RecordKind};

use super::*;

const ROOT: Id = Id([1; 16]);
const ALICE: Id = Id([2; 16]);
const BOB: Id = Id([3; 16]);
const CAROL: Id = Id([4; 16]);
const ANCHOR: Id = Id([0xa0; 16]);
const G_ALICE: Id = Id([0xa1; 16]);
const G_BOB: Id = Id([0xb1; 16]);
const G_CAROL: Id = Id([0xc1; 16]);

fn authority() -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([access_kernel::model::ActionRef {
                    namespace: "shop".to_owned(),
                    name: "read".to_owned(),
                    major: 1,
                    schema: Digest([3; 32]),
                }]),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(access_kernel::model::Structural {
                namespace: "shop".to_owned(),
                prefix: Vec::new(),
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window { from: 0, until: 10 },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth: 3,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    }
}

fn grant(basis: GrantBasis, holder: Id) -> Value {
    GrantState {
        content: GrantContent {
            basis,
            holder: SubjectSelector::Party(holder),
            authority: authority(),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        },
        since: 1,
        revision: 0,
        ended: None,
    }
    .to_value()
}

fn holding(grant: Id, holder: Id) -> GrantBasis {
    GrantBasis::Holding(HoldingRef {
        grant,
        holder,
        since: 1,
    })
}

/// ROOT roots the Anchor; ALICE holds from it, BOB from ALICE, CAROL from BOB.
fn state() -> State {
    let anchor = AnchorState {
        scope: AnchorScope::Domain,
        root: Root::Sole(ROOT),
        root_terms: BTreeSet::new(),
        since: 0,
        ended: None,
    };
    let entry = |v: Value| Entry {
        value: Some(v),
        version: 1,
    };
    BTreeMap::from([
        (key(kind::ANCHOR, &ANCHOR), entry(anchor.to_value())),
        (
            key(kind::GRANT, &G_ALICE),
            entry(grant(GrantBasis::Anchor(ANCHOR), ALICE)),
        ),
        (
            key(kind::GRANT, &G_BOB),
            entry(grant(holding(G_ALICE, ALICE), BOB)),
        ),
        (
            key(kind::GRANT, &G_CAROL),
            entry(grant(holding(G_BOB, BOB), CAROL)),
        ),
    ])
}

fn basis() -> ExerciseBasis {
    ExerciseBasis::Holding(HoldingRef {
        grant: G_CAROL,
        holder: CAROL,
        since: 1,
    })
}

fn pseudonym_key() -> PseudonymKey {
    PseudonymKey::new(Secret::new([9; 32]))
}

// §9.6.1, §13.7.5, SEC29, TI-RT10: a viewer sees its own lineage and the Grants it gave in
// clear; identities two or more hops below it only as its own stable pseudonyms
#[test]
fn identities_two_hops_below_the_viewer_are_pseudonymous() {
    let s = state();
    let k = pseudonym_key();
    let root = viewed_lineage(&s, &basis(), &ROOT, false, Some(&k)).unwrap();
    assert_eq!(root.len(), 3);
    // hop 2 = ALICE (one below ROOT), hop 1 = BOB, hop 0 = CAROL
    assert_eq!(root[2].holder, Some(Named::Clear(ALICE)));
    assert_eq!(root[2].grant, Named::Clear(G_ALICE));
    assert!(matches!(root[1].holder, Some(Named::Pseudonym(_))));
    assert!(matches!(root[0].holder, Some(Named::Pseudonym(_))));
    assert!(matches!(root[0].grant, Named::Pseudonym(_)));
    // stable for one viewer, different for another
    let again = viewed_lineage(&s, &basis(), &ROOT, false, Some(&k)).unwrap();
    assert_eq!(again, root);
    let alice = viewed_lineage(&s, &basis(), &ALICE, false, Some(&k)).unwrap();
    assert_eq!(alice[2].holder, Some(Named::Clear(ALICE)));
    assert_eq!(alice[1].holder, Some(Named::Clear(BOB)));
    assert!(matches!(alice[0].holder, Some(Named::Pseudonym(_))));
    assert_ne!(alice[0].holder, root[0].holder);
    let bob = viewed_lineage(&s, &basis(), &BOB, false, Some(&k)).unwrap();
    assert!(
        bob.iter()
            .all(|h| matches!(h.holder, Some(Named::Clear(_))))
    );
}

// §13.7.5: with the audit Grant every identity is in clear; without a pseudonym key nothing
// that needs one is shown (fail closed)
#[test]
fn the_audit_scope_sees_identities_in_clear() {
    let s = state();
    let audit = viewed_lineage(&s, &basis(), &ROOT, true, None).unwrap();
    assert_eq!(
        audit.iter().map(|h| h.holder).collect::<Vec<_>>(),
        vec![
            Some(Named::Clear(CAROL)),
            Some(Named::Clear(BOB)),
            Some(Named::Clear(ALICE))
        ]
    );
    assert!(matches!(
        viewed_lineage(&s, &basis(), &ROOT, false, None),
        Err(CoreError::Unavailable("pseudonym-key"))
    ));
    // a stranger to the lineage sees every identity pseudonymous
    let stranger =
        viewed_lineage(&s, &basis(), &Id([9; 16]), false, Some(&pseudonym_key())).unwrap();
    assert!(
        stranger
            .iter()
            .all(|h| matches!(h.holder, Some(Named::Pseudonym(_))))
    );
}

fn decision() -> Decision {
    Decision {
        outcome: Outcome::Deny,
        blockers: vec![
            Blocker {
                class: BlockerClass::Restricted,
                subcode: Some("restricted/policy:p1".to_owned()),
                position: Position::DomainPolicy,
                resolver: Resolver::RestrictionOwner,
                remediation: Remediation::NotSatisfiableByActor,
            },
            Blocker {
                class: BlockerClass::CapacityMismatch,
                subcode: Some("capacity/x".to_owned()),
                position: Position::Hop(0),
                resolver: Resolver::Actor,
                remediation: Remediation::NewRequestRequired,
            },
        ],
        unmet: vec![Unmet {
            term: RequirementTerm {
                proof_kind: ProofKind::Contribution,
                class: "approve".to_owned(),
                count: 1,
                binding: access_kernel::model::Binding::None,
                freshness_ms: None,
                independence: Independence::None,
                consumption: access_kernel::model::Consumption::Reusable,
                source: None,
                assurance: BTreeMap::new(),
            },
            missing: 1,
            position: Position::Hop(0),
            satisfiable_by_actor: false,
        }],
        relied_on: vec![Id([5; 16])],
    }
}

// P41, §9.6.1: `reason_user` carries only closed codes; `reason_admin` follows the table and
// discloses a subcode only where its row does
#[test]
fn p41_reason_user_and_reason_admin_follow_the_table() {
    let d = decision();
    assert_eq!(
        reason_user(&d),
        vec!["restricted", "capacity-mismatch", "requirement-approval"]
    );
    let admin = reason_admin(&d);
    assert_eq!(admin.len(), 3);
    assert_eq!(admin[0].subcode.as_deref(), Some("restricted/policy:p1"));
    assert_eq!(admin[1].subcode, None);
    assert_eq!(admin[2].category, "requirement missing: approval");
}

// §17.1.1, OP-148: at audit scope `basis_ref` opens into the domain, q − 1 and the digest of
// the version vector; the StateBasis and the cited proofs come from the record
#[test]
fn basis_ref_expands_to_domain_q_minus_1_and_version_digest() {
    let versions = Value::Map(vec![
        (Value::text("core"), Value::Unsigned(1)),
        (Value::text("meta_schema"), Value::Unsigned(1)),
    ]);
    let opened = |value| Opened {
        value,
        salt: [1; 32],
    };
    let record = RecordEnvelope {
        header: Header {
            domain: Some(Digest([0xd0; 32])),
            pos: 12,
            kind: RecordKind::Decision,
            recorded_at: 777,
            prev: Some(Digest([1; 32])),
        },
        fields: BTreeMap::from([
            ("versions".to_owned(), opened(versions.clone())),
            (
                "state_basis".to_owned(),
                opened(Value::Map(vec![
                    (Value::text("at"), Value::Unsigned(0)),
                    (
                        Value::text("reads"),
                        Value::Array(vec![Value::Array(vec![
                            Value::Bytes(b"k".to_vec()),
                            Value::Unsigned(3),
                        ])]),
                    ),
                ])),
            ),
        ]),
    };
    let detail = audit_detail(Digest([0xd0; 32]), &record, &decision()).unwrap();
    assert_eq!(detail.basis.domain, Digest([0xd0; 32]));
    assert_eq!(detail.basis.position_q_minus_1, 11);
    let bytes = dcbor::encode(&versions, Limits::CEILING).unwrap();
    assert_eq!(
        detail.basis.version_vector_digest,
        suiss_crypto::digest::context_digest(VERSIONS_CONTEXT, &bytes)
    );
    assert_eq!(detail.reads, vec![(b"k".to_vec(), 3)]);
    assert_eq!(detail.evaluated_at, 777);
    assert_eq!(detail.cited, vec![Id([5; 16])]);
    let mut bare = record;
    bare.fields.remove("versions");
    assert!(audit_detail(Digest([0xd0; 32]), &bare, &decision()).is_err());
}
