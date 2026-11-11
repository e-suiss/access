#![allow(clippy::unwrap_used, reason = "test code")]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, GrantBasis, GrantContent, GrantState, Payload};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, SubjectSelector, Window,
};

use super::*;

fn action(ns: &str, name: &str) -> ActionRef {
    if ns == meta::NAMESPACE {
        meta::core_action(name)
    } else {
        ActionRef {
            namespace: ns.to_owned(),
            name: name.to_owned(),
            major: 1,
            schema: Digest([9; 32]),
        }
    }
}

fn set(exact: &[ActionRef], prefix: &[&str]) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: exact.iter().cloned().collect(),
            prefix: prefix
                .iter()
                .map(|p| ((*p).to_owned(), Digest([7; 32])))
                .collect(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("access.grant"),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn canonical(authority: AuthoritySet) -> CanonicalAuthority {
    CanonicalAuthority {
        authority,
        constraints: ConstraintSet {
            validity: Window { from: 0, until: 1 },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        requirements: BTreeSet::new(),
        delegation: DelegationTerms::default(),
    }
}

fn state(authority: AuthoritySet) -> GrantState {
    GrantState {
        content: GrantContent {
            basis: GrantBasis::Anchor(Id([1; 16])),
            holder: SubjectSelector::Party(Id([2; 16])),
            authority: canonical(authority),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        },
        since: 1,
        revision: 0,
        ended: None,
    }
}

fn issue(authority: AuthoritySet) -> Payload {
    Payload::GrantIssue(state(authority).content)
}

fn amend(authority: AuthoritySet) -> Payload {
    Payload::GrantAmend {
        grant: Id([3; 16]),
        authority: canonical(authority),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    }
}

// TN-114, OP-157 m.3 (t), Ek B 5492, 5592
#[test]
fn a_grant_on_a_meta_action_needs_the_flag_and_a_domain_grant_does_not() {
    let admin = set(&[action("access", "grant_revoke")], &[]);
    let prefixed = set(&[], &["access"]);
    let plain = set(&[action("idp.account", "read")], &[]);
    let approver = set(&[action("access", "contribute")], &[]);
    assert!(!needs_open(&issue(approver), None));
    assert!(needs_open(&issue(admin), None));
    assert!(needs_open(&issue(prefixed), None));
    assert!(!needs_open(&issue(plain), None));
}

// OP-157 m.3 (t)
#[test]
fn closing_never_reaches_back_a_narrowing_or_keeping_amend_stays() {
    let both = set(
        &[
            action("access", "grant_revoke"),
            action("access", "grant_issue"),
        ],
        &[],
    );
    let revoke_only = set(&[action("access", "grant_revoke")], &[]);
    let current = state(both.clone());
    assert!(!needs_open(&amend(both.clone()), Some(&current)));
    assert!(!needs_open(&amend(revoke_only.clone()), Some(&current)));
    let current = state(revoke_only);
    assert!(needs_open(&amend(both), Some(&current)));
}
