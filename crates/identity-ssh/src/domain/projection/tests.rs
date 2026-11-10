#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use access_kernel::model::{
    ActionSet, AuthoritySet, Bound, CanonicalAuthority, ConstraintSet, DelegationTerms, EqValue,
    ResourceSelector, Structural, Window,
};
use suiss_crypto::dcbor::{self, Limits};

use super::*;

const NOW: u64 = 1_767_225_000_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

fn grant(params: BTreeMap<String, Bound>) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([schema::login_ref()]),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from(schema::NAMESPACE),
                prefix: vec![String::from(schema::HOST_GROUP)],
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params,
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: NOW + 48 * HOUR_MS,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements: BTreeSet::new(),
    }
}

fn deploy_grant() -> CanonicalAuthority {
    grant(BTreeMap::from([
        (
            String::from(PRINCIPAL),
            Bound::Enum(set(&["ayse", "deploy"])),
        ),
        (
            String::from(FORCE_COMMAND),
            Bound::Eq(EqValue::Text(String::from("/usr/local/bin/deploy"))),
        ),
        (String::from("permit_pty"), Bound::Flag(true)),
    ]))
}

fn ask(principals: Option<&[&str]>, lifetime_ms: Option<u64>) -> Ask {
    Ask {
        host_group: String::from("prod-web"),
        key: Ed25519Public([12; 32]),
        principals: principals.map(set),
        lifetime_ms,
    }
}

// IDP-32, OP-156 m.3 (o)
#[test]
fn a_person_certificate_carries_what_the_grant_names() {
    let g = deploy_grant();
    let bounds = draft(&g, Holder::Person, &ask(None, None), NOW).unwrap();
    let (group, key) = precheck(&bounds, Holder::Person, NOW).unwrap();
    assert_eq!(group, "prod-web");
    assert_eq!(key, Ed25519Public([12; 32]));
    let p = derive(&g, &bounds, Holder::Person, "prj", u64::MAX).unwrap();
    assert_eq!(p.principals, set(&["ayse", "deploy"]));
    assert_eq!(p.force_command.as_deref(), Some("/usr/local/bin/deploy"));
    assert_eq!(p.extensions, BTreeSet::from([Extension::Pty]));
    assert_eq!(
        p.valid_before - p.valid_after,
        (8 * HOUR_MS + BACKDATE_MS) / 1000
    );
    assert_eq!(p.valid_after, (NOW - BACKDATE_MS) / 1000);
}

// IDP-32, G2
#[test]
fn a_principal_outside_the_grant_never_enters_a_certificate() {
    let g = deploy_grant();
    assert_eq!(
        draft(&g, Holder::Person, &ask(Some(&["root"]), None), NOW),
        Err(SshError::NoPrincipal)
    );
    let mut bounds = draft(&g, Holder::Person, &ask(Some(&["ayse"]), None), NOW).unwrap();
    bounds
        .authority
        .params
        .insert(String::from(PRINCIPAL), Bound::Enum(set(&["ayse", "root"])));
    assert_eq!(
        derive(&g, &bounds, Holder::Person, "prj", u64::MAX),
        Err(SshError::NoPrincipal)
    );
    let open = grant(BTreeMap::new());
    assert_eq!(
        draft(&open, Holder::Person, &ask(None, None), NOW),
        Err(SshError::NoPrincipal)
    );
    assert_eq!(
        derive(&open, &bounds, Holder::Person, "prj", u64::MAX),
        Err(SshError::NoPrincipal)
    );
}

// OP-156 m.3 (o)
#[test]
fn force_command_passes_from_the_grant_and_extensions_need_its_permit() {
    let g = deploy_grant();
    let mut bounds = draft(&g, Holder::Person, &ask(None, None), NOW).unwrap();
    bounds.authority.params.remove(FORCE_COMMAND);
    assert_eq!(
        derive(&g, &bounds, Holder::Person, "prj", u64::MAX),
        Err(SshError::Constraint)
    );
    let mut bounds = draft(&g, Holder::Person, &ask(None, None), NOW).unwrap();
    bounds
        .authority
        .params
        .insert(String::from("permit_port_forwarding"), Bound::Flag(true));
    assert_eq!(
        derive(&g, &bounds, Holder::Person, "prj", u64::MAX),
        Err(SshError::Extension)
    );
    let sourced = grant(BTreeMap::from([
        (
            String::from(PRINCIPAL),
            Bound::Eq(EqValue::Text(String::from("ayse"))),
        ),
        (
            String::from(SOURCE_ADDRESS),
            Bound::Enum(set(&["10.0.0.0/8", "192.0.2.0/24"])),
        ),
    ]));
    let bounds = draft(&sourced, Holder::Person, &ask(None, None), NOW).unwrap();
    let p = derive(&sourced, &bounds, Holder::Person, "prj", u64::MAX).unwrap();
    assert_eq!(p.source_address, set(&["10.0.0.0/8", "192.0.2.0/24"]));
    assert!(p.extensions.is_empty());
    assert!(p.force_command.is_none());
}

// OP-156 m.3 (o)
#[test]
fn an_agent_certificate_never_passes_one_hour() {
    let g = deploy_grant();
    let bounds = draft(&g, Holder::Agent, &ask(Some(&["deploy"]), None), NOW).unwrap();
    let p = derive(&g, &bounds, Holder::Agent, "prj", u64::MAX).unwrap();
    assert_eq!(
        p.valid_before - p.valid_after,
        (15 * MINUTE_MS + BACKDATE_MS) / 1000
    );
    assert_eq!(
        draft(&g, Holder::Agent, &ask(None, Some(2 * HOUR_MS)), NOW),
        Err(SshError::Lifetime)
    );
    let mut long = bounds.clone();
    long.constraints.validity.until = NOW + 2 * HOUR_MS;
    assert_eq!(precheck(&long, Holder::Agent, NOW), Err(SshError::Lifetime));
    assert_eq!(
        derive(&g, &long, Holder::Agent, "prj", u64::MAX),
        Err(SshError::Lifetime)
    );
    assert!(precheck(&long, Holder::Person, NOW).is_ok());
    assert_eq!(
        draft(&g, Holder::Person, &ask(None, Some(13 * HOUR_MS)), NOW),
        Err(SshError::Lifetime)
    );
}

// §9.12, OP-156 m.3 (o)
#[test]
fn the_horizon_and_the_grant_end_the_certificate() {
    let mut g = deploy_grant();
    let bounds = draft(&g, Holder::Person, &ask(None, None), NOW).unwrap();
    let p = derive(&g, &bounds, Holder::Person, "prj", NOW + HOUR_MS).unwrap();
    assert_eq!(p.valid_before, (NOW + HOUR_MS) / 1000);
    g.constraints.validity.until = NOW + 2 * HOUR_MS;
    let bounds = draft(&g, Holder::Person, &ask(None, None), NOW).unwrap();
    assert_eq!(bounds.constraints.validity.until, NOW + 2 * HOUR_MS);
    assert_eq!(
        derive(&g, &bounds, Holder::Person, "prj", NOW - 2 * MINUTE_MS),
        Err(SshError::Lifetime)
    );
}

// OP-156 m.3 (o)
#[test]
fn the_projection_matches_the_contract_examples() {
    let p = Projection {
        key_id: String::from("prj_01HZX"),
        serial: 9_223_372_036_854_775_807,
        holder: Holder::Person,
        public_key: Ed25519Public([12; 32]),
        principals: set(&["ayse"]),
        host_group: String::from("prod-web"),
        valid_after: 1_767_225_000,
        valid_before: 1_767_253_800,
        force_command: None,
        source_address: BTreeSet::new(),
        extensions: BTreeSet::from([Extension::Pty]),
    };
    let bytes = dcbor::encode(&p.to_value(), Limits::CEILING).unwrap();
    let hex = bytes.iter().fold(String::new(), |mut h, b| {
        let _ = write!(h, "{b:02x}");
        h
    });
    assert_eq!(
        hex,
        "a966686f6c64657266706572736f6e666b65795f69646970726a5f3031485a586673657269616c1b7fffffffffffffff6a657874656e73696f6e73816a7065726d69742d7074796a686f73745f67726f75706870726f642d7765626a7072696e636970616c738164617973656a7075626c69635f6b657958200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c6b76616c69645f61667465721a6955b6a86c76616c69645f6265666f72651a69562728"
    );
    let back = dcbor::decode(&bytes, Limits::CEILING).unwrap();
    assert_eq!(Projection::of_value(&back).unwrap(), p);
    let mut bad = p.to_value();
    if let Value::Map(m) = &mut bad {
        m.push((Value::text("extra"), Value::Unsigned(1)));
    }
    assert_eq!(Projection::of_value(&bad), Err(SshError::Malformed));
}
