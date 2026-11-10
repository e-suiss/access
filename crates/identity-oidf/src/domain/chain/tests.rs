use std::collections::BTreeMap;

use super::*;
use crate::statement::{ENTITY_TYP, MarkRef, TRUST_MARK_TYP, configuration_url};
use crate::testkit::{Entity, Fed, HOUR, INT, LEAF, NOW, TA, j, refs, rp_metadata};

// IDP-19, OP-155 m.3 (j)
#[test]
fn a_valid_chain_resolves_until_its_smallest_exp() {
    let f = Fed::new();
    let exp_short = NOW.saturating_add(600_000);
    let jwts = vec![
        f.leaf_ec(),
        f.int.about(&f.leaf, None, exp_short),
        f.ta.about(&f.int, None, NOW.saturating_add(HOUR)),
        f.ta_ec(),
    ];
    let c = verify_chain(&refs(&jwts), &f.anchors(), NOW).unwrap();
    assert_eq!(c.anchor, TA);
    assert_eq!(c.leaf.sub, LEAF);
    assert_eq!(c.exp_ms, exp_short / 1000 * 1000);
    assert_eq!(
        c.metadata_of("openid_relying_party")
            .unwrap()
            .get("client_name"),
        Some(&j(r#""RP""#))
    );
    assert!(c.fresh(NOW.saturating_sub(FRESHNESS_MS), NOW));
    assert!(!c.fresh(NOW.saturating_sub(FRESHNESS_MS).saturating_sub(1), NOW));
    assert!(!c.fresh(NOW, c.exp_ms));
}

fn deep(intermediates: usize) -> (Vec<String>, Vec<TrustAnchor>) {
    let mut ents = vec![Entity::new(LEAF)];
    for n in 0..intermediates {
        ents.push(Entity::new(&format!("https://i{n}.example")));
    }
    ents.push(Entity::new(TA));
    let exp = NOW.saturating_add(HOUR);
    let mut jwts = vec![ents[0].config(&[ents[1].id.as_str()], &rp_metadata(), &[])];
    for w in ents.windows(2) {
        jwts.push(w[1].about(&w[0], None, exp));
    }
    let ta = ents.last().unwrap();
    jwts.push(ta.config(&[], &ta.federation_metadata(), &[]));
    (jwts, vec![ta.anchor()])
}

// IDP-19, OP-155 m.3 (j)
#[test]
fn a_chain_of_nine_is_refused() {
    let (eight, anchors) = deep(5);
    assert_eq!(eight.len(), MAX_LENGTH);
    assert!(verify_chain(&refs(&eight), &anchors, NOW).is_ok());
    let (nine, anchors) = deep(6);
    assert_eq!(nine.len(), 9);
    assert_eq!(
        verify_chain(&refs(&nine), &anchors, NOW),
        Err(ChainError::TooLong)
    );
    let offline = format!(
        "[{}]",
        nine.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        parse_trust_chain_json(offline.as_bytes()),
        Err(ChainError::TooLong)
    );
}

// IDP-19
#[test]
fn a_cycle_is_refused() {
    let f = Fed::new();
    let exp = NOW.saturating_add(HOUR);
    let jwts = vec![
        f.leaf_ec(),
        f.int.about(&f.leaf, None, exp),
        f.leaf.about(&f.int, None, exp),
        f.int.about(&f.leaf, None, exp),
        f.ta.about(&f.int, None, exp),
        f.ta_ec(),
    ];
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Cycle)
    );
}

// IDP-19
#[test]
fn an_expired_statement_refuses_the_chain() {
    let f = Fed::new();
    let jwts = vec![
        f.leaf_ec(),
        f.int.about(&f.leaf, None, NOW.saturating_sub(120_000)),
        f.ta.about(&f.int, None, NOW.saturating_add(HOUR)),
        f.ta_ec(),
    ];
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Statement(OidfError::Time))
    );
}

// IDP-19
#[test]
fn the_anchor_keys_are_the_pinned_ones() {
    let f = Fed::new();
    let mut jwts = f.chain();
    let impostor = Entity::new(TA);
    let impostor = Entity {
        id: impostor.id,
        key: crate::testkit::Key::new(&f.ta.key.kid),
    };
    jwts[3] = impostor.config(&[], &impostor.federation_metadata(), &[]);
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Statement(OidfError::Signature))
    );
    let other_anchor = vec![Entity::new("https://other-ta.example").anchor()];
    assert_eq!(
        verify_chain(&refs(&f.chain()), &other_anchor, NOW),
        Err(ChainError::Anchor)
    );
}

// IDP-19
#[test]
fn the_superior_publishes_the_leaf_keys() {
    let f = Fed::new();
    let mut jwts = f.chain();
    let stranger = Entity::new(LEAF);
    let stranger = Entity {
        id: stranger.id,
        key: crate::testkit::Key::new(&f.leaf.key.kid),
    };
    jwts[0] = stranger.config(&[INT], &rp_metadata(), &[]);
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Statement(OidfError::Signature))
    );
    let mut swapped = f.chain();
    swapped.swap(1, 2);
    assert!(verify_chain(&refs(&swapped), &f.anchors(), NOW).is_err());
}

// IDP-19
#[test]
fn policies_merge_from_the_anchor_down_and_narrow() {
    let f = Fed::new();
    let ta_policy = j(
        r#"{"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"]},"token_endpoint_auth_method":{"one_of":["private_key_jwt","self_signed_tls_client_auth"]}}}"#,
    );
    let int_policy = j(r#"{"openid_relying_party":{"contacts":{"add":["ops@int.example"]}}}"#);
    let jwts = f.chain_with(Some(&ta_policy), Some(&int_policy));
    let c = verify_chain(&refs(&jwts), &f.anchors(), NOW).unwrap();
    let rp = c.metadata_of("openid_relying_party").unwrap();
    assert_eq!(rp.get("grant_types"), Some(&j(r#"["authorization_code"]"#)));
    assert_eq!(rp.get("contacts"), Some(&j(r#"["ops@int.example"]"#)));
}

// IDP-19
#[test]
fn a_policy_operator_conflict_refuses_the_chain() {
    let f = Fed::new();
    let ta_policy =
        j(r#"{"openid_relying_party":{"token_endpoint_auth_method":{"value":"private_key_jwt"}}}"#);
    let int_policy = j(
        r#"{"openid_relying_party":{"token_endpoint_auth_method":{"value":"client_secret_basic"}}}"#,
    );
    let jwts = f.chain_with(Some(&ta_policy), Some(&int_policy));
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Policy(PolicyError::Conflict))
    );
    let ta_one = j(r#"{"openid_relying_party":{"client_name":{"one_of":["A"]}}}"#);
    let int_one = j(r#"{"openid_relying_party":{"client_name":{"one_of":["B"]}}}"#);
    let jwts = f.chain_with(Some(&ta_one), Some(&int_one));
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Policy(PolicyError::Conflict))
    );
    let unknown = j(r#"{"openid_relying_party":{"client_name":{"regexp":"^R"}}}"#);
    let jwts = f.chain_with(Some(&unknown), None);
    assert_eq!(
        verify_chain(&refs(&jwts), &f.anchors(), NOW),
        Err(ChainError::Policy(PolicyError::Operator))
    );
    assert_eq!(
        ChainError::Policy(PolicyError::Conflict).code(),
        "oidf-policy-conflict"
    );
}

// IDP-19
#[test]
fn max_path_length_is_honoured() {
    let f = Fed::new();
    let with_max = |max: u32| {
        let payload = crate::build::subordinate(&crate::build::Subordinate {
            iss: TA,
            sub: INT,
            iat_ms: NOW,
            exp_ms: NOW.saturating_add(HOUR),
            jwks: &f.int.key.jwks(),
            metadata_policy: None,
            metadata: None,
            max_path_length: Some(max),
        })
        .unwrap();
        let mut jwts = f.chain();
        jwts[2] = f.ta.key.sign(ENTITY_TYP, &payload);
        verify_chain(&refs(&jwts), &f.anchors(), NOW)
    };
    assert_eq!(with_max(0), Err(ChainError::PathLength));
    assert!(with_max(1).is_ok());
}

// IDP-19
#[test]
fn an_offline_trust_chain_is_accepted() {
    let f = Fed::new();
    let jwts = f.chain();
    let doc = format!(
        "[{}]",
        jwts.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    let parsed = parse_trust_chain_json(doc.as_bytes()).unwrap();
    assert_eq!(parsed, jwts);
    assert!(verify_chain(&refs(&parsed), &f.anchors(), NOW).is_ok());
    assert_eq!(parse_trust_chain_json(b"[]"), Err(ChainError::Format));
    assert_eq!(parse_trust_chain_json(b"{}"), Err(ChainError::Format));
}

// IDP-19, IDP-20
#[test]
fn only_marks_from_listed_issuers_are_kept() {
    let f = Fed::new();
    let mark = |iss: &Entity, typ: &str| {
        let payload = format!(
            r#"{{"iss":"{}","sub":"{LEAF}","iat":{},"trust_mark_type":"{typ}"}}"#,
            iss.id,
            NOW / 1000
        );
        MarkRef {
            trust_mark_type: String::from(typ),
            trust_mark: iss.key.sign(TRUST_MARK_TYP, &payload),
        }
    };
    let marks = vec![
        mark(&f.ta, "https://ta.example/member"),
        mark(&f.int, "https://ta.example/member"),
        mark(&f.ta, "https://ta.example/other"),
    ];
    let issuers = j(r#"{"https://ta.example/member":["https://ta.example"]}"#);
    let exp = NOW.saturating_add(HOUR);
    let jwts = vec![
        f.leaf.config(&[INT], &rp_metadata(), &marks),
        f.int.about(&f.leaf, None, exp),
        f.ta.about(&f.int, None, exp),
        f.ta.config_until(&[], &f.ta.federation_metadata(), &[], exp, Some(&issuers)),
    ];
    let c = verify_chain(&refs(&jwts), &f.anchors(), NOW).unwrap();
    assert_eq!(c.trust_marks.len(), 1);
    assert_eq!(c.trust_marks[0].iss, TA);
}

fn serve(f: &Fed) -> BTreeMap<String, String> {
    let exp = NOW.saturating_add(HOUR);
    let mut m = BTreeMap::new();
    m.insert(
        configuration_url(LEAF),
        f.leaf
            .config(&["https://dead.example", INT], &rp_metadata(), &[]),
    );
    m.insert(
        configuration_url(INT),
        f.int.config(&[TA], &f.int.federation_metadata(), &[]),
    );
    m.insert(configuration_url(TA), f.ta_ec());
    m.insert(
        format!("{}?sub=https%3A%2F%2Frp.example", f.int.fetch_endpoint()),
        f.int.about(&f.leaf, None, exp),
    );
    m.insert(
        format!("{}?sub=https%3A%2F%2Fint.example", f.ta.fetch_endpoint()),
        f.ta.about(&f.int, None, exp),
    );
    m
}

fn drive(r: &mut Resolver, served: &BTreeMap<String, String>) -> (Step, Vec<String>) {
    let mut asked = Vec::new();
    for _ in 0..64 {
        match r.step() {
            Step::Fetch { url } => {
                asked.push(url.clone());
                match served.get(&url) {
                    Some(b) => r.feed(&url, 200, b.as_bytes()),
                    None => r.feed(&url, 404, b""),
                }
            }
            other => return (other, asked),
        }
    }
    panic!("the resolver did not finish");
}

// IDP-19, OP-155 m.3 (j)
#[test]
fn the_resolver_fetches_bottom_up_and_tries_the_next_hint() {
    let f = Fed::new();
    let served = serve(&f);
    let mut r = Resolver::new(LEAF, f.anchors(), NOW);
    let (step, asked) = drive(&mut r, &served);
    let Step::Done(chain) = step else {
        panic!("not resolved: {step:?}");
    };
    assert_eq!(chain.anchor, TA);
    assert_eq!(chain.statements.len(), 4);
    assert_eq!(asked[0], configuration_url(LEAF));
    assert_eq!(asked[1], configuration_url("https://dead.example"));
    assert!(asked.contains(&format!(
        "{}?sub=https%3A%2F%2Fint.example",
        f.ta.fetch_endpoint()
    )));
    assert!(matches!(r.step(), Step::Done(_)));
}

// IDP-19
#[test]
fn the_resolver_fails_without_a_pinned_anchor() {
    let f = Fed::new();
    let served = serve(&f);
    let anchors = vec![Entity::new("https://other-ta.example").anchor()];
    let mut r = Resolver::new(LEAF, anchors, NOW);
    let (step, _) = drive(&mut r, &served);
    assert_eq!(step, Step::Failed(ChainError::Unresolved));
    let mut gone = Resolver::new(LEAF, f.anchors(), NOW);
    let (step, asked) = drive(&mut gone, &BTreeMap::new());
    assert_eq!(step, Step::Failed(ChainError::Unresolved));
    assert_eq!(asked.len(), 1);
}
