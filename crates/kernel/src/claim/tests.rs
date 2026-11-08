use alloc::vec;

use ed25519_dalek::Signer as _;

use super::*;
use crate::verify::cose::{ALG, CONTENT_TYPE as CT_LABEL, KID, to_be_signed};

const ISSUER: Id = Id([5; 16]);
const SUBJECT: Id = Id([6; 16]);
const DOMAIN: Digest = Digest([1; 32]);

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn key(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

fn statement() -> Statement {
    Statement {
        domain: DOMAIN,
        issuer: ISSUER,
        subject: SUBJECT,
        class: String::from("kyc"),
        value: Some(EqValue::Bool(true)),
        issued_at: 1_000,
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        assurance: BTreeMap::from([(String::from("aal"), 2)]),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    }
}

fn sign(payload: &[u8], with: &ed25519_dalek::SigningKey, ct: &str) -> Vec<u8> {
    let kid = thumbprint(&PublicKey::Ed25519(with.verifying_key().to_bytes()));
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(CT_LABEL), Value::text(ct)),
            (Value::Unsigned(KID), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = with.sign(&to_be_signed(&prot, payload).unwrap()).to_bytes();
    let body = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

fn signed(s: &Statement) -> Vec<u8> {
    sign(&s.to_bytes().unwrap(), &signing(9), CONTENT_TYPE)
}

fn gate() -> Gate {
    Gate {
        issuer: Some(ISSUER),
        use_: String::from("predicate-input"),
        classes: vec![String::from("kyc")],
        subject: SubjectSelector::Public,
        floor: BTreeMap::from([(String::from("aal"), 2)]),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        ingest_until: None,
        issued_until: None,
        quota: None,
        anchor: None,
        pinned: None,
    }
}

// L2-CLM-1, L2-CLM-2
#[test]
fn a_claim_verifies_under_its_issuers_instance() {
    let bytes = signed(&statement());
    assert_eq!(kid(&bytes).unwrap(), thumbprint(&key(9)));
    assert_eq!(
        verify(&bytes, &key(9), &ISSUER, &DOMAIN).unwrap(),
        statement()
    );
    assert_eq!(claim_id(&bytes), claim_id(&bytes));
    assert_ne!(
        claim_id(&bytes),
        claim_id(&signed(&Statement {
            issued_at: 2,
            ..statement()
        }))
    );
    assert_eq!(claim_id(&bytes).0[..], claim_digest(&bytes).0[..16]);
}

// L2-CLM-1, L2-CLM-2: another key, another issuer, another domain or content type is refused
#[test]
fn a_claim_that_is_not_the_issuers_is_refused() {
    let bytes = signed(&statement());
    assert_eq!(
        verify(&bytes, &key(8), &ISSUER, &DOMAIN).map_err(ClaimError::code),
        Err("claim-signature")
    );
    assert_eq!(
        verify(&bytes, &key(9), &SUBJECT, &DOMAIN).map_err(ClaimError::code),
        Err("claim-payload")
    );
    assert_eq!(
        verify(&bytes, &key(9), &ISSUER, &Digest([2; 32])).map_err(ClaimError::code),
        Err("claim-payload")
    );
    let ais = sign(
        &statement().to_bytes().unwrap(),
        &signing(9),
        crate::ais::CONTENT_TYPE,
    );
    assert_eq!(
        verify(&ais, &key(9), &ISSUER, &DOMAIN).map_err(ClaimError::code),
        Err("claim-signature")
    );
}

// L2-CLM-3
#[test]
fn an_acceptance_admits_a_claim() {
    // INV-15
    let s = statement();
    assert_eq!(disposition(&s, &[gate()], 2_000), Disposition::Admit);
    assert_eq!(disposition(&s, &[], 2_000), Disposition::SourceNotAccepted);
    let refusing = [
        Gate {
            use_: String::from("schema-definition"),
            ..gate()
        },
        Gate {
            issuer: Some(SUBJECT),
            ..gate()
        },
        Gate {
            classes: vec![String::from("age")],
            ..gate()
        },
        Gate {
            subject: SubjectSelector::Party(ISSUER),
            ..gate()
        },
        Gate {
            floor: BTreeMap::from([(String::from("aal"), 3)]),
            ..gate()
        },
        Gate {
            ingest_until: Some(1_500),
            ..gate()
        },
        Gate {
            validity: Window {
                from: 3_000,
                until: 4_000,
            },
            ..gate()
        },
    ];
    for g in refusing {
        assert_eq!(disposition(&s, &[g], 2_000), Disposition::SourceNotAccepted);
    }
    let future = Statement {
        issued_at: 70_001,
        ..s
    };
    assert_eq!(disposition(&future, &[gate()], 10_000), Disposition::Future);
}

fn acceptance_content() -> Value {
    map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("predicate-input"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        (
            "assurance_floor",
            Some(map([("aal", Some(Value::Unsigned(2)))])),
        ),
        ("validity", Some(gate().validity.to_value())),
    ])
}

// L2-CLM-3: the gate reads an acceptance-content
#[test]
fn a_gate_reads_acceptance_content() {
    let content = acceptance_content();
    assert_eq!(Gate::of(&content).unwrap(), gate());
}

#[test]
fn claim_state_round_trips() {
    let st = ClaimState {
        statement: Statement {
            domain: Digest([0; 32]),
            issued_at: 0,
            ..statement()
        },
        instance: Some(Id([9; 16])),
        since: 7,
        ended: None,
    };
    assert_eq!(ClaimState::from_value(&st.to_value()).unwrap(), st);
}

type VectorCase<'a> = (&'a str, &'a [&'a str], Vec<u8>, Id, Vec<Value>, u64);

// L2-CLM-1 to L2-CLM-3: Claim vectors, byte for byte. A case gives the COSE_Sign1, the issuer
// the signing Instance belongs to, the Acceptance contents that are live and the trusted time;
// the result is the disposition or the rejection.
#[test]
#[allow(clippy::too_many_lines, reason = "the vector cases are listed in full")]
fn claim_vectors_match() {
    use crate::vector_rules::{field, golden, hex};
    use alloc::format;
    let s = statement();
    let good = signed(&s);
    let accept = map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("predicate-input"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        (
            "assurance_floor",
            Some(map([("aal", Some(Value::Unsigned(2)))])),
        ),
        ("validity", Some(gate().validity.to_value())),
    ]);
    let other_use = map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("schema-definition"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        ("validity", Some(gate().validity.to_value())),
    ]);
    let binding_use = map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("actor-binding"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        ("validity", Some(gate().validity.to_value())),
    ]);
    let selection = map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("subject-selection"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        ("validity", Some(gate().validity.to_value())),
    ]);
    let cutoff = map([
        ("issuer", Some(ISSUER.to_value())),
        ("use", Some(Value::text("predicate-input"))),
        ("classes", Some(Value::Array(vec![Value::text("kyc")]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        ("validity", Some(gate().validity.to_value())),
        ("issued_until", Some(Value::Unsigned(999))),
    ]);
    let other_domain = signed(&Statement {
        domain: Digest([2; 32]),
        ..s.clone()
    });
    let future = signed(&Statement {
        issued_at: 70_001,
        ..s.clone()
    });
    let ais_typed = sign(
        &s.to_bytes().unwrap(),
        &signing(9),
        crate::ais::CONTENT_TYPE,
    );
    let cases: Vec<VectorCase<'_>> = vec![
        (
            "admitted",
            &["L2-CLM-1", "L2-CLM-2", "L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![accept.clone()],
            2_000,
        ),
        (
            "membership-use",
            &["L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![selection],
            2_000,
        ),
        (
            "issued-after-cutoff",
            &["L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![cutoff],
            2_000,
        ),
        (
            "no-acceptance",
            &["L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![],
            2_000,
        ),
        (
            "other-use",
            &["L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![other_use],
            2_000,
        ),
        (
            "actor-binding-use",
            &["L2-CLM-3"],
            good.clone(),
            ISSUER,
            vec![binding_use],
            2_000,
        ),
        (
            "future",
            &["L2-CLM-3"],
            future,
            ISSUER,
            vec![accept.clone()],
            10_000,
        ),
        (
            "other-key",
            &["L2-CLM-2"],
            sign(&s.to_bytes().unwrap(), &signing(8), CONTENT_TYPE),
            ISSUER,
            vec![accept.clone()],
            2_000,
        ),
        (
            "other-content-type",
            &["L2-CLM-2"],
            ais_typed,
            ISSUER,
            vec![accept.clone()],
            2_000,
        ),
        (
            "other-issuer",
            &["L2-CLM-1"],
            good.clone(),
            SUBJECT,
            vec![accept.clone()],
            2_000,
        ),
        (
            "other-domain",
            &["L2-CLM-1"],
            other_domain,
            ISSUER,
            vec![accept],
            2_000,
        ),
    ];
    let mut rows = Vec::new();
    for (id, rules, sign1, issuer, accepted, now) in &cases {
        let gates: Vec<Gate> = accepted.iter().map(|a| Gate::of(a).unwrap()).collect();
        let expect = match verify(sign1, &key(9), issuer, &DOMAIN) {
            Ok(st) => format!(
                "\"disposition\": \"{}\", \"claim_id\": \"{}\"",
                disposition(&st, &gates, *now).word(),
                hex(&claim_id(sign1).0)
            ),
            Err(e) => format!("\"error\": \"{}\"", e.code()),
        };
        let list = Value::Array(accepted.clone());
        rows.push(format!(
            "  {{\"id\": \"{id}\", {}, \"sign1\": \"{}\", \"issuer\": \"{}\", \"acceptances\": \"{}\", \"now\": {now}, {expect}}}",
            field(rules),
            hex(sign1),
            hex(&issuer.0),
            hex(&dcbor::encode(&list, Limits::CEILING).unwrap()),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-141\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"claim.verify\",\n {},\n \"domain\": \"{}\",\n \"key\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L2-CLM-1"]),
        hex(&dcbor::encode(&DOMAIN.to_value(), Limits::CEILING).unwrap()),
        hex(&key(9).to_bytes().unwrap()),
        rows.join(",\n")
    );
    golden(
        "claim.json",
        include_str!("../../../../conformance/vectors/core/1/claim.json"),
        &json,
    );
}

// OP-141 m.20 (b), (c)
#[test]
fn membership_entries_share_their_prefix() {
    let key = member_key("kyc", &SUBJECT, &Id([3; 16]));
    let prefix = member_prefix("kyc", &SUBJECT);
    assert!(key.starts_with(&prefix) && key.len() == prefix.len() + 17);
    assert!(!member_key("kyd", &SUBJECT, &Id([3; 16])).starts_with(&prefix));
    let state = ClaimState {
        statement: statement(),
        instance: None,
        since: 4,
        ended: None,
    };
    let conj = |value| crate::model::Conjunct {
        claim_class: String::from("kyc"),
        value,
    };
    assert!(satisfies(&conj(None), &state, 2_000));
    assert!(satisfies(&conj(Some(EqValue::Bool(true))), &state, 2_000));
    assert!(!satisfies(&conj(Some(EqValue::Bool(false))), &state, 2_000));
    assert!(!satisfies(&conj(None), &state, 2_000_000));
}

// OP-141 m.21 (a), (c)
#[test]
fn quota_and_signing_cutoff() {
    let s = statement();
    assert_eq!(quota_of(&s, &[gate()], 2_000), Some((2_000, 3_600_000)));
    let declared = Gate {
        quota: Some((5, 60)),
        ..gate()
    };
    assert_eq!(quota_of(&s, &[declared], 2_000), Some((10, 60_000)));
    assert_eq!(quota_of(&s, &[], 2_000), None);
    assert_eq!(
        quota_key(&ISSUER, 60_000, 125_000),
        quota_key(&ISSUER, 60_000, 179_999)
    );
    assert_ne!(
        quota_key(&ISSUER, 60_000, 125_000),
        quota_key(&ISSUER, 60_000, 180_000)
    );
    let cut = Gate {
        issued_until: Some(999),
        ..gate()
    };
    assert_eq!(
        disposition(&s, &[cut], 2_000),
        Disposition::SourceNotAccepted
    );
}

// OP-141 m.21 (d): an amend that only narrows is not expansion
#[test]
fn narrowing_an_acceptance() {
    // SI-18
    let old = gate();
    let narrower = [
        Gate {
            ingest_until: Some(5),
            ..gate()
        },
        Gate {
            issued_until: Some(5),
            ..gate()
        },
        Gate {
            subject: SubjectSelector::Party(SUBJECT),
            ..gate()
        },
        Gate {
            floor: BTreeMap::from([(String::from("aal"), 3)]),
            ..gate()
        },
        Gate {
            validity: Window {
                from: 10,
                until: 20,
            },
            ..gate()
        },
        Gate {
            quota: Some((5, 3_600)),
            ..gate()
        },
        gate(),
    ];
    for n in &narrower {
        assert!(narrows(&old, n), "{n:?}");
    }
    let wider = [
        Gate {
            classes: vec![String::from("kyc"), String::from("age")],
            ..gate()
        },
        Gate {
            floor: BTreeMap::new(),
            ..gate()
        },
        Gate {
            validity: Window {
                from: 0,
                until: 2_000_000,
            },
            ..gate()
        },
        Gate {
            quota: Some((5_000, 3_600)),
            ..gate()
        },
    ];
    for w in &wider {
        assert!(!narrows(&old, w), "{w:?}");
    }
    let capped = Gate {
        ingest_until: Some(5),
        ..gate()
    };
    assert!(!narrows(&capped, &old));
}

// L2-CLM-3, E18, INV-15, OP-150: an actor-binding Acceptance admits a Claim, which is then
// neither a proof nor a membership
#[test]
fn an_actor_binding_acceptance_admits_for_its_use_only() {
    let s = statement();
    let binding = Gate {
        use_: String::from(ACTOR_BINDING),
        ..gate()
    };
    assert_eq!(
        disposition(&s, core::slice::from_ref(&binding), 2_000),
        Disposition::Admit
    );
    assert!(!binding.admits(&s, 2_000));
    assert!(!binding.admits_for(SUBJECT_SELECTION, &s, 2_000));
    assert!(binding.admits_for(ACTOR_BINDING, &s, 2_000));
    assert!(quota_of(&s, &[binding], 2_000).is_some());
}

fn pinned_content(keys: Vec<Value>) -> Value {
    let mut c = acceptance_content();
    if let Value::Map(m) = &mut c {
        m.push((
            Value::text("pinned"),
            Value::Map(vec![
                (Value::text("iss"), Value::text("https://idp.example")),
                (Value::text("aud"), Value::text("access")),
                (Value::text("keys"), Value::Array(keys)),
            ]),
        ));
    }
    c
}

// OP-150, §9.13 issuer identification: a pinned key set travels in the Acceptance; dropping
// keys narrows, adding one widens
#[test]
fn a_pinned_key_set_is_read_and_only_shrinks_by_narrowing() {
    let k1 = key(9).to_value();
    let k2 = key(8).to_value();
    let both = Gate::of(&pinned_content(vec![k1.clone(), k2])).unwrap();
    let one = Gate::of(&pinned_content(vec![k1])).unwrap();
    let pinned = both.pinned.clone().unwrap();
    assert_eq!(pinned.iss, "https://idp.example");
    assert_eq!(pinned.key_set().keys.len(), 2);
    assert!(pinned.key_set().keys.contains_key(&thumbprint(&key(9))));
    assert!(narrows(&both, &one));
    assert!(!narrows(&one, &both));
    assert!(!narrows(
        &one,
        &Gate {
            pinned: None,
            ..one.clone()
        }
    ));
    assert!(Gate::of(&pinned_content(vec![])).is_err());
}

// SEC12, §13.7.7: an unknown occurredAt reaches 72 hours back from the declaration
#[test]
fn compromise_lookback_is_72_hours() {
    assert_eq!(COMPROMISE_LOOKBACK_MS, 259_200_000);
}

// TI-RT7, OP-141 m.30 (c): a successor shares issuer, subject and class, nothing else matters
#[test]
fn a_successor_is_on_the_same_line_only_with_the_same_issuer_subject_and_class() {
    let of = statement();
    let later = Statement {
        value: Some(EqValue::Bool(false)),
        issued_at: 9_000,
        ..statement()
    };
    assert!(same_line(&of, &later));
    let other_issuer = Statement {
        issuer: Id([7; 16]),
        ..statement()
    };
    let other_subject = Statement {
        subject: Id([7; 16]),
        ..statement()
    };
    let other_class = Statement {
        class: String::from("age"),
        ..statement()
    };
    for s in [&other_issuer, &other_subject, &other_class] {
        assert!(!same_line(&of, s), "{s:?}");
    }
}

fn pinned_value(iss: &str, aud: &str, keys: Vec<Value>) -> Value {
    Value::Map(vec![
        (Value::text("iss"), Value::text(iss)),
        (Value::text("aud"), Value::text(aud)),
        (Value::text("keys"), Value::Array(keys)),
    ])
}

// OP-150, §9.13 issuer identification: a pinned key set names its issuer, audience and keys
#[test]
fn a_pinned_key_set_needs_issuer_audience_and_keys() {
    let k = key(9).to_value();
    assert_eq!(
        check_pinned(&pinned_value(
            "https://idp.example",
            "access",
            vec![k.clone()]
        )),
        Ok(())
    );
    assert_eq!(
        check_pinned(&pinned_value("", "access", vec![k.clone()])),
        Err(ModelError::Range)
    );
    assert_eq!(
        check_pinned(&pinned_value("https://idp.example", "", vec![k])),
        Err(ModelError::Range)
    );
    assert_eq!(
        check_pinned(&pinned_value("https://idp.example", "access", vec![])),
        Err(ModelError::Range)
    );
    assert!(check_pinned(&Value::text("pinned")).is_err());
}

// L2-CLM-3: a predicate-input gate admits a matching Claim, also for one named subject
#[test]
fn a_gate_admits_its_subject_as_a_predicate_input() {
    let s = statement();
    assert!(gate().admits(&s, 2_000));
    let named = Gate {
        subject: SubjectSelector::Party(SUBJECT),
        ..gate()
    };
    assert!(named.admits(&s, 2_000));
    assert_eq!(disposition(&s, &[named], 2_000), Disposition::Admit);
}

// L2-CLM-3, OP-141 m.19 (c): a Claim signed exactly the allowed skew ahead is not future
#[test]
fn a_claim_at_the_skew_limit_is_not_future() {
    let at_limit = Statement {
        issued_at: 10_000 + SKEW_MS,
        ..statement()
    };
    assert_eq!(
        disposition(&at_limit, &[gate()], 10_000),
        Disposition::Admit
    );
    let beyond = Statement {
        issued_at: 10_001 + SKEW_MS,
        ..statement()
    };
    assert_eq!(disposition(&beyond, &[gate()], 10_000), Disposition::Future);
}

fn with_quota(count: u64, window_s: u64) -> Value {
    let mut c = acceptance_content();
    if let Value::Map(m) = &mut c {
        m.push((
            Value::text("quota"),
            map([
                ("count", Some(Value::Unsigned(count))),
                ("window_s", Some(Value::Unsigned(window_s))),
            ]),
        ));
    }
    c
}

// OP-141 m.21 (a): a declared quota is read as count per window; neither may be zero
#[test]
fn a_declared_quota_is_read_and_must_be_positive() {
    assert_eq!(Gate::of(&with_quota(5, 60)).unwrap().quota, Some((5, 60)));
    assert_eq!(Gate::of(&with_quota(0, 60)), Err(ModelError::Range));
    assert_eq!(Gate::of(&with_quota(5, 0)), Err(ModelError::Range));
}

// OP-141 m.21 (d): an earlier cutoff or a tighter quota narrows, a later or looser one widens
#[test]
fn cutoffs_and_quotas_narrow_only_when_tighter() {
    let old = Gate {
        ingest_until: Some(10),
        quota: Some((5, 60)),
        ..gate()
    };
    let narrower = [
        Gate {
            ingest_until: Some(5),
            ..old.clone()
        },
        Gate {
            quota: Some((3, 120)),
            ..old.clone()
        },
        old.clone(),
    ];
    for n in &narrower {
        assert!(narrows(&old, n), "{n:?}");
    }
    let wider = [
        Gate {
            ingest_until: Some(20),
            ..old.clone()
        },
        Gate {
            quota: Some((6, 60)),
            ..old.clone()
        },
        Gate {
            quota: Some((5, 30)),
            ..old.clone()
        },
    ];
    for w in &wider {
        assert!(!narrows(&old, w), "{w:?}");
    }
}

// L2-CLM-1: an Instance-signed Claim keeps its signing time in the record
#[test]
fn claim_state_keeps_the_signing_time() {
    let st = ClaimState {
        statement: Statement {
            domain: Digest([0; 32]),
            ..statement()
        },
        instance: Some(Id([9; 16])),
        since: 7,
        ended: None,
    };
    let back = ClaimState::from_value(&st.to_value()).unwrap();
    assert_eq!(back.statement.issued_at, 1_000);
    assert_eq!(back, st);
}
