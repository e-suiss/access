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
    let sig = with.sign(&to_be_signed(&prot, payload)).to_bytes();
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
    let s = statement();
    assert_eq!(disposition(&s, &[gate()], 2_000), Disposition::Admit);
    assert_eq!(disposition(&s, &[], 2_000), Disposition::SourceNotAccepted);
    let refusing = [
        Gate {
            use_: String::from("actor-binding"),
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

// L2-CLM-3: the gate reads an acceptance-content
#[test]
fn a_gate_reads_acceptance_content() {
    let content = map([
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
