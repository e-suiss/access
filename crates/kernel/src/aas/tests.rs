#![allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "test fixtures"
)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use ed25519_dalek::Signer as _;

use super::*;
use crate::vector_rules::{field, golden, hex};
use crate::verify::cose::{ALG, CONTENT_TYPE as CT_LABEL, KID, to_be_signed};

const DOMAIN: Digest = Digest([0x33; 32]);
const TARGET: Digest = Digest([0x44; 32]);
const RENDER: Digest = Digest([0x66; 32]);
const INSTANCE: Id = Id([2; 16]);
const NOW: u64 = 1_767_225_060_000;

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn key(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

fn sign(payload: &[u8], seed: u8, ct: &str) -> Vec<u8> {
    let with = signing(seed);
    let kid = thumbprint(&key(seed));
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

fn statement() -> ApprovalAct {
    ApprovalAct {
        act: Act::Contribution("approve".to_string()),
        instance: INSTANCE,
        party: Id([1; 16]),
        capacity: Capacity::Own,
        target: TARGET,
        domain: DOMAIN,
        nonce: (0..16).collect(),
        work_gate: Some((Digest([0x22; 32]), Digest([0x55; 32]))),
        surface_profile: "suiss-approval-surface".to_string(),
        surface_version: 1,
        render_digest: RENDER,
        material_fields: ["amount".to_string(), "recipient".to_string()]
            .into_iter()
            .collect(),
        issued_at: NOW - 60_000,
        expires_at: NOW + 240_000,
    }
}

fn expected(now: u64) -> Expected<'static> {
    Expected {
        domain: &DOMAIN,
        target: &TARGET,
        instance: &INSTANCE,
        render_digest: &RENDER,
        now,
    }
}

fn signed(a: &ApprovalAct) -> Vec<u8> {
    sign(&a.to_bytes().unwrap(), 9, CONTENT_TYPE)
}

fn cases() -> Vec<(&'static str, &'static [&'static str], Vec<u8>, u64)> {
    let with = |f: fn(&mut ApprovalAct)| {
        let mut a = statement();
        f(&mut a);
        signed(&a)
    };
    let mut no_class = statement().to_value();
    if let Value::Map(m) = &mut no_class {
        m.retain(|(k, _)| *k != Value::text("contribution_class"));
    }
    let no_class = sign(
        &dcbor::encode(&no_class, Limits::CEILING).unwrap(),
        9,
        CONTENT_TYPE,
    );
    vec![
        (
            "contribution",
            &["L2-AAS-1", "L2-AAS-2", "L2-AAS-3"],
            signed(&statement()),
            NOW,
        ),
        (
            "authority-act",
            &["L2-AAS-2", "L2-AAS-3"],
            with(|a| {
                a.act = Act::AuthorityAct;
                a.work_gate = None;
                a.material_fields = BTreeSet::new();
            }),
            NOW,
        ),
        (
            "another-domain",
            &["L2-AAS-3"],
            with(|a| a.domain = Digest([9; 32])),
            NOW,
        ),
        (
            "another-target",
            &["L2-AAS-3"],
            with(|a| a.target = Digest([9; 32])),
            NOW,
        ),
        (
            "another-approver",
            &["L2-AAS-3"],
            with(|a| a.instance = Id([9; 16])),
            NOW,
        ),
        (
            "another-render",
            &["L2-AAS-3"],
            with(|a| a.render_digest = Digest([9; 32])),
            NOW,
        ),
        (
            "signed-in-the-future",
            &["L2-AAS-4"],
            with(|a| a.issued_at = NOW + 60_001),
            NOW,
        ),
        (
            "skew-allowed",
            &["L2-AAS-4"],
            with(|a| a.issued_at = NOW + 60_000),
            NOW,
        ),
        (
            "expired",
            &["L2-AAS-4"],
            signed(&statement()),
            NOW + 240_001,
        ),
        (
            "expires-at-the-edge",
            &["L2-AAS-4"],
            signed(&statement()),
            NOW + 240_000,
        ),
        (
            "expires-before-issue",
            &["L2-AAS-4"],
            with(|a| a.expires_at = a.issued_at - 1),
            NOW - 60_000,
        ),
        (
            "another-key",
            &["L2-AAS-2"],
            sign(&statement().to_bytes().unwrap(), 8, CONTENT_TYPE),
            NOW,
        ),
        (
            "another-content-type",
            &["L2-AAS-2"],
            sign(
                &statement().to_bytes().unwrap(),
                9,
                "application/access-ais+cbor",
            ),
            NOW,
        ),
        ("contribution-without-class", &["L2-AAS-1"], no_class, NOW),
    ]
}

fn run(sign1: &[u8], now: u64) -> Result<Digest, AasError> {
    verify(sign1, &key(9), &expected(now)).map(|(_, h)| h)
}

// L2-AAS-1 to L2-AAS-4: each check rejects its case; H(AAS) is the digest of the statement
#[test]
fn statements_verify_or_name_their_failure() {
    let got: Vec<Result<Digest, &str>> = cases()
        .iter()
        .map(|(_, _, s, now)| run(s, *now).map_err(AasError::code))
        .collect();
    assert_eq!(got[0], Ok(digest(&statement()).unwrap()));
    assert_eq!(
        got[0].unwrap(),
        Digest(context_digest(CONTEXT, &statement().to_bytes().unwrap()).0)
    );
    assert!(got[1].is_ok());
    assert!(got[7].is_ok());
    assert!(got[9].is_ok());
    let errors: Vec<&str> = [2, 3, 4, 5, 6, 8, 10, 11, 12, 13]
        .iter()
        .map(|i| got[*i].unwrap_err())
        .collect();
    assert_eq!(
        errors,
        [
            "aas-domain",
            "aas-target",
            "aas-approver",
            "aas-render",
            "aas-future",
            "aas-expired",
            "aas-expired",
            "aas-signature",
            "aas-signature",
            "aas-malformed",
        ]
    );
}

// L2-AAS-1, E32: the statement round-trips and an act names its class exactly when it is a
// contribution
#[test]
fn statements_round_trip() {
    let a = statement();
    assert_eq!(ApprovalAct::from_bytes(&a.to_bytes().unwrap()), Ok(a));
    let mut with_class = ApprovalAct {
        act: Act::AuthorityAct,
        ..statement()
    }
    .to_value();
    if let Value::Map(m) = &mut with_class {
        m.push((Value::text("contribution_class"), Value::text("approve")));
    }
    assert_eq!(ApprovalAct::from_value(&with_class), Err(ModelError::Range));
}

// L2-AAS-1 to L2-AAS-4
#[test]
fn aas_vectors_match() {
    let rows: Vec<String> = cases()
        .iter()
        .map(|(id, rules, s, now)| {
            let out = match run(s, *now) {
                Ok(h) => format!("\"digest\": \"{}\"", hex(&h.0)),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            format!(
                "  {{\"id\": \"{id}\", {}, \"sign1\": \"{}\", \"now\": {now}, {out}}}",
                field(rules),
                hex(s)
            )
        })
        .collect();
    let enc = |v: &Value| hex(&dcbor::encode(v, Limits::CEILING).unwrap());
    let json = format!(
        "{{\n \"rule\": \"L2-AAS-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"aas.verify\",\n \"key\": \"{}\",\n \"domain\": \"{}\",\n \"target\": \"{}\",\n \"instance\": \"{}\",\n \"render_digest\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
        hex(&key(9).to_bytes().unwrap()),
        enc(&DOMAIN.to_value()),
        enc(&TARGET.to_value()),
        hex(&INSTANCE.0),
        enc(&RENDER.to_value()),
        rows.join(",\n")
    );
    golden(
        "aas.json",
        include_str!("../../../../conformance/vectors/core/1/aas.json"),
        &json,
    );
}
