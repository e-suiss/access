//! `core/1/receipt-evidence.json`: a receipt whose excerpt is signed by a superseded binding
//! key, verified with and without its inclusion evidence (L2-RCP-3, L0-SIG-64, L0-SIG-80,
//! OP-159 m.17 (a), Ek B 5780).

use ed25519_dalek::Signer as _;
use suiss_crypto::note::{Verifier, base64_encode, cosigned_message};

use super::*;
use crate::record::{Disclosure, Header, Opened, RecordKind};
use crate::verify::key_scope::{ARTIFACTS_FIELD, Inclusion, Superseded};

const ORIGIN: &str = "sha-256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

fn salt(n: u8) -> [u8; 32] {
    suiss_crypto::digest::sha256(&[b'r', b'e', b'c', n])
}

fn record(pos: u8, artifacts: &[Digest]) -> Disclosure {
    Disclosure {
        header: Header {
            domain: Some(d(1)),
            pos: u64::from(pos),
            kind: RecordKind::Decision,
            recorded_at: 10 * HOUR + u64::from(pos),
            prev: Some(d(pos)),
        },
        opened: BTreeMap::from([(
            String::from(ARTIFACTS_FIELD),
            Opened {
                value: Value::Array(artifacts.iter().map(Digest::to_value).collect()),
                salt: salt(pos),
            },
        )]),
        withheld: BTreeMap::new(),
    }
}

fn line(name: &str, id: u32, sig: &[u8]) -> String {
    let mut raw = id.to_be_bytes().to_vec();
    raw.extend_from_slice(sig);
    format!("\u{2014} {name} {}\n", base64_encode(&raw))
}

fn log() -> Verifier {
    Verifier::ed25519("log.example", ed(5).verifying_key().to_bytes()).unwrap()
}

fn witness() -> Verifier {
    Verifier::cosigner("witness.example", ed(6).verifying_key().to_bytes()).unwrap()
}

fn note(size: u64, root: [u8; 32], cosign: bool) -> String {
    let body = format!("{ORIGIN}\n{size}\n{}\n", base64_encode(&root));
    let mut text = format!("{body}\n");
    let l = log();
    text.push_str(&line(
        l.name(),
        l.id(),
        &ed(5).sign(body.as_bytes()).to_bytes(),
    ));
    if cosign {
        let w = witness();
        let mut sig = 7_u64.to_be_bytes().to_vec();
        sig.extend(ed(6).sign(&cosigned_message(7, &body)).to_bytes());
        text.push_str(&line(w.name(), w.id(), &sig));
    }
    text
}

fn superseded_at(root: [u8; 32]) -> DomainMetadata {
    let mut m = metadata();
    for b in m.binding.values_mut() {
        b.superseded = Some(Superseded {
            at: Digest(root),
            cited: Digest(root),
            cause: None,
        });
    }
    m
}

struct Ev {
    artefact: Digest,
    record: Disclosure,
    path: Vec<[u8; 32]>,
    note: String,
}

struct Case {
    id: &'static str,
    base: super::Case,
    evidence: Option<Ev>,
}

fn other() -> Receipt {
    Receipt {
        record: 6,
        ..receipt()
    }
}

fn cases() -> (DomainMetadata, Vec<Case>) {
    let own = digest(&receipt()).unwrap();
    let theirs = digest(&other()).unwrap();
    let r0 = record(1, &[d(0xa0)]);
    let r1 = record(2, &[theirs, own]);
    let genesis = suiss_crypto::digest::sha256(b"genesis leaf");
    let (h0, h1) = (r0.leaf_hash().unwrap(), r1.leaf_hash().unwrap());
    let left = suiss_crypto::digest::node_hash(&genesis, &h0);
    let root = suiss_crypto::digest::node_hash(&left, &h1);
    let good = || Ev {
        artefact: own,
        record: r1.clone(),
        path: vec![left],
        note: note(3, root, true),
    };
    let mut tampered = super::Case::of(&receipt());
    let last = tampered.receipt.len() - 1;
    tampered.receipt[last] ^= 1;
    let cases = vec![
        Case {
            id: "superseded-with-evidence-accepted",
            base: super::Case::of(&receipt()),
            evidence: Some(good()),
        },
        Case {
            id: "superseded-without-evidence-refused",
            base: super::Case::of(&receipt()),
            evidence: None,
        },
        Case {
            id: "evidence-for-another-receipt-refused",
            base: super::Case::of(&receipt()),
            evidence: Some(Ev {
                artefact: theirs,
                ..good()
            }),
        },
        Case {
            id: "record-not-committing-the-receipt-refused",
            base: super::Case::of(&receipt()),
            evidence: Some(Ev {
                record: r0.clone(),
                path: vec![genesis, h1],
                ..good()
            }),
        },
        Case {
            id: "checkpoint-without-a-witness-refused",
            base: super::Case::of(&receipt()),
            evidence: Some(Ev {
                note: note(3, root, false),
                ..good()
            }),
        },
        Case {
            id: "evidence-does-not-mend-a-signature",
            base: tampered,
            evidence: Some(good()),
        },
    ];
    (superseded_at(root), cases)
}

fn run(m: &DomainMetadata, c: &Case) -> Result<Receipt, ReceiptError> {
    let (log, witnesses) = (log(), [witness()]);
    let inclusion = c
        .evidence
        .as_ref()
        .map(|e| Inclusion::new(&e.record, &e.path, &e.note, None));
    let evidence = c.evidence.as_ref().zip(inclusion).map(|(e, i)| {
        crate::verify::key_scope::InclusionEvidence::new(e.artefact, i, ORIGIN, &log, &witnesses)
    });
    verify_with_evidence(
        &PureBackend,
        m,
        &c.base.receipt,
        &c.base.excerpt,
        &Expected {
            domain: &c.base.domain,
            audience: c.base.audience,
            intent: &c.base.intent,
            now: c.base.now,
        },
        evidence.as_ref(),
    )
}

// L2-RCP-3, L0-SIG-64, L0-SIG-80, OP-159 m.17 (a), Ek B 5780
#[test]
fn a_superseded_receipt_verifies_only_with_its_own_evidence() {
    let (m, cases) = cases();
    let got: Vec<Result<Receipt, &str>> = cases
        .iter()
        .map(|c| run(&m, c).map_err(ReceiptError::code))
        .collect();
    assert_eq!(got[0], Ok(receipt()));
    assert_eq!(
        got[1..],
        [
            Err("receipt-key"),
            Err("receipt-key"),
            Err("receipt-key"),
            Err("receipt-key"),
            Err("receipt-signature"),
        ]
    );
    let c = &cases[1];
    assert_eq!(
        verify(
            &PureBackend,
            &m,
            &c.base.receipt,
            &c.base.excerpt,
            &Expected {
                domain: &c.base.domain,
                audience: c.base.audience,
                intent: &c.base.intent,
                now: c.base.now,
            },
        ),
        Err(ReceiptError::Key(KeyScopeError::Superseded))
    );
}

// L2-RCP-3, OP-159 m.17 (a)
#[test]
fn receipt_evidence_vectors_match() {
    let (m, cases) = cases();
    let lines: Vec<String> = cases
        .iter()
        .map(|c| {
            let result = match run(&m, c) {
                Ok(r) => format!("\"receipt\": \"{}\"", hex(&r.to_bytes().unwrap())),
                Err(e) => format!("\"error\": \"{}\"", e.code()),
            };
            let evidence = c.evidence.as_ref().map_or_else(String::new, |e| {
                let path: Vec<String> = e.path.iter().map(|h| format!("\"{}\"", hex(h))).collect();
                format!(
                    "\"evidence\": {{\"artefact\": \"{}\", \"record\": \"{}\", \"path\": [{}], \"note\": {}}}, ",
                    hex(&e.artefact.0),
                    hex(&e.record.to_bytes().unwrap()),
                    path.join(", "),
                    serde_json::to_string(&e.note).unwrap(),
                )
            });
            format!(
                "  {{\"id\": \"{}\", {}, \"excerpt\": \"{}\", \"sign1\": \"{}\", \"domain\": \"{}\", \"audience\": \"{}\", \"intent\": \"{}\", \"now\": {}, {evidence}{result}}}",
                c.id,
                field(&["L2-RCP-3", "L0-SIG-80"]),
                hex(&c.base.excerpt),
                hex(&c.base.receipt),
                hex(&dcbor::encode(&c.base.domain.to_value(), Limits::CEILING).unwrap()),
                c.base.audience,
                hex(&dcbor::encode(&c.base.intent.to_value(), Limits::CEILING).unwrap()),
                c.base.now
            )
        })
        .collect();
    let json = format!(
        "{{\n \"rule\": \"L2-RCP-3\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"receipt.verify_with_evidence\",\n \"metadata\": \"{}\",\n \"origin\": \"{ORIGIN}\",\n \"log\": \"{}\",\n \"witnesses\": [\"{}\"],\n \"cases\": [\n{}\n ]\n}}\n",
        hex(&m.to_bytes().unwrap()),
        log().to_vkey(),
        witness().to_vkey(),
        lines.join(",\n")
    );
    golden(
        "receipt-evidence.json",
        include_str!("../../../../../conformance/vectors/core/1/receipt-evidence.json"),
        &json,
    );
}
