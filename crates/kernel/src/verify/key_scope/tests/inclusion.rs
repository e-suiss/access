//! `handover/1/inclusion.json`: the superseded-at predicate (§9.10, §13.3, P18, SEC25, U12,
//! U27, OP-158 m.3 (b)).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::Signer as _;
use suiss_crypto::note::{Verifier, base64_encode, cosigned_message};

use super::super::*;
use crate::record::{Disclosure, Header, Opened, RecordKind};
use crate::vector_rules::{field, golden_in, hex};
use crate::verify::PureBackend;

const DOMAIN: Digest = Digest([0x0d; 32]);
const ORIGIN: &str = "sha-256:DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0";

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn record(pos: u8, artefact: Digest) -> Disclosure {
    Disclosure {
        header: Header {
            domain: Some(DOMAIN),
            pos: u64::from(pos),
            kind: RecordKind::Decision,
            recorded_at: 1_000_u64.checked_add(u64::from(pos)).unwrap(),
            prev: Some(Digest([pos; 32])),
        },
        opened: BTreeMap::from([(
            String::from(ARTEFACT_FIELD),
            Opened {
                value: artefact.to_value(),
                salt: [0x5a; 32],
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

/// The note of `size` and `root`, signed by the log and, when `cosign`, the witness.
fn note(size: u64, root: [u8; 32], cosign: bool) -> String {
    let body = format!("{ORIGIN}\n{size}\n{}\n", base64_encode(&root));
    let log = Verifier::ed25519("log.example", key(1).verifying_key().to_bytes()).unwrap();
    let mut text = format!("{body}\n");
    text.push_str(&line(
        log.name(),
        log.id(),
        &key(1).sign(body.as_bytes()).to_bytes(),
    ));
    if cosign {
        let w = Verifier::cosigner("witness.example", key(2).verifying_key().to_bytes()).unwrap();
        let mut sig = 7_u64.to_be_bytes().to_vec();
        sig.extend(key(2).sign(&cosigned_message(7, &body)).to_bytes());
        text.push_str(&line(w.name(), w.id(), &sig));
    }
    text
}

fn binding(superseded: Option<(Digest, Digest)>) -> BindingKey {
    let k = crate::verify::cose::PublicKey::Ed25519(key(3).verifying_key().to_bytes());
    BindingKey {
        kid: thumbprint(&k),
        alg: crate::verify::cose::Algorithm::Ed25519,
        key: k,
        scope: BindingScope::Domain,
        superseded: superseded.map(|(at, cited)| Superseded {
            at,
            cited,
            cause: None,
        }),
    }
}

struct Case<'a> {
    id: &'static str,
    binding: BindingKey,
    artefact: Digest,
    record: &'a Disclosure,
    path: Vec<[u8; 32]>,
    note: String,
    consistency: Option<(u64, [u8; 32], Vec<[u8; 32]>)>,
}

fn hashes(list: &[[u8; 32]]) -> String {
    let items: Vec<String> = list.iter().map(|h| format!("\"{}\"", hex(h))).collect();
    format!("[{}]", items.join(", "))
}

// §9.10, §13.3, P18, SEC25, U12, U27, Ek B 5780
#[test]
#[allow(clippy::too_many_lines, reason = "one table of cases")]
fn inclusion_vectors_match() {
    let art = Digest([0xa1; 32]);
    let r0 = record(0, Digest([0xa0; 32]));
    let r1 = record(1, art);
    let r2 = record(2, Digest([0xa2; 32]));
    let (h0, h1, h2) = (
        r0.leaf_hash().unwrap(),
        r1.leaf_hash().unwrap(),
        r2.leaf_hash().unwrap(),
    );
    let root2 = suiss_crypto::digest::node_hash(&h0, &h1);
    let root3 = suiss_crypto::digest::node_hash(&root2, &h2);
    let recovered = Some((Digest(root2), Digest(root2)));
    let handed = Some((Digest(root3), Digest(root2)));
    let cases = [
        Case {
            id: "recovery-exact-content-accepted",
            binding: binding(recovered),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "other-content-refused",
            binding: binding(recovered),
            artefact: Digest([0xee; 32]),
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "same-exercise-other-record-refused",
            binding: binding(recovered),
            artefact: art,
            record: &r0,
            path: Vec::from([h1]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "without-a-witness-cosignature-refused",
            binding: binding(recovered),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, false),
            consistency: None,
        },
        Case {
            id: "another-checkpoint-refused",
            binding: binding(Some((Digest(root3), Digest(root3)))),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "a-bad-path-refused",
            binding: binding(recovered),
            artefact: art,
            record: &r1,
            path: Vec::from([h2]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "handover-with-consistency-accepted",
            binding: binding(handed),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: Some((3, root3, Vec::from([h2]))),
        },
        Case {
            id: "handover-without-consistency-refused",
            binding: binding(handed),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: None,
        },
        Case {
            id: "a-current-key-is-not-this-path",
            binding: binding(None),
            artefact: art,
            record: &r1,
            path: Vec::from([h0]),
            note: note(2, root2, true),
            consistency: None,
        },
    ];
    let log = Verifier::ed25519("log.example", key(1).verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner("witness.example", key(2).verifying_key().to_bytes()).unwrap();
    let mut lines = Vec::new();
    for c in cases {
        let evidence = Inclusion::new(
            c.record,
            &c.path,
            &c.note,
            c.consistency
                .as_ref()
                .map(|(s, r, p)| (*s, *r, p.as_slice())),
        );
        let got = superseded_inclusion(
            &PureBackend,
            &c.binding,
            &c.artefact,
            &evidence,
            (ORIGIN, &log, core::slice::from_ref(&witness)),
        );
        let expect = match got {
            Ok(()) => String::from("\"valid\": true"),
            Err(_) => String::from("\"error\": \"superseded\""),
        };
        let consistency = c
            .consistency
            .as_ref()
            .map_or_else(String::new, |(s, r, p)| {
                format!(
                    ", \"consistency\": {{\"to_size\": {s}, \"to_root\": \"{}\", \"path\": {}}}",
                    hex(r),
                    hashes(p)
                )
            });
        lines.push(format!(
            "  {{\"id\": \"{}\", {}, \"binding\": \"{}\", \"artefact\": \"{}\", \"record\": \"{}\", \"path\": {}, \"note\": {}{consistency}, {expect}}}",
            c.id,
            field(&["L0-SIG-80"]),
            hex(&c.binding.to_bytes().unwrap()),
            hex(&c.artefact.0),
            hex(&c.record.to_bytes().unwrap()),
            hashes(&c.path),
            serde_json::to_string(&c.note).unwrap(),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"handover\",\n \"version\": 1,\n \"operation\": \"inclusion.verify\",\n \"origin\": \"{ORIGIN}\",\n \"log\": \"{}\",\n \"witnesses\": [\"{}\"],\n \"cases\": [\n{}\n ]\n}}\n",
        log.to_vkey(),
        witness.to_vkey(),
        lines.join(",\n")
    );
    golden_in(
        "handover/1",
        "inclusion.json",
        include_str!("../../../../../../conformance/vectors/handover/1/inclusion.json"),
        &json,
    );
}

// L0-SIG-64, L0-SIG-80, P18, SEC25, U12, U27, OP-159 m.3 (i), Ek B 5780
#[test]
fn a_superseded_binding_takes_evidence_or_a_prospective_re_anchor() {
    let art = Digest([0xa1; 32]);
    let r0 = record(0, Digest([0xa0; 32]));
    let r1 = record(1, art);
    let (h0, h1) = (r0.leaf_hash().unwrap(), r1.leaf_hash().unwrap());
    let root2 = suiss_crypto::digest::node_hash(&h0, &h1);
    let text = note(2, root2, true);
    let path = [h0];
    let log = Verifier::ed25519("log.example", key(1).verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner("witness.example", key(2).verifying_key().to_bytes()).unwrap();
    let witnesses = [witness];
    let good = InclusionEvidence::new(
        art,
        Inclusion::new(&r1, &path, &text, None),
        ORIGIN,
        &log,
        &witnesses,
    );
    let other = InclusionEvidence::new(
        Digest([0xee; 32]),
        Inclusion::new(&r1, &path, &text, None),
        ORIGIN,
        &log,
        &witnesses,
    );
    let mut c = super::Case::new();
    let run = |c: &super::Case, iat: u64, e: Option<&InclusionEvidence<'_>>| {
        operational_key(
            &PureBackend,
            &c.metadata,
            &c.domain,
            &c.excerpt_bytes(),
            c.usage,
            iat,
            e,
        )
        .map(|_| ())
    };
    for cause in [
        None,
        Some(SupersededCause::ReAnchor),
        Some(SupersededCause::Handover),
        Some(SupersededCause::Recovery),
    ] {
        c.binding_mut().superseded = Some(Superseded {
            at: Digest(root2),
            cited: Digest(root2),
            cause,
        });
        assert_eq!(run(&c, c.iat, Some(&good)), Ok(()), "{cause:?}");
        assert_eq!(
            run(&c, c.iat, Some(&other)),
            Err(KeyScopeError::Superseded),
            "{cause:?}"
        );
        let before = c.metadata.issued_at;
        let bare = if cause == Some(SupersededCause::ReAnchor) {
            Ok(())
        } else {
            Err(KeyScopeError::Superseded)
        };
        assert_eq!(run(&c, before, None), bare, "{cause:?}");
        assert_eq!(
            run(&c, before + 1, None),
            Err(KeyScopeError::Superseded),
            "{cause:?}"
        );
    }
}
