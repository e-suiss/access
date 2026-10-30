//! `digest.json`: intent digest and body commitment (L0-ENC-22, L0-ENC-23, L0-ENC-29a,
//! OP-126 m.2).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::codec::Canonical as _;
use crate::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use crate::model::{ActionRef, Id, PurposeRef, ResourceRef, Window};
use suiss_crypto::dcbor::{Limits, encode};

use crate::vector_rules::hex;

fn minimal() -> IntentEnvelope {
    IntentEnvelope {
        action: ActionRef {
            namespace: "pay".to_string(),
            name: "refund".to_string(),
            major: 1,
            schema: Digest([9; 32]),
        },
        resources: vec![ResourceRef {
            namespace: "shop".to_string(),
            path: vec!["o1".to_string()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 100_000,
        },
    }
}

fn full() -> IntentEnvelope {
    let mut i = minimal();
    i.params.insert(
        "amount".to_string(),
        ParamValue::Amount {
            value: 1_250,
            unit: "eur".to_string(),
        },
    );
    i.opaque.insert("note".to_string(), Digest([7; 32]));
    i.recipient = Some(Id([5; 16]));
    i.purpose = Some(PurposeRef::Code("refund".to_string()));
    i.context.work = Some(Digest([6; 32]));
    i
}

// L0-ENC-22, L0-ENC-23, L0-ENC-29a, OP-126 m.2
#[test]
fn digest_vectors_match() {
    let mut lines = Vec::new();
    for (id, intent) in [("intent-minimal", minimal()), ("intent-full", full())] {
        let d = intent_digest(&intent).unwrap();
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"operation\": \"digest.intent\", \"intent\": \"{}\", \"digest\": \"{}\"}}",
            crate::vector_rules::field(&["L0-ENC-20", "L0-ENC-22", "L0-ENC-23"]),
            hex(&intent.to_bytes().unwrap()),
            hex(&d.to_bytes().unwrap()),
        ));
    }
    let bodies = [
        ("body-text", Value::text("refund approved"), [0x51; 32]),
        (
            "body-map",
            Value::Map(vec![
                (Value::text("amount"), Value::Unsigned(1_250)),
                (Value::text("unit"), Value::text("eur")),
            ]),
            [0x52; 32],
        ),
    ];
    for (id, body, salt) in bodies {
        let cbor = encode(&body, Limits::CEILING).unwrap();
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"operation\": \"digest.body_commit\", \"body\": \"{}\", \"salt\": \"{}\", \"commit\": \"{}\"}}",
            crate::vector_rules::field(&["L0-ENC-24", "L0-ENC-29a"]),
            hex(&cbor),
            hex(&salt),
            hex(&body_commit(&salt, &cbor)),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-126\",\n \"track\": \"core\",\n \"version\": 1,\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    crate::vector_rules::golden(
        "digest.json",
        include_str!("../../../../../conformance/vectors/core/1/digest.json"),
        &json,
    );
}
