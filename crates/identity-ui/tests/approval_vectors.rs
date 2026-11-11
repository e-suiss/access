//! The Approval Surface WYSIWYS vectors (§9.14.5 k.1, U7, PI-17, XI-8, OP-157 m.3 (l)):
//! `conformance/vectors/approval/1/wysiwys.json` is the render the Kernel computes from an
//! intent and its accepted Action Schema, its `render_digest` and material fields, and the
//! surface's check of what it shows against the statement. `ACCESS_UPDATE_VECTORS=1` rewrites
//! the file; F0 recomputes every case (`just f0`).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use access_identity_ui::domain::approval::{body_digest, wysiwys};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::render;
use access_kernel::schema::{ActionSchema, EffectClass, Reversibility};
use serde_json::{Value, json};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/approval/1/wysiwys.json")
}

fn schema() -> ActionSchema {
    ActionSchema {
        name: String::from("pay"),
        major: 1,
        effect: EffectClass::Irreversible,
        reserved: false,
        consumption_bearing: true,
        params: BTreeMap::from([
            (String::from("amount"), String::from("amount")),
            (String::from("reference"), String::from("text")),
        ]),
        resource_types: BTreeSet::new(),
        render: Some(String::from("Pay {amount} to {recipient}")),
        reversibility: Some(Reversibility::Irreversible),
    }
}

fn intent(amount: i64, recipient: u8) -> IntentEnvelope {
    IntentEnvelope {
        action: ActionRef {
            namespace: String::from("pay"),
            name: String::from("pay"),
            major: 1,
            schema: Digest([0x0c; 32]),
        },
        resources: vec![ResourceRef {
            namespace: String::from("pay.account"),
            path: vec![String::from("acc_1182")],
            incarnation: 0,
        }],
        params: BTreeMap::from([
            (
                String::from("amount"),
                ParamValue::Amount {
                    value: amount,
                    unit: String::from("eur"),
                },
            ),
            (
                String::from("reference"),
                ParamValue::Eq(access_kernel::model::EqValue::Text(String::from("PO-1182"))),
            ),
        ]),
        opaque: BTreeMap::new(),
        recipient: Some(Id([recipient; 16])),
        purpose: None,
        context: ContextRefs::default(),
        provenance: BTreeMap::new(),
        validity: Window {
            from: 1_767_225_600_000,
            until: 1_767_229_200_000,
        },
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn rendered(
    schema: Option<&ActionSchema>,
    i: &IntentEnvelope,
) -> (render::Render, Vec<u8>, Digest) {
    let r = render::of(schema, i, render::DEFAULT_LOCALE).unwrap();
    let bytes = render::encode(&r).unwrap();
    let d = render::digest(&r).unwrap();
    (r, bytes, d)
}

fn render_case(id: &str, schema: Option<&ActionSchema>, i: &IntentEnvelope) -> Value {
    let (r, bytes, d) = rendered(schema, i);
    let mut case = json!({
        "id": id,
        "rules": ["U7", "XI-8", "P58"],
        "operation": "approval.render",
        "intent": hex(&i.to_bytes().unwrap()),
        "locale": render::DEFAULT_LOCALE,
        "render": hex(&bytes),
        "render_digest": hex(&d.to_bytes().unwrap()),
        "material_fields": render::material_fields(&r).into_iter().collect::<Vec<_>>(),
    });
    if let (Some(s), Some(o)) = (schema, case.as_object_mut()) {
        o.insert(String::from("schema"), json!(hex(&s.to_bytes().unwrap())));
    }
    case
}

struct Check<'a> {
    id: &'a str,
    rules: &'a [&'a str],
    shown: Vec<u8>,
    digest: Digest,
    material: BTreeSet<String>,
    intent: Option<Vec<u8>>,
    bodies: BTreeMap<String, Vec<u8>>,
}

fn check_case(c: Check<'_>) -> Value {
    let expect = match wysiwys(
        &c.shown,
        &c.digest,
        &c.material,
        c.intent.as_deref(),
        &c.bodies,
    ) {
        Ok(()) => String::from("accept"),
        Err(e) => e.to_string(),
    };
    let mut case = json!({
        "id": c.id,
        "rules": c.rules,
        "operation": "approval.wysiwys",
        "shown": hex(&c.shown),
        "render_digest": hex(&c.digest.to_bytes().unwrap()),
        "material_fields": c.material.iter().collect::<Vec<_>>(),
        "expect": expect,
    });
    let o = case.as_object_mut().unwrap();
    if let Some(i) = &c.intent {
        o.insert(String::from("intent"), json!(hex(i)));
    }
    if !c.bodies.is_empty() {
        o.insert(
            String::from("bodies"),
            json!(
                c.bodies
                    .iter()
                    .map(|(k, v)| (k.clone(), hex(v)))
                    .collect::<BTreeMap<_, _>>()
            ),
        );
    }
    case
}

fn reencoded(mut r: render::Render, change: impl FnOnce(&mut render::Render)) -> Vec<u8> {
    change(&mut r);
    render::encode(&r).unwrap()
}

fn document() -> Value {
    let s = schema();
    let paid = intent(48_500, 0x41);
    let (r, bytes, d) = rendered(Some(&s), &paid);
    let material = render::material_fields(&r);
    let note = b"Thank you for the October delivery.".to_vec();
    let mut bodied = paid.clone();
    bodied
        .opaque
        .insert(String::from("note"), body_digest(&note));
    let (br, bbytes, bd) = rendered(Some(&s), &bodied);
    let bmaterial = render::material_fields(&br);
    let mut cases = vec![
        render_case("render-without-schema", None, &paid),
        render_case("render-with-schema", Some(&s), &paid),
        render_case("render-with-body", Some(&s), &bodied),
    ];
    let checks = [
        Check {
            id: "shown-as-rendered",
            rules: &["U7", "P58", "XI-8"],
            shown: bytes.clone(),
            digest: d,
            material: material.clone(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "material-field-missing",
            rules: &["U7", "P58"],
            shown: reencoded(r.clone(), |r| r.fields.retain(|f| f.name != "amount")),
            digest: d,
            material: material.clone(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "statement-misses-a-material-field",
            rules: &["U7", "P58"],
            shown: bytes.clone(),
            digest: d,
            material: material
                .iter()
                .filter(|m| *m != "amount")
                .cloned()
                .collect(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "fields-reordered",
            rules: &["U7", "XI-8"],
            shown: reencoded(r.clone(), |r| r.fields.reverse()),
            digest: d,
            material: material.clone(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "amount-changed",
            rules: &["U7", "SA-54"],
            shown: rendered(Some(&s), &intent(48_501, 0x41)).1,
            digest: d,
            material: material.clone(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "recipient-changed",
            rules: &["U7", "SA-54"],
            shown: rendered(Some(&s), &intent(48_500, 0x42)).1,
            digest: d,
            material: material.clone(),
            intent: None,
            bodies: BTreeMap::new(),
        },
        Check {
            id: "body-matches",
            rules: &["PI-17", "P30"],
            shown: bbytes.clone(),
            digest: bd,
            material: bmaterial.clone(),
            intent: Some(bodied.to_bytes().unwrap()),
            bodies: BTreeMap::from([(String::from("note"), note.clone())]),
        },
        Check {
            id: "body-does-not-match",
            rules: &["PI-17", "P30"],
            shown: bbytes.clone(),
            digest: bd,
            material: bmaterial.clone(),
            intent: Some(bodied.to_bytes().unwrap()),
            bodies: BTreeMap::from([(String::from("note"), b"Pay someone else.".to_vec())]),
        },
        Check {
            id: "body-of-another-intent",
            rules: &["PI-17", "P30"],
            shown: bbytes,
            digest: bd,
            material: bmaterial,
            intent: Some(paid.to_bytes().unwrap()),
            bodies: BTreeMap::from([(String::from("note"), note)]),
        },
    ];
    cases.extend(checks.into_iter().map(check_case));
    json!({
        "rule": "OP-157",
        "track": "approval",
        "version": 1,
        "cases": cases,
    })
}

// §9.14.5 k.1, U7, PI-17, XI-8, SA-54, OP-157 m.3 (l), Ek B 5639, 5602
#[test]
fn wysiwys_vectors_match_the_kernel_and_the_surface() {
    let doc = document();
    let expected: Vec<&str> = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["expect"].as_str())
        .collect();
    assert_eq!(
        expected,
        [
            "accept", "render", "material", "render", "render", "render", "accept", "body", "body"
        ]
    );
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    let file = path();
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&file).unwrap_or_default();
    assert_eq!(
        serde_json::from_str::<Value>(&committed).ok(),
        Some(doc),
        "{}: run with ACCESS_UPDATE_VECTORS=1 and review the diff",
        file.display()
    );
}
