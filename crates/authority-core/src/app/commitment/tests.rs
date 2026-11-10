use super::*;

// OP-156 m.3 (t), L2-CLB-1
#[test]
fn the_value_is_the_body_digest_and_decodes_only_when_it_matches() {
    let c = Digest([7; 32]);
    let on = value_digest(&c, true);
    let off = value_digest(&c, false);
    assert_ne!(on, off);
    assert_ne!(on, value_digest(&Digest([8; 32]), true));
    let bytes = dcbor::encode(&body(&c, false), Limits::CEILING).unwrap();
    assert_eq!(
        decode(Some(&EqValue::Bytes(off.to_vec())), &bytes),
        Some((c, false))
    );
    assert_eq!(decode(Some(&EqValue::Bytes(on.to_vec())), &bytes), None);
    assert_eq!(decode(None, &bytes), None);
}

// OP-156 m.3 (b), L2-CLB-1
#[test]
fn the_body_encodes_as_the_contract_example() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../conformance/cddl/examples/product-seam.json"
    ))
    .unwrap();
    for (id, active) in [("commitment-active", true), ("commitment-ended", false)] {
        let case = doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        let bytes = dcbor::encode(
            &Value::Array(vec![Value::text(CLASS), body(&Digest([0x0a; 32]), active)]),
            Limits::CEILING,
        )
        .unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, case["cbor"].as_str().unwrap(), "{id}");
    }
}
