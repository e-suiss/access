//! `horizon.json`: the horizon of a contract at issuance (L0-VAL-5, L0-VAL-20, OP-126 m.2).

use alloc::format;

use super::*;

// L0-VAL-5, L0-VAL-20, OP-126 m.2
#[test]
fn horizon_vectors_match() {
    let cases: [(&str, u64, &[u64], u64); 5] = [
        ("profile-max-is-earliest", 1_000, &[90_000, 50_000], 10_000),
        ("dependency-is-earliest", 1_000, &[90_000, 5_000], 10_000),
        ("dependency-equals-profile-max", 1_000, &[11_000], 10_000),
        ("no-dependency-bounds", 1_000, &[], 10_000),
        ("profile-max-overflow", u64::MAX, &[5_000], 1),
    ];
    let mut lines = Vec::new();
    for (id, issued_at, bounds, max) in cases {
        let expect = match horizon(issued_at, bounds, max) {
            Ok(h) => format!("\"horizon\": {h}"),
            Err(e) => format!(
                "\"error\": \"{}\"",
                crate::binding::Error::Validity(e).name()
            ),
        };
        let list: Vec<String> = bounds.iter().map(|b| format!("{b}")).collect();
        let rules: &[&str] = if id.ends_with("overflow") {
            &["L0-VAL-5", "L0-VAL-20"]
        } else {
            &["L0-VAL-5"]
        };
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"issued_at\": {issued_at}, \"dependency_bounds\": [{}], \"profile_max_ms\": {max}, {expect}}}",
            crate::vector_rules::field(rules),
            list.join(", ")
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-126\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"validity.horizon\",\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    crate::vector_rules::golden(
        "horizon.json",
        include_str!("../../../../../conformance/vectors/core/1/horizon.json"),
        &json,
    );
}
