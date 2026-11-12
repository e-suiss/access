//! CR-38, CR-43, OP-159 m.3 (p): the carrier size budget vectors.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use access_crypto::budget::{Carrier, OverBudget};

// CR-43, OP-159 m.3 (p), Ek B 6224
#[test]
fn every_carrier_budget_vector_holds() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../conformance/vectors/exchange/1/pq-budgets.json"
    ))
    .unwrap();
    assert_eq!(doc["operation"], "budget.fits");
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 8);
    for c in cases {
        let carrier = Carrier::of_name(c["carrier"].as_str().unwrap()).unwrap();
        let size = usize::try_from(c["size"].as_u64().unwrap()).unwrap();
        let fits = c["fits"].as_bool().unwrap();
        let got = carrier.check(size);
        if fits {
            assert_eq!(got, Ok(()), "{}", c["id"]);
        } else {
            assert_eq!(got, Err(OverBudget(carrier)), "{}", c["id"]);
        }
    }
    for carrier in Carrier::ALL {
        assert!(cases.iter().any(|c| c["carrier"] == carrier.name()));
    }
}
