//! OP-156 m.3 (q): every connector against its vendor sample. Each sample has the shape of the
//! vendor's documented employee listing with scrubbed people: two who map and one who is left
//! out for a missing id or work address. The samples hold no credential.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_hr_connector::domain::batches;
use access_hr_connector::domain::vendor::Vendor;

fn sample(v: Vendor) -> serde_json::Value {
    let path = format!(
        "{}/tests/fixtures/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        v.name()
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

// OP-156 m.3 (q), IDP-35
#[test]
fn every_vendor_maps_its_listing_to_the_batch_format() {
    for v in Vendor::ALL {
        let (records, left) = v.records(&sample(v)).unwrap();
        assert_eq!((records.len(), left), (2, 1), "{}", v.name());
        let ada = &records[0];
        assert_eq!(ada.email, "ada@acme.example", "{}", v.name());
        assert_eq!(
            ada.start_date.as_deref(),
            Some("2026-12-01"),
            "{}",
            v.name()
        );
        assert_eq!(ada.end_date, None, "{}", v.name());
        assert!(
            ada.department.is_some() && ada.title.is_some(),
            "{}",
            v.name()
        );
        assert!(ada.manager.is_some(), "{}", v.name());
        let bob = &records[1];
        assert_eq!(bob.end_date.as_deref(), Some("2026-12-31"), "{}", v.name());
        assert_eq!(
            bob.start_date.as_deref(),
            Some("2024-03-01"),
            "{}",
            v.name()
        );
        let b = batches(&records);
        assert_eq!(b.len(), 1);
        for line in b[0].content.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed["employee_id"].is_string() && parsed["email"].is_string());
        }
    }
}

// OP-156 m.3 (q)
#[test]
fn a_page_of_another_shape_is_refused() {
    let workday = sample(Vendor::Workday);
    assert!(Vendor::Personio.records(&workday).is_err());
    assert!(
        Vendor::Logo
            .records(&serde_json::json!({"Items": {}}))
            .is_err()
    );
}
