#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

// OP-149 m.5, CR-24: a kid is the canonical base64url of 32 bytes
#[test]
fn kids_are_canonical_thumbprints() {
    let text = b64url_encode(&[7; 32]);
    assert_eq!(kid(&text), Some([7; 32]));
    assert_eq!(kid(&format!("{text}=")), None);
    assert_eq!(kid(&b64url_encode(&[7; 31])), None);
}

// OP-149 m.5: as_of is a ledger position or an RFC 3339 time
#[test]
fn as_of_is_a_position_or_a_time() {
    assert_eq!(as_of(None), Ok(AsOf::Head));
    assert_eq!(as_of(Some("42")), Ok(AsOf::Position(42)));
    assert_eq!(
        as_of(Some("2026-11-04T10:00:00Z")),
        Ok(AsOf::Time(1_793_786_400_000))
    );
    assert_eq!(rfc3339(1_793_786_400_000), "2026-11-04T10:00:00Z");
    for bad in ["", "-1", "yesterday", "99999999999999999999999"] {
        assert_eq!(as_of(Some(bad)), Err(BadRequest("as_of")), "{bad}");
    }
}

// OP-149 m.5: a batch names 1 to 100 distinct kids of one domain
#[test]
fn a_batch_names_at_most_a_hundred_kids() {
    let domain = domain_text(&Digest([1; 32]));
    let kids = |n: u8| -> Vec<String> { (0..n).map(|i| b64url_encode(&[i; 32])).collect() };
    let body = |kids: Vec<String>| json!({ "domain": domain, "kids": kids }).to_string();
    let (d, k, at) = batch(body(kids(100)).as_bytes()).unwrap();
    assert_eq!((d, k.len(), at), (Digest([1; 32]), 100, AsOf::Head));
    assert_eq!(batch(body(kids(101)).as_bytes()), Err(BadRequest("kids")));
    assert_eq!(batch(body(Vec::new()).as_bytes()), Err(BadRequest("kids")));
    let twice = vec![b64url_encode(&[1; 32]), b64url_encode(&[1; 32])];
    assert_eq!(batch(body(twice).as_bytes()), Err(BadRequest("kids")));
    let extra = json!({ "domain": domain, "kids": kids(1), "x": 1 }).to_string();
    assert_eq!(batch(extra.as_bytes()), Err(BadRequest("unknown-member")));
}

// OP-149 m.4: the snapshot version follows its content
#[test]
fn the_snapshot_version_follows_its_content() {
    let t = Tenant {
        id: [1; 16],
        status: "active".into(),
        organizations: Vec::new(),
        realms: Vec::new(),
    };
    let a = snapshot("tnt_a", &t, "eu-central");
    assert_eq!(a, snapshot("tnt_a", &t, "eu-central"));
    let suspended = Tenant {
        status: "suspended".into(),
        ..t.clone()
    };
    let b = snapshot("tnt_a", &suspended, "eu-central");
    assert_ne!(a["version"], b["version"]);
    assert_eq!(a["retention"], json!({}));
    // OP-149 m.4: a new realm is a new snapshot
    let grown = Tenant {
        realms: vec![super::super::ports::Realm {
            id: [2; 16],
            issuer: "https://shop.id.example".into(),
            slug: "shop".into(),
        }],
        ..t
    };
    let c = snapshot("tnt_a", &grown, "eu-central");
    assert_ne!(a["version"], c["version"]);
    assert_eq!(
        c["realms"],
        json!([{ "id": "02020202-0202-0202-0202-020202020202", "issuer": "https://shop.id.example", "slug": "shop" }])
    );
}
