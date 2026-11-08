//! The MMDB file adapter of the `GeoResolver` (OP-151 m.1 (b)) over small databases written
//! here in the `MaxMind` DB format: lookups, reload on change, and a missing or broken file being
//! unavailable (MD-8).

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::net::IpAddr;
use std::path::PathBuf;

use access_identity_risk::adapters::mmdb::MmdbGeo;
use access_identity_risk::domain::geo::{GeoAnswer, Point};
use access_identity_risk::ports::{GeoResolver, GeoStatus};

fn ctrl(t: u8, size: usize) -> Vec<u8> {
    assert!(size < 29);
    if t <= 7 {
        vec![(t << 5) | size as u8]
    } else {
        vec![size as u8, t - 7]
    }
}

fn text(s: &str) -> Vec<u8> {
    let mut v = ctrl(2, s.len());
    v.extend_from_slice(s.as_bytes());
    v
}

fn uint(t: u8, n: u64) -> Vec<u8> {
    let bytes: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut v = ctrl(t, bytes.len());
    v.extend(bytes);
    v
}

fn double(x: f64) -> Vec<u8> {
    let mut v = ctrl(3, 8);
    v.extend_from_slice(&x.to_be_bytes());
    v
}

fn map(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut v = ctrl(7, pairs.len());
    for (k, x) in pairs {
        v.extend(text(k));
        v.extend_from_slice(x);
    }
    v
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = ctrl(11, items.len());
    for i in items {
        v.extend_from_slice(i);
    }
    v
}

/// An IPv4 database mapping `first.0.0.0/8` to `record`; everything else is unknown.
fn database(first: u8, record: &[u8]) -> Vec<u8> {
    const NODES: u32 = 8;
    let data_pointer = NODES + 16;
    let mut tree = Vec::new();
    for i in 0..8_u32 {
        let next = if i == 7 { data_pointer } else { i + 1 };
        let bit = (first >> (7 - i)) & 1;
        let (left, right) = if bit == 0 {
            (next, NODES)
        } else {
            (NODES, next)
        };
        tree.extend_from_slice(&left.to_be_bytes()[1..]);
        tree.extend_from_slice(&right.to_be_bytes()[1..]);
    }
    let mut out = tree;
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(record);
    out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    out.extend(map(&[
        ("binary_format_major_version", uint(5, 2)),
        ("binary_format_minor_version", uint(5, 0)),
        ("build_epoch", uint(9, 1_700_000_000)),
        ("database_type", text("Test-City")),
        ("description", map(&[("en", text("test"))])),
        ("ip_version", uint(5, 4)),
        ("languages", array(&[text("en")])),
        ("node_count", uint(6, u64::from(NODES))),
        ("record_size", uint(5, 24)),
    ]));
    out
}

fn city(code: &str, lat: f64, lon: f64, asn: u64) -> Vec<u8> {
    map(&[
        ("country", map(&[("iso_code", text(code))])),
        (
            "location",
            map(&[("latitude", double(lat)), ("longitude", double(lon))]),
        ),
        ("autonomous_system_number", uint(6, asn)),
    ])
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("access-mmdb-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// OP-151 m.1 (b), IDP-39
#[test]
fn lookups() {
    let path = dir("lookups").join("geo.mmdb");
    std::fs::write(&path, database(1, &city("TR", 41.01, 28.98, 64_500))).unwrap();
    let geo = MmdbGeo::open(path);
    let GeoAnswer::Found(p) = geo.locate(ip("1.2.3.4")) else {
        panic!("not found");
    };
    assert_eq!(p.country, Some(*b"TR"));
    assert_eq!(p.asn, Some(64_500));
    assert_eq!(p.point, Point::new(4101, 2898));
    assert_eq!(geo.locate(ip("::ffff:1.9.9.9")), geo.locate(ip("1.9.9.9")));
    assert_eq!(geo.locate(ip("2.2.3.4")), GeoAnswer::Unavailable);
    assert!(
        matches!(geo.status(), GeoStatus::Ready { database_type, .. } if database_type == "Test-City")
    );
}

// OP-151 m.1 (b)
#[test]
fn reload_on_change() {
    let path = dir("reload").join("geo.mmdb");
    std::fs::write(&path, database(1, &city("TR", 41.0, 29.0, 1))).unwrap();
    let geo = MmdbGeo::open(path.clone());
    assert!(!geo.refresh());
    std::fs::write(&path, database(1, &city("US", 40.7, -74.0, 70_000))).unwrap();
    assert!(geo.refresh());
    let GeoAnswer::Found(p) = geo.locate(ip("1.0.0.1")) else {
        panic!("not found");
    };
    assert_eq!((p.country, p.asn), (Some(*b"US"), Some(70_000)));
}

// MD-8, OP-151 m.1 (b)
#[test]
fn missing_or_broken_is_unavailable() {
    let d = dir("broken");
    let missing = MmdbGeo::open(d.join("none.mmdb"));
    assert_eq!(missing.locate(ip("1.2.3.4")), GeoAnswer::Unavailable);
    assert_eq!(missing.status(), GeoStatus::Unreadable);
    let path = d.join("bad.mmdb");
    std::fs::write(&path, b"not a database").unwrap();
    let broken = MmdbGeo::open(path);
    assert_eq!(broken.locate(ip("1.2.3.4")), GeoAnswer::Unavailable);
    assert_eq!(broken.status(), GeoStatus::Unreadable);
    assert_eq!(
        access_identity_risk::adapters::NoGeoSource.status().text(),
        "GeoIP source not configured"
    );
}
