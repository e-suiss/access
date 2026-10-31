use aws_lc_rs::hmac;

use super::{EventKey, label};
use crate::secret::Secret;

fn key(b: u8) -> EventKey {
    EventKey::new(Secret::new([b; 32]))
}

fn id(k: u8, domain: u8, pos: u64, idx: u32) -> Option<[u8; 32]> {
    key(k).event_id(&[domain; 32], pos, idx).ok()
}

// OP-130 m.8
#[test]
fn matches_the_documented_construction() {
    let mut msg = b"access/event/v1\0".to_vec();
    msg.extend([7; 32]);
    msg.extend(5_u64.to_be_bytes());
    msg.extend(2_u32.to_be_bytes());
    let want = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]), &msg);
    assert_eq!(
        id(1, 7, 5, 2).as_ref().map(<[u8; 32]>::as_slice),
        Some(want.as_ref())
    );
}

// TI-RT10: ids differ per domain, position, index and key
#[test]
fn every_input_changes_the_id() {
    let base = id(1, 7, 5, 2);
    assert!(base.is_some());
    assert_ne!(base, id(2, 7, 5, 2));
    assert_ne!(base, id(1, 8, 5, 2));
    assert_ne!(base, id(1, 7, 6, 2));
    assert_ne!(base, id(1, 7, 5, 3));
    assert_eq!(base, id(1, 7, 5, 2));
}

// OP-141 m.18 (d)
#[test]
fn the_label_names_the_domain_in_hex() {
    let mut d = [0; 32];
    d[0] = 0xab;
    d[31] = 0x01;
    let l = label(&d);
    assert_eq!(l.len(), "access/event/".len() + 64);
    assert!(l.starts_with("access/event/ab00"));
    assert!(l.ends_with("0001"));
}
