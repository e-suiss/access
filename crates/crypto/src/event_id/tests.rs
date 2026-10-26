use aws_lc_rs::hmac;

use super::EventKey;
use crate::secret::Secret;

fn key(b: u8) -> EventKey {
    EventKey::new(Secret::new([b; 32]))
}

// OP-130 m.8
#[test]
fn matches_the_documented_construction() {
    let mut msg = b"access/event/v1\0".to_vec();
    msg.extend([7; 32]);
    msg.extend(5_u64.to_be_bytes());
    msg.extend(2_u32.to_be_bytes());
    let want = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]), &msg);
    assert_eq!(key(1).event_id(&[7; 32], 5, 2).as_slice(), want.as_ref());
}

// TI-RT10: ids differ per domain, position, index and key
#[test]
fn every_input_changes_the_id() {
    let base = key(1).event_id(&[7; 32], 5, 2);
    assert_ne!(base, key(2).event_id(&[7; 32], 5, 2));
    assert_ne!(base, key(1).event_id(&[8; 32], 5, 2));
    assert_ne!(base, key(1).event_id(&[7; 32], 6, 2));
    assert_ne!(base, key(1).event_id(&[7; 32], 5, 3));
    assert_eq!(base, key(1).event_id(&[7; 32], 5, 2));
}
