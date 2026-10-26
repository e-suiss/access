use super::{IdKey, OpaqueIdError};
use crate::secret::Secret;

fn key(b: u8) -> IdKey {
    IdKey::new(Secret::new([b; 32]))
}

fn uuidv7(ms: u64, seq: u16) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    id[6] = 0x70 | u8::try_from(seq >> 8).unwrap_or(0);
    id[7] = u8::try_from(seq & 0xff).unwrap_or(0);
    id[8] = 0x80;
    id
}

// OP-137: round trip, type prefix, fixed length
#[test]
fn round_trips_with_its_prefix() {
    let k = key(1);
    let id = uuidv7(1_761_000_000_000, 1);
    let text = k.encode("rlm", id).unwrap();
    assert!(text.starts_with("rlm_"));
    assert_eq!(text.len(), 4 + 26);
    assert_eq!(k.decode("rlm", &text).unwrap(), id);
    assert_eq!(k.decode("ten", &text), Err(OpaqueIdError::Prefix));
}

// MD-18: consecutive UUIDv7 values share their time prefix; their external forms share nothing
#[test]
fn hides_time_and_order() {
    let k = key(1);
    let a = k.encode("grt", uuidv7(1_761_000_000_000, 1)).unwrap();
    let b = k.encode("grt", uuidv7(1_761_000_000_000, 2)).unwrap();
    let common = a
        .bytes()
        .zip(b.bytes())
        .skip(4)
        .take_while(|(x, y)| x == y)
        .count();
    assert!(common < 4, "{a} {b}");
    assert_ne!(
        key(2).encode("grt", uuidv7(1, 1)).unwrap(),
        k.encode("grt", uuidv7(1, 1)).unwrap()
    );
}

// one spelling per id: other lengths, characters and the unused top bits are refused
#[test]
fn refuses_non_canonical_text() {
    let k = key(1);
    let text = k.encode("usr", uuidv7(5, 5)).unwrap();
    for bad in [
        &text[..text.len() - 1],
        &format!("{text}0"),
        &text.to_uppercase().replace("USR_", "usr_"),
        "usr_iiiiiiiiiiiiiiiiiiiiiiiiii",
    ] {
        assert_eq!(k.decode("usr", bad), Err(OpaqueIdError::Encoding), "{bad}");
    }
    let mut high = String::from("usr_8");
    high.push_str(&text[5..]);
    assert_eq!(k.decode("usr", &high), Err(OpaqueIdError::Encoding));
    assert_eq!(k.encode("USR", [0; 16]), Err(OpaqueIdError::Prefix));
    assert_eq!(k.encode("toolong", [0; 16]), Err(OpaqueIdError::Prefix));
}
