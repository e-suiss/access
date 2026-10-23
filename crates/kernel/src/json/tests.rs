use alloc::string::ToString;
use alloc::vec;

use super::*;

fn p(s: &str) -> Result<Json, JsonError> {
    parse(s.as_bytes(), 4096)
}

#[test]
fn accepts_i_json() {
    assert_eq!(
        p(r#" {"alg":"ES256","n":-12,"a":[true,false,null],"s":"é😀\n"} "#),
        Ok(Json::Object(vec![
            ("alg".to_string(), Json::Str("ES256".to_string())),
            ("n".to_string(), Json::Int(-12)),
            (
                "a".to_string(),
                Json::Array(vec![Json::Bool(true), Json::Bool(false), Json::Null])
            ),
            ("s".to_string(), Json::Str("\u{e9}\u{1f600}\n".to_string())),
        ]))
    );
    assert_eq!(p("0"), Ok(Json::Int(0)));
    assert_eq!(p(&i64::MIN.to_string()), Ok(Json::Int(i64::MIN)));
}

// OP-110 m.2, CR-56 row 18
#[test]
fn rejects_outside_profile() {
    assert_eq!(
        p(r#"{"alg":"ES256","alg":"none"}"#),
        Err(JsonError::Duplicate)
    );
    assert_eq!(p("1.0"), Err(JsonError::Number));
    assert_eq!(p("1e3"), Err(JsonError::Number));
    assert_eq!(p("01"), Err(JsonError::Number));
    assert_eq!(p("-0"), Err(JsonError::Number));
    assert_eq!(p("9223372036854775808"), Err(JsonError::Number));
    assert_eq!(p(r#""\ud800""#), Err(JsonError::Syntax));
    assert_eq!(p(r#""\udc00""#), Err(JsonError::Syntax));
    assert_eq!(p("\"a\tb\""), Err(JsonError::Syntax));
    assert_eq!(p("{} x"), Err(JsonError::Syntax));
    assert_eq!(p("[1,]"), Err(JsonError::Syntax));
    assert_eq!(p("{'a':1}"), Err(JsonError::Syntax));
    assert_eq!(parse(b"\"\xff\"", 10), Err(JsonError::Utf8));
    assert_eq!(parse(b"[1,2,3]", 6), Err(JsonError::Size));
    let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
    assert_eq!(p(&deep), Err(JsonError::Depth));
    let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
    assert!(p(&ok).is_ok());
}

// CR-56 row 18
#[test]
fn base64url_is_strict() {
    for data in [
        &b""[..],
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        &[0xfb, 0xff, 0xfe],
    ] {
        let e = b64url_encode(data);
        assert_eq!(b64url_decode(&e).as_deref(), Ok(data), "{e}");
    }
    assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(b64url_decode("Zg=="), Err(Base64Error));
    assert_eq!(b64url_decode("Zh"), Err(Base64Error));
    assert_eq!(b64url_decode("Z"), Err(Base64Error));
    assert_eq!(b64url_decode("+/8"), Err(Base64Error));
    assert_eq!(b64url_decode("Zm9v YmFy"), Err(Base64Error));
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = parse(&bytes, 64);
        }

        #[test]
        fn base64_round_trips(data in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(b64url_decode(&b64url_encode(&data)).unwrap(), data);
        }

        #[test]
        fn base64_decode_never_panics(s in "[A-Za-z0-9_=+/-]{0,16}") {
            let _ = b64url_decode(&s);
        }
    }
}
