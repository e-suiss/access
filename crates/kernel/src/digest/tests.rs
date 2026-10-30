use super::*;
use suiss_crypto::dcbor::Value;

// OP-106 m.20, m.22
#[test]
fn tagged_digest_round_trips_and_contexts_differ() {
    let d = digest(Context::Intent, b"x");
    assert_eq!(Digest::from_value(&d.to_value()), Some(d));
    assert_ne!(digest(Context::Genesis, b"x"), d);
    let wrong_alg = Value::Array(alloc::vec![Value::int(-44), Value::Bytes(d.0.to_vec())]);
    assert_eq!(Digest::from_value(&wrong_alg), None);
    let short = Value::Array(alloc::vec![
        Value::int(SHA256_ALG),
        Value::Bytes(alloc::vec![0; 31])
    ]);
    assert_eq!(Digest::from_value(&short), None);
    assert_eq!(
        d,
        suiss_crypto::digest::context_digest("access/intent/v1", b"x")
    );
}

mod vectors;
