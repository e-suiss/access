//! CR-K6: the CBOR and `COSE_Sign1` decoders the Kernel reads every artefact with
//! (`suiss_crypto::dcbor::decode`, `suiss_crypto::cose::parse_sign1`; CR-10) on inputs of at
//! most 32 bytes: no panic, no read outside the input, canonical round trip and the depth limit.

use access_kernel::verify::cose::parse_sign1;
use suiss_crypto::dcbor::{Limits, Value, decode, encode};

/// The input bound of CR-K6.
pub(crate) const MAX_INPUT: usize = 32;

fn nesting(v: &Value) -> usize {
    match v {
        Value::Array(items) => 1 + items.iter().map(nesting).max().unwrap_or(0),
        Value::Map(entries) => {
            1 + entries
                .iter()
                .map(|(k, v)| nesting(k).max(nesting(v)))
                .max()
                .unwrap_or(0)
        }
        Value::Tag(_, inner) => 1 + nesting(inner),
        _ => 0,
    }
}

/// A decoded item re-encodes to the same bytes and nests no deeper than the limit; the
/// `COSE_Sign1` parser returns on the same bytes.
pub(crate) fn decoder_round_trips(bytes: &[u8], depth: usize) -> bool {
    let Some(limits) = Limits::tightened(depth, 8, MAX_INPUT) else {
        return true;
    };
    let _ = parse_sign1(bytes);
    match decode(bytes, limits) {
        Ok(v) => encode(&v, Limits::CEILING).is_ok_and(|e| e == bytes) && nesting(&v) <= depth,
        Err(_) => true,
    }
}

#[cfg(kani)]
mod harness {
    fn input<const N: usize>() -> ([u8; N], usize) {
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        (bytes, len)
    }

    // CR-K6, CR-10
    #[kani::proof]
    #[kani::unwind(10)]
    fn k6_decoder_round_trips_up_to_8_bytes() {
        let (bytes, len) = input::<8>();
        let depth: usize = kani::any();
        kani::assume(depth <= 4);
        assert!(super::decoder_round_trips(&bytes[..len], depth));
    }

    // CR-K6, CR-10
    #[kani::proof]
    #[kani::unwind(34)]
    fn k6_decoder_round_trips_up_to_32_bytes() {
        let (bytes, len) = input::<{ super::MAX_INPUT }>();
        assert!(super::decoder_round_trips(&bytes[..len], 16));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    use super::MAX_INPUT;

    fn cbor_like() -> impl Strategy<Value = Vec<u8>> {
        let byte = prop_oneof![
            any::<u8>(),
            0x80..=0x83u8,
            0xa0..=0xa2u8,
            0x40..=0x43u8,
            0x60..=0x63u8,
            Just(0x18u8),
            Just(0xd2u8),
            Just(0xf5u8),
        ];
        proptest::collection::vec(byte, 0..=MAX_INPUT)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 20_000, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K6, CR-10
        #[test]
        fn k6_decoder_round_trips(bytes in cbor_like(), depth in 0..=16usize) {
            prop_assert!(super::decoder_round_trips(&bytes, depth));
        }
    }
}
