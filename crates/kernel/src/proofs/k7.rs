//! CR-K7: algorithm selection (CR-5, CR-7, CR-55 m.8, L0-SIG-75a): a COSE identifier names one
//! algorithm or none, a single signature never satisfies `both`, and a JWS whose `alg` is not in
//! the accepted set is refused as an algorithm error; `none` is never an algorithm.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::{JwsError, Origin, verify_compact};
use access_kernel::verify::key_scope::{Hybrid, hybrid_admits};
use access_kernel::verify::ml_dsa::is_ml_dsa;
use access_kernel::verify::{Backend as _, PureBackend};

/// Every algorithm the Kernel knows.
pub(crate) const ALL: [Algorithm; 6] = [
    Algorithm::Ed25519,
    Algorithm::Esp256,
    Algorithm::Es256,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

/// `alg` header values: the five the JWS profile names, then three it must refuse.
pub(crate) const NAMES: [&str; 8] = [
    "Ed25519",
    "ES256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "none",
    "HS256",
    "EdDSA",
];

/// `from_cose` is the inverse of `cose` and knows no other identifier.
pub(crate) fn cose_ids_are_exact(id: i64) -> bool {
    match Algorithm::from_cose(id) {
        Some(a) => a.cose() == id,
        None => ALL.iter().all(|a| a.cose() != id),
    }
}

/// One signature satisfies `classic` (or no policy) only when classical, `pq` only when ML-DSA,
/// and `both` never.
pub(crate) fn hybrid_admits_one_signature(which: u8) -> bool {
    ALL.iter().all(|&a| {
        let policy = match which % 4 {
            0 => None,
            1 => Some(Hybrid::Classic),
            2 => Some(Hybrid::Pq),
            _ => Some(Hybrid::Both),
        };
        hybrid_admits(policy, a)
            == match policy {
                None | Some(Hybrid::Classic) => !is_ml_dsa(a),
                Some(Hybrid::Pq) => is_ml_dsa(a),
                Some(Hybrid::Both) => false,
            }
    })
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let shift = 18 - 6 * i;
            out.push(char::from(A[((n >> shift) & 63) as usize]));
        }
    }
    out
}

/// A compact JWS whose header names `alg`, signed by nothing.
pub(crate) fn token(alg: &str) -> String {
    let kid = b64url(&[0x11; 32]);
    let header = format!(r#"{{"alg":"{alg}","kid":"{kid}","typ":"t"}}"#);
    format!(
        "{}.{}.{}",
        b64url(header.as_bytes()),
        b64url(b"{}"),
        b64url(&[0x22; 64])
    )
}

/// A JWS whose `alg` is unknown, `none`, or outside `allowed` is refused with
/// [`JwsError::Algorithm`] before any key is looked up.
pub(crate) fn alg_outside_the_set_is_refused(name: usize, allowed: [bool; 6]) -> bool {
    let Some(alg) = NAMES.get(name % NAMES.len()) else {
        return false;
    };
    let keys = KeySet {
        keys: BTreeMap::new(),
        allowed: ALL
            .iter()
            .zip(allowed)
            .filter_map(|(a, on)| on.then_some(*a))
            .collect::<BTreeSet<_>>(),
    };
    let known = match *alg {
        "Ed25519" => Some(Algorithm::Ed25519),
        "ES256" => Some(Algorithm::Es256),
        "ML-DSA-44" => Some(Algorithm::MlDsa44),
        "ML-DSA-65" => Some(Algorithm::MlDsa65),
        "ML-DSA-87" => Some(Algorithm::MlDsa87),
        _ => None,
    };
    let r = verify_compact(&PureBackend, &token(alg), &keys, "t", Origin::External);
    let outside = known.is_none_or(|a| !keys.allowed.contains(&a) || !PureBackend.supports(a));
    r.is_err() && (!outside || r == Err(JwsError::Algorithm))
}

#[cfg(kani)]
mod harness {
    // CR-K7, CR-5
    #[kani::proof]
    #[kani::unwind(8)]
    fn k7_cose_ids_are_exact() {
        assert!(super::cose_ids_are_exact(kani::any()));
    }

    // CR-K7, L0-SIG-75a, CR-42 m.2
    #[kani::proof]
    #[kani::unwind(8)]
    fn k7_hybrid_admits_one_signature() {
        assert!(super::hybrid_admits_one_signature(kani::any()));
    }

    // CR-K7, CR-7, CR-55 m.8
    #[kani::proof]
    #[kani::unwind(160)]
    fn k7_alg_outside_the_set_is_refused() {
        assert!(super::alg_outside_the_set_is_refused(
            kani::any(),
            kani::any()
        ));
    }
}

#[cfg(all(test, not(kani)))]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

        // CR-K7, CR-5
        #[test]
        fn k7_cose_ids_are_exact(id in prop_oneof![-64..=64i64, any::<i64>()]) {
            prop_assert!(super::cose_ids_are_exact(id));
        }

        // CR-K7, L0-SIG-75a, CR-42 m.2
        #[test]
        fn k7_hybrid_admits_one_signature(which in any::<u8>()) {
            prop_assert!(super::hybrid_admits_one_signature(which));
        }

        // CR-K7, CR-7, CR-55 m.8
        #[test]
        fn k7_alg_outside_the_set_is_refused(name in 0..16usize, allowed in any::<[bool; 6]>()) {
            prop_assert!(super::alg_outside_the_set_is_refused(name, allowed));
        }
    }
}
