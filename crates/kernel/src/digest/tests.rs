extern crate std;

use alloc::string::String;
use alloc::vec::Vec;

use super::*;

#[derive(serde::Deserialize)]
struct Vectors {
    leaves: Vec<String>,
    roots: Vec<RootCase>,
    inclusion: Vec<InclusionCase>,
    consistency: Vec<ConsistencyCase>,
}

#[derive(serde::Deserialize)]
struct RootCase {
    size: usize,
    root: String,
}

#[derive(serde::Deserialize)]
struct InclusionCase {
    index: u64,
    size: u64,
    path: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ConsistencyCase {
    first: u64,
    second: u64,
    path: Vec<String>,
}

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn hash(s: &str) -> Hash {
    Hash::try_from(bytes(s).as_slice()).unwrap()
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../../../../conformance/vectors/core/1/merkle.json"
    ))
    .unwrap()
}

fn roots(v: &Vectors) -> Vec<Hash> {
    v.roots.iter().map(|r| hash(&r.root)).collect()
}

// OP-106 m.12, m.13
#[test]
fn roots_match_vectors() {
    let v = vectors();
    let data: Vec<Vec<u8>> = v.leaves.iter().map(|l| bytes(l)).collect();
    for case in &v.roots {
        let leaves: Vec<&[u8]> = data.iter().take(case.size).map(Vec::as_slice).collect();
        assert_eq!(root(&leaves), hash(&case.root), "size {}", case.size);
    }
}

// OP-106 m.18
#[test]
fn inclusion_proofs_match_vectors_and_tampering_fails() {
    let v = vectors();
    let roots = roots(&v);
    for case in &v.inclusion {
        let leaf = leaf_hash(&bytes(&v.leaves[usize::try_from(case.index).unwrap()]));
        let path: Vec<Hash> = case.path.iter().map(|p| hash(p)).collect();
        let r = &roots[usize::try_from(case.size).unwrap()];
        assert_eq!(
            verify_inclusion(case.index, case.size, &leaf, &path, r),
            Ok(()),
            "{}/{}",
            case.index,
            case.size
        );

        assert!(verify_inclusion(case.size, case.size, &leaf, &path, r).is_err());
        let mut longer = path.clone();
        longer.push([0; 32]);
        assert!(verify_inclusion(case.index, case.size, &leaf, &longer, r).is_err());
        if let Some((_, shorter)) = path.split_last() {
            assert!(verify_inclusion(case.index, case.size, &leaf, shorter, r).is_err());
            let mut flipped = path.clone();
            flipped[0][0] ^= 1;
            assert!(verify_inclusion(case.index, case.size, &leaf, &flipped, r).is_err());
        }
        let other = case.index.checked_add(1).filter(|i| *i < case.size);
        if let Some(i) = other {
            assert!(verify_inclusion(i, case.size, &leaf, &path, r).is_err());
        }
    }
}

// OP-106 m.18
#[test]
fn consistency_proofs_match_vectors_and_tampering_fails() {
    let v = vectors();
    let roots = roots(&v);
    for case in &v.consistency {
        let path: Vec<Hash> = case.path.iter().map(|p| hash(p)).collect();
        let a = &roots[usize::try_from(case.first).unwrap()];
        let b = &roots[usize::try_from(case.second).unwrap()];
        assert_eq!(
            verify_consistency(case.first, case.second, a, b, &path),
            Ok(()),
            "{}->{}",
            case.first,
            case.second
        );

        assert!(
            verify_consistency(case.second, case.first, b, a, &path).is_err()
                || case.first == case.second
        );
        let mut longer = path.clone();
        longer.push([0; 32]);
        assert!(verify_consistency(case.first, case.second, a, b, &longer).is_err());
        if !path.is_empty() {
            let mut flipped = path.clone();
            flipped[0][0] ^= 1;
            assert!(verify_consistency(case.first, case.second, a, b, &flipped).is_err());
            assert!(verify_consistency(case.first, case.second, b, a, &path).is_err());
        }
    }
    assert_eq!(verify_consistency(0, 5, &roots[0], &roots[5], &[]), Ok(()));
    assert_eq!(
        verify_consistency(3, 3, &roots[3], &roots[4], &[]),
        Err(ProofError::Mismatch)
    );
}

// OP-106 m.12
#[test]
fn prefixes_separate_hash_kinds() {
    let salt = [7_u8; 32];
    let x = [1_u8; 32];
    let all = [
        leaf_hash(&[salt.as_slice(), &x].concat()),
        node_hash(&salt, &x),
        field_commit(&salt, &x),
        body_commit(&salt, &x),
    ];
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
}

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
    let direct: Hash = Sha256::digest(b"access/intent/v1\x00x").into();
    assert_eq!(d.0, direct);
}
