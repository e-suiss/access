//! OP-72, P46, §9.7A.6 wall-clock micro-benchmarks of the advisory hot path (divan): the cache
//! key, a cache hit and the group closure bitmap.

use access_authority_core::app::cache::{AdvisoryCache, key};
use access_authority_core::index::Bitmap;
use divan::black_box;

fn main() {
    divan::main();
}

fn parts() -> Vec<Vec<u8>> {
    vec![
        vec![7; 32],
        b"pep.example".to_vec(),
        vec![9; 32],
        vec![1; 40],
        vec![0],
        vec![3; 32],
        Vec::new(),
        1u64.to_be_bytes().to_vec(),
        42u64.to_be_bytes().to_vec(),
    ]
}

// P45
#[divan::bench]
fn cache_key(b: divan::Bencher<'_, '_>) {
    let parts = parts();
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    b.bench(|| key(black_box(&refs)));
}

// U61
#[divan::bench]
fn cache_hit(b: divan::Bencher<'_, '_>) {
    let cache = AdvisoryCache::new();
    let k = key(&[b"hit"]);
    cache.put(k, 1, 0, u64::MAX, &support::allow());
    b.bench(|| cache.get(black_box(&k), black_box(1)).is_some());
}

// §9.7A.1
#[divan::bench]
fn bitmap_contains(b: divan::Bencher<'_, '_>) {
    let m: Bitmap = (0..100_000u32).map(|v| v.saturating_mul(7)).collect();
    b.bench(|| m.contains(black_box(69_993)));
}

// §9.7A.1
#[divan::bench]
fn bitmap_intersection(b: divan::Bencher<'_, '_>) {
    let a: Bitmap = (0..50_000u32).map(|v| v.saturating_mul(3)).collect();
    let c: Bitmap = (0..50_000u32).map(|v| v.saturating_mul(5)).collect();
    b.bench(|| a.intersects(black_box(&c)));
}

// §9.7A.1, U48
#[divan::bench]
fn bitmap_decode(b: divan::Bencher<'_, '_>) {
    let bytes = (0..20_000u32)
        .map(|v| v.saturating_mul(11))
        .collect::<Bitmap>()
        .to_bytes();
    b.bench(|| Bitmap::from_bytes(black_box(&bytes)).is_ok());
}

mod support {
    use access_authority_core::app::Response;
    use access_kernel::combinator::{Decision, Outcome};

    pub(super) fn allow() -> Response {
        Response {
            decision: Decision {
                outcome: Outcome::Allow,
                blockers: Vec::new(),
                unmet: Vec::new(),
                relied_on: Vec::new(),
            },
            exercise: None,
            record: None,
            replayed: false,
            basis_ref: None,
            consistency: None,
            receipt: None,
            signed_receipt: None,
            pap: None,
            signed_pap: None,
            ended: Vec::new(),
            explained: None,
            causal: None,
        }
    }
}
