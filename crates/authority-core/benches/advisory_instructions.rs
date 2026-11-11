//! OP-72, P46 instruction-count benchmarks of the advisory hot path (gungraun + Valgrind): the
//! cache key and the group closure bitmap. The PR gate fails above 5 %.

#![allow(
    missing_docs,
    reason = "gungraun macros generate undocumented public items in this bench binary"
)]

#[cfg(target_os = "linux")]
use std::hint::black_box;

#[cfg(target_os = "linux")]
use access_authority_core::app::cache::key;
#[cfg(target_os = "linux")]
use access_authority_core::index::Bitmap;
#[cfg(target_os = "linux")]
use gungraun::{library_benchmark, library_benchmark_group, main};

#[cfg(target_os = "linux")]
fn parts() -> Vec<Vec<u8>> {
    vec![
        vec![7; 32],
        b"pep.example".to_vec(),
        vec![9; 32],
        vec![1; 40],
        vec![0],
        vec![3; 32],
    ]
}

// P45
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::request(parts())]
fn cache_key(parts: Vec<Vec<u8>>) -> [u8; 32] {
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    key(black_box(&refs)).0
}

#[cfg(target_os = "linux")]
fn closure() -> Bitmap {
    (0..20_000u32).map(|v| v.saturating_mul(7)).collect()
}

// §9.7A.1
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::member(closure())]
fn bitmap_contains(m: Bitmap) -> bool {
    m.contains(black_box(69_993))
}

// §9.7A.1, U48
#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::encoded(closure().to_bytes())]
fn bitmap_decode(bytes: Vec<u8>) -> bool {
    Bitmap::from_bytes(black_box(&bytes)).is_ok()
}

#[cfg(target_os = "linux")]
library_benchmark_group!(
    name = advisory,
    benchmarks = [cache_key, bitmap_contains, bitmap_decode]
);

#[cfg(target_os = "linux")]
main!(library_benchmark_groups = advisory);

#[cfg(not(target_os = "linux"))]
fn main() {}
