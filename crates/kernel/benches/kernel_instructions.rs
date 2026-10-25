//! OP-72 instruction-count benchmarks for the Kernel's hot paths (gungraun + Valgrind).

#![allow(
    missing_docs,
    reason = "gungraun macros generate undocumented public items in this bench binary"
)]

#[cfg(target_os = "linux")]
#[path = "support/fixtures.rs"]
mod fixtures;

#[cfg(target_os = "linux")]
use std::hint::black_box;

#[cfg(target_os = "linux")]
use access_kernel::algebra::{Catalog, subsumes};
#[cfg(target_os = "linux")]
use access_kernel::codec::Canonical;
#[cfg(target_os = "linux")]
use access_kernel::combinator::codec::OwnedInput;
#[cfg(target_os = "linux")]
use access_kernel::combinator::{Fuel, evaluate};
#[cfg(target_os = "linux")]
use access_kernel::model::CanonicalAuthority;
#[cfg(target_os = "linux")]
use access_kernel::verify::{PureBackend, ed25519};
#[cfg(target_os = "linux")]
use access_kernel::{API_VERSION, ApiVersion};
#[cfg(target_os = "linux")]
use gungraun::{library_benchmark, library_benchmark_group, main};

/// Drops a bench input outside the measured region, so the free cost of the fixture's heap
/// layout is not counted (OP-72).
#[cfg(target_os = "linux")]
fn release<T>(out: (bool, T)) {
    black_box(out.0);
    drop(out.1);
}

#[cfg(target_os = "linux")]
#[library_benchmark]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::full(fixtures::authority_bytes())]
fn decode_canonical_authority(bytes: Vec<u8>) -> bool {
    CanonicalAuthority::from_bytes(black_box(&bytes)).is_ok()
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::full(args = (fixtures::authority()), teardown = release)]
fn subsumes_self(a: Option<CanonicalAuthority>) -> (bool, Option<CanonicalAuthority>) {
    let cat = Catalog::default();
    let ok = a
        .as_ref()
        .is_some_and(|a| subsumes(black_box(&a.authority), black_box(&a.authority), &cat));
    (ok, a)
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::allow(args = (fixtures::decision_input("allow")), teardown = release)]
#[bench::require(args = (fixtures::decision_input("require-step-up")), teardown = release)]
#[bench::deny(args = (fixtures::decision_input("deny-overrides-require")), teardown = release)]
fn evaluate_decision(input: Option<OwnedInput>) -> (bool, Option<OwnedInput>) {
    let ok = input
        .as_ref()
        .is_some_and(|i| evaluate(black_box(&i.input()), &mut Fuel(10_000)).is_ok());
    (ok, input)
}

#[cfg(target_os = "linux")]
#[library_benchmark]
#[bench::valid(fixtures::ed25519_case())]
fn ed25519_verify(case: (Vec<u8>, Vec<u8>, Vec<u8>)) -> bool {
    ed25519(
        &PureBackend,
        black_box(&case.0),
        black_box(&case.1),
        black_box(&case.2),
    )
    .is_ok()
}

#[cfg(target_os = "linux")]
library_benchmark_group!(
    name = kernel,
    benchmarks = [
        api_version_compare,
        decode_canonical_authority,
        subsumes_self,
        evaluate_decision,
        ed25519_verify
    ]
);

#[cfg(target_os = "linux")]
main!(library_benchmark_groups = kernel);

#[cfg(not(target_os = "linux"))]
fn main() {}
