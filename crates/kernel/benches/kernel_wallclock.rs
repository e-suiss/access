//! OP-72 wall-clock micro-benchmarks for the Kernel's hot paths (divan).

#[path = "support/fixtures.rs"]
mod fixtures;

use access_kernel::algebra::{Catalog, subsumes};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Fuel, evaluate};
use access_kernel::intent::intent_digest;
use access_kernel::model::CanonicalAuthority;
use access_kernel::verify::{PureBackend, ed25519};
use access_kernel::{API_VERSION, ApiVersion};
use divan::black_box;

fn main() {
    divan::main();
}

#[divan::bench]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}

// OP-106 m.1
#[divan::bench]
fn decode_canonical_authority(b: divan::Bencher<'_, '_>) {
    let bytes = fixtures::authority_bytes();
    b.bench(|| CanonicalAuthority::from_bytes(black_box(&bytes)).is_ok());
}

// OP-109 m.10
#[divan::bench]
fn subsumes_self(b: divan::Bencher<'_, '_>) {
    let a = fixtures::authority().map(|a| a.authority);
    let cat = Catalog::default();
    b.bench(|| {
        a.as_ref()
            .is_some_and(|a| subsumes(black_box(a), black_box(a), &cat))
    });
}

// OP-106 m.22
#[divan::bench]
fn intent_digest_allow_case(b: divan::Bencher<'_, '_>) {
    let input = fixtures::decision_input("allow");
    b.bench(|| {
        input
            .as_ref()
            .map(|i| intent_digest(black_box(&i.intent)).is_ok())
    });
}

// OP-111
#[divan::bench(args = ["allow", "require-step-up", "deny-overrides-require", "check-first-require"])]
fn evaluate_decision(b: divan::Bencher<'_, '_>, id: &str) {
    let input = fixtures::decision_input(id);
    b.bench(|| {
        input
            .as_ref()
            .map(|i| evaluate(black_box(&i.input()), &mut Fuel(10_000)).is_ok())
    });
}

// CR-53
#[divan::bench]
fn ed25519_verify(b: divan::Bencher<'_, '_>) {
    let (pk, m, sig) = fixtures::ed25519_case();
    b.bench(|| ed25519(&PureBackend, black_box(&pk), black_box(&m), black_box(&sig)).is_ok());
}
