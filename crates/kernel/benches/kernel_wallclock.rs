//! OP-72 wall-clock micro-benchmarks for the Kernel (divan).

use access_kernel::{API_VERSION, ApiVersion};
use divan::black_box;

fn main() {
    divan::main();
}

/// Placeholder hot path until ⊑/∩/normalize land (OP-72 #1): the Kernel API
/// version comparison that callers use to pick a Kernel semantic version (OP-1 rule 4).
#[divan::bench]
fn api_version_compare() -> bool {
    let wanted = black_box(ApiVersion { major: 0, minor: 0 });
    black_box(API_VERSION) >= wanted
}
