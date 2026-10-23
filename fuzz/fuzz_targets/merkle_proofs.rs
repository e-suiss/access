//! OP-106 m.18: proof verification never panics and never overflows.
#![no_main]

use access_kernel::digest::{Hash, verify_consistency, verify_inclusion};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_at_checked(16) else { return };
    let a = u64::from_le_bytes(head[..8].try_into().unwrap_or_default());
    let b = u64::from_le_bytes(head[8..].try_into().unwrap_or_default());
    let hashes: Vec<Hash> = rest.chunks_exact(32).map(|c| c.try_into().unwrap_or([0; 32])).collect();
    let (first, path) = hashes.split_first().map_or(([0; 32], &[][..]), |(f, p)| (*f, p));
    let _ = verify_inclusion(a, b, &first, path, &first);
    let _ = verify_consistency(a, b, &first, &first, path);
});
