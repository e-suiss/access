//! The constant-time comparisons compiled on their own for the assembly snapshot
//! (CR-39 m.5, SA-T13). `just ct-asm` builds this file; it is not part of a crate.

#[path = "../src/dit.rs"]
pub mod dit;
#[path = "../src/secret.rs"]
pub mod secret;

use secret::Secret;

/// `Secret::<[u8; 32]>::ct_eq`.
#[inline(never)]
pub fn ct_eq_32(a: &Secret<[u8; 32]>, b: &Secret<[u8; 32]>) -> bool {
    a.ct_eq(b)
}

/// `Secret::<[u8; 32]>::ct_eq_bytes`.
#[inline(never)]
pub fn ct_eq_bytes_32(a: &Secret<[u8; 32]>, candidate: &[u8]) -> bool {
    a.ct_eq_bytes(candidate)
}
