//! ctgrind (CR-39 m.5, SA-T13, SAI-42): under Valgrind memcheck the secret bytes are
//! marked undefined, so a branch or a memory index that depends on them is reported
//! as "uninitialised". `just ctgrind` runs this on Linux; natively the client
//! requests are no-ops and the tests only check the results.

#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#![allow(
    unsafe_code,
    reason = "Valgrind client requests are a fixed instruction sequence (R-2)"
)]

use std::hint::black_box;

use access_crypto::secret::Secret;

const MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const MAKE_MEM_DEFINED: usize = 0x4d43_0002;

#[cfg(target_arch = "x86_64")]
fn client_request(default: usize, request: usize, addr: usize, len: usize) -> usize {
    let args: [usize; 6] = [request, addr, len, 0, 0, 0];
    let mut result = default;
    // SAFETY: the valgrind.h amd64 client request. The four rotations of rdi add up
    // to 128 bits and leave it unchanged, `xchg rbx, rbx` does nothing natively;
    // under Valgrind the sequence reads `args` and writes rdx.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(),
            inout("rdx") result,
            options(nostack),
        );
    }
    result
}

#[cfg(target_arch = "aarch64")]
fn client_request(default: usize, request: usize, addr: usize, len: usize) -> usize {
    let args: [usize; 6] = [request, addr, len, 0, 0, 0];
    let mut result = default;
    // SAFETY: the valgrind.h arm64 client request. The four rotations of x12 add up
    // to 128 bits and leave it unchanged, `orr x10, x10, x10` does nothing natively;
    // under Valgrind the sequence reads `args` and writes x3.
    unsafe {
        core::arch::asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            in("x4") args.as_ptr(),
            inout("x3") result,
            options(nostack, preserves_flags),
        );
    }
    result
}

fn secret_bytes(bytes: &[u8]) {
    client_request(0, MAKE_MEM_UNDEFINED, bytes.as_ptr() as usize, bytes.len());
}

/// The comparison's result is public: mark it defined and read it back from memory.
fn declassify(result: bool) -> bool {
    let cell = black_box(result);
    client_request(
        0,
        MAKE_MEM_DEFINED,
        std::ptr::from_ref(&cell) as usize,
        size_of::<bool>(),
    );
    // SAFETY: `cell` is a live, aligned, initialised local.
    unsafe { std::ptr::read_volatile(&raw const cell) }
}

fn secret(fill: u8) -> Secret<[u8; 32]> {
    let s = Secret::new(black_box([fill; 32]));
    secret_bytes(s.expose());
    s
}

fn candidate(fill: u8, first: u8, len: usize) -> Vec<u8> {
    let mut c = vec![fill; len];
    if let Some(b) = c.first_mut() {
        *b = first;
    }
    let c = black_box(c);
    secret_bytes(&c);
    c
}

// CR-39 m.2, m.5, SAI-42
#[test]
fn secret_comparisons_do_not_branch_on_secret_bytes() {
    let a = secret(0x5a);
    let same = secret(0x5a);
    let other = secret(0x5b);
    assert!(declassify(black_box(&a).ct_eq(black_box(&same))));
    assert!(!declassify(black_box(&a).ct_eq(black_box(&other))));
    assert!(declassify(
        black_box(&a).ct_eq_bytes(&candidate(0x5a, 0x5a, 32))
    ));
    assert!(!declassify(
        black_box(&a).ct_eq_bytes(&candidate(0x5a, 0x00, 32))
    ));
    assert!(!declassify(
        black_box(&a).ct_eq_bytes(&candidate(0x5a, 0x5a, 31))
    ));
}

fn variable_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b) {
        if black_box(*x) != black_box(*y) {
            return false;
        }
    }
    true
}

// CR-39 m.5
#[test]
#[ignore = "control for `just ctgrind`: Valgrind must report this one"]
fn control_variable_time_comparison_is_reported() {
    let a = secret(0x5a);
    let b = candidate(0x5a, 0x00, 32);
    assert!(!declassify(variable_time_eq(a.expose(), &b)));
}
