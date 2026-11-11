//! OP-72, OP-146 m.4 (f): wall-clock cost of one password hash under each policy (divan). The
//! nightly `bench-wallclock` job runs it on the bench runner; `cargo xtask calibrate` measures
//! the same on the target host.

use access_identity_account::domain::password::{
    Argon2Params, HashPolicy, HashProfile, Password, hash_with, verify_with,
};
use divan::black_box;

fn main() {
    divan::main();
}

fn password() -> Password {
    Password::new("correct horse battery staple").unwrap_or_else(|_| std::process::abort())
}

fn salt() -> [u8; 16] {
    access_crypto::random::bytes::<16>().unwrap_or_else(|_| std::process::abort())
}

// CR-36
#[divan::bench(sample_count = 20)]
fn argon2id_canonical(b: divan::Bencher<'_, '_>) {
    let (pw, salt) = (password(), salt());
    let policy = HashPolicy::Argon2(Argon2Params::CANONICAL);
    b.bench(|| hash_with(black_box(&policy), &pw, &salt).is_ok());
}

// CR-36
#[divan::bench(sample_count = 20)]
fn argon2id_owasp_19m(b: divan::Bencher<'_, '_>) {
    let (pw, salt) = (password(), salt());
    let policy = HashPolicy::Argon2(Argon2Params {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    });
    b.bench(|| hash_with(black_box(&policy), &pw, &salt).is_ok());
}

// CR-15, CR-36 m.1
#[divan::bench(sample_count = 10)]
fn pbkdf2_sha256_fips(b: divan::Bencher<'_, '_>) {
    let (pw, salt) = (password(), salt());
    let policy = HashPolicy::of(HashProfile::Standard, true);
    b.bench(|| hash_with(black_box(&policy), &pw, &salt).is_ok());
}

// CR-36, CR-37
#[divan::bench(sample_count = 20)]
fn argon2id_canonical_verify(b: divan::Bencher<'_, '_>) {
    let (pw, salt) = (password(), salt());
    let policy = HashPolicy::Argon2(Argon2Params::CANONICAL);
    let phc = hash_with(&policy, &pw, &salt).unwrap_or_else(|_| std::process::abort());
    b.bench(|| verify_with(&pw, black_box(&phc), &policy).is_ok());
}
