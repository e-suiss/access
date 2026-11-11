//! `cargo xtask calibrate` (OP-146 m.4 (f), OP-158 m.3 (y)): on the target host, how long one
//! password hash takes under each policy, alone and with every permit busy, the semaphore size
//! the host gets, and the adaptive delay's starting mean (`login.hash_mean_ms`). Prints one JSON
//! object with the environment it ran in.

#![allow(
    clippy::print_stdout,
    reason = "a calibration tool reports to the terminal"
)]

use std::time::Instant;

use access_identity_account::domain::password::{
    Argon2Params, HashPolicy, HashProfile, Password, hash_with, permits,
};

const ROUNDS: usize = 12;

fn salt() -> [u8; 16] {
    access_crypto::random::bytes::<16>().unwrap_or_else(|_| std::process::abort())
}

/// Milliseconds of each of `rounds` hashes run by `threads` threads at once, sorted.
fn measure(policy: HashPolicy, threads: usize, rounds: usize) -> Vec<f64> {
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let pw = Password::new("correct horse battery staple")
                    .unwrap_or_else(|_| std::process::abort());
                (0..rounds)
                    .map(|_| {
                        let salt = salt();
                        let started = Instant::now();
                        let ok = hash_with(&policy, &pw, &salt).is_ok();
                        if !ok {
                            std::process::abort();
                        }
                        started.elapsed().as_secs_f64() * 1000.0
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut all: Vec<f64> = workers
        .into_iter()
        .flat_map(|w| w.join().unwrap_or_default())
        .collect();
    all.sort_by(f64::total_cmp);
    all
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "an index into a short sample"
    )]
    let i = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted.get(i).copied().unwrap_or(0.0)
}

fn main() {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let budget = std::env::var("ACCESS_CALIBRATE_MEMORY_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let candidates = [
        (
            "argon2id-canonical",
            HashPolicy::Argon2(Argon2Params::CANONICAL),
        ),
        (
            "argon2id-owasp-19m",
            HashPolicy::Argon2(Argon2Params {
                m_kib: 19 * 1024,
                t: 2,
                p: 1,
            }),
        ),
        (
            "pbkdf2-sha256-fips",
            HashPolicy::of(HashProfile::Standard, true),
        ),
    ];
    let mut rows = Vec::new();
    let mut canonical_p50 = 0.0;
    for (name, policy) in candidates {
        let n = permits(cores, budget, &policy.params_for_permits());
        let alone = measure(policy, 1, ROUNDS);
        let busy = measure(policy, n, ROUNDS);
        let p50 = quantile(&alone, 0.5);
        if name == "argon2id-canonical" {
            canonical_p50 = p50;
        }
        rows.push(format!(
            "{{\"policy\":\"{name}\",\"permits\":{n},\"alone_p50_ms\":{p50:.2},\
             \"alone_p99_ms\":{:.2},\"busy_p50_ms\":{:.2},\"busy_p99_ms\":{:.2}}}",
            quantile(&alone, 0.99),
            quantile(&busy, 0.5),
            quantile(&busy, 0.99),
        ));
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a positive millisecond count"
    )]
    let seed = canonical_p50.ceil() as u64;
    println!(
        "{{\"environment\":{{\"os\":\"{}\",\"arch\":\"{}\",\"cores\":{cores},\"memory_budget\":{}}},\
         \"policies\":[{}],\"login.hash_mean_ms\":{seed}}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        budget.map_or_else(|| "null".to_owned(), |b| b.to_string()),
        rows.join(","),
    );
}
