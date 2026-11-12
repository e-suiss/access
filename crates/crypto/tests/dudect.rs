//! dudect leakage test for the secret comparisons (CR-39 m.5, SA-T13): Welch's t-test between
//! "equal" and "differs in the first byte" inputs; |t| > 5 is a leak.

#[cfg(test)]
mod dudect {
    use std::hint::black_box;
    use std::time::Instant;

    use access_crypto::secret::Secret;

    const THRESHOLD: f64 = 5.0;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[derive(Default)]
    struct Welch {
        n: [f64; 2],
        mean: [f64; 2],
        m2: [f64; 2],
    }

    impl Welch {
        fn push(&mut self, class: usize, x: f64) {
            self.n[class] += 1.0;
            let d = x - self.mean[class];
            self.mean[class] += d / self.n[class];
            self.m2[class] += d * (x - self.mean[class]);
        }

        fn t(&self) -> f64 {
            let var = |c: usize| self.m2[c] / (self.n[c] - 1.0);
            (self.mean[0] - self.mean[1]) / (var(0) / self.n[0] + var(1) / self.n[1]).sqrt()
        }
    }

    fn leak_t(samples: usize, run: impl Fn(bool, &mut Rng) -> u128) -> f64 {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut times: Vec<(usize, u128)> = (0..samples)
            .map(|_| {
                let class = usize::from(rng.next() & 1 == 1);
                (class, run(class == 1, &mut rng))
            })
            .collect();
        let mut sorted: Vec<u128> = times.iter().map(|(_, t)| *t).collect();
        sorted.sort_unstable();
        let crop = sorted[samples
            .checked_mul(9)
            .and_then(|x| x.checked_div(10))
            .unwrap()];
        times.retain(|(_, t)| *t <= crop);
        let mut w = Welch::default();
        for (class, t) in times {
            #[allow(clippy::cast_precision_loss, reason = "nanosecond timings fit")]
            w.push(class, t as f64);
        }
        w.t()
    }

    fn timed(f: impl Fn() -> bool) -> u128 {
        let start = Instant::now();
        for _ in 0..64 {
            black_box(f());
        }
        start.elapsed().as_nanos()
    }

    // CR-39 m.5, SAI-42, U45
    #[test]
    #[ignore = "nightly: just dudect"]
    fn secret_comparisons_do_not_leak() {
        if std::env::var_os("ACCESS_DUDECT").is_none() {
            return;
        }
        let samples: usize = std::env::var("ACCESS_DUDECT_SAMPLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(200_000);
        let secret = Secret::new([0x5a_u8; 32]);
        let t_eq = leak_t(samples, |differ, rng| {
            let mut other = [0x5a_u8; 32];
            if differ {
                other[0] ^= u8::try_from(rng.next() % 255 + 1).unwrap_or(1);
            }
            let other = Secret::new(other);
            timed(|| secret.ct_eq(black_box(&other)))
        });
        let t_bytes = leak_t(samples, |differ, rng| {
            let mut other = [0x5a_u8; 32];
            if differ {
                other[0] ^= u8::try_from(rng.next() % 255 + 1).unwrap_or(1);
            }
            timed(|| secret.ct_eq_bytes(black_box(&other)))
        });
        #[allow(
            clippy::print_stdout,
            reason = "the nightly log keeps the measured t values"
        )]
        {
            println!(
                "dudect ct_eq |t| = {:.2}, ct_eq_bytes |t| = {:.2}",
                t_eq.abs(),
                t_bytes.abs()
            );
        }
        assert!(t_eq.abs() < THRESHOLD, "ct_eq leaks: |t| = {t_eq}");
        assert!(
            t_bytes.abs() < THRESHOLD,
            "ct_eq_bytes leaks: |t| = {t_bytes}"
        );
    }

    fn samples() -> Option<usize> {
        std::env::var_os("ACCESS_DUDECT")?;
        Some(
            std::env::var("ACCESS_DUDECT_SAMPLES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200_000),
        )
    }

    fn report(name: &str, t: f64) {
        #[allow(
            clippy::print_stdout,
            reason = "the nightly log keeps the measured t values"
        )]
        {
            println!("dudect {name} |t| = {:.2}", t.abs());
        }
        assert!(t.abs() < THRESHOLD, "{name} leaks: |t| = {t}");
    }

    fn key<const N: usize>() -> [u8; N] {
        access_crypto::random::bytes::<N>().unwrap()
    }

    /// `presented` equal to `real`, or differing in its first byte.
    fn flip(real: &[u8], differ: bool, rng: &mut Rng) -> Vec<u8> {
        let mut out = real.to_vec();
        if differ && let Some(b) = out.first_mut() {
            *b ^= nonzero(rng);
        }
        out
    }

    fn nonzero(rng: &mut Rng) -> u8 {
        u8::try_from(rng.next() % 255)
            .unwrap_or(0)
            .saturating_add(1)
    }

    // CR-39 m.1, m.4, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn opaque_token_digest() {
        let Some(n) = samples() else { return };
        let real = key::<32>();
        let t = leak_t(n, |differ, rng| {
            let presented = flip(&real, differ, rng);
            timed(|| {
                access_crypto::oauth::opaque_digest("access/dudect/v1", black_box(&presented))[0]
                    & 1
                    == 0
            })
        });
        report("opaque_digest", t);
    }

    // CR-39 m.1, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn hmac_jws_verify() {
        let Some(n) = samples() else { return };
        let secret = key::<32>();
        let input = key::<64>();
        let tag = aws_lc_rs::hmac::sign(
            &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &secret),
            &input,
        );
        let t = leak_t(n, |differ, rng| {
            let presented = flip(tag.as_ref(), differ, rng);
            timed(|| {
                access_crypto::client_secret_jwt::verify(&secret, &input, black_box(&presented))
                    .is_ok()
            })
        });
        report("client_secret_jwt::verify", t);
    }

    // CR-39 m.1, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn totp_matching_step() {
        let Some(n) = samples() else { return };
        let secret = Secret::new(key::<20>().to_vec());
        let params = access_crypto::totp::TotpParams {
            algorithm: access_crypto::totp::TotpAlgorithm::Sha1,
            digits: 6,
            step_s: 30,
            window: 1,
        };
        let now = 1_800_000_000;
        let real = access_crypto::totp::hotp(
            secret.expose(),
            params.algorithm,
            access_crypto::totp::step_of(now, params.step_s),
            params.digits,
        );
        let t = leak_t(n / 4, |differ, rng| {
            let mut presented = real.clone().into_bytes();
            if differ && let Some(b) = presented.first_mut() {
                let digit = b.wrapping_sub(b'0');
                let shift = u8::try_from(rng.next() % 9).unwrap_or(0).saturating_add(1);
                *b = b'0'.wrapping_add(digit.wrapping_add(shift) % 10);
            }
            let presented = String::from_utf8(presented).unwrap();
            timed(|| {
                access_crypto::totp::matching_step(&secret, &params, now, black_box(&presented))
                    .is_some()
            })
        });
        report("totp::matching_step", t);
    }

    // CR-39 m.1, m.4, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn client_secret_match() {
        let Some(n) = samples() else { return };
        let presented_real = key::<32>();
        let stored = access_crypto::oauth::secret_digest(&presented_real);
        let t = leak_t(n, |differ, rng| {
            let presented = flip(&presented_real, differ, rng);
            timed(|| access_crypto::oauth::secret_matches(&stored, black_box(&presented)))
        });
        report("oauth::secret_matches", t);
    }

    // CR-39 m.1, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn pkce_match() {
        let Some(n) = samples() else { return };
        let verifier = access_kernel::json::b64url_encode(&key::<32>());
        let challenge = sha256(verifier.as_bytes());
        let t = leak_t(n, |differ, rng| {
            let mut presented = verifier.clone().into_bytes();
            if differ && let Some(b) = presented.first_mut() {
                *b = if *b == b'A' || rng.next() & 1 == 0 {
                    b'B'
                } else {
                    b'A'
                };
            }
            let presented = String::from_utf8(presented).unwrap();
            timed(|| access_crypto::oauth::pkce_matches(&challenge, black_box(&presented)))
        });
        report("oauth::pkce_matches", t);
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
        <[u8; 32]>::try_from(d.as_ref()).unwrap()
    }

    // CR-39 m.1, SAI-42
    #[test]
    #[ignore = "nightly: just dudect"]
    fn basis_ref_open() {
        let Some(n) = samples() else { return };
        let token = access_crypto::token::TokenKey::new(Secret::new(key::<32>()));
        let domain = key::<32>();
        let sealed = token.seal(&domain, "basis_ref", &key::<48>()).unwrap();
        let raw = access_kernel::json::b64url_decode(&sealed).unwrap();
        let t = leak_t(n / 4, |at_end, rng| {
            let mut tampered = raw.clone();
            let byte = if at_end {
                tampered.last_mut()
            } else {
                tampered.get_mut(12)
            };
            if let Some(b) = byte {
                *b ^= nonzero(rng);
            }
            let text = access_kernel::json::b64url_encode(&tampered);
            timed(|| token.open(&domain, "basis_ref", black_box(&text)).is_ok())
        });
        report("token::TokenKey::open", t);
    }

    // CR-39 m.5
    #[test]
    #[ignore = "nightly: just dudect"]
    fn harness_detects_a_variable_time_comparison() {
        if std::env::var_os("ACCESS_DUDECT").is_none() {
            return;
        }
        let secret = [0x5a_u8; 4096];
        let t = leak_t(100_000, |differ, _| {
            let mut other = [0x5a_u8; 4096];
            if differ {
                other[0] ^= 1;
            }
            timed(|| black_box(&secret[..]) == black_box(&other[..]))
        });
        assert!(
            t.abs() > THRESHOLD,
            "harness missed a variable-time comparison: |t| = {t}"
        );
    }
}
