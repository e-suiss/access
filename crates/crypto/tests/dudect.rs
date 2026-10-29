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
