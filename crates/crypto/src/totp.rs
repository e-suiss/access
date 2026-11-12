//! TOTP (RFC 6238 over RFC 4226 HOTP) on aws-lc HMAC (OP-146 m.3, §10.2.2): 30-second steps,
//! a ±1 step window, and a constant-time comparison over every step of the window (CR-39).
//! The caller rejects a step it has already accepted.

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;

use crate::secret::Secret;

/// The HMAC under the code. Authenticator apps implement SHA-1 universally (RFC 6238 §1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the RFC 6238 default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
}

impl TotpAlgorithm {
    /// The `otpauth` URI name.
    #[must_use]
    pub const fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    const fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }
}

/// The parameters of one TOTP credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    /// HMAC.
    pub algorithm: TotpAlgorithm,
    /// Code length, 6 to 8.
    pub digits: u8,
    /// Step length in seconds.
    pub step_s: u64,
    /// Steps accepted on each side of the current one.
    pub window: u8,
}

impl TotpParams {
    /// §10.2.2: 30 s steps, ±1 step, six digits, SHA-1.
    pub const DEFAULT: Self = Self {
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        step_s: 30,
        window: 1,
    };
}

/// RFC 4226 §5.3: the code of `counter`, as `digits` decimal digits.
#[must_use]
pub fn hotp(key: &[u8], algorithm: TotpAlgorithm, counter: u64, digits: u8) -> String {
    let tag = hmac::sign(
        &hmac::Key::new(algorithm.hmac(), key),
        &counter.to_be_bytes(),
    );
    let mac = tag.as_ref();
    let offset = mac.last().map_or(0, |b| usize::from(b & 0x0f));
    let mut word = [0_u8; 4];
    for (w, b) in word.iter_mut().zip(mac.iter().skip(offset)) {
        *w = *b;
    }
    let binary = u32::from_be_bytes(word) & 0x7fff_ffff;
    let digits = digits.clamp(6, 8);
    let modulus = match digits {
        6 => 1_000_000,
        7 => 10_000_000,
        _ => 100_000_000_u32,
    };
    let code = binary.checked_rem(modulus).unwrap_or(0);
    format!("{code:0width$}", width = usize::from(digits))
}

/// The step of a moment.
#[must_use]
pub const fn step_of(now_s: u64, step_s: u64) -> u64 {
    match now_s.checked_div(step_s) {
        Some(s) => s,
        None => 0,
    }
}

/// The step within the window whose code equals `code`, the latest when several do. Every
/// step of the window is computed and compared, so the time does not depend on which one
/// matches.
#[must_use]
pub fn matching_step(
    key: &Secret<Vec<u8>>,
    params: &TotpParams,
    now_s: u64,
    code: &str,
) -> Option<u64> {
    // CR-39 m.6
    let _dit = crate::dit::DitGuard::new();
    let current = step_of(now_s, params.step_s);
    let window = u64::from(params.window);
    let mut found: Option<u64> = None;
    let first = current.saturating_sub(window);
    let last = current.saturating_add(window);
    let mut step = first;
    while step <= last {
        let candidate = hotp(key.expose(), params.algorithm, step, params.digits);
        let same = candidate.len() == code.len()
            && bool::from(candidate.as_bytes().ct_eq(code.as_bytes()));
        if same {
            found = Some(step);
        }
        let Some(next) = step.checked_add(1) else {
            break;
        };
        step = next;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_KEY: &[u8] = b"12345678901234567890";
    const SHA256_KEY: &[u8] = b"12345678901234567890123456789012";

    // OP-146 m.3, §10.2.2
    #[test]
    fn rfc_6238_vectors() {
        let cases: [(u64, &str, &str); 6] = [
            (59, "94287082", "46119246"),
            (1_111_111_109, "07081804", "68084774"),
            (1_111_111_111, "14050471", "67062674"),
            (1_234_567_890, "89005924", "91819424"),
            (2_000_000_000, "69279037", "90698825"),
            (20_000_000_000, "65353130", "77737706"),
        ];
        for (t, sha1, sha256) in cases {
            let step = step_of(t, 30);
            assert_eq!(hotp(SHA1_KEY, TotpAlgorithm::Sha1, step, 8), sha1);
            assert_eq!(hotp(SHA256_KEY, TotpAlgorithm::Sha256, step, 8), sha256);
        }
    }

    // OP-146 m.3
    #[test]
    fn rfc_4226_vectors() {
        let expected = ["755224", "287082", "359152", "969429", "338314"];
        for (counter, code) in (0_u64..).zip(expected) {
            assert_eq!(hotp(SHA1_KEY, TotpAlgorithm::Sha1, counter, 6), code);
        }
    }

    // §10.2.2
    #[test]
    fn the_window_is_one_step_each_side() {
        let key = Secret::new(SHA1_KEY.to_vec());
        let p = TotpParams::DEFAULT;
        let now = 1_800_000_000_u64;
        let step = step_of(now, 30);
        for (delta, accepted) in [
            (-2_i64, false),
            (-1, true),
            (0, true),
            (1, true),
            (2, false),
        ] {
            let s = step.checked_add_signed(delta).unwrap_or(0);
            let code = hotp(SHA1_KEY, TotpAlgorithm::Sha1, s, 6);
            assert_eq!(matching_step(&key, &p, now, &code).is_some(), accepted);
        }
        assert_eq!(matching_step(&key, &p, now, "12345"), None);
        assert_eq!(matching_step(&key, &p, now, ""), None);
    }
}
