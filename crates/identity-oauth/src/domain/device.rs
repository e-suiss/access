//! The device authorization grant's codes and limits (RFC 8628, OP-154 m.3 (p), TN-35, CR-38,
//! CR-39): a 256-bit `device_code` kept only as its SHA-256, an 8-character `user_code` from an
//! alphabet without vowels or look-alikes shown as `XXXX-XXXX`, ten minutes to approve, a five
//! second polling interval that grows by five on `slow_down`, and the entry limits.

/// The `user_code` alphabet (RFC 8628 §6.1): consonants only, no vowel, no `Y`.
pub const ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
/// Characters in a `user_code`.
pub const USER_CODE_LEN: usize = 8;
/// How long a device authorization waits for the person.
pub const LIFETIME_MS: u64 = 10 * 60 * 1000;
/// The polling interval the device starts with, seconds.
pub const INTERVAL_S: u32 = 5;
/// What `slow_down` adds, seconds (RFC 8628 §3.5).
pub const SLOW_DOWN_S: u32 = 5;
/// Wrong codes a person may enter before waiting.
pub const PERSON_MISSES: u64 = 5;
/// How long a person waits after them.
pub const PERSON_WAIT_MS: u64 = 15 * 60 * 1000;
/// Wrong codes an IP prefix may enter in an hour.
pub const PREFIX_MISSES_PER_HOUR: u64 = 30;
/// The verification page under the issuer.
pub const VERIFICATION_PATH: &str = "/device";

const HASH_CONTEXT: &str = "access/device-code/v1";
const USER_CONTEXT: &str = "access/device-user-code/v1";

/// The `user_code` of 8 random bytes: each picks a letter of [`ALPHABET`] without bias
/// (values ≥ 240 are redrawn by the caller's next byte).
#[must_use]
pub fn user_code(random: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(USER_CODE_LEN + 1);
    let mut n: usize = 0;
    for b in random {
        if *b >= 240 {
            continue;
        }
        let i = usize::from(*b).checked_rem(ALPHABET.len())?;
        out.push(char::from(*ALPHABET.get(i)?));
        n = n.saturating_add(1);
        if n == USER_CODE_LEN / 2 {
            out.push('-');
        }
        if n == USER_CODE_LEN {
            return Some(out);
        }
    }
    None
}

/// What the person typed, as the code it means: upper case, without spaces or dashes; `None`
/// when it cannot be a code.
#[must_use]
pub fn normalise(entered: &str) -> Option<String> {
    let s: String = entered
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (s.len() == USER_CODE_LEN && s.bytes().all(|c| ALPHABET.contains(&c))).then_some(s)
}

/// The stored digest of a `device_code` (CR-38).
#[must_use]
pub fn device_hash(code: &[u8]) -> [u8; 32] {
    access_crypto::oauth::opaque_digest(HASH_CONTEXT, code)
}

/// The stored digest of a normalised `user_code`.
#[must_use]
pub fn user_hash(normalised: &str) -> [u8; 32] {
    access_crypto::oauth::opaque_digest(USER_CONTEXT, normalised.as_bytes())
}

/// What a poll at `now_ms` answers, given the last poll and the interval (RFC 8628 §3.5): the
/// interval to keep, and whether the device polled too fast.
#[must_use]
pub fn poll(last_ms: Option<u64>, interval_s: u32, now_ms: u64) -> (u32, bool) {
    let early = last_ms.is_some_and(|l| now_ms < l.saturating_add(u64::from(interval_s) * 1000));
    if early {
        (interval_s.saturating_add(SLOW_DOWN_S).min(600), true)
    } else {
        (interval_s, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-154 m.3 (p), RFC 8628 §6.1
    #[test]
    fn a_user_code_is_eight_consonants_shown_in_two_halves() {
        let c = user_code(&[0, 1, 2, 3, 250, 4, 5, 6, 19]).unwrap();
        assert_eq!(c, "BCDF-GHJZ");
        assert_eq!(normalise("bcdf ghjk").as_deref(), Some("BCDFGHJK"));
        assert_eq!(normalise("BCDF-GHJA"), None, "a vowel is no code");
        assert_eq!(user_code(&[255; 20]), None);
    }

    // RFC 8628 §3.5, OP-154 m.3 (p)
    #[test]
    fn polling_too_fast_slows_the_device_down_by_five_seconds() {
        assert_eq!(poll(None, 5, 1_000), (5, false));
        assert_eq!(poll(Some(1_000), 5, 3_000), (10, true));
        assert_eq!(poll(Some(1_000), 5, 6_000), (5, false));
    }

    // CR-38
    #[test]
    fn only_digests_of_the_codes_are_kept() {
        assert_ne!(device_hash(b"x"), user_hash("x"));
        assert_eq!(device_hash(b"x").len(), 32);
    }
}
