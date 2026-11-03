//! Codes people read and type (§10.2.2, TN-59): TOTP seeds in base32 and their `otpauth` URI,
//! recovery codes and e-mail codes. Randomness comes in from the caller.

use core::fmt::Write as _;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps read seeds.
#[must_use]
pub fn base32(bytes: &[u8]) -> String {
    const SHIFTS: [u32; 8] = [35, 30, 25, 20, 15, 10, 5, 0];
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0_u8; 8];
        for (d, s) in buf.iter_mut().skip(3).zip(chunk) {
            *d = *s;
        }
        let v = u64::from_be_bytes(buf);
        let chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for shift in SHIFTS.iter().take(chars) {
            let index = usize::try_from(v.checked_shr(*shift).unwrap_or(0) & 31).unwrap_or(0);
            out.push(char::from(*BASE32.get(index).unwrap_or(&b'A')));
        }
    }
    out
}

fn percent(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The `otpauth://totp/` URI an authenticator app scans (Key URI Format).
#[must_use]
pub fn otpauth_uri(
    issuer: &str,
    account: &str,
    secret: &[u8],
    algorithm: &str,
    digits: u8,
) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={algorithm}&digits={digits}&period=30",
        percent(issuer),
        percent(account),
        base32(secret),
        percent(issuer),
    )
}

/// Recovery codes per set (PD).
pub const RECOVERY_CODES: usize = 10;

/// Random bytes per recovery code: 80 bits, above TN-59's 64.
pub const RECOVERY_CODE_BYTES: usize = 10;

/// A recovery code: 16 base32 characters in groups of four.
#[must_use]
pub fn recovery_code(random: &[u8; RECOVERY_CODE_BYTES]) -> String {
    let raw = base32(random);
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i.is_multiple_of(4) {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// A typed recovery code in canonical form: letters upper-cased, separators and spaces
/// dropped, `0`/`1`/`8` read as `O`/`I`/`B`.
#[must_use]
pub fn canonical_recovery_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            '0' => 'O',
            '1' => 'I',
            '8' => 'B',
            u => u,
        })
        .collect()
}

/// E-mail code length (PD).
pub const EMAIL_CODE_DIGITS: usize = 8;

/// An e-mail code from eight random bytes: eight decimal digits.
#[must_use]
pub fn email_code(random: &[u8; 8]) -> String {
    let n = u64::from_be_bytes(*random)
        .checked_rem(100_000_000)
        .unwrap_or(0);
    format!("{n:08}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.2.2
    #[test]
    fn base32_matches_rfc_4648() {
        for (input, out) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), out);
        }
    }

    // TN-59
    #[test]
    fn recovery_codes_are_grouped_and_canonical() {
        let code = recovery_code(&[0xff; RECOVERY_CODE_BYTES]);
        assert_eq!(code, "7777-7777-7777-7777");
        assert_eq!(
            canonical_recovery_code(" 7777 7777-7777-7777 "),
            "7777777777777777"
        );
        assert_eq!(canonical_recovery_code("abcd-0i18"), "ABCDOIIB");
        const { assert!(RECOVERY_CODE_BYTES * 8 >= 64) };
    }

    // §10.2.2
    #[test]
    fn otpauth_uri_escapes_labels() {
        let uri = otpauth_uri("Acme Co", "a@b.example", b"foobar", "SHA1", 6);
        assert_eq!(
            uri,
            "otpauth://totp/Acme%20Co:a%40b.example?secret=MZXW6YTBOI&issuer=Acme%20Co&algorithm=SHA1&digits=6&period=30"
        );
        assert_eq!(email_code(&[0; 8]), "00000000");
        assert_eq!(email_code(&[0xff; 8]).len(), EMAIL_CODE_DIGITS);
    }
}
