//! Phone numbers as identifiers (TN-156, OP-159 m.54 (b)): every phone number is kept, looked up
//! and sent to in E.164 (`+` and at most 15 digits). A number typed with its country code (`+` or
//! `00`) is taken as it is; one typed the national way is completed with the environment's
//! default country. Spaces, dashes, dots and parentheses are dropped; anything else is not a
//! phone number.

/// The most digits E.164 allows.
const MAX_DIGITS: usize = 15;
/// The fewest digits a full number this module accepts has.
const MIN_DIGITS: usize = 8;

/// A country the national way of writing a number is known for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Country {
    /// ISO 3166-1 alpha-2, upper case.
    pub iso: &'static str,
    /// The calling code, without `+`.
    pub code: &'static str,
    /// The national trunk prefix dropped before the national significant number.
    pub trunk: Option<char>,
    /// The national significant number's length range.
    pub nsn: (usize, usize),
}

/// The countries whose national way of writing a number is known (PD).
pub const COUNTRIES: &[Country] = &[
    Country {
        iso: "TR",
        code: "90",
        trunk: Some('0'),
        nsn: (10, 10),
    },
    Country {
        iso: "AZ",
        code: "994",
        trunk: Some('0'),
        nsn: (9, 9),
    },
    Country {
        iso: "DE",
        code: "49",
        trunk: Some('0'),
        nsn: (6, 13),
    },
    Country {
        iso: "NL",
        code: "31",
        trunk: Some('0'),
        nsn: (9, 9),
    },
    Country {
        iso: "FR",
        code: "33",
        trunk: Some('0'),
        nsn: (9, 9),
    },
    Country {
        iso: "GB",
        code: "44",
        trunk: Some('0'),
        nsn: (9, 10),
    },
    Country {
        iso: "US",
        code: "1",
        trunk: Some('1'),
        nsn: (10, 10),
    },
];

/// The known country `iso` names, in any letter case.
#[must_use]
pub fn country(iso: &str) -> Option<Country> {
    COUNTRIES
        .iter()
        .copied()
        .find(|c| c.iso.eq_ignore_ascii_case(iso))
}

/// Whether `raw` is written like a phone number rather than an e-mail address or a user name:
/// digits with an optional leading `+` and the separators people type.
#[must_use]
pub fn looks_like_phone(raw: &str) -> bool {
    let t = raw.trim();
    let mut digits = 0_usize;
    for (i, c) in t.chars().enumerate() {
        match c {
            '0'..='9' => digits = digits.saturating_add(1),
            '+' if i == 0 => {}
            ' ' | '-' | '.' | '(' | ')' | '\u{a0}' => {}
            _ => return false,
        }
    }
    digits >= 4
}

/// `raw` in E.164, completed with `default` when it is written the national way; `None` when it
/// is not a phone number this module can place.
#[must_use]
pub fn e164(raw: &str, default: Option<Country>) -> Option<String> {
    if !looks_like_phone(raw) {
        return None;
    }
    let t = raw.trim();
    let digits: String = t.chars().filter(char::is_ascii_digit).collect();
    let full = if t.starts_with('+') {
        digits
    } else if let Some(rest) = digits.strip_prefix("00") {
        String::from(rest)
    } else {
        let c = default?;
        let national = match c.trunk {
            Some(trunk) => digits.strip_prefix(trunk).unwrap_or(&digits),
            None => digits.as_str(),
        };
        if national.starts_with('0') {
            return None;
        }
        if national.len() < c.nsn.0 || national.len() > c.nsn.1 {
            return None;
        }
        format!("{}{national}", c.code)
    };
    if full.len() < MIN_DIGITS || full.len() > MAX_DIGITS || full.starts_with('0') {
        return None;
    }
    if let Some(c) = COUNTRIES.iter().find(|c| full.starts_with(c.code)) {
        let nsn = full.len().saturating_sub(c.code.len());
        if nsn < c.nsn.0 || nsn > c.nsn.1 {
            return None;
        }
    }
    Some(format!("+{full}"))
}

#[cfg(test)]
mod tests;
