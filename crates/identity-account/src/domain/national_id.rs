//! National identity numbers (TN-158): the environment names which schemes it takes. A
//! built-in scheme checks the number's shape and check digits; the generic scheme checks only
//! its length and kind of characters. The number is what the person typed; whether it belongs
//! to them is the product's concern, never Access's.

/// The characters a generic scheme takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// Digits only.
    Digits,
    /// Upper-case Latin letters and digits.
    Alphanumeric,
}

/// A national identity number scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Türkiye: T.C. Kimlik No, 11 digits and two check digits.
    TrTckn,
    /// United States: Social Security Number, 9 digits outside the never-issued ranges.
    UsSsn,
    /// Germany: Steuerliche Identifikationsnummer, 11 digits and an ISO 7064 check digit.
    DeSteuerId,
    /// United Kingdom: National Insurance number, two letters, six digits and A to D.
    GbNino,
    /// Netherlands: Burgerservicenummer, 9 digits under the eleven test.
    NlBsn,
    /// Azerbaijan: FİN, 7 letters and digits.
    AzFin,
    /// Any other: a length range and a kind of characters, no check digits.
    Generic {
        /// Fewest characters.
        min: u8,
        /// Most characters.
        max: u8,
        /// Which characters.
        charset: Charset,
    },
}

/// The built-in schemes, by stored name.
pub const BUILT_IN: [(&str, Scheme); 6] = [
    ("tr-tckn", Scheme::TrTckn),
    ("us-ssn", Scheme::UsSsn),
    ("de-steuer-id", Scheme::DeSteuerId),
    ("gb-nino", Scheme::GbNino),
    ("nl-bsn", Scheme::NlBsn),
    ("az-fin", Scheme::AzFin),
];

/// The longest number any scheme takes.
pub const MAX_CHARS: usize = 32;

impl Scheme {
    /// The built-in scheme `name` names.
    #[must_use]
    pub fn built_in(name: &str) -> Option<Self> {
        BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
    }

    /// The scheme a stored name names: a built-in one, or `generic:<min>-<max>:<digits|alnum>`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        if let Some(s) = Self::built_in(name) {
            return Some(s);
        }
        let rest = name.strip_prefix("generic:")?;
        let (range, kind) = rest.split_once(':')?;
        let (min, max) = range.split_once('-')?;
        let charset = match kind {
            "digits" => Charset::Digits,
            "alnum" => Charset::Alphanumeric,
            _ => return None,
        };
        Self::generic(min.parse().ok()?, max.parse().ok()?, charset)
    }

    /// A generic scheme, when its range is sane.
    #[must_use]
    pub fn generic(min: u8, max: u8, charset: Charset) -> Option<Self> {
        (1 <= min && min <= max && usize::from(max) <= MAX_CHARS).then_some(Self::Generic {
            min,
            max,
            charset,
        })
    }

    /// `raw` as kept: spaces, dashes and dots dropped, letters upper case; `None` when it is
    /// not a number of this scheme.
    #[must_use]
    pub fn normalize(self, raw: &str) -> Option<String> {
        let n: String = raw
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '.' | '\u{a0}'))
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if n.is_empty() || n.len() > MAX_CHARS || !n.is_ascii() {
            return None;
        }
        let ok = match self {
            Self::TrTckn => tckn(&n),
            Self::UsSsn => ssn(&n),
            Self::DeSteuerId => steuer_id(&n),
            Self::GbNino => nino(&n),
            Self::NlBsn => bsn(&n),
            Self::AzFin => n.len() == 7 && n.bytes().all(|b| b.is_ascii_alphanumeric()),
            Self::Generic { min, max, charset } => {
                (usize::from(min)..=usize::from(max)).contains(&n.len())
                    && n.bytes().all(|b| match charset {
                        Charset::Digits => b.is_ascii_digit(),
                        Charset::Alphanumeric => b.is_ascii_alphanumeric(),
                    })
            }
        };
        ok.then_some(n)
    }
}

/// The most of a number a page shows: its last four characters.
#[must_use]
pub fn masked(number: &str) -> String {
    let n = number.chars().count();
    let tail: String = number.chars().skip(n.saturating_sub(4)).collect();
    format!("{}{tail}", "*".repeat(n.saturating_sub(4)))
}

fn digits(n: &str, len: usize) -> Option<Vec<u32>> {
    (n.len() == len)
        .then(|| {
            n.chars()
                .map(|c| c.to_digit(10))
                .collect::<Option<Vec<u32>>>()
        })
        .flatten()
}

fn tckn(n: &str) -> bool {
    let Some(d) = digits(n, 11) else {
        return false;
    };
    let [d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10] = d[..] else {
        return false;
    };
    if d0 == 0 {
        return false;
    }
    let sum = |xs: &[u32]| xs.iter().fold(0_u32, |a, x| a.wrapping_add(*x));
    let odd = sum(&[d0, d2, d4, d6, d8]);
    let even = sum(&[d1, d3, d5, d7]);
    let tenth = odd
        .wrapping_mul(7)
        .wrapping_add(100)
        .wrapping_sub(even)
        .rem_euclid(10);
    let eleventh = sum(&[odd, even, d9]).rem_euclid(10);
    tenth == d9 && eleventh == d10
}

fn ssn(n: &str) -> bool {
    if digits(n, 9).is_none() {
        return false;
    }
    let (area, rest) = n.split_at(3);
    let (group, serial) = rest.split_at(2);
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

fn steuer_id(n: &str) -> bool {
    let Some(d) = digits(n, 11) else {
        return false;
    };
    if d.first() == Some(&0) {
        return false;
    }
    let mut product = 10_u32;
    for x in d.iter().take(10) {
        let mut sum = x.wrapping_add(product).rem_euclid(10);
        if sum == 0 {
            sum = 10;
        }
        product = sum.wrapping_mul(2).rem_euclid(11);
    }
    let check = 11_u32.wrapping_sub(product).rem_euclid(10);
    d.get(10) == Some(&check)
}

fn nino(n: &str) -> bool {
    let b = n.as_bytes();
    let [p0, p1, d @ .., s] = b else {
        return false;
    };
    if d.len() != 6 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let letter = |c: &u8, bad: &[u8]| c.is_ascii_uppercase() && !bad.contains(c);
    let prefix = [*p0, *p1];
    letter(p0, b"DFIQUV")
        && letter(p1, b"DFIOQUV")
        && !matches!(
            &prefix,
            b"BG" | b"GB" | b"KN" | b"NK" | b"NT" | b"TN" | b"ZZ"
        )
        && matches!(s, b'A'..=b'D')
}

fn bsn(n: &str) -> bool {
    let Some(d) = digits(n, 9) else {
        return false;
    };
    let weighted: i64 = d
        .iter()
        .zip([9_i64, 8, 7, 6, 5, 4, 3, 2, -1])
        .fold(0_i64, |a, (x, w)| {
            a.wrapping_add(i64::from(*x).wrapping_mul(w))
        });
    weighted.rem_euclid(11) == 0 && d.iter().any(|x| *x != 0)
}

#[cfg(test)]
mod tests;
