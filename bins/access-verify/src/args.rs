//! Command-line options: `--name value` pairs, each given at most once.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;

use access_kernel::digest::Hash;

/// Largest input file the verifier reads.
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// A usage or I/O problem: the inputs could not be read, so nothing was verified.
#[derive(Debug)]
pub(crate) struct Usage(pub(crate) String);

impl Usage {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The options of one subcommand.
pub(crate) struct Options {
    values: BTreeMap<String, String>,
}

impl Options {
    /// Parses `--name value` pairs and rejects any name not in `allowed`.
    pub(crate) fn parse(args: &[String], allowed: &[&str]) -> Result<Self, Usage> {
        let mut values = BTreeMap::new();
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            let name = arg
                .strip_prefix("--")
                .filter(|n| allowed.contains(n))
                .ok_or_else(|| Usage::new(format!("unknown option {arg}")))?;
            let value = rest
                .next()
                .ok_or_else(|| Usage::new(format!("--{name} needs a value")))?;
            if values.insert(name.to_owned(), value.clone()).is_some() {
                return Err(Usage::new(format!("--{name} given twice")));
            }
        }
        Ok(Self { values })
    }

    /// Whether `name` was given.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// The text value of `name`, if given.
    pub(crate) fn opt(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The text value of a required option.
    pub(crate) fn text(&self, name: &str) -> Result<&str, Usage> {
        self.opt(name)
            .ok_or_else(|| Usage::new(format!("--{name} is required")))
    }

    /// A required unsigned integer.
    pub(crate) fn uint(&self, name: &str) -> Result<u64, Usage> {
        parse_uint(name, self.text(name)?)
    }

    /// An optional unsigned integer.
    pub(crate) fn opt_uint(&self, name: &str) -> Result<Option<u64>, Usage> {
        self.opt(name).map(|v| parse_uint(name, v)).transpose()
    }

    /// A required `true` or `false`.
    pub(crate) fn boolean(&self, name: &str) -> Result<bool, Usage> {
        match self.text(name)? {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(Usage::new(format!(
                "--{name}: {other} is not true or false"
            ))),
        }
    }

    /// The bytes of the file a required option names.
    pub(crate) fn file(&self, name: &str) -> Result<Vec<u8>, Usage> {
        read_file(name, self.text(name)?)
    }

    /// The text of the file a required option names, without surrounding whitespace.
    pub(crate) fn text_file(&self, name: &str) -> Result<String, Usage> {
        let bytes = self.file(name)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| Usage::new(format!("--{name}: the file is not UTF-8")))?;
        Ok(text.trim().to_owned())
    }

    /// A required 32-byte hash in hex.
    pub(crate) fn hash(&self, name: &str) -> Result<Hash, Usage> {
        parse_hash(name, self.text(name)?)
    }

    /// A required list of 32-byte hashes in hex, separated by commas; empty text is no hash.
    pub(crate) fn hashes(&self, name: &str) -> Result<Vec<Hash>, Usage> {
        let text = self.text(name)?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        text.split(',').map(|h| parse_hash(name, h)).collect()
    }

    /// An optional list of words separated by commas; absent or empty text is no word.
    pub(crate) fn words(&self, name: &str) -> Vec<String> {
        self.opt(name)
            .filter(|t| !t.is_empty())
            .map(|t| t.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    }
}

fn parse_uint(name: &str, text: &str) -> Result<u64, Usage> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Usage::new(format!(
            "--{name}: {text} is not an unsigned integer"
        )));
    }
    text.parse()
        .map_err(|_| Usage::new(format!("--{name}: {text} does not fit 64 bits")))
}

fn parse_hash(name: &str, text: &str) -> Result<Hash, Usage> {
    unhex(text)
        .and_then(|b| Hash::try_from(b.as_slice()).ok())
        .ok_or_else(|| Usage::new(format!("--{name}: {text} is not 32 bytes of lowercase hex")))
}

fn read_file(name: &str, path: &str) -> Result<Vec<u8>, Usage> {
    let file = File::open(path).map_err(|e| Usage::new(format!("--{name} {path}: {e}")))?;
    let mut out = Vec::new();
    file.take(MAX_FILE.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| Usage::new(format!("--{name} {path}: {e}")))?;
    if u64::try_from(out.len()).map_or(true, |n| n > MAX_FILE) {
        return Err(Usage::new(format!(
            "--{name} {path}: larger than {MAX_FILE} bytes"
        )));
    }
    Ok(out)
}

/// Lowercase hex to bytes.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[hi, lo]| Some(digit(*hi)?.wrapping_shl(4) | digit(*lo)?))
        .collect()
}

/// Bytes to lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(d));
            }
        }
    }
    out
}
