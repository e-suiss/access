//! Support artifacts (§8.16 #12, TN-74, INV-30, OP-157 m.3 (g)): a person's HAR, JSON or text log
//! for a support case is redacted on upload and only the redacted text is kept, sealed under its
//! own DEK. An image or a video is refused: no automatic redaction is declared for them, so they
//! are never taken (UNDER DECLARED CAPABILITY, fail-closed).
//!
//! Redacted on upload, whatever the format:
//! - the values of the `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization`
//!   headers;
//! - the values named `access_token`, `refresh_token`, `id_token`, `code`, `client_secret`,
//!   `password`, `assertion` and `client_assertion`, in JSON members, HAR name/value pairs,
//!   query strings and form bodies;
//! - every cookie value in a HAR, and every `__Host-` and `__Secure-` cookie value anywhere;
//! - anything shaped like a JWT or JWS compact serialization.
//!
//! Each becomes `[redacted]`.

use serde_json::Value;

/// The text a redacted value becomes.
pub const REDACTED: &str = "[redacted]";

/// Deepest JSON nesting an artifact may have.
const MAX_DEPTH: usize = 64;

/// The header names whose values are always redacted.
const HEADERS: [&str; 4] = [
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
];

/// The parameter and member names whose values are always redacted.
const SECRETS: [&str; 8] = [
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "client_secret",
    "password",
    "assertion",
    "client_assertion",
];

/// What an upload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// An HTTP Archive.
    Har,
    /// A JSON document.
    Json,
    /// A plain text log.
    Log,
}

impl Format {
    /// Its stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Har => "har",
            Self::Json => "json",
            Self::Log => "log",
        }
    }

    /// The media type an artifact of this format is read back as.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Har | Self::Json => "application/json",
            Self::Log => "text/plain",
        }
    }

    /// The format named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Har, Self::Json, Self::Log]
            .into_iter()
            .find(|f| f.name() == s)
    }
}

/// Why an upload is not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// Not a text format Access can redact: `415 artifact-format-refused`.
    #[error("artifact-format-refused")]
    Format,
    /// The text is not what its format says, or nests too deep.
    #[error("artifact-malformed")]
    Malformed,
}

/// The format of an upload of media type `media`: HAR, JSON or a text log; anything else, and
/// every image or video, is refused (OP-157 m.3 (g)).
///
/// # Errors
/// [`Refused::Format`].
pub fn format_of(media: &str) -> Result<Format, Refused> {
    let essence = media
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "application/har+json" | "application/x-har" => Ok(Format::Har),
        "application/json" => Ok(Format::Json),
        "text/plain" => Ok(Format::Log),
        _ => Err(Refused::Format),
    }
}

/// An upload after redaction: the only text that is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redacted {
    /// The redacted text.
    pub text: String,
    /// How many values were redacted.
    pub count: u32,
}

/// Redacts `text` of `format` (§8.16 #12, TN-74).
///
/// # Errors
/// [`Refused::Malformed`] when a HAR or JSON upload is not JSON, or nests deeper than allowed.
pub fn redact(format: Format, text: &str) -> Result<Redacted, Refused> {
    let mut count = 0_u32;
    let text = match format {
        Format::Har | Format::Json => {
            let mut v: Value = serde_json::from_str(text).map_err(|_| Refused::Malformed)?;
            json(&mut v, format == Format::Har, 0, &mut count)?;
            serde_json::to_string(&v).map_err(|_| Refused::Malformed)?
        }
        Format::Log => text
            .split_inclusive('\n')
            .map(|line| log_line(line, &mut count))
            .collect(),
    };
    Ok(Redacted { text, count })
}

fn bump(count: &mut u32) {
    *count = count.saturating_add(1);
}

fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SECRETS.contains(&n.as_str()) || HEADERS.contains(&n.as_str())
}

fn secret_cookie(name: &str) -> bool {
    name.starts_with("__Host-") || name.starts_with("__Secure-")
}

fn set(v: &mut Value, count: &mut u32) {
    if !matches!(v, Value::String(s) if s == REDACTED) {
        *v = Value::String(String::from(REDACTED));
        bump(count);
    }
}

fn json(v: &mut Value, har: bool, depth: usize, count: &mut u32) -> Result<(), Refused> {
    if depth > MAX_DEPTH {
        return Err(Refused::Malformed);
    }
    match v {
        Value::Object(m) => {
            let pair_name = m.get("name").and_then(Value::as_str).map(str::to_owned);
            for (k, child) in m.iter_mut() {
                if secret_name(k) {
                    set(child, count);
                    continue;
                }
                json(child, har, depth.saturating_add(1), count)?;
            }
            if let Some(name) = pair_name
                && let Some(value) = m.get_mut("value")
                && (secret_name(&name) || secret_cookie(&name))
            {
                set(value, count);
            }
            if har {
                for key in ["cookies"] {
                    if let Some(Value::Array(items)) = m.get_mut(key) {
                        for item in items {
                            if let Some(value) = item.get_mut("value") {
                                set(value, count);
                            }
                        }
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                json(item, har, depth.saturating_add(1), count)?;
            }
        }
        Value::String(s) => {
            let clean = scrub(s, count);
            if clean != *s {
                *s = clean;
            }
        }
        _ => {}
    }
    Ok(())
}

fn log_line(line: &str, count: &mut u32) -> String {
    let body = line.trim_end_matches(['\n', '\r']);
    let ending = line.get(body.len()..).unwrap_or_default();
    let trimmed = body.trim_start();
    let indent = body
        .get(..body.len().saturating_sub(trimmed.len()))
        .unwrap_or_default();
    if let Some((name, value)) = trimmed.split_once(':')
        && HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())
    {
        if value.trim() != REDACTED {
            bump(count);
        }
        return format!("{indent}{}: {REDACTED}{ending}", name.trim());
    }
    let mut out = scrub(body, count);
    out.push_str(ending);
    out
}

fn jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// The length of a JWT or JWS compact serialization at the start of `s`, if one is there.
fn jwt_at(s: &str) -> Option<usize> {
    if !s.starts_with("eyJ") {
        return None;
    }
    let mut parts = 0_u32;
    let mut len = 0_usize;
    let mut run = 0_usize;
    for c in s.chars() {
        if jwt_char(c) {
            run = run.saturating_add(1);
        } else if c == '.' && run > 0 && parts < 4 {
            parts = parts.saturating_add(1);
            run = 0;
        } else {
            break;
        }
        len = len.saturating_add(c.len_utf8());
    }
    (parts >= 2 && run > 0).then_some(len)
}

/// The length of the value that follows a secret name at `i` of `s`: `name=value`,
/// `name: value` or `"name":"value"`; `None` when no secret name starts there.
fn secret_value_at(s: &str, i: usize) -> Option<(usize, usize)> {
    let rest = s.get(i..)?;
    let before = s.get(..i).and_then(|b| b.chars().next_back());
    if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    let lower = rest.to_ascii_lowercase();
    let names = SECRETS.iter().chain(HEADERS.iter());
    let name = names
        .filter(|n| lower.starts_with(**n))
        .max_by_key(|n| n.len())?;
    let mut j = name.len();
    let after = rest.get(j..)?;
    let quoted_name = after.starts_with('"');
    if quoted_name {
        j = j.saturating_add(1);
    }
    let after = rest.get(j..)?;
    let skip = after.len().saturating_sub(after.trim_start().len());
    j = j.saturating_add(skip);
    let sep = rest.get(j..)?.chars().next()?;
    if sep != '=' && sep != ':' {
        return None;
    }
    j = j.saturating_add(1);
    let after = rest.get(j..)?;
    let skip = after.len().saturating_sub(after.trim_start().len());
    j = j.saturating_add(skip);
    let value = rest.get(j..)?;
    let (start, len) = if let Some(v) = value.strip_prefix('"') {
        (j.saturating_add(1), v.find('"').unwrap_or(v.len()))
    } else {
        let end = value
            .find(|c: char| c == '&' || c == ';' || c == ',' || c.is_whitespace())
            .unwrap_or(value.len());
        (j, end)
    };
    (len > 0).then_some((i.saturating_add(start), len))
}

/// The length of a `__Host-` or `__Secure-` cookie value at `i` of `s`.
fn cookie_value_at(s: &str, i: usize) -> Option<(usize, usize)> {
    let rest = s.get(i..)?;
    if !(rest.starts_with("__Host-") || rest.starts_with("__Secure-")) {
        return None;
    }
    let eq = rest.find('=')?;
    let name = rest.get(..eq)?;
    if name.contains(|c: char| c.is_whitespace() || c == ';' || c == ',') {
        return None;
    }
    let value = rest.get(eq.saturating_add(1)..)?;
    let len = value
        .find(|c: char| c == ';' || c == ',' || c == '"' || c.is_whitespace())
        .unwrap_or(value.len());
    (len > 0).then_some((i.saturating_add(eq).saturating_add(1), len))
}

/// `s` with every JWT, secret parameter value and secure cookie value replaced.
fn scrub(s: &str, count: &mut u32) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0_usize;
    while i < s.len() {
        let Some(rest) = s.get(i..) else { break };
        if let Some(len) = jwt_at(rest) {
            out.push_str(REDACTED);
            bump(count);
            i = i.saturating_add(len);
            continue;
        }
        if let Some((start, len)) = secret_value_at(s, i).or_else(|| cookie_value_at(s, i)) {
            out.push_str(s.get(i..start).unwrap_or_default());
            if s.get(start..start.saturating_add(len)) != Some(REDACTED) {
                bump(count);
            }
            out.push_str(REDACTED);
            i = start.saturating_add(len);
            continue;
        }
        let Some(c) = rest.chars().next() else { break };
        out.push(c);
        i = i.saturating_add(c.len_utf8());
    }
    out
}

#[cfg(test)]
mod tests;
