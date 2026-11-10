//! The full SCIM 2.0 filter and PATCH path grammar of the SCIM server (RFC 7644 §3.4.2.2,
//! §3.5.2; errata 4670, 4690, 7319, 7322; IDP-23, OP-155 m.3 (g)): every comparison operator,
//! `pr`, `not`, `and` binding tighter than `or`, value paths with a filter inside brackets and
//! attribute paths with an optional schema URN and one sub-attribute. The grammar knows no
//! schema; the server resolves each path against its own. Length, depth, term count and value
//! size are bounded before any recursion (CR-10, OP-8).

use super::{FilterError, Value};

/// Longest accepted filter or path, in bytes (OP-155 m.3 (g)).
pub const MAX_LEN: usize = 4096;

/// Deepest accepted nesting of parentheses, `not` groups and brackets (OP-155 m.3 (g)).
pub const MAX_DEPTH: usize = 32;

/// Most comparisons in one filter.
pub const MAX_TERMS: usize = 256;

/// Longest accepted string value, in bytes.
pub const MAX_VALUE: usize = 2048;

/// A comparison operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Contains.
    Co,
    /// Starts with.
    Sw,
    /// Ends with.
    Ew,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
}

impl CompareOp {
    fn of(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "eq" => Self::Eq,
            "ne" => Self::Ne,
            "co" => Self::Co,
            "sw" => Self::Sw,
            "ew" => Self::Ew,
            "gt" => Self::Gt,
            "ge" => Self::Ge,
            "lt" => Self::Lt,
            "le" => Self::Le,
            _ => return None,
        })
    }

    /// Whether the operator matches substrings, which the server serves only on indexed
    /// attributes.
    #[must_use]
    pub const fn substring(self) -> bool {
        matches!(self, Self::Co | Self::Sw | Self::Ew)
    }
}

/// An attribute path: `[urn ":"] name ["." sub]`, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrPath {
    /// The schema URN, when the path names one.
    pub urn: Option<String>,
    /// The attribute.
    pub name: String,
    /// The sub-attribute.
    pub sub: Option<String>,
}

/// A filter expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// `path pr`.
    Present(AttrPath),
    /// `path op value`.
    Compare {
        /// The attribute.
        path: AttrPath,
        /// The operator.
        op: CompareOp,
        /// The value.
        value: Value,
    },
    /// `not ( filter )`.
    Not(Box<Expr>),
    /// Both hold.
    And(Box<Expr>, Box<Expr>),
    /// Either holds.
    Or(Box<Expr>, Box<Expr>),
    /// `path [ filter ]`: some value of the multi-valued `path` matches `filter`, whose paths
    /// name its sub-attributes.
    ValuePath {
        /// The multi-valued attribute.
        path: AttrPath,
        /// The filter over one of its values.
        filter: Box<Expr>,
    },
}

/// A PATCH operation's `path` (RFC 7644 §3.5.2): an attribute path, or a value path with an
/// optional sub-attribute after the bracket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchPath {
    /// `attrPath`.
    Attr(AttrPath),
    /// `attrPath "[" valFilter "]" ["." subAttr]`.
    Value {
        /// The multi-valued attribute.
        path: AttrPath,
        /// The filter selecting its values.
        filter: Expr,
        /// The sub-attribute of the selected values.
        sub: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    LBracket,
    RBracket,
    Word(String),
    Text(String),
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$' | b':' | b'+')
}

fn hex4(bytes: &[u8], at: &mut usize) -> Result<u32, FilterError> {
    let mut v = 0_u32;
    for _ in 0..4 {
        let b = *bytes.get(*at).ok_or(FilterError::Syntax)?;
        *at = at.saturating_add(1);
        let d = char::from(b).to_digit(16).ok_or(FilterError::Syntax)?;
        v = v.checked_mul(16).ok_or(FilterError::Syntax)?;
        v = v.checked_add(d).ok_or(FilterError::Syntax)?;
    }
    Ok(v)
}

fn string(bytes: &[u8], at: &mut usize) -> Result<String, FilterError> {
    let mut out = String::new();
    let mut raw = Vec::new();
    loop {
        let Some(&b) = bytes.get(*at) else {
            return Err(FilterError::Syntax);
        };
        *at = at.saturating_add(1);
        match b {
            b'"' => break,
            b'\\' => {
                let Some(&e) = bytes.get(*at) else {
                    return Err(FilterError::Syntax);
                };
                *at = at.saturating_add(1);
                let c = match e {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => char::from_u32(hex4(bytes, at)?).ok_or(FilterError::Syntax)?,
                    _ => return Err(FilterError::Syntax),
                };
                flush(&mut raw, &mut out)?;
                out.push(c);
            }
            0x00..=0x1f => return Err(FilterError::Syntax),
            _ => raw.push(b),
        }
        if out.len().saturating_add(raw.len()) > MAX_VALUE {
            return Err(FilterError::TooComplex);
        }
    }
    flush(&mut raw, &mut out)?;
    Ok(out)
}

fn flush(raw: &mut Vec<u8>, out: &mut String) -> Result<(), FilterError> {
    if raw.is_empty() {
        return Ok(());
    }
    let s = core::str::from_utf8(raw).map_err(|_| FilterError::Syntax)?;
    out.push_str(s);
    raw.clear();
    Ok(())
}

fn tokens(input: &str) -> Result<Vec<Token>, FilterError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut at = 0_usize;
    while let Some(&b) = bytes.get(at) {
        match b {
            b' ' => at = at.saturating_add(1),
            b'(' | b')' | b'[' | b']' => {
                out.push(match b {
                    b'(' => Token::Open,
                    b')' => Token::Close,
                    b'[' => Token::LBracket,
                    _ => Token::RBracket,
                });
                at = at.saturating_add(1);
            }
            b'"' => {
                at = at.saturating_add(1);
                out.push(Token::Text(string(bytes, &mut at)?));
            }
            b if word_byte(b) => {
                let start = at;
                while bytes.get(at).copied().is_some_and(word_byte) {
                    at = at.saturating_add(1);
                }
                let word = input.get(start..at).ok_or(FilterError::Syntax)?;
                out.push(Token::Word(word.to_owned()));
            }
            _ => return Err(FilterError::Syntax),
        }
    }
    Ok(out)
}

fn attr_name(s: &str) -> bool {
    s.len() <= 128
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'$'))
}

/// Parses an attribute path as written.
///
/// # Errors
/// [`FilterError::Syntax`].
pub fn attr_path(word: &str) -> Result<AttrPath, FilterError> {
    let (urn, rest) = match word.rfind(':') {
        Some(i) => {
            let urn = word.get(..i).ok_or(FilterError::Syntax)?;
            let lower = urn.to_ascii_lowercase();
            if !lower.starts_with("urn:") || urn.len() > 512 {
                return Err(FilterError::Syntax);
            }
            (
                Some(urn.to_owned()),
                word.get(i.saturating_add(1)..).ok_or(FilterError::Syntax)?,
            )
        }
        None => (None, word),
    };
    let (name, sub) = match rest.split_once('.') {
        Some((n, s)) => (n, Some(s)),
        None => (rest, None),
    };
    if !attr_name(name) || sub.is_some_and(|s| !attr_name(s)) {
        return Err(FilterError::Syntax);
    }
    Ok(AttrPath {
        urn,
        name: name.to_owned(),
        sub: sub.map(str::to_owned),
    })
}

fn literal(w: &str) -> Result<Value, FilterError> {
    match w.to_ascii_lowercase().as_str() {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "null" => return Ok(Value::Null),
        _ => {}
    }
    if number(w) {
        Ok(Value::Number(w.to_owned()))
    } else {
        Err(FilterError::Syntax)
    }
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn number(w: &str) -> bool {
    if w.len() > 64 {
        return false;
    }
    let w = w.strip_prefix('-').unwrap_or(w);
    let (mantissa, exp) = match w.find(['e', 'E']) {
        Some(i) => (w.get(..i).unwrap_or(""), w.get(i.saturating_add(1)..)),
        None => (w, None),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mantissa, None),
    };
    let int_ok = digits(int) && (int == "0" || !int.starts_with('0'));
    let frac_ok = frac.is_none_or(digits);
    let exp_ok = exp.is_none_or(|e| digits(e.strip_prefix(['+', '-']).unwrap_or(e)));
    int_ok && frac_ok && exp_ok
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    terms: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.at).cloned();
        if t.is_some() {
            self.at = self.at.saturating_add(1);
        }
        t
    }

    fn keyword(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w.eq_ignore_ascii_case(k))
    }

    fn deeper(depth: usize) -> Result<usize, FilterError> {
        let d = depth.saturating_add(1);
        if d > MAX_DEPTH {
            Err(FilterError::TooComplex)
        } else {
            Ok(d)
        }
    }

    fn or(&mut self, depth: usize, inner: bool) -> Result<Expr, FilterError> {
        let mut left = self.and(depth, inner)?;
        while self.keyword("or") {
            self.at = self.at.saturating_add(1);
            let right = self.and(depth, inner)?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize, inner: bool) -> Result<Expr, FilterError> {
        let mut left = self.unary(depth, inner)?;
        while self.keyword("and") {
            self.at = self.at.saturating_add(1);
            let right = self.unary(depth, inner)?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn group(&mut self, depth: usize, inner: bool) -> Result<Expr, FilterError> {
        let e = self.or(depth, inner)?;
        match self.next() {
            Some(Token::Close) => Ok(e),
            _ => Err(FilterError::Syntax),
        }
    }

    fn unary(&mut self, depth: usize, inner: bool) -> Result<Expr, FilterError> {
        match self.next() {
            Some(Token::Open) => self.group(Self::deeper(depth)?, inner),
            Some(Token::Word(w)) if w.eq_ignore_ascii_case("not") => match self.next() {
                Some(Token::Open) => Ok(Expr::Not(Box::new(
                    self.group(Self::deeper(depth)?, inner)?,
                ))),
                _ => Err(FilterError::Syntax),
            },
            Some(Token::Word(w)) => {
                if w.eq_ignore_ascii_case("and") || w.eq_ignore_ascii_case("or") {
                    return Err(FilterError::Syntax);
                }
                let path = attr_path(&w)?;
                if matches!(self.peek(), Some(Token::LBracket)) {
                    if inner || path.sub.is_some() {
                        return Err(FilterError::Syntax);
                    }
                    self.at = self.at.saturating_add(1);
                    let filter = self.or(Self::deeper(depth)?, true)?;
                    return match self.next() {
                        Some(Token::RBracket) => Ok(Expr::ValuePath {
                            path,
                            filter: Box::new(filter),
                        }),
                        _ => Err(FilterError::Syntax),
                    };
                }
                self.terms = self.terms.saturating_add(1);
                if self.terms > MAX_TERMS {
                    return Err(FilterError::TooComplex);
                }
                let Some(Token::Word(op)) = self.next() else {
                    return Err(FilterError::Syntax);
                };
                if op.eq_ignore_ascii_case("pr") {
                    return Ok(Expr::Present(path));
                }
                let op = CompareOp::of(&op).ok_or(FilterError::Syntax)?;
                let value = match self.next() {
                    Some(Token::Text(t)) => Value::Text(t),
                    Some(Token::Word(w)) => literal(&w)?,
                    _ => return Err(FilterError::Syntax),
                };
                if op.substring() && !matches!(value, Value::Text(_)) {
                    return Err(FilterError::Syntax);
                }
                Ok(Expr::Compare { path, op, value })
            }
            _ => Err(FilterError::Syntax),
        }
    }
}

fn parser(input: &str) -> Result<Parser, FilterError> {
    if input.len() > MAX_LEN {
        return Err(FilterError::TooComplex);
    }
    Ok(Parser {
        tokens: tokens(input)?,
        at: 0,
        terms: 0,
    })
}

/// Parses a SCIM filter.
///
/// # Errors
/// [`FilterError::Syntax`] outside the grammar; [`FilterError::TooComplex`] over a limit.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let mut p = parser(input)?;
    let e = p.or(0, false)?;
    if p.at != p.tokens.len() {
        return Err(FilterError::Syntax);
    }
    Ok(e)
}

/// Parses a PATCH operation's `path`.
///
/// # Errors
/// [`FilterError::Syntax`] outside the grammar; [`FilterError::TooComplex`] over a limit.
pub fn parse_path(input: &str) -> Result<PatchPath, FilterError> {
    let mut p = parser(input)?;
    let Some(Token::Word(w)) = p.next() else {
        return Err(FilterError::Syntax);
    };
    let path = attr_path(&w)?;
    let out = if matches!(p.peek(), Some(Token::LBracket)) {
        if path.sub.is_some() {
            return Err(FilterError::Syntax);
        }
        p.at = p.at.saturating_add(1);
        let filter = p.or(1, true)?;
        if p.next() != Some(Token::RBracket) {
            return Err(FilterError::Syntax);
        }
        let sub = match p.next() {
            None => None,
            Some(Token::Word(s)) => {
                let s = s.strip_prefix('.').ok_or(FilterError::Syntax)?;
                if !attr_name(s) {
                    return Err(FilterError::Syntax);
                }
                Some(s.to_owned())
            }
            Some(_) => return Err(FilterError::Syntax),
        };
        PatchPath::Value { path, filter, sub }
    } else {
        PatchPath::Attr(path)
    };
    if p.at != p.tokens.len() {
        return Err(FilterError::Syntax);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
