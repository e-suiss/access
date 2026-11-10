//! The SCIM filter subset of the management API (RFC 7644 §3.4.2.2; TN-112, §12.5.1 k.5):
//! attribute comparisons `eq`, `ne`, `co`, `sw`, presence `pr`, `and`, `or` and parentheses.
//! Every attribute must be one the endpoint names; an unknown one is an error, never ignored,
//! since ignoring it would widen the result to every row. Size, depth and term count are bounded
//! before any recursion (CR-10, OP-8).

pub mod protocol;

/// Longest accepted filter, in bytes.
pub const MAX_LEN: usize = 1024;

/// Deepest accepted nesting of parentheses and operators.
pub const MAX_DEPTH: usize = 8;

/// Most comparisons in one filter.
pub const MAX_TERMS: usize = 16;

/// Longest accepted string value, in bytes.
pub const MAX_VALUE: usize = 256;

/// Why a filter is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FilterError {
    /// Not in the subset's grammar.
    #[error("filter syntax")]
    Syntax,
    /// An attribute the endpoint does not filter on.
    #[error("unknown filter attribute")]
    UnknownAttribute,
    /// Longer, deeper or with more terms than the limits.
    #[error("filter too complex")]
    TooComplex,
}

impl FilterError {
    /// Stable code for problem details (RFC 9457, OP-65).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Syntax => "invalid-filter",
            Self::UnknownAttribute => "unknown-filter-attribute",
            Self::TooComplex => "filter-too-complex",
        }
    }
}

/// A comparison operator of the subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Contains.
    Co,
    /// Starts with.
    Sw,
}

/// A comparison value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A JSON string, unescaped.
    Text(String),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// A JSON integer, as written.
    Number(String),
}

/// A parsed filter. Attributes are the endpoint's own spelling of the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// `attr op value`.
    Compare {
        /// The attribute.
        attr: &'static str,
        /// The operator.
        op: Op,
        /// The value.
        value: Value,
    },
    /// `attr pr`.
    Present(&'static str),
    /// Both hold.
    And(Box<Filter>, Box<Filter>),
    /// Either holds.
    Or(Box<Filter>, Box<Filter>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    Word(String),
    Text(String),
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$' | b':')
}

fn string(bytes: &[u8], at: &mut usize) -> Result<String, FilterError> {
    let mut out = Vec::new();
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
                match e {
                    b'"' | b'\\' | b'/' => out.push(e),
                    _ => return Err(FilterError::Syntax),
                }
            }
            0x00..=0x1f => return Err(FilterError::Syntax),
            _ => out.push(b),
        }
        if out.len() > MAX_VALUE {
            return Err(FilterError::TooComplex);
        }
    }
    String::from_utf8(out).map_err(|_| FilterError::Syntax)
}

fn tokens(input: &str) -> Result<Vec<Token>, FilterError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut at = 0_usize;
    while let Some(&b) = bytes.get(at) {
        match b {
            b' ' => at = at.saturating_add(1),
            b'(' => {
                out.push(Token::Open);
                at = at.saturating_add(1);
            }
            b')' => {
                out.push(Token::Close);
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

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    attributes: &'a [&'static str],
    terms: usize,
}

impl Parser<'_> {
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

    fn or(&mut self, depth: usize) -> Result<Filter, FilterError> {
        if depth > MAX_DEPTH {
            return Err(FilterError::TooComplex);
        }
        let mut left = self.and(depth.saturating_add(1))?;
        while self.keyword("or") {
            self.at = self.at.saturating_add(1);
            let right = self.and(depth.saturating_add(1))?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize) -> Result<Filter, FilterError> {
        if depth > MAX_DEPTH {
            return Err(FilterError::TooComplex);
        }
        let mut left = self.unary(depth.saturating_add(1))?;
        while self.keyword("and") {
            self.at = self.at.saturating_add(1);
            let right = self.unary(depth.saturating_add(1))?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn attribute(&self, name: &str) -> Result<&'static str, FilterError> {
        let shaped = name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'));
        if !shaped {
            return Err(FilterError::Syntax);
        }
        self.attributes
            .iter()
            .find(|a| a.eq_ignore_ascii_case(name))
            .copied()
            .ok_or(FilterError::UnknownAttribute)
    }

    fn unary(&mut self, depth: usize) -> Result<Filter, FilterError> {
        if depth > MAX_DEPTH {
            return Err(FilterError::TooComplex);
        }
        match self.next() {
            Some(Token::Open) => {
                let inner = self.or(depth.saturating_add(1))?;
                match self.next() {
                    Some(Token::Close) => Ok(inner),
                    _ => Err(FilterError::Syntax),
                }
            }
            Some(Token::Word(name)) => {
                if ["and", "or", "not"]
                    .iter()
                    .any(|k| name.eq_ignore_ascii_case(k))
                {
                    return Err(FilterError::Syntax);
                }
                self.terms = self.terms.saturating_add(1);
                if self.terms > MAX_TERMS {
                    return Err(FilterError::TooComplex);
                }
                let Some(Token::Word(op)) = self.next() else {
                    return Err(FilterError::Syntax);
                };
                let attr = self.attribute(&name)?;
                let op = match op.to_ascii_lowercase().as_str() {
                    "pr" => return Ok(Filter::Present(attr)),
                    "eq" => Op::Eq,
                    "ne" => Op::Ne,
                    "co" => Op::Co,
                    "sw" => Op::Sw,
                    _ => return Err(FilterError::Syntax),
                };
                let value = match self.next() {
                    Some(Token::Text(t)) => Value::Text(t),
                    Some(Token::Word(w)) => literal(&w)?,
                    _ => return Err(FilterError::Syntax),
                };
                if matches!(op, Op::Co | Op::Sw) && !matches!(value, Value::Text(_)) {
                    return Err(FilterError::Syntax);
                }
                Ok(Filter::Compare { attr, op, value })
            }
            _ => Err(FilterError::Syntax),
        }
    }
}

fn literal(w: &str) -> Result<Value, FilterError> {
    match w {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "null" => Ok(Value::Null),
        _ => {
            let digits = w.strip_prefix('-').unwrap_or(w);
            let number = !digits.is_empty()
                && digits.len() <= 19
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'));
            if number {
                Ok(Value::Number(w.to_owned()))
            } else {
                Err(FilterError::Syntax)
            }
        }
    }
}

/// Parses `input` against the endpoint's filterable `attributes` (matched without regard to
/// ASCII case, as SCIM names are).
///
/// # Errors
/// [`FilterError`]: syntax outside the subset, an attribute not in `attributes`, or a filter
/// over the limits.
pub fn parse(input: &str, attributes: &[&'static str]) -> Result<Filter, FilterError> {
    if input.len() > MAX_LEN {
        return Err(FilterError::TooComplex);
    }
    let mut p = Parser {
        tokens: tokens(input)?,
        at: 0,
        attributes,
        terms: 0,
    };
    let filter = p.or(0)?;
    if p.at != p.tokens.len() {
        return Err(FilterError::Syntax);
    }
    Ok(filter)
}

#[cfg(test)]
mod tests;
