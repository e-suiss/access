//! Structural pre-check for JSON handed to a general-purpose parser (CR-10 m.3, m.5): size and
//! nesting depth are checked over the raw bytes before any recursion happens.

/// Ceiling for JSON nesting depth (CR-10 m.3).
pub const MAX_DEPTH: usize = 32;

/// Why JSON input is rejected before parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonLimitError {
    /// The input is larger than the caller's limit.
    #[error("input too large")]
    Size,
    /// Nesting is deeper than the limit.
    #[error("nesting too deep")]
    Depth,
    /// Brackets do not balance, or a string is not closed.
    #[error("unbalanced structure")]
    Unbalanced,
}

impl JsonLimitError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Size => "json-input-too-large",
            Self::Depth => "json-depth",
            Self::Unbalanced => "json-unbalanced",
        }
    }
}

/// Checks that `input` is at most `max_len` bytes and nests at most `max_depth` (capped at
/// [`MAX_DEPTH`]) levels of arrays and objects. Brackets inside strings do not count.
///
/// # Errors
/// [`JsonLimitError`].
pub fn check(input: &[u8], max_len: usize, max_depth: usize) -> Result<(), JsonLimitError> {
    if input.len() > max_len {
        return Err(JsonLimitError::Size);
    }
    let limit = max_depth.min(MAX_DEPTH);
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in input {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth = depth.checked_add(1).ok_or(JsonLimitError::Depth)?;
                if depth > limit {
                    return Err(JsonLimitError::Depth);
                }
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or(JsonLimitError::Unbalanced)?;
            }
            _ => {}
        }
    }
    if depth == 0 && !in_string {
        Ok(())
    } else {
        Err(JsonLimitError::Unbalanced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-10
    #[test]
    fn depth_and_size_are_checked_before_parsing() {
        assert_eq!(check(br#"{"a":[1,{"b":"]]]"}]}"#, 64, 3), Ok(()));
        assert_eq!(check(b"[[[[]]]]", 64, 3), Err(JsonLimitError::Depth));
        assert_eq!(check(b"[[[]]]", 4, 32), Err(JsonLimitError::Size));
        assert_eq!(check(b"[]]", 64, 32), Err(JsonLimitError::Unbalanced));
        assert_eq!(
            check(br#"{"a":"\"}"#, 64, 32),
            Err(JsonLimitError::Unbalanced)
        );
        let deep = "[".repeat(33) + &"]".repeat(33);
        assert_eq!(
            check(deep.as_bytes(), 1024, usize::MAX),
            Err(JsonLimitError::Depth)
        );
    }
}
