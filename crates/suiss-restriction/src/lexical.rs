//! Pre-parse lexical limits: Cedar's parser has no stack guard (OP-104 m.2).

use crate::CompileError;

/// Rejects sources whose bracket nesting or per-policy token count exceeds the limits.
/// Strings and `//` comments are skipped; a policy ends at a top-level `;`.
pub(crate) fn check(
    source: &str,
    max_nesting: usize,
    max_tokens: usize,
) -> Result<(), CompileError> {
    let bytes = source.as_bytes();
    let mut i = 0_usize;
    let mut depth = 0_usize;
    let mut tokens = 0_usize;
    let next = |i: usize| i.checked_add(1).ok_or(CompileError::TooManyTokens);
    while let Some(&b) = bytes.get(i) {
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => {
                i = next(i)?;
                continue;
            }
            b'/' if bytes.get(next(i)?) == Some(&b'/') => {
                while bytes.get(i).is_some_and(|c| *c != b'\n') {
                    i = next(i)?;
                }
                continue;
            }
            b'"' => {
                i = next(i)?;
                while let Some(&c) = bytes.get(i) {
                    i = next(i)?;
                    match c {
                        b'\\' => i = next(i)?,
                        b'"' => break,
                        _ => {}
                    }
                }
            }
            b'(' | b'[' | b'{' => {
                depth = depth.checked_add(1).ok_or(CompileError::NestingTooDeep)?;
                if depth > max_nesting {
                    return Err(CompileError::NestingTooDeep);
                }
                i = next(i)?;
            }
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or(CompileError::Parse)?;
                i = next(i)?;
            }
            b';' if depth == 0 => {
                tokens = 0;
                i = next(i)?;
                continue;
            }
            c if c.is_ascii_alphanumeric() || c == b'_' => {
                while bytes
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    i = next(i)?;
                }
            }
            _ => i = next(i)?,
        }
        tokens = tokens.checked_add(1).ok_or(CompileError::TooManyTokens)?;
        if tokens > max_tokens {
            return Err(CompileError::TooManyTokens);
        }
    }
    Ok(())
}
