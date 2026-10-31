//! Fresh random bytes from the operating system's source (OP-106 m.15, OP-141 m.18 (a), (e)).

use aws_lc_rs::rand;

/// No randomness was available; the caller produces nothing.
#[derive(Debug, thiserror::Error)]
#[error("no randomness available")]
pub struct RandomError;

/// `N` fresh random bytes.
///
/// # Errors
/// [`RandomError`].
pub fn bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0; N];
    rand::fill(&mut out).map_err(|_| RandomError)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_differ() {
        let (a, b) = (bytes::<32>(), bytes::<32>());
        assert!(matches!((a, b), (Ok(a), Ok(b)) if a != b));
    }
}
