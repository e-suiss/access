//! Where a production signer may run (CR-39 m.6, OP-150 (o)): the data memory-dependent
//! prefetcher of Apple Silicon breaks constant-time code (`GoFetch`), so a signer process built for
//! an `aarch64-apple-*` target refuses to start, and so does one built for aarch64 Linux that
//! finds an Apple CPU at start (OP-159 m.3 (s)). Tests build the signer crates in-process and
//! never reach this check; local work runs the Linux image.

/// The target a binary was built for, as far as the refusal needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// `target_arch = "aarch64"`.
    pub aarch64: bool,
    /// `target_vendor = "apple"`.
    pub apple: bool,
}

impl Target {
    /// The target this crate was built for.
    pub const BUILT: Self = Self {
        aarch64: cfg!(target_arch = "aarch64"),
        apple: cfg!(target_vendor = "apple"),
    };
}

/// A signer built for a host it must not run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a production signer does not run on aarch64-apple (CR-39 m.6)")]
pub struct UnsafeHost;

impl UnsafeHost {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "signer-host"
    }
}

/// Whether a signer built for `target` may start; for [`Target::BUILT`] the CPU it runs on is
/// read too.
///
/// # Errors
/// [`UnsafeHost`] on `aarch64-apple-*`, or on aarch64 hardware whose CPU is Apple's or cannot be
/// read.
pub fn signer_host(target: Target) -> Result<(), UnsafeHost> {
    let apple_cpu = target == Target::BUILT && crate::dit::apple_silicon();
    if target.aarch64 && (target.apple || apple_cpu) {
        Err(UnsafeHost)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-39, OP-150
    #[test]
    fn the_signer_refuses_apple_silicon() {
        let refused = Target {
            aarch64: true,
            apple: true,
        };
        assert_eq!(signer_host(refused), Err(UnsafeHost));
        for (aarch64, apple) in [(true, false), (false, true), (false, false)] {
            assert_eq!(signer_host(Target { aarch64, apple }), Ok(()));
        }
        assert_eq!(
            Target::BUILT.aarch64 && Target::BUILT.apple,
            signer_host(Target::BUILT).is_err()
        );
    }
}
