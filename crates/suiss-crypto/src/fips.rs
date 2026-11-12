//! The FIPS 140-3 build (CR-15, CR-44, HL-27, OP-159 m.3 (r)): with the `fips` feature the
//! primitives come from the validated AWS-LC FIPS module (`aws-lc-fips-sys`), the process
//! refuses to start unless the module reports FIPS mode, and the deployment publishes
//! `fips_module: true`. Any other build publishes `fips_module: false` and never claims a
//! validated module. The validated module has no ML-DSA, so a FIPS build holds no post-quantum
//! key (HL-27).

/// Whether this is the FIPS build.
pub const BUILD: bool = cfg!(feature = "fips");

/// Why the FIPS build refuses to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the AWS-LC FIPS module is not in FIPS mode")]
pub struct NotFipsMode;

impl NotFipsMode {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "fips-mode"
    }
}

/// The start-up check of the FIPS build: `aws_lc_rs::try_fips_mode()` must succeed, or the
/// process does not start (OP-159 m.3 (r)). Outside the FIPS build there is nothing to check.
///
/// # Errors
/// [`NotFipsMode`].
pub fn check() -> Result<(), NotFipsMode> {
    if BUILD {
        aws_lc_rs::try_fips_mode().map_err(|_| NotFipsMode)
    } else {
        Ok(())
    }
}

/// Whether the deployment declares a validated module: only the FIPS build whose module is in
/// FIPS mode does (`fips_module`, OP-159 m.3 (r)).
#[must_use]
pub fn module() -> bool {
    BUILD && check().is_ok()
}

#[cfg(test)]
mod tests {
    // CR-15, HL-27, OP-159 m.3 (r)
    #[test]
    fn only_the_fips_build_declares_a_validated_module() {
        assert_eq!(super::module(), super::BUILD);
        assert!(super::check().is_ok());
        if !super::BUILD {
            assert!(aws_lc_rs::try_fips_mode().is_err());
        }
    }
}
