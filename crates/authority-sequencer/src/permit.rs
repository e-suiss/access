//! OP-91, INV-12, OP-159 m.3 (ee): the write permit the commit entry asks for.
//!
//! The permit has no public field and is neither `Clone`, `Copy` nor `Default`, so a commit
//! spends exactly one. It is minted only by the authority core's `app` layer
//! (`access_authority_core::app::WritePermit`); xtask `write-permit` refuses a call of
//! [`WritePermit::mint`] anywhere else and a call of the test constructor outside tests.
//!
//! A struct literal does not compile outside this crate:
//!
//! ```compile_fail
//! let _ = access_authority_sequencer::permit::WritePermit { seal: () };
//! ```
//!
//! Nor does a copy of a spent permit:
//!
//! ```compile_fail
//! fn twice(p: access_authority_sequencer::permit::WritePermit) {
//!     let _a = p.clone();
//! }
//! ```
//!
//! Nor a default one:
//!
//! ```compile_fail
//! let _: access_authority_sequencer::permit::WritePermit = Default::default();
//! ```

/// The capability to append to a domain log (OP-91); consumed by one commit.
#[must_use = "a write permit is spent by one commit"]
#[derive(Debug)]
pub struct WritePermit {
    seal: (),
}

impl WritePermit {
    /// Mints a permit. Only `access-authority-core/src/app/**` calls it (xtask `write-permit`).
    #[doc(hidden)]
    pub const fn mint() -> Self {
        Self { seal: () }
    }

    /// A permit for tests that drive the leader directly.
    #[cfg(any(test, feature = "testing"))]
    pub const fn for_tests() -> Self {
        Self::mint()
    }

    pub(crate) const fn spend(self) {
        let Self { seal: () } = self;
    }
}
