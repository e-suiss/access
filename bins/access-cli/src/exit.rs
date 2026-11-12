//! Exit codes, stable for scripts and Kubernetes Jobs: 0 is success, 2 a usage error (as clap
//! reports it); the others say which step failed.

use std::process::ExitCode;

/// An exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Code(pub(crate) u8);

impl From<Code> for ExitCode {
    fn from(c: Code) -> Self {
        Self::from(c.0)
    }
}

/// Success.
pub(crate) const OK: Code = Code(0);

/// The command line is not valid.
pub(crate) const USAGE: Code = Code(2);

/// The configuration or a file it names cannot be used.
pub(crate) const CONFIG: Code = Code(3);

/// The database cannot be reached, or is not safe to use (OP-52).
pub(crate) const DATABASE: Code = Code(4);

/// The command ran and failed; nothing after the failure was applied.
pub(crate) const FAILED: Code = Code(5);

/// The management API refused or did not answer (an RFC 9457 problem on standard error).
pub(crate) const REMOTE: Code = Code(6);

/// `diff`: the desired and the runtime state differ; `replay`: the decision did not match;
/// `realm check`: a setting does not meet the profile.
pub(crate) const DIFFERS: Code = Code(7);
