//! What the domain needs from the outside world (OP-63): the authority plane, reached only
//! through `internal-api` messages (OP-62).

use std::future::Future;

use access_internal_api::idp::{GenesisOpened, GenesisOrder, Submission, Unavailable, Verdict};

/// Decides `idp.*` Exercises: the identity plane is their PEP (MD-14, E34).
pub trait Decider: Send + Sync {
    /// Commits `submission` in its domain and returns the decision.
    fn decide(
        &self,
        submission: Submission,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;
}

/// Opens the governing domain of a new realm (TN-111).
pub trait Governance: Send + Sync {
    /// Writes the Genesis of a new domain.
    fn open(
        &self,
        order: GenesisOrder,
    ) -> impl Future<Output = Result<GenesisOpened, Unavailable>> + Send;
}
