//! What forward-auth reads of the head (OP-156 m.3 (l), IDP-30): the live Grants a Party holds
//! that cover a proxy's action, each with the basis an eligibility check names and the end of
//! its validity, the decision's horizon. A read: the eligibility check decides.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id};

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live Grants `party` holds now whose actions cover `action`, each with its basis and
    /// the end of its validity, ms; a Grant already past its validity is left out.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn proxy_bases(
        &self,
        party: &Id,
        action: &ActionRef,
        now: u64,
    ) -> Result<Vec<(ExerciseBasis, u64)>, CoreError> {
        Ok(self
            .covering(party, action, now)
            .await?
            .into_iter()
            .map(|(basis, a)| (basis, a.constraints.validity.until))
            .filter(|(_, until)| *until > now)
            .collect())
    }
}
