//! What the realm's SSH certificate authority reads of the head (OP-156 m.3 (o), IDP-32): a
//! Party's live Grants that cover `ssh.login`, with the episode a `holding` basis names, and
//! whether a projection's basis still stands. Reads: they decide nothing and change nothing.

use access_authority_sequencer::ports::DomainLog;
use access_kernel::digest::Digest;
use access_kernel::meta::{self, ExerciseBasis, HoldingRef, View as _, kind};
use access_kernel::model::{ActionRef, CanonicalAuthority, Id};

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The live Grants `party` holds now whose actions cover `action`, each with the
    /// `holding` basis that names it.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn ssh_holdings(
        &self,
        party: &Id,
        action: &ActionRef,
        now: u64,
    ) -> Result<Vec<(HoldingRef, CanonicalAuthority)>, CoreError> {
        Ok(self
            .covering(party, action, now)
            .await?
            .into_iter()
            .filter_map(|(basis, authority)| match basis {
                ExerciseBasis::Holding(h) => Some((h, authority)),
                _ => None,
            })
            .collect())
    }

    /// Whether the basis of the projection that `exercise` made stands now; `None` when the
    /// head holds no such projection.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn projection_standing(&self, exercise: &Digest) -> Result<Option<bool>, CoreError> {
        let key = meta::exercise_key(kind::PROJECTION, exercise);
        let basis = self
            .settled(|snap| {
                let v = snap.get(&key)?;
                meta::exercise_basis(v.get("basis")?).ok()
            })
            .await?;
        match basis {
            None => Ok(None),
            Some(b) => self.basis_live(&b).await.map(Some),
        }
    }
}
