//! What a sync needs from outside: the directory it pulls from.

use std::future::Future;

use crate::adapters::PullError;
use crate::domain::SourceEntry;

/// A directory that answers the entries changed above a watermark.
pub trait Directory: Send + Sync {
    /// The entries whose change counter passed `watermark`.
    fn changes(
        &self,
        watermark: u64,
    ) -> impl Future<Output = Result<Vec<SourceEntry>, PullError>> + Send;
}

impl Directory for crate::adapters::Source {
    fn changes(
        &self,
        watermark: u64,
    ) -> impl Future<Output = Result<Vec<SourceEntry>, PullError>> + Send {
        crate::adapters::Source::changes(self, watermark)
    }
}
