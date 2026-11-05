//! Claim Ingest in this process (CMP-8, OP-150 m.6 (f)): the pipeline over the domains this
//! process leads, the day's submission table and trusted time.

use std::sync::Arc;

use access_authority_ingest::app::Ingest;
use access_authority_ingest::ports::{Clock, Ledger, Submissions};
use access_authority_sequencer::ports::Clock as _;
use access_internal_api::idp::Unavailable;
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::scope::DomainId;

/// The day's submissions in `access_app`.
pub(crate) struct PgSubmissions(pub(crate) Pool);

impl Submissions for PgSubmissions {
    async fn first(
        &self,
        domain: Digest,
        day: u32,
        hash: [u8; 32],
        carrier: &'static str,
    ) -> Result<bool, Unavailable> {
        access_store::claims::first_submission(
            &self.0,
            &DomainId::from_bytes(domain.0),
            day,
            &hash,
            carrier,
        )
        .await
        .map_err(|e| Unavailable(format!("claim-ingest: {e}")))
    }
}

/// Trusted time from the sequencer's sources (OP-129 m.1).
pub(crate) struct Trusted(
    pub(crate) tokio::sync::Mutex<access_authority_sequencer::adapters::SourcesClock>,
);

impl Clock for Trusted {
    async fn now(&self) -> Result<u64, Unavailable> {
        self.0
            .lock()
            .await
            .now()
            .await
            .map_err(|_| Unavailable(String::from("time")))
    }
}

/// `POST /access/v1/claims:ingest` over `domains` (CMP-8); trusted time is read as the
/// sequencer reads it, from the system clock and the database server.
pub(crate) fn routes<L: Ledger + 'static>(domains: Arc<L>, app: Pool) -> axum::Router {
    let clock = access_authority_sequencer::adapters::SourcesClock::new(app.clone());
    access_http::ingest::router(Ingest::new(
        domains,
        PgSubmissions(app),
        Trusted(tokio::sync::Mutex::new(clock)),
    ))
}
