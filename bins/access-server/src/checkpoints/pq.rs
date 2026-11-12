//! The RA-6 cadence of the post-quantum re-anchor (CR-45 RA-6, OP-159 m.3 (g)): for a domain
//! whose allowlist names ML-DSA, the first witnessed checkpoint of each UTC day; [`run`] serves
//! an operator request and the step before a classical algorithm is retired.

use std::path::Path;

use access_authority_core::adapters::{Reanchoring, reanchor};
use access_authority_core::app::reanchor::{Status, due};
use access_authority_sequencer::witness::Target;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::DomainMetadata;
use access_store::Pool;
use access_store::pq_checkpoint::Reason;
use access_store::scope::DomainId;

/// The witness addresses by note key name.
pub(crate) fn urls(targets: &[Target]) -> Vec<(String, String)> {
    targets
        .iter()
        .filter_map(|t| {
            let name = t.vkey.split_once('+')?.0;
            Some((name.to_owned(), t.url.clone()))
        })
        .collect()
}

async fn metadata(socket: &Path, domain: Digest) -> Option<DomainMetadata> {
    use access_authority_sequencer::ports::NoteSigner as _;
    let m = access_authority_sequencer::adapters::SocketSigner::new(socket.to_path_buf())
        .metadata(domain)
        .await
        .ok()?;
    let payload = suiss_crypto::cose::parse_sign1(&m).ok()?.payload?;
    DomainMetadata::from_bytes(&payload).ok()
}

/// One re-anchor of `domain` for `reason` over its latest witnessed checkpoint.
///
/// # Errors
/// The stable reason it could not run.
pub(crate) async fn run(
    (socket, app, sequencer): (&Path, &Pool, &Pool),
    domain: Digest,
    targets: &[Target],
    reason: Reason,
    now: u64,
) -> Result<Status, &'static str> {
    let id = DomainId::from_bytes(domain.0);
    let m = metadata(socket, domain).await.ok_or("signer-unreachable")?;
    let row = access_store::witness::latest_witnessed(app, &id, None)
        .await
        .map_err(|_| "store-unavailable")?
        .ok_or("checkpoint-not-witnessed")?;
    reanchor(
        Reanchoring {
            socket,
            app,
            sequencer,
        },
        domain,
        (&row, &m.declared, reason),
        &urls(targets),
        now,
    )
    .await
}

/// The cadence step of `domain` at `now`: a re-anchor when the day's is due; `None` when none
/// was.
pub(crate) async fn step(
    pools: (&Path, &Pool, &Pool),
    domain: Digest,
    targets: &[Target],
    now: u64,
) -> Option<Result<Status, &'static str>> {
    let (socket, app, _) = pools;
    let m = metadata(socket, domain).await?;
    let last = access_store::pq_checkpoint::list(app, &DomainId::from_bytes(domain.0), None, 1)
        .await
        .ok()?
        .first()
        .map(|c| c.issued_at);
    if !due(&m.algorithms, last, now) {
        return None;
    }
    Some(run(pools, domain, targets, Reason::Cadence, now).await)
}
