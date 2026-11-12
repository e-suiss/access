//! The post-quantum re-anchor of a domain's log (CR-45 RA-2, RA-3, RA-6, OP-159 m.3 (g)): the
//! signer signs the byte-identical note body of a witnessed classical checkpoint with the
//! domain's ML-DSA operational key, the declared independent ML-DSA witnesses cosign it, and
//! only then the Domain Metadata publishes it as `pq_reanchor` (RR-35). A witness that does not
//! answer leaves it pending; nothing is published and nothing says "anchored".

use std::path::Path;

use crate::app::reanchor::{Status, declared_with, pq_witnesses, status};
use access_authority_sequencer::witness::pq_cosign;
use access_authority_signer::adapters::call;
use access_authority_signer::protocol::{Request, Response};
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::Declarations;
use access_store::authority_checkpoint::AuthorityCheckpoint;
use suiss_ledger::checkpoint::witness::PqCosignRequest;

/// One re-anchor of `cp` at `now` through the signer at `socket`; `urls` maps each witness
/// name to its address. The status, or the stable reason it could not start.
///
/// # Errors
/// `reanchor-no-pq-witness` (RB-0), `pq-key-unavailable`, `reanchor-checkpoint` or
/// `signer-unreachable`.
pub async fn reanchor(
    socket: &Path,
    domain: Digest,
    (cp, declared): (&AuthorityCheckpoint, &Declarations),
    urls: &[(String, String)],
    now: u64,
) -> Result<Status, &'static str> {
    // RB-0
    let witnesses =
        pq_witnesses(declared, None).map_err(crate::app::reanchor::ReanchorError::code)?;
    let body = suiss_crypto::note::parse_note(&cp.note)
        .map_err(|_| "reanchor-checkpoint")?
        .body;
    let signed = call(
        socket,
        &Request::SignPqCheckpoint {
            domain,
            body: body.clone(),
            at: now,
        },
    )
    .await;
    let (sign1, excerpt) = match signed {
        Ok(Response::Signed { sign1, excerpt, .. }) => (sign1, excerpt),
        Ok(Response::Error(_)) => return Err("pq-key-unavailable"),
        _ => return Err("signer-unreachable"),
    };
    let request = PqCosignRequest {
        domain: domain.0,
        body: body.clone(),
        sign1,
        excerpt,
    };
    let mut cosigns = Vec::new();
    for w in &witnesses {
        let Some((_, url)) = urls.iter().find(|(n, _)| *n == w.name) else {
            continue;
        };
        if let Ok(c) = pq_cosign(url, &request).await {
            cosigns.push(c);
        }
    }
    let out = status(
        &suiss_crypto::aws::AwsLcBackend,
        &witnesses,
        (cp.size, &body),
        &cosigns,
    );
    if let Status::Anchored(r) = &out {
        let declare = Request::Declare {
            domain,
            declared: Box::new(declared_with(declared, r.clone())),
        };
        if !matches!(call(socket, &declare).await, Ok(Response::Opened)) {
            return Err("signer-unreachable");
        }
    }
    Ok(out)
}
