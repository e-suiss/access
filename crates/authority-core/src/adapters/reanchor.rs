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
use access_store::pq_checkpoint::{PqCheckpoint, PqCosignRow, Reason, append};
use access_store::scope::DomainId;
use suiss_ledger::checkpoint::witness::PqCosignRequest;

/// Where a re-anchor runs: the signer socket and the `access_app` and `access_sequencer` pools.
#[derive(Clone, Copy)]
pub struct Reanchoring<'a> {
    /// The authority signer's socket.
    pub socket: &'a Path,
    /// `access_app`.
    pub app: &'a access_store::Pool,
    /// `access_sequencer`.
    pub sequencer: &'a access_store::Pool,
}

/// One re-anchor of the witnessed checkpoint `cp` at `now` for `reason`; `urls` maps each
/// witness name to its address. The re-anchor checkpoint and whatever cosigns arrived are kept
/// (OP-73); the status, or the stable reason it could not start.
///
/// # Errors
/// `reanchor-no-pq-witness` (RB-0), `pq-key-unavailable`, `reanchor-checkpoint`,
/// `signer-unreachable` or `store-unavailable`.
pub async fn reanchor(
    at: Reanchoring<'_>,
    domain: Digest,
    (cp, declared, reason): (&AuthorityCheckpoint, &Declarations, Reason),
    urls: &[(String, String)],
    now: u64,
) -> Result<Status, &'static str> {
    let socket = at.socket;
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
        sign1: sign1.clone(),
        excerpt: excerpt.clone(),
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
    let id = DomainId::from_bytes(domain.0);
    let kept = PqCheckpoint {
        issued_at: now,
        size: cp.size,
        root: cp.root,
        body: body.clone(),
        sign1,
        excerpt,
        reason,
        cosigns: cosigns
            .iter()
            .filter(|c| {
                witnesses.iter().any(|w| {
                    crate::app::reanchor::cosign_verifies(
                        &suiss_crypto::aws::AwsLcBackend,
                        w,
                        &body,
                        c,
                    )
                })
            })
            .map(|c| PqCosignRow {
                witness: c.name.clone(),
                cosigned_at: c.timestamp,
                sign1: c.sign1.clone(),
            })
            .collect(),
    };
    // OP-73
    append(at.sequencer, &id, &kept)
        .await
        .map_err(|_| "store-unavailable")?;
    if let Status::Anchored(r) = &out {
        let declare = Request::Declare {
            domain,
            declared: Box::new(declared_with(declared, r.clone())),
        };
        if !matches!(call(socket, &declare).await, Ok(Response::Opened)) {
            return Err("signer-unreachable");
        }
        let target = format!("{}@{}", reason.as_str(), r.size);
        let _ = access_store::operational::record_operational(
            at.app,
            &access_store::operational::OperationalEvent {
                event_type: "pq.reanchored",
                occurred_at_ms: now,
                tenant: None,
                domain: Some(domain.0),
                actor: "provider",
                target: &target,
                reason: "",
                correlation: "",
            },
        )
        .await;
    }
    Ok(out)
}

/// Admits `alg` to `domain`'s allowlist, or with `retire` retires the classical `alg`, through
/// the signer (OP-159 m.9 (h), m.13 (f)).
///
/// # Errors
/// The signer's stable code, or `signer-unreachable`.
pub async fn allowlist(
    socket: &Path,
    domain: Digest,
    alg: suiss_crypto::cose::Algorithm,
    retire: bool,
) -> Result<(), String> {
    match call(
        socket,
        &Request::Allowlist {
            domain,
            alg,
            retire,
        },
    )
    .await
    {
        Ok(Response::Opened) => Ok(()),
        Ok(Response::Error(code)) => Err(code),
        _ => Err(String::from("signer-unreachable")),
    }
}
