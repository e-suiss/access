//! The post-quantum re-anchor of a domain's log (CR-45 RA-2, RA-3, RA-6, OP-159 m.3 (g)): the
//! signer signs the byte-identical note body of a witnessed classical checkpoint with the
//! domain's ML-DSA operational key, the declared independent ML-DSA witnesses cosign it, and
//! only then the Domain Metadata publishes it as `pq_reanchor` (RR-35). A witness that does not
//! answer leaves it pending; nothing is published and nothing says "anchored".

use std::path::Path;

use crate::app::reanchor::{Status, canonical_only, declared_with, pq_witnesses, status};
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

/// The cosigns of `body` that one of `witnesses` verifiably made, as stored (RA-3).
fn kept(
    witnesses: &[&access_kernel::verify::key_scope::Witness],
    body: &str,
    cosigns: &[suiss_ledger::checkpoint::witness::PqCosign],
) -> Vec<PqCosignRow> {
    cosigns
        .iter()
        .filter(|c| {
            witnesses.iter().any(|w| {
                crate::app::reanchor::cosign_verifies(&suiss_crypto::aws::AwsLcBackend, w, body, c)
            })
        })
        .map(|c| PqCosignRow {
            witness: c.name.clone(),
            cosigned_at: c.timestamp,
            sign1: c.sign1.clone(),
        })
        .collect()
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
    // OP-159 m.3 (j), m.16 (e)
    let canonical = canonical_sets(at.app, domain).await;
    // RB-0
    let witnesses = pq_witnesses(declared, Some(&canonical.witnesses))
        .map_err(crate::app::reanchor::ReanchorError::code)?;
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
        cosigns: kept(&witnesses, &body, &cosigns),
    };
    // OP-73
    append(at.sequencer, &id, &kept)
        .await
        .map_err(|_| "store-unavailable")?;
    if let Status::Anchored(r) = &out {
        let declare = Request::Declare {
            domain,
            declared: Box::new(canonical_only(
                &declared_with(declared, r.clone()),
                &canonical,
            )),
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

/// The canonical witness and replica sets of `domain`'s meta-anchor root terms; empty when
/// none were approved or the state cannot be read (OP-158 m.11, OP-159 m.3 (j)).
pub async fn canonical_sets(
    app: &access_store::Pool,
    domain: Digest,
) -> access_kernel::meta::RootSets {
    use access_kernel::codec::Canonical as _;
    let meta = access_kernel::meta::meta_anchor(&domain);
    let key = access_kernel::meta::key(access_kernel::meta::kind::ANCHOR, &meta);
    access_store::authority::state_of(app, &DomainId::from_bytes(domain.0), &[key])
        .await
        .ok()
        .and_then(|rows| rows.into_iter().find_map(|r| r.value))
        .and_then(|v| suiss_crypto::dcbor::decode(&v, suiss_crypto::dcbor::Limits::CEILING).ok())
        .and_then(|v| access_kernel::meta::AnchorState::from_value(&v).ok())
        .map(|a| a.sets)
        .unwrap_or_default()
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
