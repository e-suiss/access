//! The witness's HTTP surface (`witness.cddl`, §16.6 witness protocol):
//! - `POST /cosign`: a `cosign-request`; the answer is a `cosign-response`, `200` with the
//!   cosignature or `400`/`403`/`409`/`422` with the refusal. A request whose base is not the
//!   one the witness holds is `inconsistent`; the log reads `/gossip` and retries from it. A
//!   request carrying the `domain_handover` record its note ends with teaches the witness the
//!   new binding; the old one is then `fenced` above that note's size (U11).
//! - `GET /gossip/{domain}`: the last cosigned head as a `gossip-entry` with its note, for
//!   monitors and the log (§9.16).
//! - `GET /info`: the cosigner name, its verifier key and the operator (SI-12).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use suiss_crypto::note::parse_note;
use suiss_crypto::signer::{SoftSigner, cosign};
use suiss_ledger::checkpoint::witness::{
    CosignRequest, CosignResponse, Cosignature, GossipEntry, Refusal, Refused,
};
use tokio::sync::Mutex;

use crate::config::{Config, origin};
use crate::state::Chain;
use crate::verify::checkpoint;

/// Largest request body: the note, the excerpt and a binding-change record.
pub(crate) const MAX_BODY: usize = 1_200 * 1024;

/// The CBOR media type.
pub(crate) const CBOR: &str = "application/cbor";

/// What every handler shares.
pub(crate) struct Witness {
    config: Config,
    signer: SoftSigner,
    vkey: String,
    chains: BTreeMap<String, Mutex<Chain>>,
}

impl Witness {
    /// Opens every configured log's chain.
    pub(crate) fn open(config: Config, signer: SoftSigner, vkey: String) -> Result<Self, String> {
        let mut chains = BTreeMap::new();
        for (o, log) in &config.logs {
            chains.insert(
                o.clone(),
                Mutex::new(Chain::open(&config.state, &log.domain)?),
            );
        }
        Ok(Self {
            config,
            signer,
            vkey,
            chains,
        })
    }
}

fn cbor(status: StatusCode, r: &CosignResponse) -> Response {
    match r.to_bytes() {
        Ok(b) => (status, [(header::CONTENT_TYPE, CBOR)], b).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn refuse(r: Refused) -> Response {
    let status = match r {
        Refused::Malformed => StatusCode::BAD_REQUEST,
        Refused::UnknownKey | Refused::Fenced => StatusCode::FORBIDDEN,
        Refused::Inconsistent => StatusCode::CONFLICT,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    cbor(status, &CosignResponse::Refused(r))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

async fn cosign_request(State(w): State<Arc<Witness>>, body: Bytes) -> Response {
    let Ok(req) = CosignRequest::from_bytes(&body) else {
        return refuse(Refused::Malformed);
    };
    let o = origin(&access_kernel::digest::Digest(req.domain));
    let (Some(log), Some(chain)) = (w.config.logs.get(&o), w.chains.get(&o)) else {
        return refuse(Refused::UnknownKey);
    };
    let mut chain = chain.lock().await;
    let trusted = with_learned(log, &chain.learned);
    let (cp, binding) = match checkpoint(&trusted, &req.note, &req.excerpt) {
        Ok(v) => v,
        Err(crate::verify::Refused::Malformed) => return refuse(Refused::Malformed),
        Err(crate::verify::Refused::Key) => return refuse(Refused::UnknownKey),
    };
    // U11, §16.6 HO-7
    if chain.fenced.get(&binding).is_some_and(|max| cp.size > *max) {
        return refuse(Refused::Fenced);
    }
    let learned = match &req.binding_change {
        None => None,
        Some(change) => match crate::verify::binding_change(&log.domain, &cp, change) {
            Ok(keys) if !chain.fenced.contains_key(&binding) => Some(keys),
            _ => return refuse(Refused::UnknownKey),
        },
    };
    if req.base != chain.log.base() {
        return refuse(Refused::Inconsistent);
    }
    let old = req.base.map_or(0, |(s, _)| s);
    match chain.log.check(old, &req.consistency, &cp) {
        Ok(()) => {}
        Err(Refusal::Equivocation) => {
            // U9, HL-7
            if let Err(e) = chain.refused(&req.note) {
                return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
            }
            return refuse(Refused::Inconsistent);
        }
        Err(r) => return refuse(Refused::of(r)),
    }
    let Ok(parsed) = parse_note(&req.note) else {
        return refuse(Refused::Malformed);
    };
    let at = now_ms();
    let Ok((_, line)) = cosign(&w.signer, &w.config.name, at / 1000, &parsed.body) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "cosigner unavailable").into_response();
    };
    let Ok((cosignature, _)) = Cosignature::from_line(&line) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "cosignature").into_response();
    };
    // OP-158 m.3 (d)
    if let Err(e) = chain.cosigned(&cp, binding, at, format!("{}{line}", req.note)) {
        return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
    }
    // U11, §16.6 HO-7: the old binding signs nothing larger than C_{h+1} from now on
    if let Some(keys) = learned
        && let Err(e) = chain.rebind(binding, cp.size, keys, at)
    {
        return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
    }
    cbor(StatusCode::OK, &CosignResponse::Cosigned(cosignature))
}

/// The log's configured binding keys and those learned from handover records.
fn with_learned(log: &crate::config::Log, learned: &[[u8; 32]]) -> crate::config::Log {
    let mut out = log.clone();
    for k in learned {
        let public = suiss_crypto::cose::PublicKey::Ed25519(*k);
        let kid = access_kernel::verify::key_scope::thumbprint(&public);
        let _ = out.bindings.insert(kid, public);
    }
    out
}

async fn gossip(State(w): State<Arc<Witness>>, Path(domain): Path<String>) -> Response {
    let Some(d) = access_kernel::json::b64url_decode(&domain)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(chain) = w.chains.get(&origin(&access_kernel::digest::Digest(d))) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(latest) = chain.lock().await.latest.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(cosigned) = latest.note else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mine = format!("\u{2014} {} ", w.config.name);
    let Some((cosignature, _)) = cosigned
        .lines()
        .rev()
        .find(|l| l.starts_with(&mine))
        .and_then(|l| Cosignature::from_line(l).ok())
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let entry = GossipEntry {
        witness: w.config.name.clone(),
        domain: d,
        size: latest.size,
        root: latest.root,
        cosignature,
        note: Some(cosigned),
    };
    match entry.to_bytes() {
        Ok(b) => ([(header::CONTENT_TYPE, CBOR)], b).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn info(State(w): State<Arc<Witness>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!(
            "name {}\nvkey {}\noperator {}\n",
            w.config.name, w.vkey, w.config.operator
        ),
    )
        .into_response()
}

/// The witness router.
pub(crate) fn router(w: Arc<Witness>) -> Router {
    Router::new()
        .route("/cosign", post(cosign_request))
        .route("/gossip/{domain}", get(gossip))
        .route("/info", get(info))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(w)
}
