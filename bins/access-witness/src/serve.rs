//! The witness's HTTP surface (C2SP `tlog-witness`, §16.6 witness protocol):
//! - `POST /add-checkpoint`: the body is `old <size>`, the consistency proof and the signed
//!   note; the `Suiss-Key-Excerpt` and `Suiss-Domain-Metadata` headers carry the excerpt and
//!   the signed Domain Metadata (base64url). `200` answers the cosignature line, `409` the
//!   size the witness holds (`text/x.tlog.size`), `422` a proof that does not verify, `403` a
//!   key that is not the current binding's or a fenced binding, `404` an unknown log.
//! - `GET /checkpoint/{domain}`: the last cosigned note, for gossip and monitors (§9.16).
//! - `GET /info`: the cosigner name, its verifier key and the operator (SI-12).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use suiss_crypto::note::{Checkpoint, parse_note};
use suiss_crypto::signer::{SoftSigner, cosign};
use suiss_ledger::checkpoint::witness::{Refusal, parse_add_checkpoint};
use tokio::sync::Mutex;

use crate::config::{Config, origin};
use crate::state::{Chain, Entry};
use crate::verify::{Refused, checkpoint};

/// Largest request body (C2SP note bound plus the proof).
pub(crate) const MAX_BODY: usize = 300 * 1024;

/// Excerpt header.
pub(crate) const EXCERPT: &str = "suiss-key-excerpt";

/// Domain Metadata header.
pub(crate) const METADATA: &str = "suiss-domain-metadata";

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

fn text(status: StatusCode, body: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

fn size(n: u64) -> Response {
    (
        StatusCode::CONFLICT,
        [(header::CONTENT_TYPE, "text/x.tlog.size")],
        format!("{n}\n"),
    )
        .into_response()
}

fn header_bytes(h: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| access_kernel::json::b64url_decode(v).ok())
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn add(State(w): State<Arc<Witness>>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(body) = std::str::from_utf8(&body) else {
        return text(StatusCode::BAD_REQUEST, "not UTF-8\n".into());
    };
    let Ok((old, proof, note)) = parse_add_checkpoint(body) else {
        return text(StatusCode::BAD_REQUEST, "malformed request\n".into());
    };
    let Some(cp_origin) = parse_note(note)
        .ok()
        .and_then(|n| Checkpoint::parse(&n.body).ok())
        .map(|c| c.origin)
    else {
        return text(StatusCode::BAD_REQUEST, "malformed checkpoint\n".into());
    };
    let (Some(log), Some(chain)) = (w.config.logs.get(&cp_origin), w.chains.get(&cp_origin)) else {
        return text(StatusCode::NOT_FOUND, "unknown log\n".into());
    };
    let (Some(excerpt), Some(metadata)) = (
        header_bytes(&headers, EXCERPT),
        header_bytes(&headers, METADATA),
    ) else {
        return text(
            StatusCode::BAD_REQUEST,
            "excerpt and metadata required\n".into(),
        );
    };
    let cp = match checkpoint(log, note, &excerpt, &metadata) {
        Ok(cp) => cp,
        Err(Refused::Malformed(what)) => return text(StatusCode::BAD_REQUEST, format!("{what}\n")),
        Err(Refused::Key(why)) => return text(StatusCode::FORBIDDEN, format!("{why}\n")),
    };
    let mut chain = chain.lock().await;
    match chain.log.check(old, &proof, &cp) {
        Ok(()) => {}
        Err(Refusal::Conflict(n)) => return size(n),
        Err(Refusal::Backwards) => return size(chain.log.size()),
        Err(Refusal::Equivocation) => {
            // U9, HL-7
            let held = chain.log.size();
            if let Err(e) = chain.append(&Entry::Equivocation {
                note: note.to_owned(),
            }) {
                return text(StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n"));
            }
            return size(held);
        }
        Err(Refusal::Inconsistent(_)) => {
            return text(
                StatusCode::UNPROCESSABLE_ENTITY,
                "proof does not verify\n".into(),
            );
        }
        Err(Refusal::Fenced(n)) => {
            return text(
                StatusCode::FORBIDDEN,
                format!("binding fenced at size {n}\n"),
            );
        }
        Err(_) => return text(StatusCode::FORBIDDEN, "refused\n".into()),
    }
    let time = now_s();
    let Ok(parsed) = parse_note(note) else {
        return text(StatusCode::BAD_REQUEST, "malformed note\n".into());
    };
    let Ok((_, line)) = cosign(&w.signer, &w.config.name, time, &parsed.body) else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "cosigner unavailable\n".into(),
        );
    };
    let entry = Entry::Cosigned {
        size: cp.size,
        root: cp.root,
        time,
        note: format!("{note}{line}"),
    };
    // OP-158 m.3 (d)
    if let Err(e) = chain.append(&entry) {
        return text(StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n"));
    }
    text(StatusCode::OK, line)
}

async fn latest(State(w): State<Arc<Witness>>, Path(domain): Path<String>) -> Response {
    let Some(d) = access_kernel::json::b64url_decode(&domain)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return text(StatusCode::BAD_REQUEST, "bad domain\n".into());
    };
    let Some(chain) = w.chains.get(&origin(&access_kernel::digest::Digest(d))) else {
        return text(StatusCode::NOT_FOUND, "unknown log\n".into());
    };
    match chain.lock().await.latest.clone() {
        Some(note) => text(StatusCode::OK, note),
        None => text(StatusCode::NOT_FOUND, "nothing cosigned yet\n".into()),
    }
}

async fn info(State(w): State<Arc<Witness>>) -> Response {
    text(
        StatusCode::OK,
        format!(
            "name {}\nvkey {}\noperator {}\n",
            w.config.name, w.vkey, w.config.operator
        ),
    )
}

/// The witness router.
pub(crate) fn router(w: Arc<Witness>) -> Router {
    Router::new()
        .route("/add-checkpoint", post(add))
        .route("/checkpoint/{domain}", get(latest))
        .route("/info", get(info))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(w)
}
