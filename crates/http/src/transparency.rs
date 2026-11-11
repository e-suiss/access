//! A domain's transparency surface (§9.16, §13.3, T19, P32, OP-158 m.3 (c), (d)):
//! - `GET /access/v1/domains/{domain}/checkpoints`: `witnessed_through`, the newest checkpoint
//!   an independent witness cosigned with every cosignature it got, the declared witnesses
//!   and what may be claimed of them. Anyone may copy it (the domain's own storage, a third
//!   party log); Suiss is not a required witness or trust anchor (PI-13, Ek B 6074).
//! - `GET /access/v1/domains/{domain}/checkpoints/{size}/inclusion/{pos}`: the inclusion proof
//!   bundle of one record for an authenticated PEP: the leaf core with only `artifacts`
//!   opened, the Merkle path and the witnessed checkpoint of `size` (T19, §17.6.1 rule 5).
//! - `GET /access/v1/domains/{domain}/tile/{level}/{index}[.p/{width}]`: C2SP `tlog-tiles`
//!   hash tiles of the witnessed tree, so anyone can follow the log as a transparency log
//!   (K15); entries are not published, they are confidential records.

use std::future::Future;
use std::sync::Arc;

use access_kernel::digest::Digest;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::Problem;
use crate::adp::adapters::Pep;

/// The checkpoints route.
pub const CHECKPOINTS_PATH: &str = "/access/v1/domains/{domain}/checkpoints";

/// The inclusion bundle route.
pub const INCLUSION_PATH: &str = "/access/v1/domains/{domain}/checkpoints/{size}/inclusion/{pos}";

/// The hash tile route (C2SP `tlog-tiles`).
pub const TILE_PATH: &str = "/access/v1/domains/{domain}/tile/{level}/{*index}";

/// `Cache-Control` of a full tile: it never changes.
pub const FULL_TILE_CACHE: &str = "public, max-age=31536000, immutable";

/// Media type of an inclusion bundle.
pub const BUNDLE_CONTENT_TYPE: &str = "application/cbor";

/// `Cache-Control` of the checkpoints answer: the cadence is a minute.
pub const CACHE: &str = "public, max-age=30";

/// One declared witness as published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declared {
    /// Its cosigner `vkey`.
    pub vkey: String,
    /// Its declared operator.
    pub operator: String,
    /// Not the provider's operator (SI-12, B13).
    pub independent: bool,
}

/// What a domain's checkpoints answer carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The largest size an independent witness cosigned.
    pub witnessed_through: u64,
    /// That checkpoint's note with its cosignature lines, and its key excerpt.
    pub latest: Option<(String, Vec<u8>)>,
    /// The declared witnesses.
    pub witnesses: Vec<Declared>,
}

impl Listing {
    /// Whether equivocation may be called detectable: at least two witnesses whose views can
    /// be compared and at least one independent (U9, HL-7, P4); otherwise the claim is not made.
    #[must_use]
    pub fn equivocation_detectable(&self) -> bool {
        self.witnesses.len() >= 2 && self.witnesses.iter().any(|w| w.independent)
    }
}

/// Why an inclusion bundle is not served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InclusionError {
    /// No such domain, size or position.
    #[error("unknown")]
    Unknown,
    /// No independent witness cosigned a checkpoint of that size (SEC23: nothing is claimed).
    #[error("not witnessed")]
    NotWitnessed,
    /// The store could not be read.
    #[error("unavailable")]
    Unavailable,
}

/// Where the checkpoints are read.
pub trait Checkpoints: Send + Sync {
    /// The listing of `domain`; `None` for an unknown domain.
    fn listing(
        &self,
        domain: Digest,
    ) -> impl Future<Output = Result<Option<Listing>, InclusionError>> + Send;

    /// The inclusion bundle of the record at `pos` in the witnessed checkpoint of `size`.
    fn inclusion(
        &self,
        domain: Digest,
        size: u64,
        pos: u64,
    ) -> impl Future<Output = Result<Vec<u8>, InclusionError>> + Send;

    /// Hash tile `index` of `level` with `width` hashes, of the witnessed tree: the hashes
    /// concatenated. A width the witnessed tree does not have is [`InclusionError::Unknown`].
    fn tile(
        &self,
        domain: Digest,
        level: u32,
        index: u64,
        width: u64,
    ) -> impl Future<Output = Result<Vec<u8>, InclusionError>> + Send;
}

/// The routes over `store`.
pub fn router<C: Checkpoints + 'static>(store: C) -> Router {
    Router::new()
        .route(CHECKPOINTS_PATH, get(listing::<C>))
        .route(INCLUSION_PATH, get(inclusion::<C>))
        .route(TILE_PATH, get(tile::<C>))
        .with_state(Arc::new(store))
}

/// A C2SP tile index path: three-digit groups, all but the last prefixed `x`, and an optional
/// `.p/<width>` for a partial tile; `(index, width)` with width 256 for a full tile.
#[must_use]
pub fn tile_index(path: &str) -> Option<(u64, u64)> {
    let (path, width) = match path.split_once(".p/") {
        Some((p, w)) => {
            let w = number(w).filter(|w| (1..256).contains(w))?;
            (p, w)
        }
        None => (path, 256),
    };
    let groups: Vec<&str> = path.split('/').collect();
    let (last, rest) = groups.split_last()?;
    let mut index = 0_u64;
    for (i, g) in rest
        .iter()
        .map(|g| g.strip_prefix('x'))
        .chain([Some(*last)])
        .enumerate()
    {
        let g = g.filter(|g| g.len() == 3 && g.bytes().all(|b| b.is_ascii_digit()))?;
        if i == 0 && !rest.is_empty() && g == "000" {
            return None;
        }
        index = index
            .checked_mul(1000)?
            .checked_add(g.parse::<u64>().ok()?)?;
    }
    Some((index, width))
}

fn problem(e: InclusionError) -> Response {
    let (status, code) = match e {
        InclusionError::Unknown => (StatusCode::NOT_FOUND, "checkpoint-unknown"),
        InclusionError::NotWitnessed => (StatusCode::CONFLICT, "checkpoint-not-witnessed"),
        InclusionError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "checkpoints-unavailable"),
    };
    let title = status.canonical_reason().unwrap_or("Error");
    Problem::new(status, code, title).into_response()
}

fn number(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|n| n.to_string() == text)
}

async fn listing<C: Checkpoints>(
    State(store): State<Arc<C>>,
    Path(domain): Path<String>,
) -> Response {
    let Some(d) = crate::adp::adapters::domain_id(&domain) else {
        return problem(InclusionError::Unknown);
    };
    let l = match store.listing(d).await {
        Ok(Some(l)) => l,
        Ok(None) => return problem(InclusionError::Unknown),
        Err(e) => return problem(e),
    };
    let witnesses: Vec<_> = l
        .witnesses
        .iter()
        .map(|w| json!({"vkey": w.vkey, "operator": w.operator, "independent": w.independent}))
        .collect();
    let checkpoint = l.latest.as_ref().map(|(note, excerpt)| {
        json!({"note": note, "excerpt": access_kernel::json::b64url_encode(excerpt)})
    });
    let body = json!({
        "domain": domain,
        "witnessed_through": l.witnessed_through,
        "checkpoint": checkpoint,
        "witnesses": witnesses,
        "claims": {"equivocation_detectable": l.equivocation_detectable()},
    });
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(CACHE)),
        ],
        body.to_string(),
    )
        .into_response()
}

async fn inclusion<C: Checkpoints>(
    State(store): State<Arc<C>>,
    pep: Option<axum::Extension<Pep>>,
    Path((domain, size, pos)): Path<(String, String, String)>,
) -> Response {
    if pep.is_none() {
        return Problem::new(StatusCode::UNAUTHORIZED, "pep-required", "Unauthorized")
            .into_response();
    }
    let (Some(d), Some(size), Some(pos)) = (
        crate::adp::adapters::domain_id(&domain),
        number(&size),
        number(&pos),
    ) else {
        return problem(InclusionError::Unknown);
    };
    if pos >= size {
        return problem(InclusionError::Unknown);
    }
    match store.inclusion(d, size, pos).await {
        Ok(bundle) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(BUNDLE_CONTENT_TYPE),
            )],
            bundle,
        )
            .into_response(),
        Err(e) => problem(e),
    }
}

async fn tile<C: Checkpoints>(
    State(store): State<Arc<C>>,
    Path((domain, level, index)): Path<(String, String, String)>,
) -> Response {
    let (Some(d), Some(level), Some((index, width))) = (
        crate::adp::adapters::domain_id(&domain),
        number(&level)
            .and_then(|l| u32::try_from(l).ok())
            .filter(|l| *l < 8),
        tile_index(&index),
    ) else {
        return problem(InclusionError::Unknown);
    };
    match store.tile(d, level, index, width).await {
        Ok(hashes) => {
            let cache = if width == 256 {
                FULL_TILE_CACHE
            } else {
                "public, max-age=30"
            };
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    ),
                    (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
                ],
                hashes,
            )
                .into_response()
        }
        Err(e) => problem(e),
    }
}

#[cfg(test)]
mod tests;
