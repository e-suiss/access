//! The Replica Mirror and the streamed Record Export of a domain (§16.6.1, T21, CMP-21, TI-13,
//! AP-14, G28, TN-79, OP-158 m.3 (f), (g)):
//! - `POST /access/v1/domains/{domain}/exports`: the body is the ADP request that committed an
//!   `access.audit_export` Exercise, with its AIS. A package streams at once as a CBOR sequence
//!   (`export.cddl`) read a chunk of [`CHUNK`] records at a time, with no limit on the range;
//!   with `stream: "mirror"` the answer names the mirror run. Billing, quota or plan state
//!   never closes it (anti-hostage k.2). It is the domain's record, apart from a person's
//!   export.
//! - `GET /access/v1/domains/{domain}/exports/{export}?from=`: the same package again from
//!   `from`, for the PEP that committed it.
//! - `GET /access/v1/domains/{domain}/mirror?export=&from=&checkpoint=`: the next records from
//!   tree size `from` and the checkpoints after `checkpoint`, long-polled (`mirror.cddl`).
//! - `POST /access/v1/domains/{domain}/mirror`: a replica's `signed-replica-ack`.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::Domains;
use access_authority_core::app::Incoming;
use access_authority_core::app::mirror::{ExportRun, Frame, RunKind, SignedReplicaAck};
use access_authority_core::domain::export::{CHUNK, Coverage, Streamer};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::Problem;
use crate::adp::adapters::Pep;
use crate::adp::app::{Reply, bad, failed};
use crate::adp::domain::{Body as AdpBody, decode};

/// The exports route.
pub const EXPORTS_PATH: &str = "/access/v1/domains/{domain}/exports";

/// One export's resumable stream.
pub const EXPORT_PATH: &str = "/access/v1/domains/{domain}/exports/{export}";

/// The mirror route.
pub const MIRROR_PATH: &str = "/access/v1/domains/{domain}/mirror";

/// Media type of a CBOR sequence (RFC 8742).
pub const SEQUENCE: &str = "application/cbor-seq";

/// The longest a mirror answer waits for something new (below the request timeout).
pub const LONG_POLL: Duration = Duration::from_secs(5);

/// Longest replica ack body.
const MAX_ACK: usize = 4_096;

/// A stored record: its envelope and its stored leaf hash.
pub type Stored = (Vec<u8>, [u8; 32]);

/// What the routes need of the decision point.
pub trait Mirror: Send + Sync {
    /// Starts the run of the allowed export Exercise `inc` names.
    fn start(&self, inc: Incoming) -> impl Future<Output = Result<ExportRun, CoreError>> + Send;

    /// The run `export` of `domain` for `pep`.
    fn run(
        &self,
        domain: Digest,
        export: [u8; 32],
        pep: String,
    ) -> impl Future<Output = Result<ExportRun, CoreError>> + Send;

    /// The next mirror answer of `run`.
    fn batch(
        &self,
        run: ExportRun,
        domain: Digest,
        from: (u64, u64),
        wait: Duration,
    ) -> impl Future<Output = Result<Vec<Frame>, CoreError>> + Send;

    /// Takes a replica's signed ack.
    fn ack(&self, signed: SignedReplicaAck)
    -> impl Future<Output = Result<bool, CoreError>> + Send;

    /// The leaf hashes before `from`.
    fn leaves(
        &self,
        domain: Digest,
        from: u64,
    ) -> impl Future<Output = Result<Vec<[u8; 32]>, CoreError>> + Send;

    /// The stored records `from..=to`: each envelope and its stored leaf hash.
    fn records(
        &self,
        domain: Digest,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<Stored>, CoreError>> + Send;

    /// The checkpoints with size in `(after, upto]`.
    fn checkpoints(
        &self,
        domain: Digest,
        after: u64,
        upto: u64,
    ) -> impl Future<Output = Result<Vec<(u64, [u8; 32], String)>, CoreError>> + Send;
}

impl<K, B, S, C> Mirror for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn start(&self, inc: Incoming) -> Result<ExportRun, CoreError> {
        self.start_export(&inc).await
    }

    async fn run(
        &self,
        domain: Digest,
        export: [u8; 32],
        pep: String,
    ) -> Result<ExportRun, CoreError> {
        self.export_run(domain, &export, &pep).await
    }

    async fn batch(
        &self,
        run: ExportRun,
        domain: Digest,
        from: (u64, u64),
        wait: Duration,
    ) -> Result<Vec<Frame>, CoreError> {
        self.mirror(&run, domain, from, wait).await
    }

    async fn ack(&self, signed: SignedReplicaAck) -> Result<bool, CoreError> {
        self.replica_ack(&signed).await
    }

    async fn leaves(&self, domain: Digest, from: u64) -> Result<Vec<[u8; 32]>, CoreError> {
        self.leaves_before(domain, from).await
    }

    async fn records(&self, domain: Digest, from: u64, to: u64) -> Result<Vec<Stored>, CoreError> {
        Ok(Domains::records(self, domain, from, to)
            .await?
            .into_iter()
            .map(|r| (r.envelope, r.leaf_hash))
            .collect())
    }

    async fn checkpoints(
        &self,
        domain: Digest,
        after: u64,
        upto: u64,
    ) -> Result<Vec<(u64, [u8; 32], String)>, CoreError> {
        self.checkpoints_in(domain, after, upto).await
    }
}

impl<M: Mirror> Mirror for Arc<M> {
    fn start(&self, inc: Incoming) -> impl Future<Output = Result<ExportRun, CoreError>> + Send {
        (**self).start(inc)
    }

    fn run(
        &self,
        domain: Digest,
        export: [u8; 32],
        pep: String,
    ) -> impl Future<Output = Result<ExportRun, CoreError>> + Send {
        (**self).run(domain, export, pep)
    }

    fn batch(
        &self,
        run: ExportRun,
        domain: Digest,
        from: (u64, u64),
        wait: Duration,
    ) -> impl Future<Output = Result<Vec<Frame>, CoreError>> + Send {
        (**self).batch(run, domain, from, wait)
    }

    fn ack(
        &self,
        signed: SignedReplicaAck,
    ) -> impl Future<Output = Result<bool, CoreError>> + Send {
        (**self).ack(signed)
    }

    fn leaves(
        &self,
        domain: Digest,
        from: u64,
    ) -> impl Future<Output = Result<Vec<[u8; 32]>, CoreError>> + Send {
        (**self).leaves(domain, from)
    }

    fn records(
        &self,
        domain: Digest,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<Stored>, CoreError>> + Send {
        (**self).records(domain, from, to)
    }

    fn checkpoints(
        &self,
        domain: Digest,
        after: u64,
        upto: u64,
    ) -> impl Future<Output = Result<Vec<(u64, [u8; 32], String)>, CoreError>> + Send {
        (**self).checkpoints(domain, after, upto)
    }
}

struct Shared<M> {
    mirror: M,
    max_body: usize,
    chunk: u64,
}

/// The routes over `mirror`, reading ADP bodies of at most `max_body` bytes.
pub fn router<M: Mirror + 'static>(mirror: M, max_body: usize) -> Router {
    router_with_chunk(mirror, max_body, CHUNK)
}

/// [`router`] reading a package `chunk` records at a time (a test shows a range larger than a
/// chunk streams whole).
pub fn router_with_chunk<M: Mirror + 'static>(mirror: M, max_body: usize, chunk: u64) -> Router {
    Router::new()
        .route(EXPORTS_PATH, post(start::<M>))
        .route(EXPORT_PATH, get(resume::<M>))
        .route(MIRROR_PATH, get(follow::<M>).post(acked::<M>))
        .with_state(Arc::new(Shared {
            mirror,
            max_body,
            chunk: chunk.max(1),
        }))
}

fn reply(e: CoreError, headers: &HeaderMap) -> Response {
    crate::adp::adapters::respond(failed(e, AdpBody::Context), headers)
}

fn unauthenticated(headers: &HeaderMap) -> Response {
    crate::adp::adapters::respond(Reply::Unauthenticated, headers)
}

fn protocol(code: &'static str) -> Response {
    Problem::new(StatusCode::BAD_REQUEST, code, "Protocol Error").into_response()
}

fn domain_of(text: &str) -> Option<Digest> {
    b64url_decode(text)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
}

fn query(uri: &Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// The number `name` of the query, `default` when absent; `None` when malformed.
fn number(uri: &Uri, name: &str, default: u64) -> Option<u64> {
    match query(uri, name) {
        None => Some(default),
        Some(v) if v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()) => v.parse::<u64>().ok(),
        Some(_) => None,
    }
}

fn sequence(body: Body) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(SEQUENCE)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

async fn start<M: Mirror + 'static>(
    State(shared): State<Arc<Shared<M>>>,
    Path(domain): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return unauthenticated(&headers);
    };
    let Some(domain) = domain_of(&domain) else {
        return protocol("domain");
    };
    let decoded = match decode(&body, shared.max_body) {
        Ok(d) => d,
        Err(e) => return crate::adp::adapters::respond(bad(e, AdpBody::Context), &headers),
    };
    if decoded.request.domain != domain {
        return protocol("domain");
    }
    let inc = Incoming {
        request: decoded.request,
        ais: decoded.ais,
        pep,
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    let run = match shared.mirror.start(inc).await {
        Ok(r) => r,
        Err(e) => return reply(e, &headers),
    };
    let export = b64url_encode(&run.export);
    match run.kind {
        RunKind::Mirror => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            axum::Json(serde_json::json!({
                "export": export,
                "kind": "mirror",
                "from": run.from.to_string(),
            })),
        )
            .into_response(),
        RunKind::Package => {
            let mut r = package(shared, domain, run.clone(), run.from);
            if let Ok(v) = HeaderValue::from_str(&format!(
                "/access/v1/domains/{}/exports/{export}",
                b64url_encode(&domain.0)
            )) {
                r.headers_mut().insert(header::CONTENT_LOCATION, v);
            }
            r
        }
    }
}

async fn resume<M: Mirror + 'static>(
    State(shared): State<Arc<Shared<M>>>,
    Path((domain, export)): Path<(String, String)>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return unauthenticated(&headers);
    };
    let (Some(domain), Some(export)) = (domain_of(&domain), domain_of(&export)) else {
        return protocol("export-run");
    };
    let run = match shared.mirror.run(domain, export.0, pep).await {
        Ok(r) => r,
        Err(e) => return reply(e, &headers),
    };
    let Some(from) = number(&uri, "from", run.from) else {
        return protocol("mirror-query");
    };
    if run.kind != RunKind::Package || from < run.from || run.to.is_some_and(|t| from > t) {
        return protocol("export-range");
    }
    package(shared, domain, run, from)
}

/// Streams the package of `run` from `from` a chunk at a time; a check that fails mid-stream
/// ends the stream without its end frame, which a reader refuses (INV-27).
fn package<M: Mirror + 'static>(
    shared: Arc<Shared<M>>,
    domain: Digest,
    run: ExportRun,
    from: u64,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    tokio::spawn(async move {
        let _ = stream_package(&shared, domain, &run, from, &tx).await;
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|b| (Ok::<_, Infallible>(b), rx))
    });
    sequence(Body::from_stream(stream))
}

async fn stream_package<M: Mirror>(
    shared: &Shared<M>,
    domain: Digest,
    run: &ExportRun,
    from: u64,
    tx: &tokio::sync::mpsc::Sender<Bytes>,
) -> Option<()> {
    let to = run.to?;
    let coverage = if run.full {
        Coverage::Full
    } else {
        Coverage::Digest
    };
    let prefix = shared.mirror.leaves(domain, from).await.ok()?;
    let (mut s, head) =
        Streamer::start(domain, (from, to), coverage, Digest(run.export), &prefix).ok()?;
    tx.send(Bytes::from(head)).await.ok()?;
    let mut at = from;
    while at <= to {
        let last = at.saturating_add(shared.chunk).saturating_sub(1).min(to);
        let records = shared.mirror.records(domain, at, last).await.ok()?;
        let mut out = Vec::new();
        for (envelope, leaf) in &records {
            out.extend(s.push(envelope, leaf).ok()?);
        }
        tx.send(Bytes::from(out)).await.ok()?;
        at = last.checked_add(1)?;
    }
    let checkpoints = shared
        .mirror
        .checkpoints(domain, from, to.saturating_add(1))
        .await
        .ok()?;
    let end = s.finish(&checkpoints).ok()?;
    tx.send(Bytes::from(end)).await.ok()
}

async fn follow<M: Mirror + 'static>(
    State(shared): State<Arc<Shared<M>>>,
    Path(domain): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return unauthenticated(&headers);
    };
    let (Some(domain), Some(export)) = (
        domain_of(&domain),
        query(&uri, "export").as_deref().and_then(domain_of),
    ) else {
        return protocol("export-run");
    };
    let (Some(from), Some(checkpoint)) = (number(&uri, "from", 0), number(&uri, "checkpoint", 0))
    else {
        return protocol("mirror-query");
    };
    let run = match shared.mirror.run(domain, export.0, pep).await {
        Ok(r) => r,
        Err(e) => return reply(e, &headers),
    };
    let frames = match shared
        .mirror
        .batch(run, domain, (from, checkpoint), LONG_POLL)
        .await
    {
        Ok(f) => f,
        Err(e) => return reply(e, &headers),
    };
    let mut out = Vec::new();
    for f in &frames {
        match f.to_bytes() {
            Ok(b) => out.extend(b),
            Err(_) => return reply(CoreError::Unavailable("mirror"), &headers),
        }
    }
    sequence(Body::from(out))
}

async fn acked<M: Mirror + 'static>(
    State(shared): State<Arc<Shared<M>>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(domain) = domain_of(&domain) else {
        return protocol("domain");
    };
    if body.len() > MAX_ACK {
        return protocol("replica-ack");
    }
    let Ok(signed) = SignedReplicaAck::from_bytes(&body) else {
        return protocol("replica-ack");
    };
    if signed.ack.domain != domain.0 {
        return protocol("domain");
    }
    match shared.mirror.ack(signed).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(CoreError::Protocol(code)) => {
            Problem::new(StatusCode::FORBIDDEN, code, "Forbidden").into_response()
        }
        Err(e) => reply(e, &headers),
    }
}
