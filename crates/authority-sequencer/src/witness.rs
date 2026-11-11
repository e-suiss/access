//! The provider's side of the witness protocol and of trusted time (§16.6 witness protocol,
//! CMP-6, T17, SEC23, TI-RT2, OP-158 m.3 (c), (d), (k)):
//! - each declared witness gets every checkpoint as a C2SP `add-checkpoint` request with the
//!   consistency proof from the size it last cosigned, and its cosignature is verified before
//!   it is kept;
//! - [`Board`] holds what this process knows of each led domain's witnessed size and the
//!   out-of-cycle checkpoints commits wait for (coalesced, OP-38);
//! - a cosignature time earlier than the checkpoint's newest record marks the leader unhealthy
//!   and the clock port refuses until a later cosignature agrees ("Unavailable — time check");
//! - Roughtime servers are sampled in the background as a third time source.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use access_kernel::digest::Digest;
use suiss_crypto::note::{Verifier, verify_note};
use suiss_crypto::sig::PureBackend;
use suiss_ledger::time::{Sample, TimeError, UNCERTAINTY_MS, check_against_witness};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;

/// How long one witness exchange may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest an SEC23 answer waits for its covering cosignature (OP-158 m.3 (e), PD).
pub const ACK_WAIT: Duration = Duration::from_secs(2);

/// Excerpt header of an `add-checkpoint` request.
pub const EXCERPT_HEADER: &str = "Suiss-Key-Excerpt";

/// Domain Metadata header of an `add-checkpoint` request.
pub const METADATA_HEADER: &str = "Suiss-Domain-Metadata";

const MAX_ANSWER: u64 = 512 * 1024;

/// Why a witness exchange gave no cosignature.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// Not reachable in time.
    #[error("unreachable")]
    Unreachable,
    /// It holds another base size (C2SP `409`).
    #[error("witness is at size {0}")]
    Conflict(u64),
    /// It refused with this status.
    #[error("refused with {0}")]
    Refused(u16),
    /// The answer is malformed or its cosignature does not verify under the declared key.
    #[error("cosignature")]
    Cosignature,
    /// The declaration is malformed.
    #[error("declaration: {0}")]
    Declaration(String),
}

/// A declared witness: where checkpoints go, the key its cosignatures verify under and
/// whether it counts as independent of the provider operator (SI-12, B13).
#[derive(Clone, Debug)]
pub struct Target {
    /// `http://host:port[/prefix]`.
    pub url: String,
    /// Its `vkey`.
    pub vkey: String,
    /// The operator it declares.
    pub operator: String,
    /// Not run by the provider operator.
    pub independent: bool,
    verifier: Verifier,
}

/// Whether two operator names are the same operator (trimmed, case-insensitive).
#[must_use]
pub fn same_operator(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

impl Target {
    /// A witness at `url` with `vkey`, run by `operator`, for a provider run by `provider`.
    /// A witness of the provider's own operator is never independent (SI-12, B13, 6082).
    ///
    /// # Errors
    /// [`WitnessError::Declaration`].
    pub fn new(
        url: &str,
        vkey: &str,
        operator: &str,
        provider: &str,
    ) -> Result<Self, WitnessError> {
        split(url).map_err(WitnessError::Declaration)?;
        let verifier =
            Verifier::parse(vkey).map_err(|e| WitnessError::Declaration(e.to_string()))?;
        if !verifier.is_cosigner() {
            return Err(WitnessError::Declaration("not a cosigner key".into()));
        }
        if operator.trim().is_empty() || provider.trim().is_empty() {
            return Err(WitnessError::Declaration(
                "operator names are required".into(),
            ));
        }
        Ok(Self {
            url: url.to_owned(),
            vkey: vkey.to_owned(),
            operator: operator.to_owned(),
            independent: !same_operator(operator, provider),
            verifier,
        })
    }

    /// Verifies that `line` is this witness's cosignature over the checkpoint `note`; its
    /// time in seconds.
    ///
    /// # Errors
    /// [`WitnessError::Cosignature`].
    pub fn verify(&self, note: &str, line: &str) -> Result<u64, WitnessError> {
        let cosigned = format!("{note}{line}");
        let (_, accepted) = verify_note(
            &PureBackend,
            &cosigned,
            std::slice::from_ref(&self.verifier),
        )
        .map_err(|_| WitnessError::Cosignature)?;
        accepted
            .iter()
            .find_map(|a| a.timestamp)
            .ok_or(WitnessError::Cosignature)
    }
}

fn split(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("not an http:// URL: {url}"))?;
    let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    if host.is_empty() || !host.contains(':') {
        return Err(format!("URL needs host:port: {url}"));
    }
    Ok((host.to_owned(), format!("/{}", path.trim_end_matches('/'))))
}

/// One HTTP/1.1 exchange on its own connection: status and body.
async fn exchange(
    url: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(u16, String), WitnessError> {
    let (host, prefix) = split(url).map_err(WitnessError::Declaration)?;
    let target = format!("{}{path}", prefix.trim_end_matches('/'));
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    let io = async {
        let mut s = tokio::net::TcpStream::connect(host.as_str()).await.ok()?;
        s.write_all(request.as_bytes()).await.ok()?;
        let mut raw = Vec::new();
        s.take(MAX_ANSWER).read_to_end(&mut raw).await.ok()?;
        String::from_utf8(raw).ok()
    };
    let text = tokio::time::timeout(EXCHANGE_TIMEOUT, io)
        .await
        .ok()
        .flatten()
        .ok_or(WitnessError::Unreachable)?;
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or(WitnessError::Cosignature)?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(WitnessError::Cosignature)?;
    Ok((status, rest.to_owned()))
}

/// Sends `note` to `target` with the consistency `proof` from base size `old`; the verified
/// cosignature line and its time in seconds.
///
/// # Errors
/// [`WitnessError`]; [`WitnessError::Conflict`] names the base the witness holds.
pub async fn add_checkpoint(
    target: &Target,
    (old, proof): (u64, &[[u8; 32]]),
    note: &str,
    excerpt: &[u8],
    metadata: &[u8],
) -> Result<(String, u64), WitnessError> {
    let body = suiss_ledger::checkpoint::witness::add_checkpoint(old, proof, note);
    let excerpt = access_kernel::json::b64url_encode(excerpt);
    let metadata = access_kernel::json::b64url_encode(metadata);
    let (status, answer) = exchange(
        &target.url,
        "POST",
        "/add-checkpoint",
        &[
            ("Content-Type", "text/plain; charset=utf-8"),
            (EXCERPT_HEADER, &excerpt),
            (METADATA_HEADER, &metadata),
        ],
        &body,
    )
    .await?;
    match status {
        200 => {
            let time = target.verify(note, &answer)?;
            Ok((answer, time))
        }
        409 => answer
            .trim()
            .parse::<u64>()
            .map_or(Err(WitnessError::Refused(409)), |n| {
                Err(WitnessError::Conflict(n))
            }),
        other => Err(WitnessError::Refused(other)),
    }
}

/// The latest cosigned note `target` holds for `domain` (gossip, §9.16).
///
/// # Errors
/// [`WitnessError`].
pub async fn latest(target: &Target, domain: &Digest) -> Result<String, WitnessError> {
    let path = format!(
        "/checkpoint/{}",
        access_kernel::json::b64url_encode(&domain.0)
    );
    match exchange(&target.url, "GET", &path, &[], "").await? {
        (200, note) => {
            verify_note(&PureBackend, &note, std::slice::from_ref(&target.verifier))
                .map_err(|_| WitnessError::Cosignature)?;
            Ok(note)
        }
        (other, _) => Err(WitnessError::Refused(other)),
    }
}

#[derive(Default)]
struct Slot {
    witnessed: u64,
    wanted: u64,
}

/// What this process knows of its led domains' witnessed sizes, and the out-of-cycle
/// checkpoints commits ask for.
#[derive(Default)]
pub struct Board {
    slots: Mutex<HashMap<Digest, Slot>>,
    wake: Notify,
    progress: Notify,
}

impl Board {
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<Digest, Slot>) -> T) -> T {
        f(&mut self.slots.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Asks for a checkpoint covering `size` records of `domain` before the cadence's next
    /// one; asks that arrive together are served by one checkpoint (OP-38).
    pub fn want(&self, domain: Digest, size: u64) {
        let new = self.with(|s| {
            let slot = s.entry(domain).or_default();
            let new = size > slot.wanted.max(slot.witnessed);
            slot.wanted = slot.wanted.max(size);
            new
        });
        if new {
            self.wake.notify_one();
        }
    }

    /// The out-of-cycle size waiting for `domain`, if any is above what is witnessed.
    #[must_use]
    pub fn wanted(&self, domain: &Digest) -> Option<u64> {
        self.with(|s| {
            s.get(domain)
                .filter(|slot| slot.wanted > slot.witnessed)
                .map(|slot| slot.wanted)
        })
    }

    /// The largest size an independent witness cosigned, as this process saw it.
    #[must_use]
    pub fn witnessed(&self, domain: &Digest) -> u64 {
        self.with(|s| s.get(domain).map_or(0, |slot| slot.witnessed))
    }

    /// An independent witness cosigned `size`; waiters it covers return.
    pub fn set_witnessed(&self, domain: Digest, size: u64) {
        self.with(|s| {
            let slot = s.entry(domain).or_default();
            slot.witnessed = slot.witnessed.max(size);
        });
        self.progress.notify_waiters();
    }

    /// Resolves when an out-of-cycle checkpoint was asked for.
    pub async fn woken(&self) {
        self.wake.notified().await;
    }

    /// Waits until `size` records of `domain` are witnessed, at most `wait`; the witnessed
    /// size either way (`Err` when it is still below `size`: the answer says `ack: pending`).
    ///
    /// # Errors
    /// The witnessed size, below `size`.
    pub async fn wait(&self, domain: Digest, size: u64, wait: Duration) -> Result<u64, u64> {
        self.want(domain, size);
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let progressed = self.progress.notified();
            let now = self.witnessed(&domain);
            if now >= size {
                return Ok(now);
            }
            if tokio::time::timeout_at(deadline, progressed).await.is_err() {
                let now = self.witnessed(&domain);
                return if now >= size { Ok(now) } else { Err(now) };
            }
        }
    }
}

/// The process's board.
#[must_use]
pub fn board() -> &'static Board {
    static BOARD: OnceLock<Board> = OnceLock::new();
    BOARD.get_or_init(Board::default)
}

static AHEAD_OF_WITNESS: AtomicBool = AtomicBool::new(false);

/// Records the cross-check of a cosignature at `cosigned_seconds` against the newest record
/// time `recorded_at` of its checkpoint (TI-RT2, FA-3, OP-158 m.3 (k)); a failure marks the
/// leader unhealthy until a later cosignature agrees.
///
/// # Errors
/// [`TimeError::AheadOfWitness`].
pub fn cross_check(recorded_at: u64, cosigned_seconds: u64) -> Result<(), TimeError> {
    let result = check_against_witness(recorded_at, cosigned_seconds, UNCERTAINTY_MS);
    AHEAD_OF_WITNESS.store(result.is_err(), Ordering::SeqCst);
    if result.is_err() {
        tracing::error!(
            recorded_at,
            cosigned_seconds,
            "the log clock is ahead of a witness: commits stop until a cosignature agrees (TI-RT2)"
        );
    }
    result
}

/// Whether the last witness cross-check passed.
///
/// # Errors
/// [`TimeError::AheadOfWitness`]: no commit.
pub fn time_check() -> Result<(), TimeError> {
    if AHEAD_OF_WITNESS.load(Ordering::SeqCst) {
        Err(TimeError::AheadOfWitness)
    } else {
        Ok(())
    }
}

/// A Roughtime server: `host:port` and its long-term Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoughtimeServer {
    /// `host:port` (UDP).
    pub addr: String,
    /// Long-term public key.
    pub key: [u8; 32],
}

/// Readings older than this are not used.
pub const ROUGHTIME_STALE: Duration = Duration::from_secs(300);

/// The latest Roughtime readings, extrapolated by the monotonic clock.
#[derive(Default)]
pub struct Roughtime {
    last: Mutex<Option<(Sample, Instant)>>,
}

fn nonce() -> Option<[u8; 32]> {
    aws_lc_rs::rand::generate::<[u8; 32]>(&aws_lc_rs::rand::SystemRandom::new())
        .ok()
        .map(aws_lc_rs::rand::Random::expose)
}

/// One verified reading from `server`.
///
/// # Errors
/// A short reason; the source is left out.
pub async fn read_roughtime(server: &RoughtimeServer) -> Result<Sample, String> {
    let n = nonce().ok_or("no randomness")?;
    let request = suiss_crypto::roughtime::request(&n).map_err(|e| e.to_string())?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    socket
        .connect(server.addr.as_str())
        .await
        .map_err(|e| e.to_string())?;
    socket.send(&request).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0_u8; suiss_crypto::roughtime::MAX_RESPONSE];
    let len = tokio::time::timeout(EXCHANGE_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let answer = buf.get(..len).ok_or("short answer")?;
    let r =
        suiss_crypto::roughtime::verify_response(&PureBackend, &server.key, &request, &n, answer)
            .map_err(|e| e.to_string())?;
    Ok(Sample {
        at: r.midpoint_ms(),
        radius: r.radius_ms(),
    })
}

impl Roughtime {
    /// Reads every server once and keeps the reading of the first that answers.
    pub async fn sample(&self, servers: &[RoughtimeServer]) {
        for s in servers {
            match read_roughtime(s).await {
                Ok(sample) => {
                    *self.last.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some((sample, Instant::now()));
                    return;
                }
                Err(error) => {
                    tracing::warn!(server = %s.addr, %error, "Roughtime source not read");
                }
            }
        }
    }

    /// The latest reading moved forward by the time since it was taken, its radius widened by
    /// one millisecond per second of age; `None` when there is none or it is stale.
    #[must_use]
    pub fn current(&self) -> Option<Sample> {
        let (s, at) = (*self.last.lock().unwrap_or_else(PoisonError::into_inner))?;
        let age = at.elapsed();
        if age > ROUGHTIME_STALE {
            return None;
        }
        let ms = u64::try_from(age.as_millis()).ok()?;
        Some(Sample {
            at: s.at.saturating_add(ms),
            radius: s.radius.saturating_add(age.as_secs()),
        })
    }
}

/// The process's Roughtime source, read by the clock port.
#[must_use]
pub fn roughtime() -> &'static Roughtime {
    static SOURCE: OnceLock<Roughtime> = OnceLock::new();
    SOURCE.get_or_init(Roughtime::default)
}

#[cfg(test)]
mod tests;
