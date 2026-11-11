//! The provider's side of the witness protocol and of trusted time (§16.6 witness protocol,
//! CMP-6, T17, SEC23, TI-RT2, OP-158 m.3 (c), (d), (k)):
//! - each declared witness gets every checkpoint as a `cosign-request` (`witness.cddl`) with
//!   the consistency proof from the head it last cosigned, and its cosignature is verified
//!   before it is kept;
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
use suiss_ledger::checkpoint::witness::{CosignRequest, CosignResponse, GossipEntry, Refused};
use suiss_ledger::time::{Sample, TimeError, UNCERTAINTY_MS, check_against_witness};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;

/// How long one witness exchange may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest an SEC23 answer waits for its covering cosignature (OP-158 m.3 (e), PD).
pub const ACK_WAIT: Duration = Duration::from_secs(2);

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
    /// It answered this status without a refusal it names.
    #[error("refused with {0}")]
    Refused(u16),
    /// It refused, naming why (`cosign-refusal`), with this status.
    #[error("refused: {}", .0.name())]
    Said(Refused, u16),
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

/// The configured witnesses the domain's Domain Metadata declares (OP-158 m.3 (d), m.6 (e)):
/// a witness counts only when the metadata names its key, and is independent only when both
/// the declaration and the operators say so (SI-12, B13). Without a declaration none counts.
#[must_use]
pub fn declared(
    targets: &[Target],
    declared: &access_kernel::verify::key_scope::Declarations,
) -> Vec<Target> {
    targets
        .iter()
        .filter_map(|t| {
            let w = declared.witnesses.iter().find(|w| {
                let suiss_crypto::cose::PublicKey::Ed25519(k) = w.key else {
                    return false;
                };
                Verifier::cosigner(&w.name, k).is_ok_and(|v| v.to_vkey() == t.vkey)
            })?;
            let mut t = t.clone();
            t.independent = t.independent && w.independent;
            Some(t)
        })
        .collect()
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
    body: &[u8],
) -> Result<(u16, Vec<u8>), WitnessError> {
    let (host, prefix) = split(url).map_err(WitnessError::Declaration)?;
    let target = format!("{}{path}", prefix.trim_end_matches('/'));
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let io = async {
        let mut s = tokio::net::TcpStream::connect(host.as_str()).await.ok()?;
        s.write_all(&request).await.ok()?;
        let mut raw = Vec::new();
        s.take(MAX_ANSWER).read_to_end(&mut raw).await.ok()?;
        Some(raw)
    };
    let raw = tokio::time::timeout(EXCHANGE_TIMEOUT, io)
        .await
        .ok()
        .flatten()
        .ok_or(WitnessError::Unreachable)?;
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(WitnessError::Cosignature)?;
    let (head, rest) = raw.split_at(at);
    let status = std::str::from_utf8(head)
        .ok()
        .and_then(|h| h.split(' ').nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(WitnessError::Cosignature)?;
    Ok((status, rest.get(4..).unwrap_or_default().to_vec()))
}

/// A witness's base: the size and root it last cosigned.
pub type Base = (u64, [u8; 32]);

/// Asks `target` to cosign `note` of `domain`, extending its `base` by the consistency
/// `proof` (`witness.cddl` `cosign-request`); the verified cosignature line and its time in
/// seconds.
///
/// # Errors
/// [`WitnessError`]; [`WitnessError::Refused`] with the witness's status.
pub async fn add_checkpoint(
    target: &Target,
    domain: &Digest,
    (base, proof): (Option<Base>, &[[u8; 32]]),
    note: &str,
    excerpt: &[u8],
) -> Result<(String, u64), WitnessError> {
    let body = CosignRequest {
        domain: domain.0,
        note: note.to_owned(),
        excerpt: excerpt.to_vec(),
        base,
        consistency: proof.to_vec(),
        binding_change: None,
    }
    .to_bytes()
    .map_err(|_| WitnessError::Cosignature)?;
    let (status, answer) = exchange(&target.url, "POST", "/cosign", &body).await?;
    match CosignResponse::from_bytes(&answer) {
        Ok(CosignResponse::Cosigned(c)) if status == 200 => {
            let line = c.line(target.verifier.id());
            let time = target.verify(note, &line)?;
            Ok((line, time))
        }
        Ok(CosignResponse::Refused(r)) => Err(WitnessError::Said(r, status)),
        _ => Err(WitnessError::Refused(status)),
    }
}

/// The latest head `target` cosigned for `domain`, its cosignature verified over the note it
/// carries (gossip, §9.16): the entry and the cosigned note.
///
/// # Errors
/// [`WitnessError`].
pub async fn latest(
    target: &Target,
    domain: &Digest,
) -> Result<(GossipEntry, String), WitnessError> {
    let path = format!("/gossip/{}", access_kernel::json::b64url_encode(&domain.0));
    let (status, body) = exchange(&target.url, "GET", &path, &[]).await?;
    if status != 200 {
        return Err(WitnessError::Refused(status));
    }
    let entry = GossipEntry::from_bytes(&body).map_err(|_| WitnessError::Cosignature)?;
    let note = entry.note.clone().ok_or(WitnessError::Cosignature)?;
    let (n, accepted) = verify_note(&PureBackend, &note, std::slice::from_ref(&target.verifier))
        .map_err(|_| WitnessError::Cosignature)?;
    let cp =
        suiss_crypto::note::Checkpoint::parse(&n.body).map_err(|_| WitnessError::Cosignature)?;
    let covered = (cp.size, cp.root) == (entry.size, entry.root)
        && entry.domain == domain.0
        && accepted
            .iter()
            .any(|a| a.timestamp == Some(entry.cosignature.timestamp));
    if !covered {
        return Err(WitnessError::Cosignature);
    }
    Ok((entry, note))
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
    access_crypto::random::bytes::<32>().ok()
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
