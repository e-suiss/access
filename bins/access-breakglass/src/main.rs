//! Access operator break-glass tool (OP-46, CMP-25, G63, OP-157 m.3 (j)).
//!
//! A separate code path for a cell's infrastructure operator when the normal path is down: no
//! database, Redis, signer, Relay, risk engine or MFA orchestrator. A use needs a short-lived
//! document approved M-of-N (default 2-of-3) by the cell's Ed25519 or FIDO2 keys, verified
//! offline; each nonce works once, a used key set must be rotated, and every step goes to a
//! hash-chained local trail, syslog, the SIEM when it answers and the on-call alarm hook. The
//! tool reads configuration and health, and leaves signed directives (epoch floor, leader
//! unhealthy or healthy, feature flags) for `access-server`. It makes no authority decision
//! and touches no authority state or user data (SI-22).
//!
//! ```text
//! access-breakglass keygen <seed-file>
//! access-breakglass document <cell> <op,op,...> <minutes> <document>
//! access-breakglass approve <document> <key-id> <seed-file>
//! access-breakglass run <cell-dir> <document>
//! access-breakglass drill <cell-dir> <document>
//! access-breakglass rotate <cell-dir> <new-keys>
//! access-breakglass verify <cell-dir>
//! ```

mod cell;
mod syslog;
mod trail;

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use access_crypto::breakglass::{Directive, Document, KeySet, Op, OperatorKey, hex};
use access_crypto::secret_file::SecretFile;

use cell::Cell;
use trail::Trail;

/// The largest document read.
const MAX_DOCUMENT: u64 = 64 * 1024;

/// How long the alarm hook may run.
const ALARM_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the tool stopped.
#[derive(Debug)]
pub(crate) enum Failure {
    /// Wrong arguments.
    Usage,
    /// The cell directory is incomplete or unreadable.
    Setup(&'static str),
    /// The document or key set was refused, with the reason code.
    Refused(&'static str),
    /// The trail does not verify or cannot be written.
    Trail,
    /// The alarm hook did not confirm.
    Alarm,
}

impl Failure {
    fn exit(&self) -> ExitCode {
        let (code, text) = match self {
            Self::Usage => (2, "usage: see `access-breakglass` documentation".to_owned()),
            Self::Setup(what) => (2, format!("cell setup: {what}")),
            Self::Refused(code) => (1, format!("refused: {code}")),
            Self::Trail => (3, "trail broken or unwritable; refusing to run".to_owned()),
            Self::Alarm => (4, "alarm hook failed; nothing was applied".to_owned()),
        };
        let _ = writeln!(std::io::stderr(), "access-breakglass: {text}");
        ExitCode::from(code)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn out(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

fn warn(line: &str) {
    let _ = writeln!(std::io::stderr(), "access-breakglass: {line}");
}

/// One trail line, then its syslog and SIEM copies.
fn record(cell: &Cell, trail: &mut Trail, event: &str, fields: &str) -> Result<u64, Failure> {
    let at = now_ms();
    let seq = trail.write(at, event, fields)?;
    let msg = syslog::message(at, event, &format!("cell={} seq={seq} {fields}", cell.name));
    match &cell.syslog {
        Some(target) => {
            if let Err(e) = syslog::send(target, &msg) {
                warn(e);
            }
        }
        None => warn("no syslog target"),
    }
    if let Some(addr) = &cell.siem
        && let Err(e) = syslog::siem(addr, &msg)
    {
        warn(e);
    }
    Ok(seq)
}

/// Runs the cell's alarm hook with `event cell document` and waits for it (§17.7.3 principle 7).
fn alarm(cell: &Cell, event: &str, document: &str) -> Result<(), Failure> {
    let mut child = std::process::Command::new(&cell.alarm)
        .args([event, cell.name.as_str(), document])
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|_| Failure::Alarm)?;
    let deadline = Instant::now()
        .checked_add(ALARM_TIMEOUT)
        .ok_or(Failure::Alarm)?;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| Failure::Alarm)? {
            return if status.success() {
                Ok(())
            } else {
                Err(Failure::Alarm)
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Failure::Alarm);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_document(path: &Path) -> Result<Document, Failure> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_DOCUMENT).read_to_end(&mut bytes))
        .map_err(|_| Failure::Setup("document"))?;
    Document::decode(&bytes).map_err(|e| Failure::Refused(e.code()))
}

fn operator_key(path: &Path) -> Result<OperatorKey, Failure> {
    let seed = SecretFile::load(path).map_err(|_| Failure::Setup("key file"))?;
    OperatorKey::from_hex(seed.value()).map_err(|_| Failure::Setup("key file"))
}

/// Checks the document against the cell's keys, its nonces and its spent generation.
fn admit(cell: &Cell, keys: &KeySet, doc: &Document) -> Result<Vec<String>, &'static str> {
    let approvers = doc
        .verify(keys, &cell.name, now_ms())
        .map_err(|e| e.code())?;
    if cell
        .nonce_used(&hex(&doc.nonce))
        .map_err(|_| "nonce-file")?
    {
        return Err("replayed");
    }
    // §17.7.3 principle 8
    if cell
        .spent_generation()
        .map_err(|_| "spent-file")?
        .is_some_and(|g| g >= keys.generation)
    {
        return Err("rotation-required");
    }
    Ok(approvers)
}

fn health(addr: &str) -> String {
    use std::net::ToSocketAddrs as _;
    let Some(sock) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return "health address invalid".to_owned();
    };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)) else {
        return "health unreachable".to_owned();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return "health unreachable".to_owned();
    }
    let mut answer = Vec::new();
    let _ = s.take(4096).read_to_end(&mut answer);
    String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap_or("health no answer")
        .to_owned()
}

/// `run` and `drill`: the whole path; a drill applies nothing (§17.7.3 principle 9).
fn use_document(dir: &Path, document: &Path, drill: bool) -> Result<(), Failure> {
    let cell = Cell::load(dir)?;
    cell.ensure_state()?;
    let mut trail = Trail::open(&cell.trail())?;
    let keys = cell.keys()?;
    let doc = read_document(document)?;
    let digest = hex(&doc.digest().map_err(|e| Failure::Refused(e.code()))?);
    let approvers = match admit(&cell, &keys, &doc) {
        Ok(a) => a,
        Err(code) => {
            record(
                &cell,
                &mut trail,
                "refused",
                &format!("doc={digest},reason={code}"),
            )?;
            let _ = alarm(&cell, "refused", &digest);
            return Err(Failure::Refused(code));
        }
    };
    cell.use_nonce(&hex(&doc.nonce))?;
    let ops: Vec<String> = doc.ops.iter().map(Op::name).collect();
    let event = if drill { "drill" } else { "used" };
    record(
        &cell,
        &mut trail,
        event,
        &format!(
            "doc={digest},generation={},approvers={},ops={}",
            keys.generation,
            approvers.join("+"),
            ops.join("+")
        ),
    )?;
    if alarm(&cell, event, &digest).is_err() {
        record(&cell, &mut trail, "alarm-failed", &format!("doc={digest}"))?;
        return Err(Failure::Alarm);
    }
    if drill {
        operator_key(&cell.directive_key())?;
        if !cell.ops.is_dir() {
            return Err(Failure::Setup("ops directory"));
        }
        record(&cell, &mut trail, "drill-done", &format!("doc={digest}"))?;
        out(&format!(
            "drill {digest}: verified, recorded, alarmed; nothing applied"
        ));
        return Ok(());
    }
    let key = operator_key(&cell.directive_key())?;
    // §17.7.3 principle 8
    cell.spend(keys.generation)?;
    record(
        &cell,
        &mut trail,
        "spent",
        &format!("generation={}", keys.generation),
    )?;
    apply(&cell, &mut trail, &doc, &key)?;
    out("key set spent: rotate it before the next use");
    Ok(())
}

/// Carries out the document's operations: reads print, the rest become directives.
fn apply(cell: &Cell, trail: &mut Trail, doc: &Document, key: &OperatorKey) -> Result<(), Failure> {
    let document_digest = doc.digest().map_err(|e| Failure::Refused(e.code()))?;
    let digest = hex(&document_digest);
    let directives = cell.directives();
    std::fs::create_dir_all(&directives).map_err(|_| Failure::Setup("ops directory"))?;
    for op in &doc.ops {
        match op {
            Op::ConfigRead => {
                let path = cell.config.as_ref().ok_or(Failure::Setup("config path"))?;
                record(cell, trail, "read", &format!("doc={digest},op=config.read"))?;
                let text = std::fs::read_to_string(path).map_err(|_| Failure::Setup("config"))?;
                out(&text);
            }
            Op::Health => {
                let addr = cell
                    .health
                    .as_ref()
                    .ok_or(Failure::Setup("health address"))?;
                record(cell, trail, "read", &format!("doc={digest},op=health"))?;
                out(&health(addr));
            }
            _ => {
                let seq = record(
                    cell,
                    trail,
                    "directive",
                    &format!("doc={digest},op={}", op.name()),
                )?;
                let file = Directive {
                    cell: cell.name.clone(),
                    seq,
                    op: op.clone(),
                    at_ms: now_ms(),
                    document: document_digest,
                }
                .sign(key)
                .map_err(|e| Failure::Refused(e.code()))?;
                let path = directives.join(format!("{seq:020}.cbor"));
                cell::replace(&path, &file).map_err(|_| Failure::Setup("ops directory"))?;
                out(&format!("directive {seq} {}", op.name()));
            }
        }
    }
    Ok(())
}

/// `rotate`: installs a key set of a higher generation sharing no key with the current one.
fn rotate(dir: &Path, new: &Path) -> Result<(), Failure> {
    let cell = Cell::load(dir)?;
    cell.ensure_state()?;
    let mut trail = Trail::open(&cell.trail())?;
    let current = cell.keys()?;
    let text = std::fs::read_to_string(new).map_err(|_| Failure::Setup("new keys"))?;
    let next = KeySet::parse(&text).map_err(|e| Failure::Refused(e.code()))?;
    if next.generation <= current.generation || next.shares_key_with(&current) {
        return Err(Failure::Refused("rotation-not-new"));
    }
    cell.install_keys(&text)?;
    record(
        &cell,
        &mut trail,
        "rotated",
        &format!("from={},to={}", current.generation, next.generation),
    )?;
    out(&format!("rotated to generation {}", next.generation));
    Ok(())
}

fn keygen(path: &Path) -> Result<(), Failure> {
    let (key, seed) = OperatorKey::generate().map_err(|_| Failure::Setup("randomness"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(path).map_err(|_| Failure::Setup("key file"))?;
    f.write_all(seed.expose().as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| Failure::Setup("key file"))?;
    out(&format!("ed25519 {}", hex(&key.public())));
    Ok(())
}

fn document(cell: &str, ops: &str, minutes: &str, path: &Path) -> Result<(), Failure> {
    let ops = ops
        .split(',')
        .map(Op::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Failure::Refused(e.code()))?;
    let minutes: u64 = minutes.parse().map_err(|_| Failure::Usage)?;
    let now = now_ms();
    let end = minutes
        .checked_mul(60_000)
        .and_then(|w| now.checked_add(w))
        .ok_or(Failure::Usage)?;
    let nonce = access_crypto::random::bytes::<16>().map_err(|_| Failure::Setup("randomness"))?;
    let doc = Document::new(cell, ops, nonce, now, end).map_err(|e| Failure::Refused(e.code()))?;
    let bytes = doc.encode().map_err(|e| Failure::Refused(e.code()))?;
    std::fs::write(path, bytes).map_err(|_| Failure::Setup("document"))?;
    out(&format!(
        "{} challenge {}",
        hex(&doc.digest().map_err(|e| Failure::Refused(e.code()))?),
        doc.challenge().map_err(|e| Failure::Refused(e.code()))?
    ));
    Ok(())
}

fn approve(path: &Path, id: &str, seed: &Path) -> Result<(), Failure> {
    let mut doc = read_document(path)?;
    let key = operator_key(seed)?;
    doc.approve(id, &key)
        .map_err(|e| Failure::Refused(e.code()))?;
    let bytes = doc.encode().map_err(|e| Failure::Refused(e.code()))?;
    cell::replace(path, &bytes).map_err(|_| Failure::Setup("document"))
}

fn verify(dir: &Path) -> Result<(), Failure> {
    let cell = Cell::load(dir)?;
    Trail::open(&cell.trail())?;
    cell.keys()?;
    out("trail verifies; key set valid");
    Ok(())
}

fn dispatch(args: &[OsString]) -> Result<(), Failure> {
    let s: Vec<&str> = args
        .iter()
        .map(|a| a.to_str().ok_or(Failure::Usage))
        .collect::<Result<_, _>>()?;
    let p = PathBuf::from;
    match s.as_slice() {
        ["keygen", file] => keygen(&p(file)),
        ["document", cell, ops, minutes, file] => document(cell, ops, minutes, &p(file)),
        ["approve", file, id, seed] => approve(&p(file), id, &p(seed)),
        ["run", dir, file] => use_document(&p(dir), &p(file), false),
        ["drill", dir, file] => use_document(&p(dir), &p(file), true),
        ["rotate", dir, keys] => rotate(&p(dir), &p(keys)),
        ["verify", dir] => verify(&p(dir)),
        _ => Err(Failure::Usage),
    }
}

fn main() -> ExitCode {
    // OP-129 m.3
    if access_crypto::secret_file::refuse_secret_environment(
        std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
    )
    .is_err()
    {
        return Failure::Setup("secret in the environment").exit();
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => f.exit(),
    }
}
