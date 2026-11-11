//! `access-signer ceremony init|approve|sign|transcript` (CR-29, OP-157 m.3 (x)): the software
//! quorum over the binding keys. Ceremony keys and assertions come from files the operator
//! names, never from arguments or the environment.
//!
//! ```text
//! access-signer ceremony init <transcript> <permit> roster <roster.toml>
//! access-signer ceremony init <transcript> <permit> activate <hours>
//! access-signer ceremony init <transcript> <permit> deactivate
//! access-signer ceremony approve <transcript> <permit> <member> ed25519 <key-file>
//! access-signer ceremony approve <transcript> <permit> <member> fido2 <assertion-file>
//! access-signer ceremony sign <transcript> <permit>
//! access-signer ceremony transcript <transcript> <genesis-hex>
//! ```

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use access_authority_signer::ceremony::{
    Approval, CeremonyError, Member, NONCE_LEN, Op, Permit, Roster, State, Transcript,
    policy_digest,
};
use access_crypto::secret_file::SecretFile;
use figment::Figment;
use figment::providers::{Format, Toml};
use serde::Deserialize;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::rotation::Policy;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::SoftSigner;

/// Why a ceremony command failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommandError {
    /// The arguments do not name a command.
    #[error("usage: access-signer ceremony init|approve|sign|transcript ...")]
    Usage,
    /// A file could not be read or written.
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::ErrorKind),
    /// A file is not what it should hold.
    #[error("{0}: {1}")]
    Content(PathBuf, &'static str),
    /// The ceremony refused.
    #[error("{}", .0.code())]
    Ceremony(#[from] CeremonyError),
    /// No randomness for the nonce.
    #[error("no randomness available")]
    Random,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
        out
    })
}

/// Bytes of a hex string.
pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>, CommandError> {
    std::fs::read(path).map_err(|e| CommandError::Io(path.to_path_buf(), e.kind()))
}

/// Replaces `path` atomically.
fn write(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).map_err(|e| CommandError::Io(tmp.clone(), e.kind()))?;
    std::fs::rename(&tmp, path).map_err(|e| CommandError::Io(path.to_path_buf(), e.kind()))
}

fn say(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterFile {
    threshold: Option<u8>,
    members: Vec<MemberFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberFile {
    ed25519: Option<String>,
    fido2: Option<String>,
    rp_id: Option<String>,
}

/// A roster TOML file: `threshold` (default 2) and `[[members]]` with `ed25519 = "<hex>"` or
/// `fido2 = "<hex SEC1>"` and `rp_id`.
pub(crate) fn roster_file(path: &Path) -> Result<Roster, CommandError> {
    let bad = |what| CommandError::Content(path.to_path_buf(), what);
    let file: RosterFile = Figment::from(Toml::file_exact(path))
        .extract()
        .map_err(|_| bad("not a roster file"))?;
    let mut members = Vec::with_capacity(file.members.len());
    for m in file.members {
        members.push(match (m.ed25519, m.fido2, m.rp_id) {
            (Some(k), None, None) => Member::Ed25519(
                unhex(&k)
                    .and_then(|k| k.try_into().ok())
                    .ok_or_else(|| bad("ed25519 must be 32 bytes of hex"))?,
            ),
            (None, Some(k), Some(rp_id)) => Member::Fido2 {
                sec1: unhex(&k).ok_or_else(|| bad("fido2 must be hex"))?,
                rp_id,
            },
            _ => return Err(bad("a member is ed25519, or fido2 with rp_id")),
        });
    }
    let roster = Roster {
        threshold: file
            .threshold
            .unwrap_or(access_authority_signer::ceremony::DEFAULT_THRESHOLD),
        members,
    };
    roster.check()?;
    Ok(roster)
}

/// An Ed25519 ceremony key: one line of hex PKCS#8 in a file only its owner reads.
pub(crate) fn member_key(path: &Path) -> Result<SoftSigner, CommandError> {
    let file = SecretFile::load(path)
        .map_err(|_| CommandError::Content(path.to_path_buf(), "unreadable key file"))?;
    let der = unhex(file.value().expose())
        .ok_or(CommandError::Content(path.to_path_buf(), "not hex PKCS#8"))?;
    SoftSigner::ed25519_from_pkcs8(&Secret::new(der))
        .map_err(|_| CommandError::Content(path.to_path_buf(), "not an Ed25519 PKCS#8 key"))
}

fn assertion(path: &Path, member: u8) -> Result<Approval, CommandError> {
    let bad = || CommandError::Content(path.to_path_buf(), "not a CBOR {auth_data, sig} map");
    let v = dcbor::decode(&read(path)?, Limits::CEILING).map_err(|_| bad())?;
    match (v.get("auth_data"), v.get("sig")) {
        (Some(Value::Bytes(a)), Some(Value::Bytes(s))) => Ok(Approval::Fido2 {
            member,
            auth_data: a.clone(),
            sig: s.clone(),
        }),
        _ => Err(bad()),
    }
}

/// The transcript at `path`, verified against its own first entry. The signer itself pins the
/// genesis; this read only finds the roster.
fn unpinned(path: &Path) -> Result<Transcript, CommandError> {
    let bytes = read(path)?;
    let genesis = Transcript::genesis_of(&bytes)?;
    Ok(Transcript::open(&bytes, &genesis)?)
}

fn roster_for(transcript: &Path, permit: &Permit) -> Result<Roster, CommandError> {
    match &permit.op {
        Op::Init(r) => Ok(r.clone()),
        _ => Ok(unpinned(transcript)?.state().roster.clone()),
    }
}

/// CR-29, OP-157 m.3 (x)
fn audit(step: &str, op: &str, state: &State, approvals: usize) {
    tracing::info!(
        event = "signer.ceremony",
        step,
        op,
        seq = state.len.saturating_sub(1),
        head = hex(&state.head),
        genesis = hex(&state.genesis),
        approvals,
        "binding key ceremony"
    );
}

/// Logs the activation the signer adopted from `state`.
pub(crate) fn adopted(state: &State) {
    audit("adopted", "activate", state, 0);
}

fn draft(args: &[OsString], transcript: &Path, permit: &Path) -> Result<(), CommandError> {
    let now = now_ms();
    let op = match args {
        [kind, file] if kind == "roster" => {
            if transcript.exists() {
                return Err(CommandError::Content(
                    transcript.to_path_buf(),
                    "a transcript exists; init starts a new one",
                ));
            }
            Op::Init(roster_file(Path::new(file))?)
        }
        [kind, hours] if kind == "activate" => {
            let hours: u64 = hours
                .to_str()
                .and_then(|h| h.parse().ok())
                .ok_or(CommandError::Usage)?;
            Op::Activate {
                policy: policy_digest(&Policy::AUTHORITY),
                until: hours
                    .checked_mul(3_600_000)
                    .and_then(|ms| now.checked_add(ms))
                    .ok_or(CommandError::Usage)?,
            }
        }
        [kind] if kind == "deactivate" => Op::Deactivate,
        _ => return Err(CommandError::Usage),
    };
    let nonce = access_crypto::random::bytes::<NONCE_LEN>().map_err(|_| CommandError::Random)?;
    let p = Permit::draft(op, now, nonce)?;
    write(permit, &p.encode()?)?;
    say(&format!(
        "permit {} until {}; FIDO2 client data hash {}",
        p.op.name(),
        p.not_after,
        hex(&access_crypto::webauthn::sha256(&p.signed_bytes()?))
    ));
    Ok(())
}

fn approve(args: &[OsString], transcript: &Path, permit: &Path) -> Result<(), CommandError> {
    let [member, kind, file] = args else {
        return Err(CommandError::Usage);
    };
    let member: u8 = member
        .to_str()
        .and_then(|m| m.parse().ok())
        .ok_or(CommandError::Usage)?;
    let mut p = Permit::decode(&read(permit)?)?;
    let roster = roster_for(transcript, &p)?;
    if kind == "ed25519" {
        p.approve_with(&roster, member, &member_key(Path::new(file))?)?;
    } else if kind == "fido2" {
        p.approve(&roster, assertion(Path::new(file), member)?)?;
    } else {
        return Err(CommandError::Usage);
    }
    write(permit, &p.encode()?)?;
    say(&format!(
        "approvals {} of {}",
        p.approvals.len(),
        roster.threshold
    ));
    Ok(())
}

fn seal(transcript: &Path, permit: &Path) -> Result<(), CommandError> {
    let p = Permit::decode(&read(permit)?)?;
    let now = now_ms();
    let t = if let Op::Init(_) = p.op {
        if transcript.exists() {
            return Err(CommandError::Content(
                transcript.to_path_buf(),
                "a transcript exists",
            ));
        }
        Transcript::genesis(&p, now)?
    } else {
        let mut t = unpinned(transcript)?;
        t.seal(&p, now)?;
        t
    };
    write(transcript, t.bytes())?;
    audit("sealed", p.op.name(), t.state(), p.approvals.len());
    say(&hex(&t.state().head));
    Ok(())
}

fn show(transcript: &Path, genesis: &str) -> Result<(), CommandError> {
    let pin: [u8; 32] = unhex(genesis)
        .and_then(|g| g.try_into().ok())
        .ok_or(CommandError::Usage)?;
    let t = Transcript::open(&read(transcript)?, &pin)?;
    let s = t.state();
    say(&format!(
        "entries {}; head {}; {}-of-{}; activation {}",
        s.len,
        hex(&s.head),
        s.roster.threshold,
        s.roster.members.len(),
        s.activation
            .map_or_else(|| String::from("none"), |a| format!("until {}", a.until)),
    ));
    Ok(())
}

/// Runs `access-signer ceremony <args>`.
///
/// # Errors
/// [`CommandError`].
pub(crate) fn run(args: &[OsString]) -> Result<(), CommandError> {
    match args {
        [cmd, transcript, permit, rest @ ..] if cmd == "init" => {
            draft(rest, Path::new(transcript), Path::new(permit))
        }
        [cmd, transcript, permit, rest @ ..] if cmd == "approve" => {
            approve(rest, Path::new(transcript), Path::new(permit))
        }
        [cmd, transcript, permit] if cmd == "sign" => {
            seal(Path::new(transcript), Path::new(permit))
        }
        [cmd, transcript, genesis] if cmd == "transcript" => show(
            Path::new(transcript),
            genesis.to_str().ok_or(CommandError::Usage)?,
        ),
        _ => Err(CommandError::Usage),
    }
}

/// The genesis digest the signer pins, from a read-only file of hex (CR-29).
///
/// # Errors
/// [`CommandError`] when it is unreadable or not 32 bytes of hex.
pub(crate) fn pin(genesis_file: &Path) -> Result<[u8; 32], CommandError> {
    let text = read(genesis_file)?;
    std::str::from_utf8(&text)
        .ok()
        .and_then(unhex)
        .and_then(|g| g.try_into().ok())
        .ok_or(CommandError::Content(
            genesis_file.to_path_buf(),
            "not 32 bytes of hex",
        ))
}

/// The whole transcript at `path`, verified from the pinned genesis `pin` (CR-29).
///
/// # Errors
/// [`CommandError`] when it is unreadable or the chain does not verify.
pub(crate) fn pinned(path: &Path, pin: &[u8; 32]) -> Result<Transcript, CommandError> {
    Ok(Transcript::open(&read(path)?, pin)?)
}

#[cfg(test)]
mod tests;
