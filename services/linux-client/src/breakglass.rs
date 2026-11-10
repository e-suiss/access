//! Local break-glass (OP-156 m.3 (p), Ek B 5207): the only way into the host when Access cannot
//! be reached and the offline limits have run out. The person presents the PAP of the reserved
//! break-glass Grant Access issued in advance (`idp.linux.break_glass_policy`, CT3) with a
//! presentation over the daemon's nonce; the offline verifier (`esuiss-access-verifier`) checks
//! it and draws its one-use slice from the host's counter. An allowed use leaves an allowance
//! that the user's next console sign-in takes once, within [`ALLOWANCE_MS`]. The use is also
//! marked spent on the host, so a restarted daemon never admits the same PAP again.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use access_kernel::intent::ParamValue;
use access_kernel::model::EqValue;
use access_verifier::counter::{CounterError, CounterId, CounterReading, TamperEvidentCounter};
use access_verifier::offline::{Denial, OfflineVerifier, Use, Verdict};
use access_verifier::time::TrustedClock;

/// The reserved break-glass action's namespace.
pub const NAMESPACE: &str = "linux";

/// The reserved break-glass action's name.
pub const ACTION: &str = "break_glass";

/// The parameter that names the Linux user.
pub const PRINCIPAL: &str = "principal";

/// How long an allowance waits for the console sign-in, ms.
pub const ALLOWANCE_MS: u64 = 5 * 60_000;

/// Why no allowance was left.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The intent is not the break-glass action for this user.
    #[error("linux-break-glass-intent")]
    Intent,
    /// The offline verifier denied the use: the slice is spent, the horizon passed, the
    /// clock or counter cannot be trusted, or the PAP does not verify.
    #[error("{0}")]
    Verifier(Denial),
    /// The PAP's break-glass use was spent on this host before (kept across restarts).
    #[error("linux-break-glass-spent")]
    Spent,
    /// The allowance could not be written.
    #[error("linux-break-glass-write")]
    Write,
}

fn allowance(dir: &Path, user: &str) -> PathBuf {
    dir.join(format!("{user}.allow"))
}

/// Verifies one break-glass use for `user` and leaves its allowance in `dir`.
///
/// # Errors
/// [`Refused`].
pub fn admit<K: TrustedClock, C: TamperEvidentCounter>(
    verifier: &mut OfflineVerifier<K, C>,
    dir: &Path,
    user: &str,
    u: &Use<'_>,
) -> Result<(), Refused> {
    let i = u.intent;
    let named = matches!(
        i.params.get(PRINCIPAL),
        Some(ParamValue::Enum(t) | ParamValue::Eq(EqValue::Text(t))) if t == user
    );
    if i.action.namespace != NAMESPACE || i.action.name != ACTION || !named {
        return Err(Refused::Intent);
    }
    let spent_dir = dir.join("spent");
    let spent = |exercise: &access_kernel::digest::Digest| {
        let name: String = exercise.0.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        spent_dir.join(name)
    };
    if let Ok(p) = access_verifier::offline::peek(u.pap)
        && spent(&p.projection_exercise).exists()
    {
        return Err(Refused::Spent);
    }
    let allowed = match verifier.verify(u) {
        Verdict::Allow(a) => a,
        Verdict::Deny(d) => return Err(Refused::Verifier(d)),
    };
    std::fs::create_dir_all(&spent_dir).map_err(|_| Refused::Write)?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(spent(&allowed.pap.projection_exercise))
    {
        Ok(f) => f.sync_all().map_err(|_| Refused::Write)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(Refused::Spent),
        Err(_) => return Err(Refused::Write),
    }
    let until = allowed.now.saturating_add(ALLOWANCE_MS);
    write_atomic(&allowance(dir, user), until.to_string().as_bytes()).map_err(|()| Refused::Write)
}

/// Takes `user`'s allowance once: `true` when one was left before `now` ended it. The
/// allowance is moved aside before it is read, so two sign-ins never share it.
#[must_use]
pub fn take(dir: &Path, user: &str, now: u64) -> bool {
    let from = allowance(dir, user);
    let spent = dir.join(format!("{user}.spent.{now}"));
    if std::fs::rename(&from, &spent).is_err() {
        return false;
    }
    std::fs::read_to_string(&spent)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .is_some_and(|until| now < until)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|_| ())?;
    f.write_all(bytes).map_err(|_| ())?;
    f.sync_all().map_err(|_| ())?;
    std::fs::rename(&tmp, path).map_err(|_| ())
}

/// The host's slice counter in a file: its identity and value, moved forward only. It answers
/// [`CounterError::RolledBack`] when the file goes back below a value this handle saw, and
/// [`CounterError::Wiped`] when its identity changes.
#[derive(Debug)]
pub struct FileCounter {
    path: PathBuf,
    seen: Option<CounterReading>,
}

impl FileCounter {
    /// The counter in `path`, made with identity `id` when the file does not exist.
    ///
    /// # Errors
    /// [`CounterError::Unavailable`].
    pub fn open(path: &Path, id: [u8; 16]) -> Result<Self, CounterError> {
        if !path.exists() {
            let text = format!("{} 0", hex(&id));
            write_atomic(path, text.as_bytes()).map_err(|()| CounterError::Unavailable)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            seen: None,
        })
    }

    fn parse(&self) -> Result<CounterReading, CounterError> {
        let text = std::fs::read_to_string(&self.path).map_err(|_| CounterError::Unavailable)?;
        let (id, value) = text
            .trim()
            .split_once(' ')
            .ok_or(CounterError::Unavailable)?;
        let id = unhex(id).ok_or(CounterError::Unavailable)?;
        let value = value.parse().map_err(|_| CounterError::Unavailable)?;
        let r = CounterReading {
            id: CounterId(id),
            value,
        };
        if let Some(s) = self.seen {
            if s.id != r.id {
                return Err(CounterError::Wiped);
            }
            if r.value < s.value {
                return Err(CounterError::RolledBack);
            }
        }
        Ok(r)
    }
}

fn hex(b: &[u8; 16]) -> String {
    b.iter().fold(String::new(), |mut out, x| {
        let _ = write!(out, "{x:02x}");
        out
    })
}

fn unhex(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if s.len() != 32 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *o = u8::from_str_radix(s.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

impl TamperEvidentCounter for FileCounter {
    fn read(&self) -> Result<CounterReading, CounterError> {
        self.parse()
    }

    fn advance(&mut self, step: u64) -> Result<CounterReading, CounterError> {
        let r = self.parse()?;
        let next = CounterReading {
            id: r.id,
            value: r.value.checked_add(step).ok_or(CounterError::OutOfRange)?,
        };
        write_atomic(
            &self.path,
            format!("{} {}", hex(&next.id.0), next.value).as_bytes(),
        )
        .map_err(|()| CounterError::Unavailable)?;
        self.seen = Some(next);
        Ok(next)
    }
}
