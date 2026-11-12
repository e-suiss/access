//! The solver as a sibling process (OP-157 m.8 (a), OP-159 m.3 (aa)): the server asks
//! `access-policy-solver` over a Unix socket and keeps its own seccomp profile. One request is
//! the schema and the two policy sets; one reply is the relation. Every failure on either side is
//! [`Relation::Unknown`], which raises the change (fail-closed).
//!
//! Wire form: the magic `APS1`, then three strings, each a 4-byte big-endian length and UTF-8
//! bytes; the reply is one byte, [`Relation::code`].

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Change;

/// The request magic and version.
pub const MAGIC: &[u8; 4] = b"APS1";

/// The longest schema or policy set one request carries.
pub const MAX_PART: usize = 1 << 20;

/// What the solver answered, without its counterexample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// Same outcome for every request.
    Equivalent,
    /// Restricts at least as much everywhere and more somewhere.
    Narrowing,
    /// Restricts less somewhere and nowhere more.
    Widening,
    /// Restricts less somewhere and more elsewhere.
    Incomparable,
    /// A policy can raise an evaluation error.
    MayError,
    /// No relation was proved, or the solver could not be asked.
    Unknown,
}

impl Relation {
    /// The reply byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Equivalent => 1,
            Self::Narrowing => 2,
            Self::Widening => 3,
            Self::Incomparable => 4,
            Self::MayError => 5,
            Self::Unknown => 6,
        }
    }

    /// The relation of a reply byte; any other byte is [`Relation::Unknown`].
    #[must_use]
    pub const fn of_code(b: u8) -> Self {
        match b {
            1 => Self::Equivalent,
            2 => Self::Narrowing,
            3 => Self::Widening,
            4 => Self::Incomparable,
            5 => Self::MayError,
            _ => Self::Unknown,
        }
    }

    /// The relation of a [`Change`].
    #[must_use]
    pub const fn of_change(c: &Change) -> Self {
        match c {
            Change::Equivalent => Self::Equivalent,
            Change::Narrowing => Self::Narrowing,
            Change::Widening(_) => Self::Widening,
            Change::Incomparable(_) => Self::Incomparable,
            Change::MayError(_) => Self::MayError,
            Change::Unknown(_) => Self::Unknown,
        }
    }
}

/// Why a socket or its directory is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SocketError {
    /// The path cannot be read.
    #[error("socket {0}: cannot be read")]
    Missing(PathBuf),
    /// The path is not a Unix socket.
    #[error("socket {0}: not a socket")]
    NotASocket(PathBuf),
    /// Someone other than the expected owner owns it.
    #[error("socket {0}: owned by uid {1}, expected {2}")]
    Owner(PathBuf, u32, u32),
    /// Others may connect to it.
    #[error("socket {0}: mode {1:o} lets others connect")]
    Mode(PathBuf, u32),
    /// Its directory is writable by others than its owner, or owned by someone else.
    #[error("socket directory {0}: mode {1:o} or owner uid {2} is not safe")]
    Directory(PathBuf, u32, u32),
}

/// Checks the socket at `path` (OP-159 m.3 (aa)): a Unix socket owned by `owner` (by default the
/// owner of its directory), with no access for others, in a directory only its owner can write.
///
/// # Errors
/// [`SocketError`].
pub fn check_socket(path: &Path, owner: Option<u32>) -> Result<(), SocketError> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let d = std::fs::metadata(dir).map_err(|_| SocketError::Missing(dir.to_path_buf()))?;
    if !d.is_dir() || d.mode() & 0o022 != 0 {
        return Err(SocketError::Directory(
            dir.to_path_buf(),
            d.mode() & 0o7777,
            d.uid(),
        ));
    }
    let m =
        std::fs::symlink_metadata(path).map_err(|_| SocketError::Missing(path.to_path_buf()))?;
    if !m.file_type().is_socket() {
        return Err(SocketError::NotASocket(path.to_path_buf()));
    }
    let want = owner.unwrap_or(d.uid());
    if m.uid() != want {
        return Err(SocketError::Owner(path.to_path_buf(), m.uid(), want));
    }
    if d.uid() != want {
        return Err(SocketError::Directory(
            dir.to_path_buf(),
            d.mode() & 0o7777,
            d.uid(),
        ));
    }
    if m.mode() & 0o007 != 0 {
        return Err(SocketError::Mode(path.to_path_buf(), m.mode() & 0o7777));
    }
    Ok(())
}

fn write_part(out: &mut Vec<u8>, part: &str) -> Option<()> {
    if part.len() > MAX_PART {
        return None;
    }
    out.extend_from_slice(&u32::try_from(part.len()).ok()?.to_be_bytes());
    out.extend_from_slice(part.as_bytes());
    Some(())
}

/// The request bytes, or `None` when a part is longer than [`MAX_PART`].
#[must_use]
pub fn request(schema: &str, old: &str, new: &str) -> Option<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    for p in [schema, old, new] {
        write_part(&mut out, p)?;
    }
    Some(out)
}

fn read_part(r: &mut impl Read) -> Option<String> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = usize::try_from(u32::from_be_bytes(len)).ok()?;
    if n > MAX_PART {
        return None;
    }
    let mut buf = Vec::new();
    r.take(u64::try_from(n).ok()?).read_to_end(&mut buf).ok()?;
    if buf.len() != n {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// Reads one request: `(schema, old, new)`, or `None` for anything else.
pub fn read_request(r: &mut impl Read) -> Option<(String, String, String)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).ok()?;
    if &magic != MAGIC {
        return None;
    }
    Some((read_part(r)?, read_part(r)?, read_part(r)?))
}

/// The blocking client the server runs off its async threads.
#[derive(Clone, Debug)]
pub struct Client {
    path: PathBuf,
    owner: Option<u32>,
    timeout: Duration,
}

impl Client {
    /// A client of the socket at `path` owned by `owner` (by default its directory's owner),
    /// waiting at most `timeout` for each read and write.
    #[must_use]
    pub const fn new(path: PathBuf, owner: Option<u32>, timeout: Duration) -> Self {
        Self {
            path,
            owner,
            timeout,
        }
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Checks the socket now (OP-159 m.3 (aa)).
    ///
    /// # Errors
    /// [`SocketError`].
    pub fn check(&self) -> Result<(), SocketError> {
        check_socket(&self.path, self.owner)
    }

    /// Asks the solver; every failure is [`Relation::Unknown`] (OP-157 m.8 (b)).
    #[must_use]
    pub fn compare(&self, schema: &str, old: &str, new: &str) -> Relation {
        self.ask(schema, old, new).unwrap_or(Relation::Unknown)
    }

    fn ask(&self, schema: &str, old: &str, new: &str) -> Option<Relation> {
        self.check().ok()?;
        let body = request(schema, old, new)?;
        let mut s = UnixStream::connect(&self.path).ok()?;
        s.set_read_timeout(Some(self.timeout)).ok()?;
        s.set_write_timeout(Some(self.timeout)).ok()?;
        s.write_all(&body).ok()?;
        s.shutdown(std::net::Shutdown::Write).ok()?;
        let mut reply = [0u8; 1];
        s.read_exact(&mut reply).ok()?;
        Some(Relation::of_code(reply[0]))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    // OP-159 m.3 (aa)
    #[test]
    fn requests_round_trip_and_oversized_parts_are_refused() {
        let body = request("s", "old", "new").unwrap();
        let got = read_request(&mut body.as_slice()).unwrap();
        assert_eq!(got, ("s".into(), "old".into(), "new".into()));
        assert!(request(&"x".repeat(MAX_PART + 1), "", "").is_none());
        let mut bad = body.clone();
        bad[0] = b'X';
        assert!(read_request(&mut bad.as_slice()).is_none());
        assert!(read_request(&mut &body[..body.len() - 1]).is_none());
        for r in [
            Relation::Equivalent,
            Relation::Narrowing,
            Relation::Widening,
            Relation::Incomparable,
            Relation::MayError,
            Relation::Unknown,
        ] {
            assert_eq!(Relation::of_code(r.code()), r);
        }
        assert_eq!(Relation::of_code(0), Relation::Unknown);
    }

    // OP-159 m.3 (aa)
    #[test]
    fn the_socket_owner_and_mode_are_checked() {
        let d = dir("check");
        let path = d.join("s.sock");
        let _l = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check_socket(&path, None), Ok(()));
        let me = std::fs::metadata(&path).unwrap().uid();
        assert!(matches!(
            check_socket(&path, Some(me.wrapping_add(1))),
            Err(SocketError::Owner(..))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            check_socket(&path, None),
            Err(SocketError::Mode(..))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            check_socket(&path, None),
            Err(SocketError::Directory(..))
        ));
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = d.join("plain");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            check_socket(&file, None),
            Err(SocketError::NotASocket(..))
        ));
        assert!(matches!(
            check_socket(&d.join("gone.sock"), None),
            Err(SocketError::Missing(..))
        ));
        let client = Client::new(d.join("gone.sock"), None, Duration::from_millis(200));
        assert_eq!(client.compare("s", "a", "b"), Relation::Unknown);
        let _ = std::fs::remove_dir_all(&d);
    }
}
