//! The messages of `conformance/cddl/linux-client.cddl` (OP-156 m.3 (p)): deterministic CBOR
//! (RFC 8949 §4.2.1), one per frame of a big-endian `u32` length and at most
//! [`MAX_FRAME`] bytes. Anything outside the CDDL is refused on both sides.

use suiss_crypto::dcbor::{self, Limits, Value};

/// Longest frame on the socket, in bytes.
pub const MAX_FRAME: u32 = 65_536;

/// Most members one group answer names (the CBOR profile's item ceiling).
pub const MAX_MEMBERS: usize = 256;

/// Why bytes are not a message of the channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Not canonical CBOR, or longer than a frame.
    #[error("linux-wire-cbor")]
    Cbor,
    /// CBOR, but not a message the CDDL admits.
    #[error("linux-wire-shape")]
    Shape,
}

/// A user or group name: `[a-z_][a-z0-9_-]{0,31}`.
#[must_use]
pub fn name_ok(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == b'_')
        && s.len() <= 32
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// A `TextId`: `[a-z][a-z0-9_]*(\.[a-z0-9_]+)+`.
#[must_use]
pub fn text_id_ok(s: &str) -> bool {
    let mut parts = s.split('.');
    let first = parts.next().unwrap_or_default();
    let mut fb = first.bytes();
    let head = fb.next().is_some_and(|c| c.is_ascii_lowercase())
        && fb.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    let mut rest = 0_usize;
    for p in parts {
        if p.is_empty()
            || !p
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        {
            return false;
        }
        rest = rest.saturating_add(1);
    }
    head && rest >= 1
}

fn size_ok(s: &str, min: usize, max: usize) -> bool {
    let n = s.len();
    n >= min && n <= max
}

/// What the NSS and PAM modules ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// `getpwnam`.
    Getpwnam(String),
    /// `getpwuid`.
    Getpwuid(u32),
    /// `getgrnam`.
    Getgrnam(String),
    /// `getgrgid`.
    Getgrgid(u32),
    /// `getgrouplist`.
    Getgrouplist(String),
    /// A console sign-in.
    Authenticate {
        /// The user.
        user: String,
        /// The PAM service.
        service: String,
        /// The terminal.
        tty: Option<String>,
    },
    /// A `sudo` step-up.
    Sudo {
        /// The user.
        user: String,
        /// SHA-256 of the command line.
        command: [u8; 32],
    },
    /// Polls a pending sign-in or step-up.
    Poll([u8; 16]),
}

/// A `passwd` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passwd {
    /// Name.
    pub name: String,
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    /// GECOS field.
    pub gecos: String,
    /// Home directory.
    pub dir: String,
    /// Login shell.
    pub shell: String,
}

/// A `group` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Name.
    pub name: String,
    /// Group id.
    pub gid: u32,
    /// Members by name.
    pub members: Vec<String>,
}

/// A sign-in or step-up waiting for the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The attempt to poll.
    pub attempt: [u8; 16],
    /// The `TextId` the module shows.
    pub text: String,
    /// The device flow's user code.
    pub user_code: Option<String>,
    /// Where the person enters it.
    pub verification_uri: Option<String>,
    /// Seconds until the attempt ends.
    pub expires_in: u64,
}

/// What the daemon answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// A user.
    Passwd(Passwd),
    /// A group.
    Group(Group),
    /// A user's group ids.
    Groups(Vec<u32>),
    /// Waiting for the person.
    Pending(Pending),
    /// Decided: `allow` or not, and whether the console cache served it.
    Done {
        /// Allowed.
        allow: bool,
        /// Served offline from the console cache.
        offline: Option<bool>,
    },
    /// No such user or group.
    NotFound,
    /// Access cannot answer and nothing cached may; the `TextId` to show.
    Unavailable(String),
}

fn text(v: &str) -> Value {
    Value::text(v)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn uint(v: &Value) -> Option<u64> {
    match v {
        Value::Unsigned(n) => Some(*n),
        _ => None,
    }
}

fn id32(v: &Value) -> Option<u32> {
    u32::try_from(uint(v)?).ok()
}

fn tstr(v: &Value) -> Option<&str> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

fn bytes<const N: usize>(v: &Value) -> Option<[u8; N]> {
    match v {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
}

fn name(v: &Value) -> Option<String> {
    tstr(v).filter(|s| name_ok(s)).map(String::from)
}

/// The map's entries by key, refused when a key is not text, repeats or is not in `allowed`.
fn fields<'a>(v: &'a Value, allowed: &[&str]) -> Option<Vec<(&'a str, &'a Value)>> {
    let Value::Map(entries) = v else { return None };
    let mut out: Vec<(&str, &Value)> = Vec::with_capacity(entries.len());
    for (k, val) in entries {
        let k = tstr(k)?;
        if !allowed.contains(&k) || out.iter().any(|(seen, _)| *seen == k) {
            return None;
        }
        out.push((k, val));
    }
    Some(out)
}

fn get<'a>(f: &[(&str, &'a Value)], key: &str) -> Option<&'a Value> {
    f.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn encode(v: &Value) -> Result<Vec<u8>, WireError> {
    let out = dcbor::encode(v, Limits::CEILING).map_err(|_| WireError::Cbor)?;
    if out.len() > MAX_FRAME as usize {
        return Err(WireError::Cbor);
    }
    Ok(out)
}

fn decode(b: &[u8]) -> Result<Value, WireError> {
    if b.len() > MAX_FRAME as usize {
        return Err(WireError::Cbor);
    }
    dcbor::decode(b, Limits::CEILING).map_err(|_| WireError::Cbor)
}

impl Request {
    /// Whether it is an NSS lookup, which any local process may ask.
    #[must_use]
    pub const fn is_lookup(&self) -> bool {
        matches!(
            self,
            Self::Getpwnam(_)
                | Self::Getpwuid(_)
                | Self::Getgrnam(_)
                | Self::Getgrgid(_)
                | Self::Getgrouplist(_)
        )
    }

    /// Whether the request is inside the CDDL.
    #[must_use]
    pub fn valid(&self) -> bool {
        match self {
            Self::Getpwnam(n) | Self::Getgrnam(n) | Self::Getgrouplist(n) => name_ok(n),
            Self::Getpwuid(_) | Self::Getgrgid(_) | Self::Poll(_) => true,
            Self::Authenticate { user, service, tty } => {
                name_ok(user)
                    && size_ok(service, 1, 64)
                    && tty.as_deref().is_none_or(|t| size_ok(t, 1, 64))
            }
            Self::Sudo { user, .. } => name_ok(user),
        }
    }

    /// The request's CBOR.
    ///
    /// # Errors
    /// [`WireError::Shape`] outside the CDDL.
    pub fn to_cbor(&self) -> Result<Vec<u8>, WireError> {
        if !self.valid() {
            return Err(WireError::Shape);
        }
        let v = match self {
            Self::Getpwnam(n) => map(vec![("op", text("getpwnam")), ("name", text(n))]),
            Self::Getpwuid(u) => map(vec![
                ("op", text("getpwuid")),
                ("uid", Value::Unsigned(u64::from(*u))),
            ]),
            Self::Getgrnam(n) => map(vec![("op", text("getgrnam")), ("name", text(n))]),
            Self::Getgrgid(g) => map(vec![
                ("op", text("getgrgid")),
                ("gid", Value::Unsigned(u64::from(*g))),
            ]),
            Self::Getgrouplist(n) => map(vec![("op", text("getgrouplist")), ("name", text(n))]),
            Self::Authenticate { user, service, tty } => {
                let mut e = vec![
                    ("op", text("authenticate")),
                    ("user", text(user)),
                    ("service", text(service)),
                ];
                if let Some(t) = tty {
                    e.push(("tty", text(t)));
                }
                map(e)
            }
            Self::Sudo { user, command } => map(vec![
                ("op", text("sudo")),
                ("user", text(user)),
                ("command", Value::Bytes(command.to_vec())),
            ]),
            Self::Poll(a) => map(vec![
                ("op", text("poll")),
                ("attempt", Value::Bytes(a.to_vec())),
            ]),
        };
        encode(&v)
    }

    /// A request from its CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_cbor(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        Self::of(&v).ok_or(WireError::Shape)
    }

    fn of(v: &Value) -> Option<Self> {
        let op = tstr(v.get("op")?)?;
        let r = match op {
            "getpwnam" | "getgrnam" | "getgrouplist" => {
                let f = fields(v, &["op", "name"])?;
                let n = name(get(&f, "name")?)?;
                match op {
                    "getpwnam" => Self::Getpwnam(n),
                    "getgrnam" => Self::Getgrnam(n),
                    _ => Self::Getgrouplist(n),
                }
            }
            "getpwuid" => Self::Getpwuid(id32(get(&fields(v, &["op", "uid"])?, "uid")?)?),
            "getgrgid" => Self::Getgrgid(id32(get(&fields(v, &["op", "gid"])?, "gid")?)?),
            "authenticate" => {
                let f = fields(v, &["op", "user", "service", "tty"])?;
                Self::Authenticate {
                    user: name(get(&f, "user")?)?,
                    service: String::from(tstr(get(&f, "service")?)?),
                    tty: match get(&f, "tty") {
                        None => None,
                        Some(t) => Some(String::from(tstr(t)?)),
                    },
                }
            }
            "sudo" => {
                let f = fields(v, &["op", "user", "command"])?;
                Self::Sudo {
                    user: name(get(&f, "user")?)?,
                    command: bytes(get(&f, "command")?)?,
                }
            }
            "poll" => Self::Poll(bytes(get(&fields(v, &["op", "attempt"])?, "attempt")?)?),
            _ => return None,
        };
        r.valid().then_some(r)
    }
}

impl Response {
    /// Whether the answer is inside the CDDL.
    #[must_use]
    pub fn valid(&self) -> bool {
        match self {
            Self::Passwd(p) => {
                name_ok(&p.name)
                    && size_ok(&p.gecos, 0, 256)
                    && size_ok(&p.dir, 1, 4096)
                    && size_ok(&p.shell, 1, 4096)
            }
            Self::Group(g) => {
                name_ok(&g.name)
                    && g.members.len() <= MAX_MEMBERS
                    && g.members.iter().all(|m| name_ok(m))
            }
            Self::Groups(g) => g.len() <= MAX_MEMBERS,
            Self::Pending(p) => {
                text_id_ok(&p.text)
                    && p.user_code.as_deref().is_none_or(|c| size_ok(c, 1, 16))
                    && p.verification_uri
                        .as_deref()
                        .is_none_or(|u| size_ok(u, 1, 2048))
            }
            Self::Done { .. } | Self::NotFound => true,
            Self::Unavailable(t) => text_id_ok(t),
        }
    }

    /// The answer's CBOR.
    ///
    /// # Errors
    /// [`WireError::Shape`] outside the CDDL.
    pub fn to_cbor(&self) -> Result<Vec<u8>, WireError> {
        if !self.valid() {
            return Err(WireError::Shape);
        }
        let v = match self {
            Self::Passwd(p) => map(vec![
                ("kind", text("passwd")),
                ("name", text(&p.name)),
                ("uid", Value::Unsigned(u64::from(p.uid))),
                ("gid", Value::Unsigned(u64::from(p.gid))),
                ("gecos", text(&p.gecos)),
                ("dir", text(&p.dir)),
                ("shell", text(&p.shell)),
            ]),
            Self::Group(g) => map(vec![
                ("kind", text("group")),
                ("name", text(&g.name)),
                ("gid", Value::Unsigned(u64::from(g.gid))),
                (
                    "members",
                    Value::Array(g.members.iter().map(|m| text(m)).collect()),
                ),
            ]),
            Self::Groups(g) => map(vec![
                ("kind", text("groups")),
                (
                    "gids",
                    Value::Array(g.iter().map(|g| Value::Unsigned(u64::from(*g))).collect()),
                ),
            ]),
            Self::Pending(p) => {
                let mut e = vec![
                    ("kind", text("pending")),
                    ("attempt", Value::Bytes(p.attempt.to_vec())),
                    ("text", text(&p.text)),
                    ("expires_in", Value::Unsigned(p.expires_in)),
                ];
                if let Some(c) = &p.user_code {
                    e.push(("user_code", text(c)));
                }
                if let Some(u) = &p.verification_uri {
                    e.push(("verification_uri", text(u)));
                }
                map(e)
            }
            Self::Done { allow, offline } => {
                let mut e = vec![
                    ("kind", text("done")),
                    ("outcome", text(if *allow { "allow" } else { "deny" })),
                ];
                if let Some(o) = offline {
                    e.push(("offline", Value::Bool(*o)));
                }
                map(e)
            }
            Self::NotFound => map(vec![("kind", text("not_found"))]),
            Self::Unavailable(t) => map(vec![("kind", text("unavailable")), ("text", text(t))]),
        };
        encode(&v)
    }

    /// An answer from its CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_cbor(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        Self::of(&v).ok_or(WireError::Shape)
    }

    fn of(v: &Value) -> Option<Self> {
        let kind = tstr(v.get("kind")?)?;
        let r = match kind {
            "passwd" => {
                let f = fields(v, &["kind", "name", "uid", "gid", "gecos", "dir", "shell"])?;
                Self::Passwd(Passwd {
                    name: name(get(&f, "name")?)?,
                    uid: id32(get(&f, "uid")?)?,
                    gid: id32(get(&f, "gid")?)?,
                    gecos: String::from(tstr(get(&f, "gecos")?)?),
                    dir: String::from(tstr(get(&f, "dir")?)?),
                    shell: String::from(tstr(get(&f, "shell")?)?),
                })
            }
            "group" => {
                let f = fields(v, &["kind", "name", "gid", "members"])?;
                let Value::Array(m) = get(&f, "members")? else {
                    return None;
                };
                Self::Group(Group {
                    name: name(get(&f, "name")?)?,
                    gid: id32(get(&f, "gid")?)?,
                    members: m.iter().map(name).collect::<Option<Vec<_>>>()?,
                })
            }
            "groups" => {
                let f = fields(v, &["kind", "gids"])?;
                let Value::Array(g) = get(&f, "gids")? else {
                    return None;
                };
                Self::Groups(g.iter().map(id32).collect::<Option<Vec<_>>>()?)
            }
            "pending" => {
                let f = fields(
                    v,
                    &[
                        "kind",
                        "attempt",
                        "text",
                        "user_code",
                        "verification_uri",
                        "expires_in",
                    ],
                )?;
                let opt = |k: &str| -> Option<Option<String>> {
                    match get(&f, k) {
                        None => Some(None),
                        Some(t) => Some(Some(String::from(tstr(t)?))),
                    }
                };
                Self::Pending(Pending {
                    attempt: bytes(get(&f, "attempt")?)?,
                    text: String::from(tstr(get(&f, "text")?)?),
                    user_code: opt("user_code")?,
                    verification_uri: opt("verification_uri")?,
                    expires_in: uint(get(&f, "expires_in")?)?,
                })
            }
            "done" => {
                let f = fields(v, &["kind", "outcome", "offline"])?;
                let allow = match tstr(get(&f, "outcome")?)? {
                    "allow" => true,
                    "deny" => false,
                    _ => return None,
                };
                let offline = match get(&f, "offline") {
                    None => None,
                    Some(Value::Bool(b)) => Some(*b),
                    Some(_) => return None,
                };
                Self::Done { allow, offline }
            }
            "not_found" => {
                fields(v, &["kind"])?;
                Self::NotFound
            }
            "unavailable" => {
                let f = fields(v, &["kind", "text"])?;
                Self::Unavailable(String::from(tstr(get(&f, "text")?)?))
            }
            _ => return None,
        };
        r.valid().then_some(r)
    }
}

/// `body` as one frame: its length, big-endian, then the bytes.
///
/// # Errors
/// [`WireError::Cbor`] past [`MAX_FRAME`].
pub fn frame(body: &[u8]) -> Result<Vec<u8>, WireError> {
    let n = u32::try_from(body.len()).map_err(|_| WireError::Cbor)?;
    if n > MAX_FRAME {
        return Err(WireError::Cbor);
    }
    let mut out = Vec::with_capacity(body.len().saturating_add(4));
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// The length a frame header announces, refused past [`MAX_FRAME`].
///
/// # Errors
/// [`WireError::Cbor`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, WireError> {
    let n = u32::from_be_bytes(header);
    if n > MAX_FRAME {
        return Err(WireError::Cbor);
    }
    usize::try_from(n).map_err(|_| WireError::Cbor)
}
