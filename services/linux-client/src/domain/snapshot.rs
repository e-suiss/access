//! The host's NSS data (OP-156 m.3 (p), Ek B 5206, 5207): who may sign in to this host, as
//! Access derived it from the `ssh.login` Grants on the host's server group, and how long the
//! daemon may answer from it without Access. A user is in it only while a Grant names them; the
//! snapshot as a whole answers for at most 12 hours and never past the host's horizon.

use access_linux_module::wire::{Group, Passwd, Request, Response, name_ok};
use serde::{Deserialize, Serialize};

/// The longest an NSS snapshot answers offline (m.3 (p)): 12 hours.
pub const NSS_MAX_MS: u64 = 12 * 3_600_000;

/// The longest a console sign-in is reused offline (m.3 (p)): 8 hours.
pub const CONSOLE_MAX_MS: u64 = 8 * 3_600_000;

/// Most users or groups one snapshot carries.
pub const MAX_ENTRIES: usize = 4096;

/// One user as Access serves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// The Linux name, a principal of the user's Grant.
    pub name: String,
    /// User id.
    pub uid: u32,
    /// Primary group id: the host's server group.
    pub gid: u32,
    /// Home directory.
    pub dir: String,
    /// Login shell.
    pub shell: String,
    /// When the Grant that names them ends, ms.
    pub until_ms: u64,
    /// Whether a console sign-in and `sudo` may be asked for: the Grant carries no constraint
    /// only `sshd` can enforce (`force_command`, `source_address`).
    pub console: bool,
}

/// One group as Access serves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    /// Name.
    pub name: String,
    /// Group id.
    pub gid: u32,
    /// Members.
    pub members: Vec<String>,
}

/// What `POST /linux/v1/nss` answers, as the daemon keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Access's time when it answered, ms.
    pub now_ms: u64,
    /// The host's horizon: no cached answer is served at or after it, ms.
    pub horizon_ms: u64,
    /// How long the NSS data may be served offline, seconds (≤ 12 h).
    pub nss_ttl_s: u64,
    /// How long a console sign-in may be reused offline, seconds (≤ 8 h).
    pub console_ttl_s: u64,
    /// Users.
    pub users: Vec<User>,
    /// Groups.
    pub groups: Vec<GroupEntry>,
}

/// Why a snapshot is not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("linux-snapshot")]
pub struct Malformed;

fn path_ok(s: &str) -> bool {
    s.starts_with('/') && !s.is_empty() && s.len() <= 4096 && !s.contains(['\0', ':', '\n'])
}

impl Snapshot {
    /// The snapshot from Access's JSON, refused when any entry is outside the channel's
    /// rules, a name or id repeats, or a time is missing.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn parse(body: &[u8]) -> Result<Self, Malformed> {
        let s: Self = serde_json::from_slice(body).map_err(|_| Malformed)?;
        s.check()?;
        Ok(s)
    }

    /// Whether every entry is inside the rules.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn check(&self) -> Result<(), Malformed> {
        if self.users.len() > MAX_ENTRIES || self.groups.len() > MAX_ENTRIES {
            return Err(Malformed);
        }
        let mut names = std::collections::BTreeSet::new();
        let mut uids = std::collections::BTreeSet::new();
        for u in &self.users {
            if !name_ok(&u.name)
                || !path_ok(&u.dir)
                || !path_ok(&u.shell)
                || u.uid == 0
                || u.gid == 0
                || !names.insert(u.name.as_str())
                || !uids.insert(u.uid)
            {
                return Err(Malformed);
            }
        }
        let mut gnames = std::collections::BTreeSet::new();
        let mut gids = std::collections::BTreeSet::new();
        for g in &self.groups {
            if !name_ok(&g.name)
                || g.gid == 0
                || g.members.len() > access_linux_module::wire::MAX_MEMBERS
                || !g.members.iter().all(|m| names.contains(m.as_str()))
                || !gnames.insert(g.name.as_str())
                || !gids.insert(g.gid)
            {
                return Err(Malformed);
            }
        }
        Ok(())
    }

    /// Until when the NSS data answers, ms: its age limit, never past 12 hours or the horizon.
    #[must_use]
    pub fn nss_until(&self) -> u64 {
        let ttl = self.nss_ttl_s.saturating_mul(1000).min(NSS_MAX_MS);
        self.now_ms.saturating_add(ttl).min(self.horizon_ms)
    }

    /// How long a console sign-in is reused offline, ms (≤ 8 h).
    #[must_use]
    pub fn console_ttl_ms(&self) -> u64 {
        self.console_ttl_s.saturating_mul(1000).min(CONSOLE_MAX_MS)
    }

    /// The user named `name`, while the snapshot and their Grant answer at `now`.
    #[must_use]
    pub fn user(&self, name: &str, now: u64) -> Option<&User> {
        if now >= self.nss_until() {
            return None;
        }
        self.users
            .iter()
            .find(|u| u.name == name && now < u.until_ms.min(self.horizon_ms))
    }

    fn live(&self, now: u64) -> impl Iterator<Item = &User> {
        let open = now < self.nss_until();
        self.users
            .iter()
            .filter(move |u| open && now < u.until_ms.min(self.horizon_ms))
    }

    fn group_of(&self, g: &GroupEntry, now: u64) -> Group {
        let live: Vec<&str> = self.live(now).map(|u| u.name.as_str()).collect();
        Group {
            name: g.name.clone(),
            gid: g.gid,
            members: g
                .members
                .iter()
                .filter(|m| live.contains(&m.as_str()))
                .cloned()
                .collect(),
        }
    }

    /// The NSS answer to `request` at `now`; `None` when the snapshot no longer answers or the
    /// request is not an NSS lookup.
    #[must_use]
    pub fn answer(&self, request: &Request, now: u64) -> Option<Response> {
        if now >= self.nss_until() {
            return None;
        }
        let passwd = |u: &User| {
            Response::Passwd(Passwd {
                name: u.name.clone(),
                uid: u.uid,
                gid: u.gid,
                gecos: String::new(),
                dir: u.dir.clone(),
                shell: u.shell.clone(),
            })
        };
        let found = |r: Option<Response>| Some(r.unwrap_or(Response::NotFound));
        match request {
            Request::Getpwnam(n) => found(self.user(n, now).map(passwd)),
            Request::Getpwuid(uid) => found(self.live(now).find(|u| u.uid == *uid).map(passwd)),
            Request::Getgrnam(n) => found(
                self.groups
                    .iter()
                    .find(|g| g.name == *n)
                    .map(|g| Response::Group(self.group_of(g, now))),
            ),
            Request::Getgrgid(gid) => found(
                self.groups
                    .iter()
                    .find(|g| g.gid == *gid)
                    .map(|g| Response::Group(self.group_of(g, now))),
            ),
            Request::Getgrouplist(n) => {
                let Some(u) = self.user(n, now) else {
                    return Some(Response::NotFound);
                };
                let mut gids = vec![u.gid];
                for g in &self.groups {
                    if g.members.contains(n) && !gids.contains(&g.gid) {
                        gids.push(g.gid);
                    }
                }
                Some(Response::Groups(gids))
            }
            _ => None,
        }
    }
}
