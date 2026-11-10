//! The NSS module's safe half (OP-156 m.3 (p)): what to ask the daemon and how an answer is laid
//! out in the caller's buffer as glibc's `getpwnam_r` and `getgrnam_r` expect. The C ABI shell
//! only turns pointers into slices and stores the offsets this returns.

use crate::wire::{Group, Passwd};

/// The `passwd` password field: no password lives on the host.
pub const NO_PASSWORD: &str = "x";

/// Where each string of a `passwd` entry starts in the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswdLayout {
    /// `pw_name`.
    pub name: usize,
    /// `pw_passwd`.
    pub passwd: usize,
    /// `pw_gecos`.
    pub gecos: usize,
    /// `pw_dir`.
    pub dir: usize,
    /// `pw_shell`.
    pub shell: usize,
}

/// Where each part of a `group` entry starts in the buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupLayout {
    /// `gr_name`.
    pub name: usize,
    /// `gr_passwd`.
    pub passwd: usize,
    /// `gr_mem`: the NULL-terminated array of member pointers.
    pub members: usize,
}

struct Packer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Packer<'_> {
    fn string(&mut self, s: &str) -> Option<usize> {
        if s.as_bytes().contains(&0) {
            return None;
        }
        let start = self.at;
        let end = start.checked_add(s.len())?;
        self.buf.get_mut(start..end)?.copy_from_slice(s.as_bytes());
        *self.buf.get_mut(end)? = 0;
        self.at = end.checked_add(1)?;
        Some(start)
    }

    fn align(&mut self, base: usize) -> Option<()> {
        let word = core::mem::size_of::<usize>();
        let addr = base.checked_add(self.at)?;
        let pad = addr.next_multiple_of(word).checked_sub(addr)?;
        self.at = self.at.checked_add(pad)?;
        (self.at <= self.buf.len()).then_some(())
    }

    fn word(&mut self, v: usize) -> Option<()> {
        let b = v.to_ne_bytes();
        let end = self.at.checked_add(b.len())?;
        self.buf.get_mut(self.at..end)?.copy_from_slice(&b);
        self.at = end;
        Some(())
    }
}

/// Lays `p` out in `buf`; `None` when it does not fit (`ERANGE`).
#[must_use]
pub fn pack_passwd(p: &Passwd, buf: &mut [u8]) -> Option<PasswdLayout> {
    let mut k = Packer { buf, at: 0 };
    Some(PasswdLayout {
        name: k.string(&p.name)?,
        passwd: k.string(NO_PASSWORD)?,
        gecos: k.string(&p.gecos)?,
        dir: k.string(&p.dir)?,
        shell: k.string(&p.shell)?,
    })
}

/// Lays `g` out in `buf`, whose first byte is at address `base`: the strings, then the
/// pointer-aligned, NULL-terminated array of member pointers; `None` when it does not fit.
#[must_use]
pub fn pack_group(g: &Group, buf: &mut [u8], base: usize) -> Option<GroupLayout> {
    let mut k = Packer { buf, at: 0 };
    let name = k.string(&g.name)?;
    let passwd = k.string(NO_PASSWORD)?;
    let mut members = Vec::with_capacity(g.members.len());
    for m in &g.members {
        members.push(k.string(m)?);
    }
    k.align(base)?;
    let array = k.at;
    for m in members {
        k.word(base.checked_add(m)?)?;
    }
    k.word(0)?;
    Some(GroupLayout {
        name,
        passwd,
        members: array,
    })
}

/// The group ids `initgroups` adds for `user`: every id the daemon named except `skip`, the
/// primary group the caller already holds.
#[must_use]
pub fn extra_groups(gids: &[u32], skip: u32) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for g in gids {
        if *g != skip && !out.contains(g) {
            out.push(*g);
        }
    }
    out
}
