//! The glibc NSS ABI over the module's safe half.

#![allow(
    unsafe_code,
    reason = "R-2, OP-156 m.3 (p): the C ABI shell of the module"
)]

use std::ffi::{CStr, c_char, c_int, c_long};
use std::path::Path;

use access_linux_module::client::{SOCKET, TIMEOUT, ask};
use access_linux_module::nss::{extra_groups, pack_group, pack_passwd};
use access_linux_module::wire::{Request, Response};

const SUCCESS: c_int = 1;
const NOTFOUND: c_int = 0;
const UNAVAIL: c_int = -1;
const TRYAGAIN: c_int = -2;

fn answer(r: &Request) -> Option<Response> {
    ask(Path::new(SOCKET), r, TIMEOUT).ok()
}

fn name_of(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: glibc passes a NUL-terminated name that lives for the call.
    let c = unsafe { CStr::from_ptr(p) };
    c.to_str().ok().map(String::from)
}

fn buffer<'a>(buf: *mut c_char, len: usize) -> Option<&'a mut [u8]> {
    if buf.is_null() {
        return None;
    }
    // SAFETY: glibc hands a writable buffer of `len` bytes that the caller owns for the call.
    Some(unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), len) })
}

fn set_errno(errnop: *mut c_int, v: c_int) {
    if !errnop.is_null() {
        // SAFETY: glibc passes a valid errno pointer for the call.
        unsafe { errnop.write(v) };
    }
}

fn passwd(
    a: Option<Response>,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    len: usize,
    errnop: *mut c_int,
) -> c_int {
    let p = match a {
        Some(Response::Passwd(p)) => p,
        Some(Response::NotFound) => return NOTFOUND,
        _ => return UNAVAIL,
    };
    let (Some(slice), false) = (buffer(buf, len), pwd.is_null()) else {
        return UNAVAIL;
    };
    let Some(l) = pack_passwd(&p, slice) else {
        set_errno(errnop, libc::ERANGE);
        return TRYAGAIN;
    };
    let at = |o: usize| buf.wrapping_add(o);
    let entry = libc::passwd {
        pw_name: at(l.name),
        pw_passwd: at(l.passwd),
        pw_uid: p.uid,
        pw_gid: p.gid,
        pw_gecos: at(l.gecos),
        pw_dir: at(l.dir),
        pw_shell: at(l.shell),
    };
    // SAFETY: `pwd` is the caller's writable `struct passwd` for the call.
    unsafe { pwd.write(entry) };
    SUCCESS
}

fn group(
    a: Option<Response>,
    grp: *mut libc::group,
    buf: *mut c_char,
    len: usize,
    errnop: *mut c_int,
) -> c_int {
    let g = match a {
        Some(Response::Group(g)) => g,
        Some(Response::NotFound) => return NOTFOUND,
        _ => return UNAVAIL,
    };
    let (Some(slice), false) = (buffer(buf, len), grp.is_null()) else {
        return UNAVAIL;
    };
    let Some(l) = pack_group(&g, slice, buf.addr()) else {
        set_errno(errnop, libc::ERANGE);
        return TRYAGAIN;
    };
    let at = |o: usize| buf.wrapping_add(o);
    let entry = libc::group {
        gr_name: at(l.name),
        gr_passwd: at(l.passwd),
        gr_gid: g.gid,
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "pack_group aligns the member array to a pointer"
        )]
        gr_mem: at(l.members).cast::<*mut c_char>(),
    };
    // SAFETY: `grp` is the caller's writable `struct group` for the call.
    unsafe { grp.write(entry) };
    SUCCESS
}

fn initgroups(
    user: *const c_char,
    skip: libc::gid_t,
    start: *mut c_long,
    size: *mut c_long,
    groupsp: *mut *mut libc::gid_t,
    limit: c_long,
) -> c_int {
    let Some(name) = name_of(user) else {
        return NOTFOUND;
    };
    let gids = match answer(&Request::Getgrouplist(name)) {
        Some(Response::Groups(g)) => extra_groups(&g, skip),
        Some(Response::NotFound) => return NOTFOUND,
        _ => return UNAVAIL,
    };
    if start.is_null() || size.is_null() || groupsp.is_null() {
        return UNAVAIL;
    }
    for gid in gids {
        // SAFETY: glibc passes its counters and array for the call; the array holds `*size`
        // entries and is grown with realloc as glibc expects.
        let added = unsafe {
            if *start >= *size {
                if limit > 0 && *size >= limit {
                    return SUCCESS;
                }
                let grown = (*size).saturating_mul(2).max(8);
                let grown = if limit > 0 { grown.min(limit) } else { grown };
                let bytes = usize::try_from(grown)
                    .ok()
                    .and_then(|n| n.checked_mul(size_of::<libc::gid_t>()));
                let Some(bytes) = bytes else { return UNAVAIL };
                let p = libc::realloc((*groupsp).cast(), bytes).cast::<libc::gid_t>();
                if p.is_null() {
                    return TRYAGAIN;
                }
                *groupsp = p;
                *size = grown;
            }
            let Ok(i) = usize::try_from(*start) else {
                return UNAVAIL;
            };
            (*groupsp).add(i).write(gid);
            *start = (*start).saturating_add(1);
            true
        };
        if !added {
            return UNAVAIL;
        }
    }
    SUCCESS
}

/// `getpwnam_r`.
// SAFETY: the NSS ABI name glibc looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn _nss_access_getpwnam_r(
    n: *const c_char,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    len: usize,
    e: *mut c_int,
) -> c_int {
    passwd(
        name_of(n).and_then(|n| answer(&Request::Getpwnam(n))),
        pwd,
        buf,
        len,
        e,
    )
}

/// `getpwuid_r`.
// SAFETY: the NSS ABI name glibc looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn _nss_access_getpwuid_r(
    uid: libc::uid_t,
    pwd: *mut libc::passwd,
    buf: *mut c_char,
    len: usize,
    e: *mut c_int,
) -> c_int {
    passwd(answer(&Request::Getpwuid(uid)), pwd, buf, len, e)
}

/// `getgrnam_r`.
// SAFETY: the NSS ABI name glibc looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn _nss_access_getgrnam_r(
    n: *const c_char,
    grp: *mut libc::group,
    buf: *mut c_char,
    len: usize,
    e: *mut c_int,
) -> c_int {
    group(
        name_of(n).and_then(|n| answer(&Request::Getgrnam(n))),
        grp,
        buf,
        len,
        e,
    )
}

/// `getgrgid_r`.
// SAFETY: the NSS ABI name glibc looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn _nss_access_getgrgid_r(
    gid: libc::gid_t,
    grp: *mut libc::group,
    buf: *mut c_char,
    len: usize,
    e: *mut c_int,
) -> c_int {
    group(answer(&Request::Getgrgid(gid)), grp, buf, len, e)
}

/// `initgroups_dyn`.
// SAFETY: the NSS ABI name glibc looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn _nss_access_initgroups_dyn(
    u: *const c_char,
    skip: libc::gid_t,
    start: *mut c_long,
    size: *mut c_long,
    groupsp: *mut *mut libc::gid_t,
    limit: c_long,
    _e: *mut c_int,
) -> c_int {
    initgroups(u, skip, start, size, groupsp, limit)
}
