//! The Linux-PAM module ABI over the module's safe half.

#![allow(
    unsafe_code,
    reason = "R-2, OP-156 m.3 (p): the C ABI shell of the module"
)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::Path;
use std::time::Duration;

use access_linux_module::client::{SOCKET, decide};
use access_linux_module::pam::{PAM_IGNORE, PAM_USER_UNKNOWN, request, result, text};

const PAM_SERVICE: c_int = 1;
const PAM_TTY: c_int = 3;
const PAM_CONV: c_int = 5;
const PAM_TEXT_INFO: c_int = 4;

/// How often a pending sign-in is polled.
const POLL: Duration = Duration::from_secs(5);

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type Conv =
    extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<Conv>,
    appdata_ptr: *mut c_void,
}

// SAFETY: Linux-PAM's own functions, called with the handle PAM gave this module; they resolve
// from libpam, which the process loading the module has loaded (no link-time libpam).
unsafe extern "C" {
    fn pam_get_user(pamh: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_item(pamh: *const c_void, item: c_int, out: *mut *const c_void) -> c_int;
}

fn text_of(p: *const c_void) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: PAM's string items and user name are NUL-terminated and live with the handle.
    let c = unsafe { CStr::from_ptr(p.cast::<c_char>()) };
    c.to_str().ok().map(String::from)
}

fn item(pamh: *mut c_void, kind: c_int) -> *const c_void {
    let mut out: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is the handle PAM called us with; `out` is a local PAM writes once.
    let rc = unsafe { pam_get_item(pamh, kind, &raw mut out) };
    if rc == 0 { out } else { std::ptr::null() }
}

fn user(pamh: *mut c_void) -> Option<String> {
    let mut out: *const c_char = std::ptr::null();
    // SAFETY: as for `item`; a null prompt lets PAM use its own.
    let rc = unsafe { pam_get_user(pamh, &raw mut out, std::ptr::null()) };
    if rc == 0 { text_of(out.cast()) } else { None }
}

fn show(pamh: *mut c_void, message: &str) {
    let conv = item(pamh, PAM_CONV).cast::<PamConv>();
    let Ok(m) = CString::new(message) else { return };
    if conv.is_null() {
        return;
    }
    // SAFETY: PAM_CONV is the application's `struct pam_conv`, alive with the handle.
    let PamConv { conv, appdata_ptr } = unsafe { conv.read() };
    let Some(f) = conv else { return };
    let msg = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: m.as_ptr(),
    };
    let mut list = [&raw const msg];
    let mut resp: *mut PamResponse = std::ptr::null_mut();
    let _ = f(1, list.as_mut_ptr(), &raw mut resp, appdata_ptr);
    // SAFETY: `as_ref` yields a reference only when the application stored a non-null
    // response; it allocated that one `pam_response` with malloc for our one message, and it
    // stays valid until we free it below.
    let Some(answer) = (unsafe { resp.as_ref() }) else {
        return;
    };
    let text = answer.resp;
    // SAFETY: both blocks came from the application's malloc and are ours to free once;
    // `free` accepts a null text.
    unsafe {
        libc::free(text.cast());
        libc::free(resp.cast());
    }
}

fn authenticate(pamh: *mut c_void) -> c_int {
    let Some(name) = user(pamh) else {
        return PAM_USER_UNKNOWN;
    };
    let service = text_of(item(pamh, PAM_SERVICE)).unwrap_or_default();
    let tty = text_of(item(pamh, PAM_TTY));
    let cmdline = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    let r = request(&name, &service, tty.as_deref(), &cmdline);
    let decided = decide(Path::new(SOCKET), &r, POLL, |a| {
        if let Some(t) = text(a) {
            show(pamh, &t);
        }
    });
    result(decided)
}

/// `pam_sm_authenticate`.
// SAFETY: the PAM module ABI name Linux-PAM looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _f: c_int,
    _n: c_int,
    _v: *const *const c_char,
) -> c_int {
    authenticate(pamh)
}

/// `pam_sm_setcred`: nothing to set; the decision is Access's.
// SAFETY: the PAM module ABI name Linux-PAM looks up; nothing else exports it.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _h: *mut c_void,
    _f: c_int,
    _n: c_int,
    _v: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
