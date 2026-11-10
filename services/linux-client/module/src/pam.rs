//! The PAM module's safe half (OP-156 m.3 (p)): the request for a PAM service, the command a
//! `sudo` step-up names, the text shown to the person and the PAM result of an answer.

use suiss_crypto::digest::sha256;

use crate::wire::{Request, Response};

/// `PAM_SUCCESS`.
pub const PAM_SUCCESS: i32 = 0;
/// `PAM_AUTH_ERR`.
pub const PAM_AUTH_ERR: i32 = 7;
/// `PAM_AUTHINFO_UNAVAIL`.
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
/// `PAM_USER_UNKNOWN`.
pub const PAM_USER_UNKNOWN: i32 = 10;
/// `PAM_IGNORE`.
pub const PAM_IGNORE: i32 = 25;

/// The PAM services that are a `sudo` step-up.
pub const SUDO_SERVICES: [&str; 2] = ["sudo", "sudo-i"];

/// The request for a sign-in to `service` by `user` on `tty`; for `sudo`, a step-up naming the
/// SHA-256 of the process's command line (`/proc/self/cmdline`).
#[must_use]
pub fn request(user: &str, service: &str, tty: Option<&str>, cmdline: &[u8]) -> Request {
    if SUDO_SERVICES.contains(&service) {
        Request::Sudo {
            user: String::from(user),
            command: sha256(cmdline),
        }
    } else {
        Request::Authenticate {
            user: String::from(user),
            service: String::from(service),
            tty: tty
                .filter(|t| !t.is_empty() && t.len() <= 64)
                .map(String::from),
        }
    }
}

/// The text the person reads for an answer, in English; the daemon names it by `TextId`
/// (`locales/en/login.ftl`).
#[must_use]
pub fn text(answer: &Response) -> Option<String> {
    match answer {
        Response::Pending(p) if p.text == "linux.signin_pending" || p.text == "linux.step_up" => {
            let open = match (&p.verification_uri, &p.user_code) {
                (Some(uri), Some(code)) => format!("To sign in, open {uri} and enter {code}."),
                _ => String::new(),
            };
            if p.text == "linux.step_up" {
                Some(format!(
                    "Confirm it's you with your security key to run this command. {open}"
                ))
            } else {
                Some(open)
            }
        }
        Response::Unavailable(_) => Some(String::from(
            "Access can't be reached and this computer's saved sign-in has run out. Try again when it's online.",
        )),
        _ => None,
    }
}

/// The PAM result of the daemon's final word: success only for `allow`; no answer at all is
/// `PAM_AUTHINFO_UNAVAIL`, never a success.
#[must_use]
pub const fn result(allowed: Option<bool>) -> i32 {
    match allowed {
        Some(true) => PAM_SUCCESS,
        Some(false) => PAM_AUTH_ERR,
        None => PAM_AUTHINFO_UNAVAIL,
    }
}
