//! A blocking client of the daemon's socket (OP-156 m.3 (p)): one request and one answer per
//! connection, every wait bounded. Any failure, a missing daemon included, is
//! [`Unanswered`]; the modules turn it into a refusal (fail-closed, TI-9).

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::wire::{self, Request, Response};

/// The daemon's socket.
pub const SOCKET: &str = "/run/access-linuxd/socket";

/// How long one exchange may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The daemon did not answer within the CDDL; the module refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("linux-daemon-unanswered")]
pub struct Unanswered;

/// Asks the daemon at `socket` once.
///
/// # Errors
/// [`Unanswered`].
pub fn ask(socket: &Path, request: &Request, timeout: Duration) -> Result<Response, Unanswered> {
    let body = request.to_cbor().map_err(|_| Unanswered)?;
    let out = wire::frame(&body).map_err(|_| Unanswered)?;
    let mut s = UnixStream::connect(socket).map_err(|_| Unanswered)?;
    s.set_read_timeout(Some(timeout)).map_err(|_| Unanswered)?;
    s.set_write_timeout(Some(timeout)).map_err(|_| Unanswered)?;
    s.write_all(&out).map_err(|_| Unanswered)?;
    let mut header = [0u8; 4];
    s.read_exact(&mut header).map_err(|_| Unanswered)?;
    let n = wire::frame_len(header).map_err(|_| Unanswered)?;
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).map_err(|_| Unanswered)?;
    Response::from_cbor(&body).map_err(|_| Unanswered)
}

/// The final answer of a sign-in or step-up: polls a pending attempt until it is decided or
/// ends, calling `show` once with the first pending answer and with an `unavailable` answer.
/// `Some(true)` only for `allow`; `None` when the daemon did not decide.
pub fn decide(
    socket: &Path,
    request: &Request,
    interval: Duration,
    mut show: impl FnMut(&Response),
) -> Option<bool> {
    let mut answer = ask(socket, request, TIMEOUT);
    let mut shown = false;
    let mut rounds = 0_u32;
    loop {
        match answer {
            Ok(Response::Done { allow, .. }) => return Some(allow),
            Ok(Response::Pending(p)) => {
                if !shown {
                    show(&Response::Pending(p.clone()));
                    shown = true;
                }
                let most = p.expires_in.div_ceil(interval.as_secs().max(1));
                if u64::from(rounds) >= most.min(u64::from(u32::MAX)) {
                    return Some(false);
                }
                rounds = rounds.saturating_add(1);
                std::thread::sleep(interval);
                answer = ask(socket, &Request::Poll(p.attempt), TIMEOUT);
            }
            Ok(other @ Response::Unavailable(_)) => {
                show(&other);
                return None;
            }
            Ok(_) | Err(Unanswered) => return None,
        }
    }
}
