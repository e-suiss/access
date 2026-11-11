//! The syslog and SIEM copies of each trail line (§17.7.3 principle 6, §17.8.2): RFC 5424
//! messages, `authpriv.alert`, over a local datagram socket or UDP, and over TCP with octet
//! counting (RFC 6587) to the cell's SIEM collector when it answers.

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs as _, UdpSocket};
use std::time::Duration;

/// `authpriv` (10) × 8 + `alert` (1).
const PRI: u8 = 81;

/// How long the SIEM leg may take.
const SIEM_TIMEOUT: Duration = Duration::from_secs(2);

#[allow(
    clippy::arithmetic_side_effects,
    reason = "days-from-civil inverse (Hinnant) on a bounded day count"
)]
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// RFC 3339 UTC with milliseconds.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bounded calendar arithmetic on a u64 millisecond count"
)]
pub(crate) fn timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty() && h.len() <= 255 && h.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_else(|| "-".to_owned())
}

/// One RFC 5424 message; `msgid` is the trail event.
pub(crate) fn message(at_ms: u64, msgid: &str, text: &str) -> String {
    format!(
        "<{PRI}>1 {} {} access-breakglass {} {msgid} - {text}",
        timestamp(at_ms),
        hostname(),
        std::process::id()
    )
}

/// Sends `msg` to `target`: `unix:<path>` or `udp:<host:port>`. Datagrams carry no answer, so
/// only a local failure is reported.
pub(crate) fn send(target: &str, msg: &str) -> Result<(), &'static str> {
    if let Some(path) = target.strip_prefix("unix:") {
        #[cfg(unix)]
        {
            let s = std::os::unix::net::UnixDatagram::unbound().map_err(|_| "syslog socket")?;
            s.send_to(msg.as_bytes(), path).map_err(|_| "syslog send")?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err("syslog socket");
        }
    }
    let addr = target.strip_prefix("udp:").ok_or("syslog target")?;
    let s = UdpSocket::bind("0.0.0.0:0").map_err(|_| "syslog socket")?;
    s.send_to(msg.as_bytes(), addr).map_err(|_| "syslog send")?;
    Ok(())
}

/// Sends `msg` to the SIEM collector at `addr` (`host:port`), framed by its length.
pub(crate) fn siem(addr: &str, msg: &str) -> Result<(), &'static str> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|_| "siem address")?
        .next()
        .ok_or("siem address")?;
    let mut s = TcpStream::connect_timeout(&sock, SIEM_TIMEOUT).map_err(|_| "siem unreachable")?;
    s.set_write_timeout(Some(SIEM_TIMEOUT))
        .map_err(|_| "siem unreachable")?;
    s.write_all(format!("{} {msg}", msg.len()).as_bytes())
        .map_err(|_| "siem send")?;
    s.flush().map_err(|_| "siem send")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §17.7.3 principle 6, RFC 5424
    #[test]
    fn op_46_messages_are_rfc_5424() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(1_709_251_199_999), "2024-02-29T23:59:59.999Z");
        assert_eq!(timestamp(1_798_761_600_000), "2027-01-01T00:00:00.000Z");
        let m = message(0, "used", "cell=eu-1");
        assert!(m.starts_with("<81>1 1970-01-01T00:00:00.000Z "), "{m}");
        assert!(m.contains(" access-breakglass ") && m.ends_with(" used - cell=eu-1"));
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        send(&format!("udp:{}", rx.local_addr().unwrap()), &m).unwrap();
        let mut buf = vec![0_u8; 512];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(buf.get(..n).unwrap(), m.as_bytes());
        assert!(send("tcp:x", &m).is_err());
    }
}
