//! Syslog messages of the copy (RFC 5424) and their framing over TLS (RFC 5425 octet counting,
//! OP-156 m.3 (s)). Facility 13 (log audit); a failure is a warning, anything else
//! informational. The message is the record's CEF or LEEF line.

use access_identity_audit::adapters::cef;
use access_identity_audit::domain::record::AuditRecord;
use access_identity_audit::domain::taxonomy::{Outcome, TaxonomyError, entry};

use super::copy;
use super::leef;
use super::sink::Format;

/// The `MSGID` of every message.
pub const MSGID: &str = "audit-copy";

/// Facility 13: log audit (RFC 5424 §6.2.1).
const FACILITY: u16 = 13;

/// `PRI`: facility 13 with warning (4) or informational (6) severity.
const fn pri(o: Outcome) -> u16 {
    match o {
        Outcome::Failure => FACILITY * 8 + 4,
        Outcome::Success | Outcome::Unknown => FACILITY * 8 + 6,
    }
}

/// `PRINTUSASCII` without spaces, at most `max` characters, `-` when empty (RFC 5424 §6).
fn field(v: &str, max: usize) -> String {
    let s: String = v.chars().filter(char::is_ascii_graphic).take(max).collect();
    if s.is_empty() { String::from("-") } else { s }
}

fn utc(ms: u64) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).checked_mul(1_000_000)?).ok()
}

/// `ms` as an RFC 3339 UTC timestamp with milliseconds.
#[must_use]
pub fn timestamp(ms: u64) -> String {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    utc(ms)
        .and_then(|t| t.format(&format).ok())
        .unwrap_or_default()
}

/// The UTC date of `ms` as `YYYYMMDD`.
#[must_use]
pub fn day(ms: u64) -> String {
    let format = time::macros::format_description!("[year][month][day]");
    utc(ms)
        .and_then(|t| t.format(&format).ok())
        .unwrap_or_default()
}

/// The RFC 5424 message of `record`'s copy in `format`, from `hostname` and `app`.
///
/// # Errors
/// [`TaxonomyError`]; nothing is rendered.
pub fn message(
    record: &AuditRecord,
    format: Format,
    (hostname, app): (&str, &str),
) -> Result<String, TaxonomyError> {
    let e = entry(&record.event)?;
    let pri = pri(e.outcome);
    let msg = match format {
        Format::Cef => {
            let line = cef::render(record)?;
            format!("{line} cs5Label=record cs5={}", copy::VALUE)
        }
        Format::Leef => leef::render(record)?,
    };
    Ok(format!(
        "<{pri}>1 {} {} {} - {MSGID} - {msg}",
        timestamp(record.occurred_at_ms),
        field(hostname, 255),
        field(app, 48),
    ))
}

/// `message` framed for TLS transport: `MSG-LEN SP SYSLOG-MSG` (RFC 5425 §4.3).
#[must_use]
pub fn frame(message: &str) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message.as_bytes());
    out
}

/// Splits a stream of frames back into messages; `None` when it is not a sequence of frames.
#[must_use]
pub fn unframe(mut bytes: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let sp = bytes.iter().position(|b| *b == b' ')?;
        let len: usize = core::str::from_utf8(bytes.get(..sp)?).ok()?.parse().ok()?;
        let start = sp.checked_add(1)?;
        let end = start.checked_add(len)?;
        out.push(String::from_utf8(bytes.get(start..end)?.to_vec()).ok()?);
        bytes = bytes.get(end..)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (s)
    #[test]
    fn frames_round_trip_and_times_are_utc() {
        let f = [frame("<110>1 a"), frame("<108>1 bb")].concat();
        assert_eq!(unframe(&f).unwrap(), ["<110>1 a", "<108>1 bb"]);
        assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(1_762_772_400_123), "2025-11-10T11:00:00.123Z");
        assert_eq!(field("a b\nc", 10), "abc");
        assert_eq!(field("", 10), "-");
    }
}
