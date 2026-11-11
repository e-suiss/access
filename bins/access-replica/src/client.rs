//! One HTTP/1.1 exchange at a time with the provider's listener, on its own connection.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// How long one exchange may take: above the mirror's long poll.
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Most bytes an answer may carry.
const MAX_ANSWER: u64 = 64 * 1024 * 1024;

fn chunked(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = body.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(body.get(..line)?)
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        let start = line.checked_add(2)?;
        if size == 0 {
            return Some(out);
        }
        let end = start.checked_add(size)?;
        out.extend_from_slice(body.get(start..end)?);
        body = body.get(end.checked_add(2)?..)?;
    }
}

/// Sends `method path` with `body` to `host` (`host:port`); the status and the body.
pub(crate) async fn exchange(
    host: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    let io = async {
        let mut s = tokio::net::TcpStream::connect(host)
            .await
            .map_err(|e| e.to_string())?;
        s.write_all(&request).await.map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        s.take(MAX_ANSWER)
            .read_to_end(&mut raw)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(raw)
    };
    let raw = tokio::time::timeout(EXCHANGE_TIMEOUT, io)
        .await
        .map_err(|_| "timed out".to_owned())??;
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header end")?;
    let (head, rest) = raw.split_at(at);
    let head = std::str::from_utf8(head).map_err(|_| "header not text")?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("no status")?;
    let body = rest.get(4..).unwrap_or_default();
    let is_chunked = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = if is_chunked {
        chunked(body).ok_or("malformed chunked body")?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}
