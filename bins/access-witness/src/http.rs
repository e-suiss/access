//! A small HTTP/1.1 client for gossip: one request per connection, plain `http://` (the
//! answers are signed notes, verified after reading; OP-158 m.6 proposal (a)).

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// How long one exchange may take.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);

/// Largest answer read.
const MAX_ANSWER: u64 = 512 * 1024;

/// `host:port` and the path prefix of an `http://` URL.
pub(crate) fn split(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("not an http:// URL: {url}"))?;
    let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    if host.is_empty() || !host.contains(':') {
        return Err(format!("URL needs host:port: {url}"));
    }
    Ok((host.to_owned(), format!("/{}", path.trim_end_matches('/'))))
}

/// `GET url + path`: the status and the body.
pub(crate) async fn get(url: &str, path: &str) -> Result<(u16, String), String> {
    let (host, prefix) = split(url)?;
    let target = format!("{}{path}", prefix.trim_end_matches('/'));
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(TIMEOUT, exchange(&host, request.as_bytes()))
        .await
        .map_err(|_| format!("{url}: timed out"))?
}

async fn exchange(host: &str, request: &[u8]) -> Result<(u16, String), String> {
    let mut s = tokio::net::TcpStream::connect(host)
        .await
        .map_err(|e| format!("{host}: {e}"))?;
    s.write_all(request).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(MAX_ANSWER)
        .read_to_end(&mut raw)
        .await
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8(raw).map_err(|_| "answer is not UTF-8".to_owned())?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed answer".to_owned())?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| "malformed status line".to_owned())?;
    Ok((status, body.to_owned()))
}
