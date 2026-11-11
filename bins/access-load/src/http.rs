//! A small HTTP/1.1 client on keep-alive TCP connections: enough to send one prepared request
//! and read its status and body (`Content-Length` or chunked). No redirects, no TLS.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

/// Most bytes of one response read.
pub(crate) const MAX_BODY: usize = 1 << 22;
/// Most header lines of one response.
const MAX_HEADERS: usize = 128;

/// One prepared request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Prepared {
    /// Method.
    pub(crate) method: String,
    /// Path and query.
    pub(crate) path: String,
    /// Extra headers.
    pub(crate) headers: Vec<(String, String)>,
    /// Body.
    pub(crate) body: Vec<u8>,
}

/// Why a request got no status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HttpError {
    /// The connection failed or closed early.
    Io,
    /// The response is not HTTP/1.1 as read here.
    Malformed,
    /// No response within the timeout.
    Timeout,
}

/// One keep-alive connection.
pub(crate) struct Connection {
    stream: BufReader<TcpStream>,
    host: String,
}

impl Connection {
    /// Connects to `host` (`name:port`).
    ///
    /// # Errors
    /// [`HttpError::Io`].
    pub(crate) async fn open(host: &str) -> Result<Self, HttpError> {
        let stream = TcpStream::connect(host).await.map_err(|_| HttpError::Io)?;
        stream.set_nodelay(true).map_err(|_| HttpError::Io)?;
        Ok(Self {
            stream: BufReader::new(stream),
            host: host.to_owned(),
        })
    }

    /// Sends `req` and reads the status, within `timeout`.
    ///
    /// # Errors
    /// [`HttpError`]; the connection is then not reused.
    pub(crate) async fn send(
        &mut self,
        req: &Prepared,
        timeout: Duration,
    ) -> Result<u16, HttpError> {
        tokio::time::timeout(timeout, self.exchange(req))
            .await
            .map_err(|_| HttpError::Timeout)?
    }

    async fn exchange(&mut self, req: &Prepared) -> Result<u16, HttpError> {
        let mut head = format!(
            "{} {} HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\n",
            req.method,
            req.path,
            self.host,
            req.body.len()
        );
        for (k, v) in &req.headers {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let s = self.stream.get_mut();
        s.write_all(head.as_bytes())
            .await
            .map_err(|_| HttpError::Io)?;
        s.write_all(&req.body).await.map_err(|_| HttpError::Io)?;
        let mut line = String::new();
        self.read_line(&mut line).await?;
        let status = line
            .strip_prefix("HTTP/1.1 ")
            .and_then(|r| r.get(..3))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or(HttpError::Malformed)?;
        let mut length: Option<usize> = None;
        let mut chunked = false;
        for _ in 0..MAX_HEADERS {
            line.clear();
            self.read_line(&mut line).await?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            let Some((k, v)) = l.split_once(':') else {
                return Err(HttpError::Malformed);
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "content-length" {
                length = Some(v.parse().map_err(|_| HttpError::Malformed)?);
            } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
        if chunked {
            self.skip_chunks().await?;
        } else {
            self.skip(length.unwrap_or(0)).await?;
        }
        Ok(status)
    }

    async fn read_line(&mut self, line: &mut String) -> Result<(), HttpError> {
        let n = self
            .stream
            .read_line(line)
            .await
            .map_err(|_| HttpError::Io)?;
        if n == 0 {
            return Err(HttpError::Io);
        }
        Ok(())
    }

    async fn skip(&mut self, n: usize) -> Result<(), HttpError> {
        if n > MAX_BODY {
            return Err(HttpError::Malformed);
        }
        let mut left = n;
        let mut buf = [0u8; 8192];
        while left > 0 {
            let want = left.min(buf.len());
            let got = self
                .stream
                .read(buf.get_mut(..want).ok_or(HttpError::Malformed)?)
                .await
                .map_err(|_| HttpError::Io)?;
            if got == 0 {
                return Err(HttpError::Io);
            }
            left = left.saturating_sub(got);
        }
        Ok(())
    }

    async fn skip_chunks(&mut self) -> Result<(), HttpError> {
        let mut total = 0usize;
        loop {
            let mut line = String::new();
            self.read_line(&mut line).await?;
            let size =
                usize::from_str_radix(line.trim_end().split(';').next().unwrap_or_default(), 16)
                    .map_err(|_| HttpError::Malformed)?;
            total = total.saturating_add(size);
            if total > MAX_BODY {
                return Err(HttpError::Malformed);
            }
            if size == 0 {
                line.clear();
                self.read_line(&mut line).await?;
                return Ok(());
            }
            self.skip(size.saturating_add(2)).await?;
        }
    }
}

/// Reads a requests file: one JSON object per line, `{"method", "path", "headers", "body"}`;
/// `path` defaults to `default_path`, `method` to `POST`, and a string `body` is sent as is
/// while any other body is sent as JSON.
///
/// # Errors
/// The line number of a line that is not such an object.
pub(crate) fn requests(text: &str, default_path: &str) -> Result<Vec<Prepared>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| format!("requests line {}", n.saturating_add(1)))?;
        let field = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
        let headers = match v.get("headers") {
            None => Vec::new(),
            Some(serde_json::Value::Object(m)) => m
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                .collect(),
            Some(_) => return Err(format!("requests line {} headers", n.saturating_add(1))),
        };
        let body = match v.get("body") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::String(s)) => s.clone().into_bytes(),
            Some(other) => other.to_string().into_bytes(),
        };
        let mut headers = headers;
        if v.get("body").is_some_and(serde_json::Value::is_object)
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push((
                String::from("content-type"),
                String::from("application/json"),
            ));
        }
        out.push(Prepared {
            method: field("method").unwrap_or("POST").to_owned(),
            path: field("path").unwrap_or(default_path).to_owned(),
            headers,
            body,
        });
    }
    if out.is_empty() {
        return Err(String::from("requests file is empty"));
    }
    Ok(out)
}
