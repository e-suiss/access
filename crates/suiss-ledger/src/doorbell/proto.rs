//! The NATS client protocol, sans I/O (OP-63): the operations a client writes, a parser for
//! the operations a server sends, and the `JetStream` publish acknowledgement. Only what a
//! doorbell needs: `INFO`, `CONNECT`, `PUB`/`HPUB`, `SUB`, `MSG`/`HMSG`, `PING`/`PONG`,
//! `+OK`/`-ERR`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The longest control line accepted (`INFO` included).
pub const MAX_LINE: usize = 8 * 1024;

/// The largest message payload accepted, headers included.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// A protocol violation by the peer, or an item this client will not write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("nats protocol: {0}")]
pub struct ProtoError(pub &'static str);

/// What a server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerOp {
    /// `INFO`: the server's JSON description.
    Info(String),
    /// `MSG` or `HMSG`.
    Msg(Message),
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
    /// `+OK`.
    Ok,
    /// `-ERR` and its text.
    Err(String),
}

/// One delivered message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Its subject.
    pub subject: String,
    /// The subscription it came through.
    pub sid: String,
    /// Where an answer goes.
    pub reply: Option<String>,
    /// Its header block, `NATS/1.0` line included; `None` for `MSG`.
    pub headers: Option<Vec<u8>>,
    /// Its payload.
    pub payload: Vec<u8>,
}

impl Message {
    /// The status code of a header block's first line (`NATS/1.0 503`), if it has one.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        let h = self.headers.as_deref()?;
        let line = h.split(|b| *b == b'\r').next()?;
        let rest = line.strip_prefix(b"NATS/1.0")?;
        let code = core::str::from_utf8(rest).ok()?.split_whitespace().next()?;
        code.parse().ok()
    }

    /// The value of header `name`, matched without case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<String> {
        header(self.headers.as_deref()?, name)
    }
}

/// The value of `name` in a header block.
#[must_use]
pub fn header(block: &[u8], name: &str) -> Option<String> {
    let text = core::str::from_utf8(block).ok()?;
    text.split("\r\n").skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// Whether `s` is a subject a client may publish to or subscribe to: dot-separated tokens of
/// printable ASCII without white space; `*` and `>` only as whole tokens, `>` only last.
#[must_use]
pub fn subject_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let tokens: Vec<&str> = s.split('.').collect();
    let last = tokens.len().saturating_sub(1);
    tokens.iter().enumerate().all(|(i, t)| {
        !t.is_empty()
            && t.bytes().all(|b| b.is_ascii_graphic())
            && (*t == "*" || *t == ">" || !t.contains(['*', '>']))
            && (*t != ">" || i == last)
    })
}

/// Whether `subject` falls under the subscription `filter`.
#[must_use]
pub fn matches(filter: &str, subject: &str) -> bool {
    let mut f = filter.split('.');
    let mut s = subject.split('.');
    loop {
        match (f.next(), s.next()) {
            (Some(">"), Some(_)) | (None, None) => return true,
            (Some("*"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

fn token(s: &str) -> Result<&str, ProtoError> {
    if subject_ok(s) {
        Ok(s)
    } else {
        Err(ProtoError("subject"))
    }
}

/// `CONNECT` with its JSON options, then `PING`.
#[must_use]
pub fn connect(options: &str) -> Vec<u8> {
    format!("CONNECT {options}\r\nPING\r\n").into_bytes()
}

/// `PING`.
#[must_use]
pub fn ping() -> &'static [u8] {
    b"PING\r\n"
}

/// `PONG`.
#[must_use]
pub fn pong() -> &'static [u8] {
    b"PONG\r\n"
}

/// `SUB subject sid`.
///
/// # Errors
/// [`ProtoError`] for a subject or sid that is not a token.
pub fn sub(subject: &str, sid: &str) -> Result<Vec<u8>, ProtoError> {
    Ok(format!("SUB {} {}\r\n", token(subject)?, token(sid)?).into_bytes())
}

/// `PUB`, or `HPUB` when there are headers.
///
/// # Errors
/// [`ProtoError`] for a bad subject, a header with a line break or a colon in its name, or a
/// message above [`MAX_PAYLOAD`].
pub fn publish(
    subject: &str,
    reply: Option<&str>,
    headers: &[(&str, &str)],
    payload: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    let subject = token(subject)?;
    let reply = reply.map(token).transpose()?;
    let mut out = Vec::new();
    let head = match reply {
        Some(r) => format!("{subject} {r}"),
        None => String::from(subject),
    };
    if headers.is_empty() {
        if payload.len() > MAX_PAYLOAD {
            return Err(ProtoError("payload"));
        }
        out.extend_from_slice(format!("PUB {head} {}\r\n", payload.len()).as_bytes());
    } else {
        let mut block = String::from("NATS/1.0\r\n");
        for (k, v) in headers {
            if k.is_empty()
                || k.contains([':', '\r', '\n', ' '])
                || v.contains(['\r', '\n'])
                || !k.is_ascii()
            {
                return Err(ProtoError("header"));
            }
            block.push_str(k);
            block.push_str(": ");
            block.push_str(v);
            block.push_str("\r\n");
        }
        block.push_str("\r\n");
        let total = block
            .len()
            .checked_add(payload.len())
            .filter(|t| *t <= MAX_PAYLOAD)
            .ok_or(ProtoError("payload"))?;
        out.extend_from_slice(format!("HPUB {head} {} {total}\r\n", block.len()).as_bytes());
        out.extend_from_slice(block.as_bytes());
    }
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// What a client sends, as a server reads it (the in-process twin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientOp {
    /// `CONNECT` and its JSON.
    Connect(String),
    /// `PUB` or `HPUB`.
    Pub(Message),
    /// `SUB subject sid`.
    Sub {
        /// The filter.
        subject: String,
        /// The client's id for it.
        sid: String,
    },
    /// `UNSUB sid`.
    Unsub(String),
    /// `PING`.
    Ping,
    /// `PONG`.
    Pong,
}

/// An incremental reader of one side of a connection.
#[derive(Debug, Default)]
pub struct Parser {
    buf: Vec<u8>,
}

enum Framed {
    Line(String),
    Body(String, Vec<u8>, Vec<u8>),
}

impl Parser {
    /// An empty parser.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends bytes read from the connection.
    ///
    /// # Errors
    /// [`ProtoError`] when unparsed input grows past a line and a payload.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), ProtoError> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > MAX_LINE.saturating_add(MAX_PAYLOAD).saturating_add(4) {
            return Err(ProtoError("buffer"));
        }
        Ok(())
    }

    /// Bytes fed and not yet parsed; for a TLS upgrade after `INFO` there must be none.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    fn line(&self) -> Result<Option<usize>, ProtoError> {
        match self.buf.windows(2).position(|w| w == b"\r\n") {
            Some(n) if n > MAX_LINE => Err(ProtoError("line")),
            Some(n) => Ok(Some(n)),
            None if self.buf.len() > MAX_LINE => Err(ProtoError("line")),
            None => Ok(None),
        }
    }

    /// One framed item: a control line, or a line whose last two numbers are the header and
    /// total lengths of the body that follows (`body` decides).
    fn frame(
        &mut self,
        body: impl Fn(&str) -> Result<Option<(usize, usize)>, ProtoError>,
    ) -> Result<Option<Framed>, ProtoError> {
        let Some(n) = self.line()? else {
            return Ok(None);
        };
        let line = core::str::from_utf8(self.buf.get(..n).ok_or(ProtoError("line"))?)
            .map_err(|_| ProtoError("utf-8"))?
            .to_string();
        let start = n.checked_add(2).ok_or(ProtoError("line"))?;
        let Some((hdr, total)) = body(&line)? else {
            self.buf.drain(..start);
            return Ok(Some(Framed::Line(line)));
        };
        if hdr > total || total > MAX_PAYLOAD {
            return Err(ProtoError("length"));
        }
        let end = start.checked_add(total).ok_or(ProtoError("length"))?;
        let after = end.checked_add(2).ok_or(ProtoError("length"))?;
        if self.buf.len() < after {
            return Ok(None);
        }
        if self.buf.get(end..after) != Some(b"\r\n".as_slice()) {
            return Err(ProtoError("terminator"));
        }
        let split = start.checked_add(hdr).ok_or(ProtoError("length"))?;
        let headers = self.buf.get(start..split).unwrap_or_default().to_vec();
        let payload = self.buf.get(split..end).unwrap_or_default().to_vec();
        self.buf.drain(..after);
        Ok(Some(Framed::Body(line, headers, payload)))
    }

    /// The next complete server operation, if one is buffered.
    ///
    /// # Errors
    /// [`ProtoError`] for anything that is not one.
    pub fn server_op(&mut self) -> Result<Option<ServerOp>, ProtoError> {
        let framed = self.frame(|line| {
            let mut w = line.split_ascii_whitespace();
            match w.next().map(str::to_ascii_uppercase).as_deref() {
                Some("MSG") => {
                    let n = w.last().ok_or(ProtoError("msg"))?;
                    Ok(Some((0, number(n)?)))
                }
                Some("HMSG") => {
                    let parts: Vec<&str> = w.collect();
                    let [.., h, t] = parts.as_slice() else {
                        return Err(ProtoError("hmsg"));
                    };
                    Ok(Some((number(h)?, number(t)?)))
                }
                _ => Ok(None),
            }
        })?;
        let Some(framed) = framed else {
            return Ok(None);
        };
        Ok(Some(match framed {
            Framed::Line(line) => {
                let (op, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                match op.to_ascii_uppercase().as_str() {
                    "INFO" => ServerOp::Info(rest.trim().to_string()),
                    "PING" => ServerOp::Ping,
                    "PONG" => ServerOp::Pong,
                    "+OK" => ServerOp::Ok,
                    "-ERR" => ServerOp::Err(rest.trim().trim_matches('\'').to_string()),
                    _ => return Err(ProtoError("operation")),
                }
            }
            Framed::Body(line, headers, payload) => {
                let parts: Vec<&str> = line.split_ascii_whitespace().collect();
                let hmsg = parts
                    .first()
                    .is_some_and(|p| p.eq_ignore_ascii_case("HMSG"));
                let fixed = if hmsg { 2 } else { 1 };
                let (subject, sid, reply) = match parts.as_slice() {
                    [_, s, i, rest @ ..] if rest.len() == fixed => (s, i, None),
                    [_, s, i, r, rest @ ..] if rest.len() == fixed => (s, i, Some(*r)),
                    _ => return Err(ProtoError("msg")),
                };
                ServerOp::Msg(Message {
                    subject: (*subject).to_string(),
                    sid: (*sid).to_string(),
                    reply: reply.map(ToString::to_string),
                    headers: hmsg.then_some(headers),
                    payload,
                })
            }
        }))
    }

    /// The next complete client operation, if one is buffered.
    ///
    /// # Errors
    /// [`ProtoError`] for anything that is not one.
    pub fn client_op(&mut self) -> Result<Option<ClientOp>, ProtoError> {
        let framed = self.frame(|line| {
            let mut w = line.split_ascii_whitespace();
            match w.next().map(str::to_ascii_uppercase).as_deref() {
                Some("PUB") => {
                    let n = w.last().ok_or(ProtoError("pub"))?;
                    Ok(Some((0, number(n)?)))
                }
                Some("HPUB") => {
                    let parts: Vec<&str> = w.collect();
                    let [.., h, t] = parts.as_slice() else {
                        return Err(ProtoError("hpub"));
                    };
                    Ok(Some((number(h)?, number(t)?)))
                }
                _ => Ok(None),
            }
        })?;
        let Some(framed) = framed else {
            return Ok(None);
        };
        Ok(Some(match framed {
            Framed::Line(line) => {
                let (op, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                let words: Vec<&str> = rest.split_ascii_whitespace().collect();
                match (op.to_ascii_uppercase().as_str(), words.as_slice()) {
                    ("CONNECT", _) => ClientOp::Connect(rest.trim().to_string()),
                    ("PING", _) => ClientOp::Ping,
                    ("PONG", _) => ClientOp::Pong,
                    ("SUB", [s, .., i]) => ClientOp::Sub {
                        subject: (*s).to_string(),
                        sid: (*i).to_string(),
                    },
                    ("UNSUB", [i, ..]) => ClientOp::Unsub((*i).to_string()),
                    _ => return Err(ProtoError("operation")),
                }
            }
            Framed::Body(line, headers, payload) => {
                let parts: Vec<&str> = line.split_ascii_whitespace().collect();
                let hpub = parts
                    .first()
                    .is_some_and(|p| p.eq_ignore_ascii_case("HPUB"));
                let fixed = if hpub { 2 } else { 1 };
                let (subject, reply) = match parts.as_slice() {
                    [_, s, rest @ ..] if rest.len() == fixed => (s, None),
                    [_, s, r, rest @ ..] if rest.len() == fixed => (s, Some(*r)),
                    _ => return Err(ProtoError("pub")),
                };
                ClientOp::Pub(Message {
                    subject: (*subject).to_string(),
                    sid: String::new(),
                    reply: reply.map(ToString::to_string),
                    headers: hpub.then_some(headers),
                    payload,
                })
            }
        }))
    }
}

fn number(s: &str) -> Result<usize, ProtoError> {
    s.parse().map_err(|_| ProtoError("length"))
}

/// `MSG` or `HMSG` as a server writes it.
#[must_use]
pub fn deliver(m: &Message) -> Vec<u8> {
    let reply = m
        .reply
        .as_deref()
        .map(|r| format!(" {r}"))
        .unwrap_or_default();
    let mut out = Vec::new();
    match &m.headers {
        Some(h) => {
            let total = h.len().saturating_add(m.payload.len());
            out.extend_from_slice(
                format!(
                    "HMSG {} {}{reply} {} {total}\r\n",
                    m.subject,
                    m.sid,
                    h.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(h);
        }
        None => out.extend_from_slice(
            format!("MSG {} {}{reply} {}\r\n", m.subject, m.sid, m.payload.len()).as_bytes(),
        ),
    }
    out.extend_from_slice(&m.payload);
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests;
