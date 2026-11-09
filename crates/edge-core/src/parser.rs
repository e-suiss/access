//! A gateway's client of the parser worker supervisor (OP-155 m.3 (c), MD-18): XML, DER and ASN.1
//! never parse in the gateway; they go over the supervisor's Unix socket to a disposable worker.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use crate::ipc::{MAX_HEADER, MAX_SEGMENT, Op, Reply, Request, length};

/// Longest a gateway waits for one answer: the worker's wall clock and room to replace it.
pub const DEADLINE: Duration = Duration::from_secs(7);

/// Why the supervisor gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParserError {
    /// The input is larger than one segment.
    #[error("input too large")]
    TooLarge,
    /// The socket failed, the peer is not the supervisor, or the deadline passed.
    #[error("parser unavailable")]
    Unavailable,
}

/// The supervisor at a socket path.
#[derive(Clone, Debug)]
pub struct ParserClient {
    path: PathBuf,
    supervisor_uid: Option<u32>,
}

impl ParserClient {
    /// The supervisor at `path`; with `supervisor_uid` the peer must run as that user.
    #[must_use]
    pub const fn new(path: PathBuf, supervisor_uid: Option<u32>) -> Self {
        Self {
            path,
            supervisor_uid,
        }
    }

    /// Parses `input` with `op` in a worker.
    ///
    /// # Errors
    /// [`ParserError`]; a refusal or a crashed worker is a [`Reply`], not an error.
    pub async fn parse(&self, op: Op, input: Vec<u8>) -> Result<Reply, ParserError> {
        let frame = Request { op, input }
            .encode()
            .map_err(|_| ParserError::TooLarge)?;
        tokio::time::timeout(DEADLINE, self.exchange(&frame))
            .await
            .map_err(|_| ParserError::Unavailable)?
    }

    async fn exchange(&self, frame: &[u8]) -> Result<Reply, ParserError> {
        let down = |_| ParserError::Unavailable;
        let mut s = UnixStream::connect(&self.path).await.map_err(down)?;
        if let Some(uid) = self.supervisor_uid
            && s.peer_cred().map_err(down)?.uid() != uid
        {
            return Err(ParserError::Unavailable);
        }
        s.write_all(frame).await.map_err(down)?;
        let mut whole = Vec::new();
        for max in [MAX_HEADER, MAX_SEGMENT] {
            let mut prefix = [0_u8; 4];
            s.read_exact(&mut prefix).await.map_err(down)?;
            let n = length(prefix, max).map_err(|_| ParserError::Unavailable)?;
            whole.extend_from_slice(&prefix);
            let mut part = vec![0_u8; n];
            s.read_exact(&mut part).await.map_err(down)?;
            whole.extend_from_slice(&part);
        }
        Reply::decode(&whole).map_err(|_| ParserError::Unavailable)
    }
}
