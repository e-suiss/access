//! The adapter as a child process speaking the JSON-lines protocol on its stdin and stdout.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::protocol::{CaseMessage, CaseResult, FromSut, PROTOCOL, ToSut};
use crate::run::{Adapter, AdapterError};

/// A child process adapter, started with `sh -c <command>`.
#[derive(Debug)]
pub struct Subprocess {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::UnboundedReceiver<String>,
    name: String,
}

fn io(e: impl std::fmt::Display) -> AdapterError {
    AdapterError::Io(e.to_string())
}

impl Subprocess {
    /// Starts `command` and completes the handshake within `wait`.
    ///
    /// # Errors
    /// [`AdapterError`] when the process does not start or does not answer `ready`.
    pub async fn start(command: &str, wait: Duration) -> Result<Self, AdapterError> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(io)?;
        let stdin = child.stdin.take().ok_or_else(|| io("no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| io("no stdout"))?;
        let (tx, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut sut = Self {
            child,
            stdin,
            lines,
            name: String::new(),
        };
        sut.send(&ToSut::Hello {
            protocol: PROTOCOL.to_owned(),
        })?;
        match sut.receive(wait).await? {
            Some(FromSut::Ready { protocol, name }) if protocol == PROTOCOL => {
                sut.name = name;
                Ok(sut)
            }
            Some(other) => Err(AdapterError::Protocol(format!(
                "expected ready for {PROTOCOL}, got {other:?}"
            ))),
            None => Err(AdapterError::Protocol(String::from("no ready line"))),
        }
    }

    /// The name the adapter announced.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn send(&mut self, msg: &ToSut) -> Result<(), AdapterError> {
        let line = serde_json::to_string(msg).map_err(io)?;
        writeln!(self.stdin, "{line}").map_err(io)?;
        self.stdin.flush().map_err(io)
    }

    async fn receive(&mut self, wait: Duration) -> Result<Option<FromSut>, AdapterError> {
        match tokio::time::timeout(wait, self.lines.recv()).await {
            Err(_) => Ok(None),
            Ok(None) => Err(io("adapter closed its stdout")),
            Ok(Some(line)) => serde_json::from_str(&line)
                .map(Some)
                .map_err(|e| AdapterError::Protocol(format!("{e}: {line}"))),
        }
    }

    /// Says goodbye and stops the process.
    pub fn stop(mut self) {
        let _ = self.send(&ToSut::Bye);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Adapter for Subprocess {
    async fn exchange(
        &mut self,
        msg: &CaseMessage,
        wait: Duration,
    ) -> Result<Option<CaseResult>, AdapterError> {
        self.send(&ToSut::Case(Box::new(msg.clone())))?;
        let start = tokio::time::Instant::now();
        let until = start.checked_add(wait).unwrap_or(start);
        loop {
            let left = until.saturating_duration_since(tokio::time::Instant::now());
            match self.receive(left).await? {
                Some(FromSut::Result(r)) if r.case == msg.case => return Ok(Some(r)),
                Some(FromSut::Result(_)) => {}
                Some(other) => {
                    return Err(AdapterError::Protocol(format!(
                        "expected a result, got {other:?}"
                    )));
                }
                None => return Ok(None),
            }
        }
    }
}
