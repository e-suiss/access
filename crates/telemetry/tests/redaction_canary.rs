//! CR-35 / OP-64 rule 6 canary: a secret placed in a request-like structure never
//! reaches the log output, whatever way the structure is logged.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use access_crypto::Secret;
use tracing_subscriber::fmt::MakeWriter;

const CANARY: &str = "CANARY-7f3c9a-do-not-log";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A request type as a handler would hold it. `Secret` has no `Debug`, so the
/// type must implement `Debug` by hand and decide what to show.
struct LoginRequest {
    username: String,
    password: Secret<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[test]
fn password_never_appears_in_logs() {
    let capture = Capture::default();
    access_telemetry::init_with_writer("trace", capture.clone()).unwrap();

    let request = LoginRequest {
        username: "alice".into(),
        password: Secret::new(CANARY.to_owned()),
    };
    assert!(request.password.ct_eq_bytes(CANARY.as_bytes()));

    tracing::info!(?request, "login attempt");
    tracing::info!(request = ?request, user = %request.username, "structured fields");
    let span = tracing::info_span!("login", req = ?request);
    span.in_scope(|| tracing::warn!("inside span"));

    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("alice"),
        "log capture did not work: {output}"
    );
    assert!(output.contains("[redacted]"));
    assert!(
        !output.contains(CANARY),
        "secret leaked into logs: {output}"
    );
}
