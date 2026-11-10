//! A vendor answer relayed as the source's own Claim (OP-156 m.3 (r)): mapped by the source's
//! declared format, then signed and sent by its issuer. An answer that maps to nothing is no
//! Claim; nothing is ever inferred in its place.

use access_internal_api::signals::Signal;
use serde_json::Value as Json;

use crate::domain::source::{Format, Source};
use crate::domain::vendor;
use crate::ports::{Issuer, Unavailable};

/// Why an answer was not relayed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// The answer does not map to a signal of the source's kind.
    #[error("no signal: {0}")]
    NoSignal(&'static str),
    /// The issuer could not send it.
    #[error(transparent)]
    Unavailable(#[from] Unavailable),
}

/// The signal `answer` states in `source`'s format; `provider` is the `ref` its body names.
///
/// # Errors
/// [`RelayError::NoSignal`]: also for the `claim` and `okta-ssf` formats, whose Claims the
/// source signs itself or Claim Ingest maps from its SETs.
pub fn map(source: &Source, provider: &str, answer: &Json) -> Result<Signal, RelayError> {
    let signal = match source.format {
        Format::Intune => vendor::intune(answer, provider),
        Format::Jamf => vendor::jamf(answer, provider),
        Format::Onfido => vendor::onfido(answer, provider),
        Format::Persona => vendor::persona(answer, provider),
        Format::Claim | Format::OktaSsf => return Err(RelayError::NoSignal("format")),
    }
    .map_err(|e| RelayError::NoSignal(e.0))?;
    if signal.class() == source.kind.class() {
        Ok(signal)
    } else {
        Err(RelayError::NoSignal("kind"))
    }
}

/// Maps `answer` and issues it about `subject` through `issuer`.
///
/// # Errors
/// [`RelayError`].
pub async fn relay<I: Issuer>(
    issuer: &I,
    source: &Source,
    provider: &str,
    subject: [u8; 16],
    answer: &Json,
) -> Result<Signal, RelayError> {
    let signal = map(source, provider, answer)?;
    issuer.issue(subject, &signal).await?;
    Ok(signal)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::sync::Mutex;

    use serde_json::json;

    use super::*;
    use crate::domain::source::Kind;

    struct Sent(Mutex<Vec<([u8; 16], Signal)>>);

    impl Issuer for Sent {
        fn issue(
            &self,
            subject: [u8; 16],
            signal: &Signal,
        ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
            self.0.lock().unwrap().push((subject, signal.clone()));
            std::future::ready(Ok(()))
        }
    }

    fn source(kind: Kind, format: Format) -> Source {
        Source {
            name: String::from("s"),
            kind,
            provider: String::from("Acme MDM"),
            issuer: [7; 16],
            format,
            transmitter: None,
            expected_interval_s: 86_400,
        }
    }

    // OP-156 m.3 (r)
    #[test]
    fn a_vendor_answer_is_relayed_only_as_its_sources_class() {
        let sent = Sent(Mutex::new(Vec::new()));
        let device = json!({"managementState": "managed", "complianceState": "compliant"});
        let mdm = source(Kind::Mdm, Format::Intune);
        let s = futures_lite(relay(&sent, &mdm, "acme-mdm", [1; 16], &device)).unwrap();
        assert_eq!(s.class(), "posture_mdm");
        assert_eq!(sent.0.lock().unwrap().len(), 1);
        assert!(map(&source(Kind::Mdm, Format::Claim), "acme-mdm", &device).is_err());
        let check = json!({"status": "complete", "result": "consider",
                           "report_names": ["document"], "created_at": "2026-11-01T10:00:00Z"});
        assert!(map(&source(Kind::Kyc, Format::Onfido), "onfido", &check).is_err());
    }

    fn futures_lite<F: std::future::Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
