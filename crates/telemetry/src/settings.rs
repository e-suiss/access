//! The `[telemetry]` configuration section a process reads (OP-67, OP-151 m.3 (p)).

use serde::{Deserialize, Serialize};

use crate::{Config, LogFormat};

/// The `[telemetry]` section.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// `json` (default) or `text`.
    pub log_format: LogFormat,
    /// OTLP/gRPC collector, `http://<host>:<port>` with no path: a collector next to the
    /// process (sidecar or node agent) that forwards to the backends. `None` exports nothing.
    pub otlp_endpoint: Option<String>,
    /// `deployment.environment`.
    pub environment: Option<String>,
    /// Share of traces kept, 0.0 to 1.0 (PD: 0.1).
    pub trace_sample_ratio: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Json,
            otlp_endpoint: None,
            environment: None,
            trace_sample_ratio: 0.1,
        }
    }
}

/// Why the `[telemetry]` section was rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// The endpoint is not `http://<host>:<port>`.
    #[error(
        "telemetry.otlp_endpoint must be http://<host>:<port> with no path, user info or query"
    )]
    Endpoint,
    /// The sampling ratio is outside 0..=1.
    #[error("telemetry.trace_sample_ratio must be between 0 and 1")]
    SampleRatio,
    /// The environment name is not a short lowercase token.
    #[error("telemetry.environment must be 1 to 32 lowercase letters, digits or '-'")]
    Environment,
}

/// The host and port of an `http://<host>:<port>` endpoint.
fn endpoint(url: &str) -> Option<(&str, u16)> {
    let rest = url.strip_prefix("http://")?;
    let (host, port) = rest.rsplit_once(':')?;
    let valid_host = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'));
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    valid_host.then_some((host, port))
}

impl Settings {
    /// Checks the section.
    ///
    /// # Errors
    /// [`SettingsError`].
    pub fn validate(&self) -> Result<(), SettingsError> {
        if let Some(url) = &self.otlp_endpoint
            && endpoint(url).is_none()
        {
            return Err(SettingsError::Endpoint);
        }
        if !(0.0..=1.0).contains(&self.trace_sample_ratio) {
            return Err(SettingsError::SampleRatio);
        }
        let token = |e: &String| {
            (1..=32).contains(&e.len())
                && e.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if self.environment.as_ref().is_some_and(|e| !token(e)) {
            return Err(SettingsError::Environment);
        }
        Ok(())
    }

    /// The collector's TCP port, for the runtime lockdown's connect allowlist (SA-22).
    #[must_use]
    pub fn otlp_port(&self) -> Option<u16> {
        self.otlp_endpoint
            .as_deref()
            .and_then(endpoint)
            .map(|(_, p)| p)
    }

    /// The facade configuration of a process.
    #[must_use]
    pub fn config(&self, filter: &str, service: &'static str, version: &'static str) -> Config {
        Config {
            filter: filter.to_owned(),
            log_format: self.log_format,
            otlp_endpoint: self.otlp_endpoint.clone(),
            service,
            version,
            environment: self
                .environment
                .clone()
                .unwrap_or_else(|| String::from("unspecified")),
            trace_sample_ratio: self.trace_sample_ratio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-67, TI-9: only a plain collector endpoint is accepted; anything else refuses to start
    #[test]
    fn the_endpoint_is_checked() {
        let ok = Settings {
            otlp_endpoint: Some("http://otel-collector:4317".into()),
            ..Settings::default()
        };
        assert_eq!(ok.validate(), Ok(()));
        assert_eq!(ok.otlp_port(), Some(4317));
        for bad in [
            "otel-collector:4317",
            "http://otel-collector",
            "http://otel-collector:0",
            "http://user@otel-collector:4317",
            "http://otel-collector:4317/v1",
            "https://otel-collector:4317",
            "http://:4317",
        ] {
            let s = Settings {
                otlp_endpoint: Some(bad.into()),
                ..Settings::default()
            };
            assert_eq!(s.validate(), Err(SettingsError::Endpoint), "{bad}");
        }
    }

    // OP-47: sampling stays within bounds; the environment is a short token
    #[test]
    fn ratio_and_environment_are_checked() {
        let s = Settings {
            trace_sample_ratio: 1.5,
            ..Settings::default()
        };
        assert_eq!(s.validate(), Err(SettingsError::SampleRatio));
        let s = Settings {
            environment: Some("Prod Env".into()),
            ..Settings::default()
        };
        assert_eq!(s.validate(), Err(SettingsError::Environment));
        let s = Settings {
            environment: Some("production".into()),
            ..Settings::default()
        };
        assert_eq!(s.validate(), Ok(()));
        assert_eq!(
            s.config("info", "access-server", "1").environment,
            "production"
        );
    }
}
