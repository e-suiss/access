//! The OpenTelemetry facade of Access (OP-47, OP-67, OP-151 m.3 (p)).
//!
//! `tracing` is the only API the rest of the code base uses; this crate bridges it to
//! OpenTelemetry (traces over OTLP/gRPC), keeps the metrics SDK behind typed constructors
//! ([`metrics`]) and writes the OP-67 m.2 JSON log line. Telemetry is minimised and
//! pseudonymous, carries no body or PII and is never a decision input (TI-18).

pub mod counters;
mod export;
mod log;
pub mod metrics;
pub mod oracle;
// OP-158 m.3 (v)
pub mod rate_board;
mod settings;
pub mod signals;
pub mod trace;

use std::io::Write;
use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt};

pub use export::ExportError;
pub use log::LogFormat;
pub use settings::{Settings, SettingsError};

/// Error returned when the global subscriber cannot be installed.
#[derive(Debug, thiserror::Error)]
#[error("telemetry init failed: {0}")]
pub struct InitError(String);

/// What a process tells the facade about itself. Resource attributes come from here only,
/// never from `OTEL_*` environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// `tracing` directive syntax (e.g. `info`, `access_server=debug`).
    pub filter: String,
    /// Log line format.
    pub log_format: LogFormat,
    /// OTLP/gRPC collector endpoint (`http://host:4317`); `None` exports nothing and still
    /// keeps the local metrics.
    pub otlp_endpoint: Option<String>,
    /// `service.name`.
    pub service: &'static str,
    /// `service.version`.
    pub version: &'static str,
    /// `deployment.environment`.
    pub environment: String,
    /// Share of traces kept, 0.0 to 1.0, decided from the trace id alone so a caller's sampled
    /// flag is never trusted (PD).
    pub trace_sample_ratio: f64,
}

impl Config {
    /// A configuration with only a filter, for tests and one-shot commands.
    #[must_use]
    pub fn local(filter: &str) -> Self {
        Self {
            filter: filter.to_owned(),
            log_format: LogFormat::Json,
            otlp_endpoint: None,
            service: "access",
            version: env!("CARGO_PKG_VERSION"),
            environment: String::from("unspecified"),
            trace_sample_ratio: 1.0,
        }
    }

    fn resource(&self) -> Resource {
        Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", self.service),
                KeyValue::new("service.version", self.version),
                KeyValue::new("deployment.environment", self.environment.clone()),
            ])
            .build()
    }
}

/// The installed facade; start the export with [`Telemetry::start_export`] once the async
/// runtime runs, and call [`Telemetry::shutdown`] before exit.
#[derive(Debug)]
pub struct Telemetry {
    tracer: SdkTracerProvider,
    deferred: export::Deferred,
    endpoint: Option<String>,
}

static STARTED: OnceLock<()> = OnceLock::new();

impl Telemetry {
    /// Starts the OTLP export when an endpoint is configured; must run inside the Tokio
    /// runtime, after the lockdown (SA-22). Without an endpoint it does nothing.
    ///
    /// # Errors
    /// [`ExportError`] when the exporter cannot be built or was started already.
    pub fn start_export(&self) -> Result<Option<tokio::task::JoinHandle<()>>, ExportError> {
        let Some(endpoint) = self.endpoint.as_deref() else {
            return Ok(None);
        };
        if STARTED.set(()).is_err() {
            return Err(ExportError::Started);
        }
        export::start(endpoint, &self.deferred).map(Some)
    }

    /// Flushes and stops the trace export.
    pub fn shutdown(&self) {
        let _ = self.tracer.shutdown();
    }
}

/// Installs the process-wide subscriber: the OP-67 m.2 log line on `writer`, the
/// OpenTelemetry bridge and the metric resource.
///
/// # Errors
/// Fails if a global subscriber is already installed or the configuration is unusable.
pub fn install<W>(config: &Config, writer: W) -> Result<Telemetry, InitError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    if !(0.0..=1.0).contains(&config.trace_sample_ratio) {
        return Err(InitError(String::from(
            "trace_sample_ratio must be between 0 and 1",
        )));
    }
    let resource = config.resource();
    let _ = metrics::set_resource(resource.clone());
    let deferred = export::Deferred::default();
    let tracer = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(config.trace_sample_ratio))
        .with_span_processor(deferred.clone())
        .build();
    let otel = tracing_opentelemetry::layer()
        .with_tracer(tracer.tracer("access"))
        .with_location(false)
        .with_threads(false);
    let lines = match config.log_format {
        LogFormat::Json => fmt::layer()
            .event_format(log::JsonLines {
                service: config.service,
                version: config.version,
            })
            .with_writer(writer)
            .boxed(),
        LogFormat::Text => fmt::layer().with_ansi(false).with_writer(writer).boxed(),
    };
    Registry::default()
        .with(EnvFilter::new(&config.filter))
        .with(otel)
        .with(lines)
        .try_init()
        .map_err(|e| InitError(e.to_string()))?;
    Ok(Telemetry {
        tracer,
        deferred,
        endpoint: config.otlp_endpoint.clone(),
    })
}

/// Installs the process-wide JSON log subscriber on standard output.
///
/// `filter` uses `tracing` directive syntax (e.g. `info`, `access_server=debug`).
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init(filter: &str) -> Result<Telemetry, InitError> {
    init_with_writer(filter, std::io::stdout)
}

/// Installs the JSON log subscriber with a custom writer (used by tests and one-shot commands).
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init_with_writer<W>(filter: &str, writer: W) -> Result<Telemetry, InitError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    install(&Config::local(filter), writer)
}

/// A writer that discards output; useful where logging must be silenced explicitly.
#[derive(Clone, Copy, Debug, Default)]
pub struct Discard;

impl Write for Discard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
