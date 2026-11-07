//! OTLP/gRPC export of traces and metrics (OP-47, OP-151 m.3 (p)). The exporters start inside
//! the async runtime, after the runtime lockdown (SA-22): the lockdown runs while the process
//! is single-threaded, so nothing here starts a thread before it.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use opentelemetry::Context;
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter as _;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::{Span, SpanData, SpanProcessor};

use crate::signals;

/// How often metrics are pushed (PD).
pub(crate) const METRIC_INTERVAL: Duration = Duration::from_secs(30);
/// Deadline of one export call (PD).
pub(crate) const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// A span processor whose exporting half is attached once the runtime runs. Before that,
/// and when no endpoint is configured, finished spans are dropped: traces are telemetry, never
/// a record (OP-47, §9.7.1).
#[derive(Clone, Debug, Default)]
pub(crate) struct Deferred(Arc<Slot>);

#[derive(Debug, Default)]
pub(crate) struct Slot {
    inner: OnceLock<Box<dyn SpanProcessor>>,
    resource: OnceLock<Resource>,
}

impl Deferred {
    fn attach(&self, mut processor: Box<dyn SpanProcessor>) -> bool {
        if let Some(resource) = self.0.resource.get() {
            processor.set_resource(resource);
        }
        self.0.inner.set(processor).is_ok()
    }
}

impl SpanProcessor for Deferred {
    fn on_start(&self, span: &mut Span, cx: &Context) {
        if let Some(p) = self.0.inner.get() {
            p.on_start(span, cx);
        }
    }

    fn on_end(&self, span: SpanData) {
        if let Some(p) = self.0.inner.get() {
            p.on_end(span);
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.inner.get().map_or(Ok(()), |p| p.force_flush())
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0
            .inner
            .get()
            .map_or(Ok(()), |p| p.shutdown_with_timeout(timeout))
    }

    fn set_resource(&mut self, resource: &Resource) {
        let _ = self.0.resource.set(resource.clone());
    }
}

/// Why the export could not start.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The exporter could not be built (endpoint unusable).
    #[error("OTLP exporter: {0}")]
    Build(String),
    /// The export was already started.
    #[error("OTLP export already started")]
    Started,
}

/// Starts the span and metric export to `endpoint`. Must run inside the Tokio runtime.
pub(crate) fn start(
    endpoint: &str,
    deferred: &Deferred,
) -> Result<tokio::task::JoinHandle<()>, ExportError> {
    let spans = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT)
        .build()
        .map_err(|e| ExportError::Build(e.to_string()))?;
    let metrics = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT)
        .with_temporality(Temporality::Cumulative)
        .build()
        .map_err(|e| ExportError::Build(e.to_string()))?;
    if !deferred.attach(Box::new(BatchSpanProcessor::builder(spans, Tokio).build())) {
        return Err(ExportError::Started);
    }
    Ok(tokio::spawn(push(metrics)))
}

async fn push(exporter: MetricExporter) {
    let mut tick = tokio::time::interval(METRIC_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(rm) = crate::metrics::collect() else {
            signals::TELEMETRY_EXPORT_FAILURES.incr(["metrics"]);
            continue;
        };
        if exporter.export(&rm).await.is_err() {
            // TI-18: a failed export is counted and dropped; nothing waits on it
            signals::TELEMETRY_EXPORT_FAILURES.incr(["metrics"]);
        }
    }
}
