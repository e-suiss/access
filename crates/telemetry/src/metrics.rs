//! Typed metric constructors over the OpenTelemetry metrics SDK (OP-47, OP-151 m.3 (p)).
//!
//! Label names come from the closed [`Label`] set and label values are `&'static str`, so no
//! request-derived value (identifier, address, tenant, realm, domain) can become a series. The
//! same SDK pipeline feeds the pull exposition at `/metrics` and the OTLP push export.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Meter, MeterProvider as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{
    InstrumentKind, ManualReader, Pipeline as SdkPipeline, SdkMeterProvider, Temporality,
};

/// The closed set of metric label names (OP-47). Adding a name is a reviewed change; the
/// names in [`FORBIDDEN_LABELS`] can never be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Label {
    /// Result class: `ok`, `error`, `deny`, `allow`, `require_action`, …
    Outcome,
    /// A fixed reason code.
    Reason,
    /// A fixed kind of artefact, event or request.
    Kind,
    /// A version track (`core`, `meta_schema`, `profile`).
    Track,
    /// A readiness check name.
    Check,
    /// A database pool role.
    Pool,
    /// An HTTP status code.
    Status,
    /// An API surface (`adp`, `oauth`, `login`, …).
    Surface,
    /// A plane (`authority`, `identity`).
    Plane,
    /// A fixed operation name.
    Operation,
    /// An outbox consumer name.
    Consumer,
    /// A sign-in factor class.
    Factor,
    /// A passkey client capability or ceremony stage.
    Stage,
    /// A mode (`normal`, `degraded`, …).
    Mode,
}

impl Label {
    /// Every label, for the allowlist check.
    pub const ALL: [Self; 14] = [
        Self::Outcome,
        Self::Reason,
        Self::Kind,
        Self::Track,
        Self::Check,
        Self::Pool,
        Self::Status,
        Self::Surface,
        Self::Plane,
        Self::Operation,
        Self::Consumer,
        Self::Factor,
        Self::Stage,
        Self::Mode,
    ];

    /// The label name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::Reason => "reason",
            Self::Kind => "kind",
            Self::Track => "track",
            Self::Check => "check",
            Self::Pool => "pool",
            Self::Status => "status",
            Self::Surface => "surface",
            Self::Plane => "plane",
            Self::Operation => "operation",
            Self::Consumer => "consumer",
            Self::Factor => "factor",
            Self::Stage => "stage",
            Self::Mode => "mode",
        }
    }
}

/// Label names that never appear on a metric (OP-47: tenant, realm and domain breakdowns come
/// from the analytics summary tables; identifiers, addresses and e-mail are PII).
pub const FORBIDDEN_LABELS: [&str; 12] = [
    "tenant_id",
    "realm_id",
    "domain_id",
    "client_id",
    "sub",
    "email",
    "ip",
    "instance_id",
    "account_id",
    "session_id",
    "user_id",
    "party_id",
];

/// A [`MetricReader`] shared between the pull exposition and the push export.
#[derive(Clone, Debug)]
struct Shared(Arc<ManualReader>);

impl MetricReader for Shared {
    fn register_pipeline(&self, pipeline: Weak<SdkPipeline>) {
        self.0.register_pipeline(pipeline);
    }

    fn collect(&self, rm: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(rm)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

struct Pipeline {
    _provider: SdkMeterProvider,
    reader: Arc<ManualReader>,
    meter: Meter,
}

static RESOURCE: OnceLock<Resource> = OnceLock::new();
static PIPELINE: OnceLock<Pipeline> = OnceLock::new();

/// Sets the resource of the metrics pipeline; `false` when the pipeline already exists.
pub(crate) fn set_resource(resource: Resource) -> bool {
    PIPELINE.get().is_none() && RESOURCE.set(resource).is_ok()
}

fn pipeline() -> &'static Pipeline {
    PIPELINE.get_or_init(|| {
        let reader = Arc::new(
            ManualReader::builder()
                .with_temporality(Temporality::Cumulative)
                .build(),
        );
        let resource = RESOURCE.get().cloned().unwrap_or_else(|| {
            Resource::builder_empty()
                .with_service_name("access")
                .build()
        });
        let provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(Shared(reader.clone()))
            .build();
        let meter = provider.meter("access");
        Pipeline {
            _provider: provider,
            reader,
            meter,
        }
    })
}

/// Collects the current cumulative values of every metric. Telemetry never fails a caller
/// (TI-18): an SDK error yields `None`.
#[must_use]
pub fn collect() -> Option<ResourceMetrics> {
    let mut rm = ResourceMetrics::default();
    pipeline().reader.collect(&mut rm).ok().map(|()| rm)
}

fn attributes<const N: usize>(labels: &[Label; N], values: [&'static str; N]) -> Vec<KeyValue> {
    labels
        .iter()
        .zip(values)
        .map(|(l, v)| KeyValue::new(l.name(), v))
        .collect()
}

/// A monotonic counter with the label set `labels`.
#[derive(Debug)]
pub struct Counter<const N: usize> {
    name: &'static str,
    help: &'static str,
    labels: [Label; N],
    total: AtomicU64,
    inner: OnceLock<opentelemetry::metrics::Counter<u64>>,
}

impl<const N: usize> Counter<N> {
    /// A counter; `name` starts with `access_` and ends with `_total`.
    #[must_use]
    pub const fn new(name: &'static str, help: &'static str, labels: [Label; N]) -> Self {
        Self {
            name,
            help,
            labels,
            total: AtomicU64::new(0),
            inner: OnceLock::new(),
        }
    }

    /// The metric name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The label names.
    #[must_use]
    pub const fn labels(&self) -> &[Label; N] {
        &self.labels
    }

    /// Adds `n` to the series `values`; returns the process total over all series.
    pub fn add(&self, n: u64, values: [&'static str; N]) -> u64 {
        self.inner
            .get_or_init(|| {
                pipeline()
                    .meter
                    .u64_counter(self.name)
                    .with_description(self.help)
                    .build()
            })
            .add(n, &attributes(&self.labels, values));
        let before = self
            .total
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_add(n))
            })
            .unwrap_or(u64::MAX);
        before.saturating_add(n)
    }

    /// Adds one to the series `values`; returns the process total over all series.
    pub fn incr(&self, values: [&'static str; N]) -> u64 {
        self.add(1, values)
    }

    /// The process total over all series.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// A gauge (last value wins) with the label set `labels`.
#[derive(Debug)]
pub struct Gauge<const N: usize> {
    name: &'static str,
    help: &'static str,
    labels: [Label; N],
    inner: OnceLock<opentelemetry::metrics::Gauge<i64>>,
}

impl<const N: usize> Gauge<N> {
    /// A gauge; `name` starts with `access_`.
    #[must_use]
    pub const fn new(name: &'static str, help: &'static str, labels: [Label; N]) -> Self {
        Self {
            name,
            help,
            labels,
            inner: OnceLock::new(),
        }
    }

    /// The metric name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The label names.
    #[must_use]
    pub const fn labels(&self) -> &[Label; N] {
        &self.labels
    }

    /// Sets the series `values` to `value`.
    pub fn set(&self, value: i64, values: [&'static str; N]) {
        self.inner
            .get_or_init(|| {
                pipeline()
                    .meter
                    .i64_gauge(self.name)
                    .with_description(self.help)
                    .build()
            })
            .record(value, &attributes(&self.labels, values));
    }

    /// Sets the series `values` from an unsigned quantity, saturating.
    pub fn set_u64(&self, value: u64, values: [&'static str; N]) {
        self.set(i64::try_from(value).unwrap_or(i64::MAX), values);
    }
}

/// A histogram with fixed bucket bounds and the label set `labels`.
#[derive(Debug)]
pub struct Histogram<const N: usize> {
    name: &'static str,
    help: &'static str,
    labels: [Label; N],
    bounds: &'static [f64],
    inner: OnceLock<opentelemetry::metrics::Histogram<f64>>,
}

/// Bucket bounds in seconds for latencies from 0.5 ms to 10 s.
pub const LATENCY_SECONDS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Bucket bounds in seconds for ages from 1 s to 1 day.
pub const AGE_SECONDS: &[f64] = &[
    1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 1800.0, 3600.0, 21600.0, 86400.0,
];

/// Bucket bounds for counts (batch sizes, queue depths).
pub const COUNT: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0];

impl<const N: usize> Histogram<N> {
    /// A histogram; `name` starts with `access_` and carries its unit (`_seconds`, …).
    #[must_use]
    pub const fn new(
        name: &'static str,
        help: &'static str,
        labels: [Label; N],
        bounds: &'static [f64],
    ) -> Self {
        Self {
            name,
            help,
            labels,
            bounds,
            inner: OnceLock::new(),
        }
    }

    /// The metric name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The label names.
    #[must_use]
    pub const fn labels(&self) -> &[Label; N] {
        &self.labels
    }

    /// Records one observation in the series `values`.
    pub fn record(&self, value: f64, values: [&'static str; N]) {
        self.inner
            .get_or_init(|| {
                pipeline()
                    .meter
                    .f64_histogram(self.name)
                    .with_description(self.help)
                    .with_boundaries(self.bounds.to_vec())
                    .build()
            })
            .record(value, &attributes(&self.labels, values));
    }

    /// Records a duration in seconds.
    pub fn record_duration(&self, value: Duration, values: [&'static str; N]) {
        self.record(value.as_secs_f64(), values);
    }
}

/// Measures an elapsed time for a histogram. Telemetry only: a measured duration never feeds
/// a decision (TI-18); trusted time enters decisions through the clock port.
#[derive(Clone, Copy, Debug)]
pub struct Stopwatch(std::time::Instant);

impl Stopwatch {
    /// Starts measuring.
    #[must_use]
    pub fn start() -> Self {
        Self(std::time::Instant::now())
    }

    /// Time since [`Stopwatch::start`].
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn label_set<'a>(attrs: impl Iterator<Item = &'a KeyValue>, extra: Option<(&str, &str)>) -> String {
    let mut parts: Vec<String> = attrs
        .map(|kv| format!("{}=\"{}\"", kv.key.as_str(), escape(&kv.value.as_str())))
        .collect();
    parts.sort();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{v}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn number(v: f64) -> String {
    if v.is_infinite() {
        if v.is_sign_positive() { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{v}")
    }
}

trait Num: Copy {
    fn text(self) -> String;
}
impl Num for u64 {
    fn text(self) -> String {
        self.to_string()
    }
}
impl Num for i64 {
    fn text(self) -> String {
        self.to_string()
    }
}
impl Num for f64 {
    fn text(self) -> String {
        number(self)
    }
}

fn render_data<T: Num>(out: &mut String, name: &str, help: &str, data: &MetricData<T>) {
    match data {
        MetricData::Sum(sum) => {
            let kind = if sum.is_monotonic() {
                "counter"
            } else {
                "gauge"
            };
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for p in sum.data_points() {
                let _ = writeln!(
                    out,
                    "{name}{} {}",
                    label_set(p.attributes(), None),
                    p.value().text()
                );
            }
        }
        MetricData::Gauge(gauge) => {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge");
            for p in gauge.data_points() {
                let _ = writeln!(
                    out,
                    "{name}{} {}",
                    label_set(p.attributes(), None),
                    p.value().text()
                );
            }
        }
        MetricData::Histogram(h) => {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} histogram");
            for p in h.data_points() {
                let mut cumulative: u64 = 0;
                for (bound, count) in p.bounds().zip(p.bucket_counts()) {
                    cumulative = cumulative.saturating_add(count);
                    let le = number(bound);
                    let _ = writeln!(
                        out,
                        "{name}_bucket{} {cumulative}",
                        label_set(p.attributes(), Some(("le", &le)))
                    );
                }
                let _ = writeln!(
                    out,
                    "{name}_bucket{} {}",
                    label_set(p.attributes(), Some(("le", "+Inf"))),
                    p.count()
                );
                let labels = label_set(p.attributes(), None);
                let _ = writeln!(out, "{name}_sum{labels} {}", p.sum().text());
                let _ = writeln!(out, "{name}_count{labels} {}", p.count());
            }
        }
        MetricData::ExponentialHistogram(_) => {}
    }
}

/// The Prometheus text exposition (format 0.0.4) of every metric, for `/metrics` on the
/// internal listener (OP-67 m.3).
#[must_use]
pub fn render_prometheus() -> String {
    let mut out = String::new();
    let Some(rm) = collect() else {
        return out;
    };
    for scope in rm.scope_metrics() {
        for metric in scope.metrics() {
            let (name, help) = (metric.name(), metric.description());
            match metric.data() {
                AggregatedMetrics::U64(d) => render_data(&mut out, name, help, d),
                AggregatedMetrics::I64(d) => render_data(&mut out, name, help, d),
                AggregatedMetrics::F64(d) => render_data(&mut out, name, help, d),
            }
        }
    }
    out
}

/// The content type of [`render_prometheus`].
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[cfg(test)]
mod tests {
    use super::*;

    // OP-47: the label allowlist never contains a tenant, realm, domain or personal identifier
    #[test]
    fn the_allowlist_has_no_forbidden_label() {
        for label in Label::ALL {
            assert!(
                !FORBIDDEN_LABELS.contains(&label.name()),
                "{}",
                label.name()
            );
            assert!(
                label
                    .name()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
        }
    }

    static TEST_COUNTER: Counter<1> =
        Counter::new("access_test_render_total", "test counter", [Label::Outcome]);
    static TEST_HISTOGRAM: Histogram<0> = Histogram::new(
        "access_test_render_seconds",
        "test histogram",
        [],
        LATENCY_SECONDS,
    );
    static TEST_GAUGE: Gauge<1> =
        Gauge::new("access_test_render_depth", "test gauge", [Label::Pool]);

    // OP-67 m.3: counters, gauges and histograms reach the pull exposition with their labels
    #[test]
    fn prometheus_exposition_carries_every_kind() {
        TEST_COUNTER.incr(["ok"]);
        TEST_COUNTER.add(2, ["deny"]);
        TEST_HISTOGRAM.record(0.003, []);
        TEST_GAUGE.set(7, ["app"]);
        let text = render_prometheus();
        assert!(
            text.contains("# TYPE access_test_render_total counter"),
            "{text}"
        );
        assert!(
            text.contains("access_test_render_total{outcome=\"deny\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("access_test_render_seconds_bucket{le=\"0.005\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("access_test_render_seconds_bucket{le=\"+Inf\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("access_test_render_seconds_count 1"),
            "{text}"
        );
        assert!(
            text.contains("access_test_render_depth{pool=\"app\"} 7"),
            "{text}"
        );
        assert!(TEST_COUNTER.get() >= 3);
    }

    // OP-47: label values are escaped, never raw
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
