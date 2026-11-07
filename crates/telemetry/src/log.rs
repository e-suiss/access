//! The JSON log line (OP-67 m.2): `timestamp`, `level`, `target`, `service`, `version`,
//! `trace_id`, `span_id`, `event`, `outcome`, `message`, the event's own fields and the current
//! span's name.

use std::fmt;

use opentelemetry::trace::TraceContextExt;
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// The log line format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line (the default; what the collector parses).
    #[default]
    Json,
    /// Human-readable text with the same fields.
    Text,
}

/// Formats events as OP-67 m.2 JSON lines.
#[derive(Clone, Debug)]
pub(crate) struct JsonLines {
    pub(crate) service: &'static str,
    pub(crate) version: &'static str,
}

struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        let v = serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number);
        self.0.insert(field.name().to_owned(), v);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0
            .insert(field.name().to_owned(), Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Value::from(format!("{value:?}")));
    }
}

fn trace_ids<S>(
    ctx: &FmtContext<'_, S, impl for<'w> FormatFields<'w> + 'static>,
) -> Option<(String, String)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let current = ctx.lookup_current()?;
    let cx = tracing::dispatcher::get_default(|d| {
        tracing_opentelemetry::get_otel_context(&current.id(), d)
    })?;
    let span = cx.span();
    let sc = span.span_context();
    sc.is_valid()
        .then(|| (format!("{}", sc.trace_id()), format!("{}", sc.span_id())))
}

impl<S, N> FormatEvent<S, N> for JsonLines
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields(Map::new());
        event.record(&mut fields);
        let mut line = Map::new();
        let mut ts = String::new();
        let _ = SystemTime.format_time(&mut Writer::new(&mut ts));
        line.insert("timestamp".into(), Value::from(ts));
        line.insert(
            "level".into(),
            Value::from(event.metadata().level().as_str()),
        );
        line.insert("target".into(), Value::from(event.metadata().target()));
        line.insert("service".into(), Value::from(self.service));
        line.insert("version".into(), Value::from(self.version));
        if let Some((trace_id, span_id)) = trace_ids(ctx) {
            line.insert("trace_id".into(), Value::from(trace_id));
            line.insert("span_id".into(), Value::from(span_id));
        }
        for key in ["event", "outcome", "message"] {
            if let Some(v) = fields.0.remove(key) {
                line.insert(key.into(), v);
            }
        }
        if let Some(span) = ctx.lookup_current() {
            line.insert("span".into(), Value::from(span.name()));
        }
        if !fields.0.is_empty() {
            line.insert("fields".into(), Value::Object(fields.0));
        }
        let text = serde_json::to_string(&Value::Object(line)).map_err(|_| fmt::Error)?;
        writeln!(writer, "{text}")
    }
}
