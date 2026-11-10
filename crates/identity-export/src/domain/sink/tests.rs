use serde_json::json;

use super::*;

// OP-156 m.3 (a), (s)
#[test]
fn every_adapter_and_preset_reads_its_settings_strictly() {
    let ok = [
        json!({"name": "lake", "adapter": "s3_parquet", "endpoint": "https://s3.eu-central-1.amazonaws.com",
               "settings": {"bucket": "audit-lake", "region": "eu-central-1", "access_key_id": "AKID",
                            "account_id": "123456789012"}, "secret": "s"}),
        json!({"name": "otel", "adapter": "otlp", "endpoint": "https://otel.example/v1/logs"}),
        json!({"name": "hec", "adapter": "collector", "preset": "splunk",
               "endpoint": "https://hec.example/services/collector/event", "secret": "t"}),
        json!({"name": "sentinel", "adapter": "collector", "preset": "sentinel",
               "endpoint": "https://dce.ingest.monitor.azure.com",
               "settings": {"dcr_immutable_id": "dcr-1", "stream": "Custom-Access", "tenant_id": "t",
                            "client_id": "c"}, "secret": "s"}),
        json!({"name": "dd", "adapter": "collector", "preset": "datadog",
               "endpoint": "https://http-intake.logs.datadoghq.eu/api/v2/logs", "secret": "k"}),
        json!({"name": "es", "adapter": "collector", "preset": "elastic",
               "endpoint": "https://es.example", "settings": {"index": "logs-access-default"},
               "secret": "k"}),
        json!({"name": "qradar", "adapter": "syslog", "format": "leef",
               "endpoint": "siem.example:6514"}),
    ];
    for b in &ok {
        let c = ExportChange::register(b).unwrap();
        assert_eq!(c.action(), IdpAction::ExportSinkRegister, "{b}");
        assert!(c.check().is_ok(), "{b}");
    }
    let bad = [
        json!({"name": "Lake", "adapter": "otlp", "endpoint": "https://o.example/v1/logs"}),
        json!({"name": "x", "adapter": "otlp", "endpoint": "http://o.example/v1/logs"}),
        json!({"name": "x", "adapter": "s3_parquet", "endpoint": "https://s3.example",
               "settings": {"bucket": "b", "region": "r", "access_key_id": "a"}, "secret": "s"}),
        json!({"name": "x", "adapter": "collector", "preset": "splunk",
               "endpoint": "https://hec.example/services/collector/event"}),
        json!({"name": "x", "adapter": "syslog", "endpoint": "siem.example:6514"}),
        json!({"name": "x", "adapter": "syslog", "format": "cef", "endpoint": "siem.example:6514",
               "secret": "s"}),
        json!({"name": "x", "adapter": "otlp", "endpoint": "https://o.example/v1/logs",
               "settings": {"sampling": 0.1}}),
        json!({"name": "x", "adapter": "otlp", "endpoint": "https://o.example/v1/logs", "extra": 1}),
    ];
    for b in &bad {
        assert!(ExportChange::register(b).is_err(), "{b}");
    }
    let u = ExportChange::update(
        "hec",
        &json!({"adapter": "collector", "preset": "splunk",
        "endpoint": "https://hec.example/services/collector/event"}),
    )
    .unwrap();
    assert!(u.check().is_ok());
    assert_eq!(u.path(), ["export-sink", "hec"]);
    assert!(ExportChange::retire("hec", &json!({"x": 1})).is_err());
}

// OP-64
#[test]
fn the_secret_never_shows() {
    let c = ExportChange::register(
        &json!({"name": "hec", "adapter": "collector", "preset": "splunk",
        "endpoint": "https://hec.example/services/collector/event", "secret": "hec-token-value"}),
    )
    .unwrap();
    assert!(!format!("{c:?}").contains("hec-token-value"));
    let body =
        suiss_crypto::dcbor::encode(&c.body(), suiss_crypto::dcbor::Limits::CEILING).unwrap();
    assert!(!body.windows(15).any(|w| w == b"hec-token-value"));
}
