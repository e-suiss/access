//! The read-only SIEM projection on the real server (OP-156 m.3 (s), OP-41, OP-44, X22, Ek B 5299,
//! 5300, 5312, 5313, 5314): sinks of every adapter and preset are registered through the admin
//! REST surface and committed by the real decision point, the server's export pass sends the
//! realm's audit log to the S3, collector and syslog TLS twins over the guarded outbound client,
//! and the audit question is answered from the record however the copy changes. A sink that is
//! down keeps its cursor and loses nothing; its secret never shows.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through the projection's rules"
)]

use std::collections::BTreeSet;

use access_identity_export::adapters::OutboundWire;
use access_identity_export::testing::{SinkTwin, SyslogTwin, parquet_rows};
use access_identity_oauth::adapters::outbound::DeclaredTarget;

use super::*;
use crate::export::{INTERVAL, tick};

fn token() -> String {
    b64url_encode(&access_crypto::random::bytes::<24>().unwrap())
}

/// The event ids of the realm's audit record.
async fn record(c: &Console) -> BTreeSet<String> {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let rows = t.list_audit(10_000).await.unwrap();
    t.commit().await.unwrap();
    rows.iter()
        .map(|r| format!("{}:{}", access_identity_signer::cell::IDENTITY_CHAIN, r.id))
        .collect()
}

/// Passes at most this often before a phase fails: each moves every sink forward by up to 20
/// batches, so a sink that can accept catches up in a handful.
const MAX_PASSES: usize = 600;

/// The position of the newest row of the realm's audit record.
async fn head(c: &Console) -> access_store::identity::Cursor {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let rows = t.list_audit(10_000).await.unwrap();
    t.commit().await.unwrap();
    rows.iter()
        .map(|r| access_store::identity::Cursor {
            xid: r.xid,
            id: r.id,
        })
        .max_by_key(|c| (c.xid, c.id))
        .unwrap()
}

/// The live sinks other than `skip` whose cursor is still before `target`.
async fn behind(c: &Console, target: access_store::identity::Cursor, skip: &str) -> Vec<String> {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let mut out = Vec::new();
    for s in access_store::export::sinks(&mut t).await.unwrap() {
        if s.state != "live" || s.name == skip {
            continue;
        }
        let at = access_store::export::cursor(&mut t, s.id)
            .await
            .unwrap()
            .unwrap()
            .after;
        if (at.xid, at.id) < (target.xid, target.id) {
            out.push(s.name);
        }
    }
    t.commit().await.unwrap();
    out
}

/// Waits for the syslog receiver, which reads each stream after the sender closed it, to hold
/// what the sinks' cursors say they accepted.
async fn delivered(
    http: &SinkTwin,
    syslog: &SyslogTwin,
    want: &BTreeSet<String>,
    skip: &str,
) -> Vec<(&'static str, usize)> {
    let mut missing = Vec::new();
    for _ in 0..400 {
        missing = copies(http, syslog)
            .into_iter()
            .filter(|(n, _)| *n != skip)
            .map(|(n, got)| (n, want.difference(&got).count()))
            .filter(|(_, m)| *m > 0)
            .collect();
        if missing.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    missing
}

/// The event ids each sink holds, by sink: from the Parquet objects, the collectors' bodies and
/// the syslog messages.
fn copies(http: &SinkTwin, syslog: &SyslogTwin) -> Vec<(&'static str, BTreeSet<String>)> {
    const PREFIX: &str = "identity-audit:";
    let uids = |text: &str| -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut rest = text;
        while let Some(at) = rest.find(PREFIX) {
            let tail = &rest[at + PREFIX.len()..];
            let end = tail
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len());
            out.insert(format!("{PREFIX}{}", &tail[..end]));
            rest = &tail[end..];
        }
        out
    };
    let seen = http.seen();
    let by = |f: &dyn Fn(&str) -> bool| {
        seen.iter()
            .filter(|s| s.status < 300 && f(&s.path))
            .flat_map(|s| uids(&String::from_utf8_lossy(&s.body)))
            .collect::<BTreeSet<_>>()
    };
    let mut lake = BTreeSet::new();
    for file in http.objects().values() {
        for row in parquet_rows(file).unwrap_or_default() {
            lake.extend(uids(&row));
        }
    }
    let mut cef = BTreeSet::new();
    let mut leef = BTreeSet::new();
    for m in syslog.messages() {
        if m.contains(" CEF:0|") {
            cef.extend(uids(&m));
        } else {
            leef.extend(uids(&m));
        }
    }
    vec![
        ("lake", lake),
        ("hec", by(&|p| p == "/services/collector/event")),
        ("sentinel", by(&|p| p.contains("/dataCollectionRules/"))),
        ("dd", by(&|p| p == "/api/v2/logs")),
        ("es", by(&|p| p.ends_with("/_bulk"))),
        ("otel", by(&|p| p == "/v1/logs")),
        ("collector", by(&|p| p == "/events")),
        ("arcsight", cef),
        ("qradar", leef),
    ]
}

// OP-156 m.3 (s), OP-41, OP-44, X22, OP-64, Ek B 5299, 5300, 5312, 5313, 5314
#[tokio::test(flavor = "multi_thread")]
async fn the_siem_projection_is_a_copy_that_loses_nothing_and_never_answers_for_the_record() {
    let http = SinkTwin::start().await;
    let syslog = SyslogTwin::start().await;
    let s3_secret = token();
    http.s3("AKIDEXPORTTEST", s3_secret.as_bytes());
    let syslog_target = format!("https://localhost:{}/", syslog.port);
    let declared = vec![
        DeclaredTarget::new(&format!("{}/", http.base), Some(http.tls.clone())).unwrap(),
        DeclaredTarget::new(&syslog_target, Some(syslog.tls.clone())).unwrap(),
    ];
    let targets = DeclaredTargets::new(declared.iter().map(|d| d.url().to_owned()));
    let c = console_declaring("export", false, &plan(), targets).await;
    let hec_token = token();

    // OP-156 m.3 (a), (s)
    let sinks = [
        serde_json::json!({ "name": "lake", "adapter": "s3_parquet", "endpoint": http.base,
            "settings": { "bucket": "audit-lake", "region": "eu-central-1",
                          "access_key_id": "AKIDEXPORTTEST", "account_id": "123456789012",
                          "path_style": true },
            "secret": s3_secret }),
        serde_json::json!({ "name": "hec", "adapter": "collector", "preset": "splunk",
            "endpoint": format!("{}/services/collector/event", http.base),
            "settings": { "index": "access" }, "secret": hec_token }),
        serde_json::json!({ "name": "sentinel", "adapter": "collector", "preset": "sentinel",
            "endpoint": http.base,
            "settings": { "dcr_immutable_id": "dcr-1", "stream": "Custom-Access",
                          "tenant_id": "t", "client_id": "c",
                          "token_url": format!("{}/oauth2/token", http.base) },
            "secret": hec_token }),
        serde_json::json!({ "name": "dd", "adapter": "collector", "preset": "datadog",
            "endpoint": format!("{}/api/v2/logs", http.base), "secret": hec_token }),
        serde_json::json!({ "name": "es", "adapter": "collector", "preset": "elastic",
            "endpoint": http.base, "settings": { "index": "logs-access-default" },
            "secret": hec_token }),
        serde_json::json!({ "name": "otel", "adapter": "otlp",
            "endpoint": format!("{}/v1/logs", http.base) }),
        serde_json::json!({ "name": "collector", "adapter": "collector",
            "endpoint": format!("{}/events", http.base), "secret": hec_token }),
        serde_json::json!({ "name": "arcsight", "adapter": "syslog", "format": "cef",
            "endpoint": format!("localhost:{}", syslog.port) }),
        serde_json::json!({ "name": "qradar", "adapter": "syslog", "format": "leef",
            "endpoint": format!("localhost:{}", syslog.port) }),
    ];
    for body in &sinks {
        let w = c
            .rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/export-sinks",
                ("registerExportSink", None),
                body.clone(),
                None,
            )
            .await;
        assert!(w.status.is_success(), "{body}: {:?}", w.body);
    }
    // OP-44
    for (body, code) in [
        (
            serde_json::json!({ "name": "sampled", "adapter": "otlp",
                "endpoint": format!("{}/v1/logs", http.base), "settings": { "sample_rate": 0.1 } }),
            "invalid-export-sink",
        ),
        (
            serde_json::json!({ "name": "private", "adapter": "otlp",
                "endpoint": "https://10.0.0.7/v1/logs" }),
            "invalid-export-sink",
        ),
        (
            serde_json::json!({ "name": "hec", "adapter": "otlp",
                "endpoint": format!("{}/v1/logs", http.base) }),
            "export-sink-exists",
        ),
    ] {
        let w = c
            .rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/export-sinks",
                ("registerExportSink", None),
                body,
                None,
            )
            .await;
        assert_eq!(w.body["code"], code, "{:?}", w.body);
    }

    // OP-64
    let (status, page, _) = c.rest_read("/admin/v1/realms/acme/export-sinks").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let text = page.to_string();
    assert!(!text.contains(&hec_token) && !text.contains(&s3_secret));
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), sinks.len());
    assert!(
        items
            .iter()
            .all(|i| i["record"] == "copy" && i["status"] == "live")
    );
    assert_eq!(
        items.iter().find(|i| i["name"] == "lake").unwrap()["has_secret"],
        true
    );

    let outbound = Outbound::new(http.tls.clone(), Duration::from_secs(10)).declaring(declared);
    let wire = OutboundWire(outbound);
    let keys = crate::login::RealmKeks::new(Arc::clone(&c.w.keys));
    let pools = (&c.w.db.app, &c.w.db.router);
    let step = u64::try_from(INTERVAL.as_millis()).unwrap();
    let mut clock = now();
    let mut pass = || {
        clock += step;
        let at = clock;
        let (wire, keys) = (&wire, &keys);
        async move { tick(pools, (wire, keys), "q10-test", at).await.unwrap() }
    };

    // OP-44, X22
    let want = record(&c).await;
    assert!(!want.is_empty());
    let target = head(&c).await;
    let mut lagging = Vec::new();
    for _ in 0..MAX_PASSES {
        pass().await;
        lagging = behind(&c, target, "").await;
        if lagging.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(lagging, Vec::<String>::new());
    assert_eq!(delivered(&http, &syslog, &want, "").await, []);
    let seen = http.seen();
    assert!(
        seen.iter()
            .filter(|s| !s.path.ends_with("/token"))
            .all(|s| s.header("x-access-record") == Some("copy"))
    );
    assert!(
        syslog
            .messages()
            .iter()
            .all(|m| m.contains("cs5=copy") || m.contains("accessRecord=copy"))
    );

    // X22
    let (_, before, _) = c
        .rest_read("/admin/v1/realms/acme/audit/events?page%5Bsize%5D=100")
        .await;
    for path in http.objects().keys() {
        http.tamper(path, b"not the record".to_vec());
    }
    let (_, after, _) = c
        .rest_read("/admin/v1/realms/acme/audit/events?page%5Bsize%5D=100")
        .await;
    assert_eq!(before["items"], after["items"]);
    assert_ne!(before["items"].as_array().map(Vec::len), Some(0));

    // X22
    http.set_down(true);
    syslog.set_down(true);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/export-sinks/collector/retire",
            ("retireExportSink", Some("collector")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{:?}", w.body);
    let held_before = record(&c).await;
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    for i in 0..3 {
        t.audit(&access_store::audit::AuditEvent {
            event_type: "login.password.succeeded",
            actor: "person",
            target: &format!("session-{i}"),
            correlation: "-",
        })
        .await
        .unwrap();
    }
    t.commit().await.unwrap();
    let fresh: BTreeSet<String> = record(&c).await.difference(&held_before).cloned().collect();
    assert!(fresh.len() >= 3);
    let sent_before: Vec<String> = {
        let (_, page, _) = c.rest_read("/admin/v1/realms/acme/export-sinks").await;
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["delivery"]["sent"].as_str().unwrap().to_owned())
            .collect()
    };
    let mut refused = false;
    for _ in 0..MAX_PASSES {
        pass().await;
        let (_, page, _) = c.rest_read("/admin/v1/realms/acme/export-sinks").await;
        let live: Vec<&serde_json::Value> = page["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["status"] == "live")
            .collect();
        if live
            .iter()
            .all(|i| i["delivery"]["failures"].as_u64() >= Some(3))
        {
            // OP-64
            assert!(!page.to_string().contains(&hec_token));
            for i in &live {
                let e = i["delivery"]["last_error"].as_str().unwrap();
                assert!(
                    ["status-503", "token-503", "unreachable"].contains(&e),
                    "{e}"
                );
            }
            let sent_now: Vec<String> = page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["delivery"]["sent"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(sent_now, sent_before);
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let failed = t
        .list_audit(500)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.event_type == "export.sink_failed")
        .count();
    t.commit().await.unwrap();
    assert_eq!(failed, sinks.len() - 1);

    // OP-156 m.3 (s)
    let rotated = token();
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/export-sinks/hec",
            ("putExportSink", Some("hec")),
            serde_json::json!({ "adapter": "collector", "preset": "splunk",
                "endpoint": format!("{}/services/collector/event", http.base),
                "settings": { "index": "access" }, "secret": rotated }),
            Some("*"),
        )
        .await;
    assert!(w.status.is_success(), "{:?}", w.body);

    http.set_down(false);
    syslog.set_down(false);
    let target = head(&c).await;
    let mut lagging = Vec::new();
    for _ in 0..MAX_PASSES {
        pass().await;
        lagging = behind(&c, target, "collector").await;
        if lagging.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(lagging, Vec::<String>::new());
    assert_eq!(delivered(&http, &syslog, &fresh, "collector").await, []);
    let after_rotation = http
        .seen()
        .into_iter()
        .rev()
        .find(|s| s.path == "/services/collector/event" && s.status < 300)
        .unwrap();
    assert_eq!(
        after_rotation.header("authorization"),
        Some(format!("Splunk {rotated}").as_str())
    );
    // OP-156 m.3 (s)
    let retired = copies(&http, &syslog)
        .into_iter()
        .find(|(n, _)| *n == "collector")
        .unwrap()
        .1;
    assert!(fresh.is_disjoint(&retired));
}
