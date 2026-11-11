//! The export pass on real Postgres against the S3, collector and syslog TLS twins over the
//! guarded outbound client (OP-156 m.3 (s), OP-41, OP-44, X22): every audit row goes, labelled a
//! copy; a sink that is down keeps its cursor and loses nothing; its secret never shows.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::time::Duration;

use access_identity_export::adapters::OutboundWire;
use access_identity_export::app::{NOTIFY_AFTER, Pass};
use access_identity_export::domain::secret::seal;
use access_identity_export::domain::sink::SinkSecret;
use access_identity_export::domain::syslog;
use access_identity_export::ports::RealmKek;
use access_identity_export::testing::{SinkTwin, SyslogTwin};
use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};
use access_store::audit::AuditEvent;
use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::export::{NewSink, cursor, write};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use bytes::Bytes;
use parquet::file::reader::{FileReader as _, SerializedFileReader};
use suiss_crypto::envelope::{Kek, SoftKek};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];

struct Keys(Arc<SoftKek>);

impl RealmKek for Keys {
    fn kek(&self, _: TenantId, _: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows {
        let pos = head.pos + 1;
        let leaf = [seed.wrapping_add(i); 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: INTENT,
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            beside: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    r
}

struct Sink<'a> {
    id: u8,
    name: &'a str,
    adapter: &'a str,
    preset: Option<&'a str>,
    format: Option<&'a str>,
    endpoint: String,
    settings: String,
    secret: Option<&'a str>,
}

async fn register(
    db: &TestDb,
    (tenant, r, d): (TenantId, RealmId, &DomainId),
    pos: u64,
    kek: &SoftKek,
    s: &Sink<'_>,
) {
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    let nonce = [u8::try_from(pos).unwrap(); 16];
    let bound = bind(
        &mut tx,
        &Decision {
            domain: d,
            position: pos,
            nonce: &nonce,
            intent: INTENT,
            change: [5; 32],
            action: "idp.export.sink_register",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let sealed = s
        .secret
        .map(|v| seal(kek, (tenant, r), &[s.id; 16], &SinkSecret::new(v)).unwrap());
    write(
        &mut tx,
        &bound,
        &NewSink {
            id: [s.id; 16],
            name: s.name,
            state: "live",
            adapter: s.adapter,
            preset: s.preset,
            format: s.format,
            endpoint: &s.endpoint,
            settings: &s.settings,
            secret: sealed.as_ref(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn audit(db: &TestDb, tenant: TenantId, r: RealmId, n: usize) {
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    for i in 0..n {
        tx.audit(&AuditEvent {
            event_type: "login.password.succeeded",
            actor: "person",
            target: &format!("session-{i}"),
            correlation: "-",
        })
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn token() -> String {
    access_kernel::json::b64url_encode(&access_crypto::random::bytes::<24>().unwrap())
}

/// Passes at most this often before a phase fails; a sink that can accept catches up in a few.
const MAX_PASSES: usize = 600;

/// Runs passes until every sink has sent `want` rows, at most [`MAX_PASSES`].
async fn drain<W: access_identity_export::ports::Wire>(
    pass: &Pass<'_, W, Keys>,
    scope: (TenantId, RealmId),
    sent: &mut u64,
    want: u64,
) {
    for _ in 0..MAX_PASSES {
        if *sent >= want {
            return;
        }
        *sent += pass.realm(scope, now_ms()).await.unwrap().sent;
        if *sent < want {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

// OP-156 m.3 (s), OP-41, OP-44, X22, Ek B 5299, 5300, 5312, 5313, 5314
#[tokio::test(flavor = "multi_thread")]
async fn every_row_reaches_every_sink_as_a_copy_and_a_sink_that_is_down_loses_nothing() {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, 51, 6).await;
    let r = realm(&db, tenant, &d).await;
    let kek = Arc::new(SoftKek::new(
        "kek-1",
        access_crypto::random::bytes::<32>().unwrap(),
    ));

    let http = SinkTwin::start().await;
    let s3_secret = token();
    http.s3("AKIDEXPORTTEST", s3_secret.as_bytes());
    let syslog_twin = SyslogTwin::start().await;
    let hec_token = token();
    let sinks = [
        Sink {
            id: 1,
            name: "lake",
            adapter: "s3_parquet",
            preset: None,
            format: None,
            endpoint: http.base.clone(),
            settings: String::from(
                "{\"bucket\":\"audit-lake\",\"region\":\"eu-central-1\",\"access_key_id\":\"AKIDEXPORTTEST\",\"account_id\":\"123456789012\",\"path_style\":true}",
            ),
            secret: Some(&s3_secret),
        },
        Sink {
            id: 2,
            name: "hec",
            adapter: "collector",
            preset: Some("splunk"),
            format: None,
            endpoint: format!("{}/services/collector/event", http.base),
            settings: String::from("{\"index\":\"access\"}"),
            secret: Some(&hec_token),
        },
        Sink {
            id: 3,
            name: "sentinel",
            adapter: "collector",
            preset: Some("sentinel"),
            format: None,
            endpoint: http.base.clone(),
            settings: format!(
                "{{\"dcr_immutable_id\":\"dcr-1\",\"stream\":\"Custom-Access\",\"tenant_id\":\"t\",\"client_id\":\"c\",\"token_url\":\"{}/oauth2/token\"}}",
                http.base
            ),
            secret: Some(&hec_token),
        },
        Sink {
            id: 4,
            name: "dd",
            adapter: "collector",
            preset: Some("datadog"),
            format: None,
            endpoint: format!("{}/api/v2/logs", http.base),
            settings: String::from("{}"),
            secret: Some(&hec_token),
        },
        Sink {
            id: 5,
            name: "es",
            adapter: "collector",
            preset: Some("elastic"),
            format: None,
            endpoint: http.base.clone(),
            settings: String::from("{\"index\":\"logs-access-default\"}"),
            secret: Some(&hec_token),
        },
        Sink {
            id: 6,
            name: "qradar",
            adapter: "syslog",
            preset: None,
            format: Some("leef"),
            endpoint: format!("localhost:{}", syslog_twin.port),
            settings: String::from("{}"),
            secret: None,
        },
    ];
    for (i, s) in sinks.iter().enumerate() {
        register(&db, (tenant, r, &d), u64::try_from(i + 1).unwrap(), &kek, s).await;
    }
    audit(&db, tenant, r, 7).await;

    let outbound = Outbound::new(http.tls.clone(), Duration::from_secs(10)).declaring(vec![
        DeclaredTarget::new(&format!("{}/", http.base), Some(http.tls.clone())).unwrap(),
        DeclaredTarget::new(
            &format!("https://localhost:{}/", syslog_twin.port),
            Some(syslog_twin.tls.clone()),
        )
        .unwrap(),
    ]);
    let wire = OutboundWire(outbound);
    let keys = Keys(kek.clone());
    let pass = Pass {
        app: &db.app,
        wire: &wire,
        keys: &keys,
    };
    let mut sent = 0;
    // OP-44
    drain(&pass, (tenant, r), &mut sent, 6 * 7).await;
    assert!(sent >= 6 * 7, "{sent}");
    for _ in 0..MAX_PASSES {
        if logins(&http, &syslog_twin, 7).await == [7; 6] {
            break;
        }
        pass.realm((tenant, r), now_ms()).await.unwrap();
    }
    assert_eq!(logins(&http, &syslog_twin, 7).await, [7; 6]);

    let seen = http.seen();
    // X22
    assert!(
        seen.iter()
            .filter(|s| !s.path.ends_with("/token"))
            .all(|s| s.header("x-access-record") == Some("copy"))
    );
    let hec = seen
        .iter()
        .find(|s| s.path == "/services/collector/event")
        .unwrap();
    assert_eq!(
        hec.header("authorization"),
        Some(format!("Splunk {hec_token}").as_str())
    );
    let sentinel = seen
        .iter()
        .find(|s| {
            s.path
                .contains("/dataCollectionRules/dcr-1/streams/Custom-Access")
        })
        .unwrap();
    assert!(
        sentinel
            .header("authorization")
            .unwrap()
            .starts_with("Bearer ")
    );
    let dd = seen.iter().find(|s| s.path == "/api/v2/logs").unwrap();
    assert_eq!(dd.header("dd-api-key"), Some(hec_token.as_str()));
    let es = seen
        .iter()
        .find(|s| s.path == "/logs-access-default/_bulk")
        .unwrap();
    assert!(String::from_utf8_lossy(&es.body).starts_with("{\"create\":{}}\n"));

    // OP-156 m.3 (s)
    let objects = http.objects();
    let (path, file) = objects.iter().next().unwrap();
    assert!(
        path.starts_with(
            "/audit-lake/ext/access/region%3Deu-central-1/accountId%3D123456789012/eventDay%3D"
        ),
        "{path}"
    );
    let reader = SerializedFileReader::new(Bytes::from(file.clone())).unwrap();
    let cols: Vec<String> = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .map(|c| c.path().string())
        .collect();
    for c in [
        "class_uid",
        "metadata.uid",
        "actor.user.uid",
        "unmapped.access_record",
    ] {
        assert!(cols.iter().any(|x| x == c), "{c}");
    }

    let messages = syslog_twin.messages();
    assert!(messages.iter().all(|m| m.starts_with("<110>1 ")
        && m.contains(&format!(" - {} - LEEF:2.0|Suiss|Access|", syslog::MSGID))
        && m.contains("accessRecord=copy")));

    // X22
    http.set_down(true);
    syslog_twin.set_down(true);
    audit(&db, tenant, r, 3).await;
    let before = {
        let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
        let c = cursor(&mut tx, [2; 16]).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        c
    };
    let mut notified = 0;
    for _ in 0..MAX_PASSES {
        if notified >= 6 {
            break;
        }
        let o = pass.realm((tenant, r), now_ms()).await.unwrap();
        assert_eq!(o.sent, 0);
        notified += o.notified;
        if o.refused == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    assert_eq!(notified, 6);
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    let after = cursor(&mut tx, [2; 16]).await.unwrap().unwrap();
    assert_eq!(after.after, before.after);
    assert_eq!(after.failures, NOTIFY_AFTER);
    // OP-64
    let err = after.last_error.clone().unwrap();
    assert_eq!(err, "status-503");
    assert!(!err.contains(&hec_token));
    let failed: Vec<String> = tx
        .list_audit(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|a| a.event_type == "export.sink_failed")
        .map(|a| a.target)
        .collect();
    assert_eq!(failed.len(), 6, "{failed:?}");
    tx.commit().await.unwrap();

    http.set_down(false);
    syslog_twin.set_down(false);
    let mut counts = [0; 6];
    for _ in 0..MAX_PASSES {
        pass.realm((tenant, r), now_ms()).await.unwrap();
        counts = logins(&http, &syslog_twin, 0).await;
        if counts == [10; 6] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // OP-44, X22
    assert_eq!(counts, [10; 6]);
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    for id in 1..=6 {
        let c = cursor(&mut tx, [id; 16]).await.unwrap().unwrap();
        assert_eq!(c.failures, 0, "sink {id}");
        assert!(c.sent >= 10, "sink {id}: {}", c.sent);
    }
    tx.commit().await.unwrap();
}

/// How many login rows each sink holds (lake, hec, sentinel, dd, es, qradar), once the syslog
/// receiver holds `want`.
async fn logins(http: &SinkTwin, syslog_twin: &SyslogTwin, want: usize) -> [usize; 6] {
    const EVENT: &str = "login.password.succeeded";
    let count_syslog = || {
        syslog_twin
            .messages()
            .iter()
            .filter(|m| m.contains(&format!("|{EVENT}|")))
            .count()
    };
    for _ in 0..400 {
        if count_syslog() >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let seen = http.seen();
    let accepted = |f: &dyn Fn(&str) -> bool| {
        seen.iter()
            .filter(|s| s.status < 300 && f(&s.path))
            .map(|s| String::from_utf8_lossy(&s.body).matches(EVENT).count())
            .sum::<usize>()
    };
    let mut lake = 0;
    for file in http.objects().values() {
        let reader = SerializedFileReader::new(Bytes::from(file.clone())).unwrap();
        for row in reader.get_row_iter(None).unwrap() {
            if format!("{}", row.unwrap()).contains(EVENT) {
                lake += 1;
            }
        }
    }
    [
        lake,
        accepted(&|p| p == "/services/collector/event"),
        accepted(&|p| p.contains("/dataCollectionRules/")),
        accepted(&|p| p == "/api/v2/logs"),
        accepted(&|p| p.ends_with("/_bulk")),
        count_syslog(),
    ]
}
