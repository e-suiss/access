//! The export adapters against real implementations, CI only (OP-156 m.1 (d), m.3 (s)): the OCSF
//! Parquet object goes to `MinIO` under our own Signature Version 4 and reads back with the OCSF
//! schema; syslog over TLS reaches `syslog-ng` with CEF and LEEF messages. `scripts/ci/export-env.sh
//! up` starts both and exports their addresses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;
use std::time::Duration;

use access_identity_audit::domain::record::AuditRecord;
use access_identity_export::adapters::OutboundWire;
use access_identity_export::domain::fields::sample;
use access_identity_export::domain::sink::{Adapter, Format, SinkSecret, SinkSpec};
use access_identity_export::domain::{parquet, s3, syslog};
use access_identity_export::ports::Wire as _;
use access_identity_export::testing::parquet_rows;
use access_identity_oauth::adapters::outbound::{DeclaredTarget, Outbound};
use rustls::pki_types::ServerName;
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by scripts/ci/export-env.sh"))
}

fn tls() -> Arc<rustls::ClientConfig> {
    let pem = std::fs::read(env("ACCESS_TEST_EXPORT_CA")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile_certs(&pem) {
        roots.add(cert).unwrap();
    }
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

fn rustls_pemfile_certs(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem)
        .map(Result::unwrap)
        .collect()
}

fn records(n: usize) -> Vec<AuditRecord> {
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    (0..n)
        .map(|i| {
            let mut r = sample(if i % 2 == 0 {
                "login.password.succeeded"
            } else {
                "export.batch_sent"
            });
            r.id = format!("identity-audit:{}", i + 1);
            r.occurred_at_ms = now;
            r.recorded_at_ms = now;
            r
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// A path-style `GET` of `path` signed with Signature Version 4, over TLS to `localhost:port`.
async fn get(port: u16, path: &str, (key, secret): (&str, &str), region: &str) -> Vec<u8> {
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let stamp = s3::amz_date(now);
    let date = &stamp[..8];
    let host = format!("localhost:{port}");
    let empty = hex(&suiss_crypto::digest::sha256(b""));
    let canonical = format!(
        "GET\n{path}\n\nhost:{host}\nx-amz-content-sha256:{empty}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{empty}"
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&suiss_crypto::digest::sha256(canonical.as_bytes()))
    );
    let sig = access_crypto::sigv4::signature(secret.as_bytes(), (date, region, "s3"), &to_sign);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nx-amz-content-sha256: {empty}\r\nx-amz-date: {stamp}\r\n\
         Authorization: AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}\r\n\
         Connection: close\r\n\r\n",
        hex(&sig)
    );
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut s = tokio_rustls::TlsConnector::from(tls())
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut out))
        .await
        .unwrap()
        .ok();
    let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..at]).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    out[at + 4..].to_vec()
}

// OP-156 m.3 (s), OP-41, Ek B 5312, 5313
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI: MinIO from scripts/ci/export-env.sh"]
async fn the_parquet_object_lands_in_minio_and_reads_back_with_the_ocsf_schema() {
    let url = env("ACCESS_TEST_MINIO_URL");
    let key = env("ACCESS_TEST_MINIO_KEY");
    let secret = env("ACCESS_TEST_MINIO_SECRET");
    let bucket = env("ACCESS_TEST_MINIO_BUCKET");
    let mut settings = Map::new();
    settings.insert("bucket".into(), Value::from(bucket.as_str()));
    settings.insert("region".into(), "eu-central-1".into());
    settings.insert("access_key_id".into(), Value::from(key.as_str()));
    settings.insert("account_id".into(), "123456789012".into());
    settings.insert("path_style".into(), true.into());
    let spec = SinkSpec {
        adapter: Adapter::S3Parquet,
        preset: None,
        format: None,
        endpoint: url.clone(),
        settings,
    };
    let recs = records(6);
    let file = parquet::file(&recs).unwrap();
    let object = s3::key(&spec, "realm-ci", (7, 1), recs[0].occurred_at_ms);
    let now = recs[0].occurred_at_ms;
    let request = s3::put(&spec, &SinkSecret::new(&secret), &object, file, now).unwrap();
    let outbound = Outbound::new(tls(), Duration::from_secs(30)).declaring(vec![
        DeclaredTarget::new(&format!("{url}/"), Some(tls())).unwrap(),
    ]);
    let (status, body) = OutboundWire(outbound)
        .http(&request, 64 * 1024)
        .await
        .unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));

    let path = format!("/{bucket}/{}", s3::encode_key(&object));
    let back = get(9000, &path, (&key, &secret), "eu-central-1").await;
    let rows = parquet_rows(&back).unwrap();
    assert_eq!(rows.len(), 6);
    for (row, r) in rows.iter().zip(&recs) {
        assert!(row.contains(&r.id), "{row}");
        assert!(row.contains("access_record: \"copy\""), "{row}");
        assert!(row.contains("class_uid: "), "{row}");
    }
}

// OP-156 m.3 (s), Ek B 5312
#[tokio::test(flavor = "multi_thread")]
#[ignore = "CI: syslog-ng from scripts/ci/export-env.sh"]
async fn syslog_ng_takes_cef_and_leef_over_tls() {
    let port: u16 = env("ACCESS_TEST_SYSLOG_PORT").parse().unwrap();
    let out = env("ACCESS_TEST_SYSLOG_OUT");
    let target = format!("https://localhost:{port}/");
    let wire = OutboundWire(
        Outbound::new(tls(), Duration::from_secs(30))
            .declaring(vec![DeclaredTarget::new(&target, Some(tls())).unwrap()]),
    );
    let recs = records(4);
    let mut frames = Vec::new();
    for (i, r) in recs.iter().enumerate() {
        let format = if i % 2 == 0 {
            Format::Cef
        } else {
            Format::Leef
        };
        let m = syslog::message(r, format, ("access-ci", "access")).unwrap();
        frames.extend_from_slice(&syslog::frame(&m));
    }
    wire.syslog(("localhost", port), &frames).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let text = loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if recs.iter().all(|r| text.contains(&r.id)) || std::time::Instant::now() > deadline {
            break text;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    for r in &recs {
        assert!(text.contains(&r.id), "{text}");
    }
    assert!(
        text.contains("CEF:0|Suiss|Access|") && text.contains("cs5=copy"),
        "{text}"
    );
    assert!(
        text.contains("LEEF:2.0|Suiss|Access|") && text.contains("accessRecord=copy"),
        "{text}"
    );
}
