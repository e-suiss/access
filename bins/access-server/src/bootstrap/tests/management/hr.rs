//! The HR batch API and the HR connector on the real server path (OP-156 m.3 (q), OP-153 m.3
//! (gg), IDP-35): an administrator registers an HR source and a connector through the
//! realm-admin surface; a CSV file with an unknown column is refused whole and writes nothing;
//! the connector service reads its Personio sample and pushes it through the same
//! `importHrBatch` route, each batch drafted, signed by the operator's Instance key and committed
//! on the real sequencer. The connector reaches Access only through the realm-admin contract
//! (`admin-v1.json`) and the public crates.

use std::sync::Arc;

use access_hr_connector::app::Connector;
use access_hr_connector::domain::vendor::Vendor;
use access_hr_connector::ports::{Access, Clock, Fault, Pull, Random, Sign};
use access_hr_connector::service::{Service, router};
use access_identity_account::app::hr::file_digest;

use super::*;

fn import_body(content: &str, records: u64) -> serde_json::Value {
    serde_json::json!({
        "file": b64url_encode(&file_digest(content)),
        "records": records,
        "content": content,
    })
}

/// The Personio sample, in the shape the HR system answers its employee listing.
struct Recorded;

impl Pull for Recorded {
    fn pages(&self) -> impl Future<Output = Result<Vec<serde_json::Value>, Fault>> + Send {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../services/hr-connector/tests/fixtures/personio.json"
        );
        let page = std::fs::read(path)
            .map_err(|_| Fault::Unreachable)
            .and_then(|b| serde_json::from_slice(&b).map_err(|_| Fault::Malformed));
        std::future::ready(page.map(|p| vec![p]))
    }
}

/// The realm-admin surface as the operator's tool reaches it: through the console's signed-in
/// session, which the operator's Instance key stands behind.
#[derive(Clone)]
struct Admin(Arc<Console>);

impl Access for Admin {
    async fn draft(&self, slug: &str, ask: serde_json::Value) -> Result<serde_json::Value, Fault> {
        let c = &self.0;
        let drafts = format!("/admin/v1/realms/{slug}/intents");
        let proof = c.browser.ais(
            c.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, &drafts),
            Mode::Check,
            c.idp_anchor(),
        );
        let (r, out) = send(
            &c.management,
            c.browser
                .request(
                    &Method::POST,
                    &drafts.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                    "x",
                )
                .header("x-access-ais", proof)
                .body(Body::from(ask.to_string()))
                .unwrap(),
        )
        .await;
        let v: serde_json::Value = serde_json::from_slice(&out).map_err(|_| Fault::Malformed)?;
        if r.status() == StatusCode::OK {
            Ok(v)
        } else {
            Err(Fault::Refused(
                r.status().as_u16(),
                String::from(v["code"].as_str().unwrap_or("")),
            ))
        }
    }

    async fn commit(
        &self,
        path: &str,
        body: serde_json::Value,
        (ais, key): (&str, &str),
    ) -> Result<(u16, serde_json::Value), Fault> {
        let c = &self.0;
        let (r, out) = send(
            &c.management,
            c.browser
                .request(
                    &Method::POST,
                    &path.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                    "x",
                )
                .header("x-access-ais", ais)
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        Ok((
            r.status().as_u16(),
            serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
        ))
    }
}

impl Sign for Admin {
    fn ais(
        &self,
        domain: [u8; 32],
        nonce: &[u8; 16],
        intent: [u8; 32],
        pep: &str,
    ) -> Option<String> {
        Some(self.0.browser.ais_for(
            pep,
            Digest(domain),
            nonce,
            Digest(intent),
            Mode::Commit,
            self.0.idp_anchor(),
        ))
    }
}

struct Os;

impl Random for Os {
    fn bytes(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes::<16>().ok()
    }
}

impl Clock for Os {
    fn now(&self) -> Option<u64> {
        Some(now())
    }
}

async fn people(c: &Console, source: &str) -> u64 {
    let (st, list, _) = c.rest_read("/admin/v1/realms/acme/hr-sources").await;
    assert_eq!(st, StatusCode::OK, "{list}");
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == source)
        .unwrap()["people"]
        .as_u64()
        .unwrap()
}

// IDP-35, OP-156 m.3 (q), (gg), Ek B 5148, 5149, 5288
#[tokio::test]
async fn hr_records_arrive_by_batch_csv_and_the_connector_service_and_a_bad_file_writes_nothing() {
    let c = console("hr-rest", false).await;
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/hr-sources",
            ("registerHrSource", None),
            serde_json::json!({ "name": "personio-hr" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    assert_eq!(w.body["resource"]["status"], "live", "{}", w.body);
    assert!(w.body["resource"]["issuer"].is_string());
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/hr-connectors",
            ("registerHrConnector", None),
            serde_json::json!({ "name": "personio-1", "source": "personio-hr", "vendor": "personio" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/hr-connectors",
            ("registerHrConnector", None),
            serde_json::json!({ "name": "sheet", "source": "personio-hr", "vendor": "spreadsheet" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    assert_eq!(w.body["code"], "invalid-hr-connector");

    // OP-156 m.3 (q)
    let bad = "employee_id,email,salary\nE9,eve@acme.example,1\nE8,fay@acme.example,2\n";
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/hr-sources/personio-hr/records:csv",
            ("importHrCsv", Some("personio-hr")),
            import_body(bad, 2),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    assert_eq!(w.body["code"], "invalid-hr-records");
    assert_eq!(people(&c, "personio-hr").await, 0);

    let csv = "employee_id,email,department,start_date\r\nE9,eve@acme.example,Legal,2026-12-01\r\n";
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/hr-sources/personio-hr/records:csv",
            ("importHrCsv", Some("personio-hr")),
            import_body(csv, 1),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    assert_eq!(people(&c, "personio-hr").await, 1);

    // OP-156 m.3 (q)
    let c = Arc::new(c);
    let (store, _) = access_hr_connector::testing::store().await.unwrap();
    let service = Arc::new(Service {
        connector: Connector {
            name: String::from("personio-1"),
            vendor: Vendor::Personio,
            realm: String::from("acme"),
            source: String::from("personio-hr"),
        },
        pull: Recorded,
        access: Admin(Arc::clone(&c)),
        sign: Admin(Arc::clone(&c)),
        random: Os,
        clock: Os,
        store,
        running: tokio::sync::Mutex::new(()),
    });
    let api = router(Arc::clone(&service));
    let (r, out) = send(
        &api,
        Request::post("/hr-connector/v1/connectors/personio-1/runs")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let run: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(run["outcome"], "done", "{run}");
    assert_eq!(run["report"]["read"], 3);
    assert_eq!(run["report"]["left_out"], 1);
    assert_eq!(run["report"]["pushed"], 2);
    assert_eq!(run["report"]["refused"], 0);
    assert_eq!(people(&c, "personio-hr").await, 3);
    let (r, out) = send(
        &api,
        Request::get(format!(
            "/hr-connector/v1/connectors/personio-1/runs/{}",
            run["run"].as_str().unwrap()
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
        run
    );
    let (r, out) = send(
        &api,
        Request::get("/hr-connector/v1/connectors")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let list: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(list["connectors"][0]["last_run"], run);
    let (r, _) = send(
        &api,
        Request::get("/hr-connector/v1/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let again = service.run_once().await.unwrap();
    assert_eq!(again.report.pushed, 2);
    assert_eq!(people(&c, "personio-hr").await, 3);

    let (st, list, _) = c.rest_read("/admin/v1/realms/acme/hr-connectors").await;
    assert_eq!(st, StatusCode::OK, "{list}");
    assert_eq!(list["items"][0]["vendor"], "personio");
}
