#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::cell::RefCell;

use access_kernel::claim::COMPROMISE_LOOKBACK_MS;
use clap::Parser as _;

use super::*;
use crate::http::{HttpError, Response};

struct Ingest {
    status: u16,
    answer: Value,
    seen: RefCell<Vec<Request>>,
}

impl Ingest {
    fn new(status: u16, answer: Value) -> Self {
        Self {
            status,
            answer,
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for Ingest {
    async fn send(&self, request: Request) -> Result<Response, HttpError> {
        self.seen.borrow_mut().push(request);
        Ok(Response {
            status: self.status,
            headers: Vec::new(),
            body: self.answer.to_string().into_bytes(),
        })
    }
}

fn declaration(occurred_at: Option<u64>) -> Declaration {
    Declaration {
        api: String::from("https://access.example:8443/"),
        domain: Digest([1; 32]),
        declarant: Id([2; 16]),
        party: Id([3; 16]),
        occurred_at,
        leaf: vec![0xc3; 40],
    }
}

const AT: u64 = 400 * 3_600_000;

fn admitted() -> Value {
    json!({ "claim": "AAAA", "position": "17", "disposition": "admit", "replayed": false })
}

// TN-48, §12.2.4, OP-149 m.17 (d), OP-157 m.3 (i), Ek B 5582
#[tokio::test]
async fn a_containment_declares_once_and_writes_its_steps_and_the_open_window() {
    let t = Ingest::new(200, admitted());
    let d = declaration(None);
    let r = contain(&t, &d, AT, "k1").await.unwrap();
    let seen = t.seen.borrow().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(
        seen[0].url,
        "https://access.example:8443/access/v1/claims:ingest"
    );
    assert_eq!(seen[0].header("idempotency-key"), Some("k1"));
    let body: Value = serde_json::from_slice(&seen[0].body.as_ref().unwrap().1).unwrap();
    assert_eq!(body["carrier"], "unsigned");
    let claim = b64url_decode(body["claim"].as_str().unwrap()).unwrap();
    let channel = Channel::Pep(suiss_crypto::digest::sha256(&d.leaf));
    let u = access_kernel::claim::unsigned(&claim, &d.domain, &channel).unwrap();
    assert_eq!(u.statement.class, PARTY_COMPROMISE);
    assert_eq!(
        (u.statement.issuer, u.statement.subject),
        (d.declarant, d.party)
    );
    assert_eq!(u.statement.value, None);
    assert_eq!(u.statement.issued_at, AT);

    assert_eq!(r["window"]["from"], AT - COMPROMISE_LOOKBACK_MS);
    assert_eq!(r["window"]["until"], AT);
    assert_eq!(r["window"]["assumed"], true);
    let steps: Vec<u64> = r["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["step"].as_u64().unwrap())
        .collect();
    assert_eq!(steps, [1, 2, 3]);
    assert_eq!(r["steps"][0]["claim"], "AAAA");
    assert_eq!(r["open_window"]["from"], AT);
    assert_eq!(r["open_window"]["until"], AT + 72 * 3_600_000);
    let strict = r["open_window"]["by_variant"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["variant"] == "online-strict")
        .unwrap()
        .clone();
    let longest = [Tier::Ct0, Tier::Ct1, Tier::Ct2]
        .into_iter()
        .filter_map(|t| ceiling::policy(ProfileVariant::OnlineStrict, t))
        .map(|c| c.horizon_ms)
        .max()
        .unwrap();
    assert_eq!(strict["until"].as_u64().unwrap(), AT + longest);

    let known = contain(
        &Ingest::new(200, admitted()),
        &declaration(Some(AT - 5_000)),
        AT,
        "k2",
    )
    .await
    .unwrap();
    assert_eq!(known["window"]["from"], AT - 5_000);
    assert_eq!(known["window"]["assumed"], false);
}

// SI-4, fail-closed
#[tokio::test]
async fn a_refused_or_quarantined_declaration_contains_nothing() {
    let refused = Ingest::new(400, json!({ "code": "claim-issuer" }));
    assert!(matches!(
        contain(&refused, &declaration(None), AT, "k").await,
        Err(IncidentError::Refused { status: 400, ref detail }) if detail == "claim-issuer"
    ));
    let held = Ingest::new(
        200,
        json!({ "claim": "AAAA", "position": "3", "disposition": "quarantine", "reason": "quota" }),
    );
    assert!(matches!(
        contain(&held, &declaration(None), AT, "k").await,
        Err(IncidentError::Refused { status: 200, .. })
    ));
}

// OP-129 m.3, TN-130
#[test]
fn the_command_names_the_party_and_no_secret() {
    let cli = crate::Cli::try_parse_from([
        "access-cli",
        "--config",
        "/etc/access/incident.toml",
        "incident",
        "contain",
        "--party",
        "AwMDAwMDAwMDAwMDAwMDAw",
        "--occurred-at",
        "5000",
    ])
    .unwrap();
    assert!(matches!(cli.command, crate::Command::Incident(_)));
    for args in [
        &["access-cli", "incident", "contain"][..],
        &[
            "access-cli",
            "incident",
            "contain",
            "--party",
            "x",
            "--token",
            "t",
        ],
        &[
            "access-cli",
            "incident",
            "contain",
            "--party",
            "x",
            "--pep-key",
            "k",
        ],
    ] {
        assert!(crate::Cli::try_parse_from(args).is_err(), "{args:?}");
    }
}
