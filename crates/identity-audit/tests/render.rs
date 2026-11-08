//! OP-41, CMP-27, §17.6.8: the renderings of channel B against the vectors in
//! `conformance/audit/vectors.json`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::single_match_else,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_audit::adapters::{cef, ocsf, set};
use access_identity_audit::domain::record::{AuditRecord, Scope};
use access_identity_audit::domain::taxonomy::TaxonomyError;
use access_kernel::json::b64url_decode;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../conformance/audit/vectors.json");

fn uuid(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn record(v: &Value) -> AuditRecord {
    let text = |k: &str| v[k].as_str().unwrap().to_owned();
    let scope = match v["scope"].as_str().unwrap() {
        "none" => Scope::None,
        s if s.starts_with("realm:") => Scope::Realm(uuid(&s[6..])),
        s => Scope::Domain(
            b64url_decode(s.strip_prefix("domain:").unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    };
    AuditRecord {
        id: text("id"),
        event: text("event"),
        txn: text("txn"),
        occurred_at_ms: v["occurred_at_ms"].as_u64().unwrap(),
        recorded_at_ms: v["recorded_at_ms"].as_u64().unwrap(),
        checkpoint_at_ms: v.get("checkpoint_at_ms").and_then(Value::as_u64),
        tenant: v.get("tenant").and_then(Value::as_str).map(uuid),
        scope,
        actor: text("actor"),
        target: text("target"),
        reason: v.get("reason").and_then(Value::as_str).map(String::from),
    }
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

// OP-41, CMP-27
#[test]
fn op_41_cmp_27_renderings_match_the_vectors() {
    let v = vectors();
    let iss = v["iss"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for case in cases {
        let r = record(&case["record"]);
        let name = case["name"].as_str().unwrap();
        assert_eq!(ocsf::render(&r).unwrap(), case["ocsf"], "{name}: ocsf");
        assert_eq!(
            cef::render(&r).unwrap(),
            case["cef"].as_str().unwrap(),
            "{name}: cef"
        );
        assert_eq!(set::claims(&r, iss).unwrap(), case["set"], "{name}: set");
    }
}

// CMP-27, OP-41
#[test]
fn cmp_27_the_three_renderings_agree() {
    let v = vectors();
    let iss = v["iss"].as_str().unwrap();
    for case in v["cases"].as_array().unwrap() {
        let r = record(&case["record"]);
        let o = ocsf::render(&r).unwrap();
        let c = cef::render(&r).unwrap();
        let s = set::claims(&r, iss).unwrap();
        assert_eq!(o["metadata"]["correlation_uid"], r.txn.as_str());
        assert_eq!(s["txn"], r.txn.as_str());
        assert!(c.contains(&format!(" externalId={} ", r.txn)), "{c}");
        assert_eq!(o["metadata"]["uid"], r.id.as_str());
        assert_eq!(s["jti"], r.id.as_str());
        assert_eq!(o["time"], r.occurred_at_ms);
        assert_eq!(o["metadata"]["logged_time"], r.recorded_at_ms);
        let body = s["events"].as_object().unwrap().values().next().unwrap();
        assert_eq!(body["occurred_at"], r.occurred_at_ms);
        assert_eq!(body["recorded_at"], r.recorded_at_ms);
        assert!(c.contains(&format!("rt={} end={}", r.recorded_at_ms, r.occurred_at_ms)));
        match r.checkpoint_at_ms {
            Some(t) => {
                assert_eq!(o["unmapped"]["checkpoint_at"], t);
                assert_eq!(body["checkpoint_at"], t);
                assert!(c.contains(&format!("cs2={t}")));
            }
            None => {
                assert!(o["unmapped"].get("checkpoint_at").is_none());
                assert!(body.get("checkpoint_at").is_none());
            }
        }
    }
}

// OP-41
#[test]
fn an_unknown_event_renders_nowhere() {
    let v = vectors();
    let mut r = record(&v["cases"][0]["record"]);
    r.event = String::from("session.revoked");
    assert_eq!(ocsf::render(&r).err(), Some(TaxonomyError::Unknown));
    assert_eq!(cef::render(&r).err(), Some(TaxonomyError::Unknown));
    assert_eq!(set::claims(&r, "x").err(), Some(TaxonomyError::Unknown));
}
