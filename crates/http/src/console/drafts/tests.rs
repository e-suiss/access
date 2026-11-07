#![allow(clippy::unwrap_used, reason = "test")]

use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_encode;
use access_kernel::meta::core_action;
use serde_json::json;

use super::*;
use crate::adp::domain::decode_eligibility;

const NOW: u64 = 1_800_000_000_000;

fn ask(v: &Value) -> Result<Drafted, DraftError> {
    draft(v.to_string().as_bytes(), "acme", NOW)
}

fn wanted(namespace: &str, name: &str, rns: &str, path: &[&str], mode: &str) -> Value {
    json!({
        "action": { "namespace": namespace, "name": name, "major": 1 },
        "resources": [{ "namespace": rns, "path": path }],
        "mode": mode,
    })
}

// OP-151 m.19 (a), PI-7, L1-ADP-8: a catalogued action on the session's realm is drafted with
// its pinned schema digest and the write path's validity; the wire JSON is what ADP decodes to
// the same envelope, and the envelope's bytes are what the Kernel reads back
#[test]
fn a_catalogued_action_is_drafted_as_adp_reads_it() {
    let d = ask(&wanted("idp.account", "suspend", "idp", &["acme"], "check")).unwrap();
    assert_eq!(d.envelope.action, IdpAction::AccountSuspend.action_ref());
    assert_eq!(d.envelope.validity.from, NOW - VALID_BEFORE_MS);
    assert_eq!(d.envelope.validity.until, NOW + VALID_FOR_MS);
    assert_eq!(IntentEnvelope::from_bytes(&d.bytes).unwrap(), d.envelope);
    let answer = d.answer();
    assert_eq!(answer["envelope"], b64url_encode(&d.bytes));
    let body = json!({
        "subject": b64url_encode(&[1; 16]),
        "set": {
            "domain": b64url_encode(&[3; 32]),
            "intent": answer["intent"],
            "basis": { "public": b64url_encode(&[1; 16]) },
            "capacity": "own",
        },
    });
    let (decoded, _) = decode_eligibility(body.to_string().as_bytes(), 1 << 16).unwrap();
    assert_eq!(decoded.request.intent, d.envelope);
}

// OP-151 m.8 (b), m.19 (a), (d): the export is `access`/`audit_export` on the realm's audit
// resource with typed range and disclosure, draftable for commit
#[test]
fn the_export_is_drafted_with_its_typed_parameters() {
    let mut w = wanted(
        "access",
        "audit_export",
        "access.audit",
        &["acme"],
        "commit",
    );
    w["params"] = json!({ "from": 1, "to": 9, "disclosure": "redacted" });
    let d = ask(&w).unwrap();
    assert_eq!(d.envelope.action, core_action("audit_export"));
    assert_eq!(d.envelope.params["from"], ParamValue::Count(1));
    assert_eq!(
        d.envelope.params["disclosure"],
        ParamValue::Enum("redacted".to_owned())
    );
    assert_eq!(d.answer()["intent"]["params"]["to"], json!({ "count": 9 }));
    w["params"] = json!({ "disclosure": "everything" });
    assert_eq!(ask(&w), Err(DraftError::Params));
    w["params"] = json!({ "from": -1 });
    assert_eq!(ask(&w), Err(DraftError::Params));
    w["params"] = json!({ "until": 1 });
    assert_eq!(ask(&w), Err(DraftError::Params));
}

// OP-151 m.19 (a), (d), fail closed: nothing outside the catalogue, the session's realm or the
// action's resources is drafted; the dotted export name the Kernel cannot read is not
// catalogued; reads and meta-actions without a payload are never drafted for commit
#[test]
#[allow(clippy::too_many_lines, reason = "one table of refusals")]
fn anything_else_is_refused() {
    let refused = [
        (
            wanted("shop", "refund", "shop", &["acme"], "check"),
            DraftError::Action,
        ),
        (
            wanted(
                "access",
                "audit.export",
                "access.audit",
                &["acme"],
                "commit",
            ),
            DraftError::Action,
        ),
        (
            wanted("access", "no_such", "access.domain", &["acme"], "check"),
            DraftError::Action,
        ),
        (
            wanted("idp.platform", "realm_create", "idp", &["acme"], "check"),
            DraftError::Action,
        ),
        (
            wanted("idp.account", "suspend", "idp", &["other"], "check"),
            DraftError::Resource,
        ),
        (
            wanted("idp.account", "suspend", "idp.realm", &["acme"], "check"),
            DraftError::Resource,
        ),
        (
            wanted("access", "read", "access.audit", &["other"], "check"),
            DraftError::Resource,
        ),
        (
            wanted("access", "read", "access.search", &["secrets"], "check"),
            DraftError::Resource,
        ),
        (
            wanted(
                "access",
                "audit_export",
                "access.domain",
                &["acme"],
                "commit",
            ),
            DraftError::Resource,
        ),
        (
            wanted("access", "read", "access.audit", &["acme"], "commit"),
            DraftError::Mode,
        ),
        (
            wanted(
                "access",
                "grant_issue",
                "access.domain",
                &["acme"],
                "commit",
            ),
            DraftError::Mode,
        ),
        (
            wanted("idp.account", "suspend", "idp", &["acme"], "evaluate"),
            DraftError::Malformed,
        ),
    ];
    for (w, e) in refused {
        assert_eq!(ask(&w), Err(e), "{w}");
    }
    let mut extra = wanted("idp.account", "suspend", "idp", &["acme"], "check");
    extra["opaque"] = json!({});
    assert_eq!(ask(&extra), Err(DraftError::Malformed));
    let mut major = wanted("idp.account", "suspend", "idp", &["acme"], "check");
    major["action"]["major"] = json!(2);
    assert_eq!(ask(&major), Err(DraftError::Action));
    let mut two = wanted("idp.account", "suspend", "idp", &["acme"], "check");
    two["resources"] = json!([
        { "namespace": "idp", "path": ["acme"] },
        { "namespace": "idp", "path": ["acme"] },
    ]);
    assert_eq!(ask(&two), Err(DraftError::Resource));
    let mut params = wanted("idp.account", "suspend", "idp", &["acme"], "check");
    params["params"] = json!({ "from": 1 });
    assert_eq!(ask(&params), Err(DraftError::Params));
    assert!(
        ask(&wanted(
            "access",
            "grant_issue",
            "access.domain",
            &["acme"],
            "check"
        ))
        .is_ok()
    );
    assert!(
        ask(&wanted(
            "access",
            "read",
            "access.search",
            &["change-impact"],
            "check"
        ))
        .is_ok()
    );
    assert_eq!(draft(b"[]", "acme", NOW), Err(DraftError::Malformed));
}
