#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_kernel::combinator::Decision;

use super::*;

const MAX: usize = 256 * 1024;

fn b64(bytes: &[u8]) -> String {
    b64url_encode(bytes)
}

fn body(context_extra: &str, carriers: &str) -> String {
    format!(
        r#"{{{carriers}, "context": {{
            "domain": "{d}", "mode": "commit", "nonce": "{n}",
            "basis": {{"holding": {{"grant": "{g}", "holder": "{h}", "since": 7}}}},
            "capacity": "own",
            "intent": {{
                "action": {{"namespace": "shop", "name": "read", "major": 1, "schema": "{s}"}},
                "resources": [{{"namespace": "shop", "path": ["items", "1"], "incarnation": 0}}],
                "params": {{"limit": {{"amount": {{"value": 500, "unit": "EUR"}}}}, "tag": {{"eq": {{"bytes": "AQI"}}}}}},
                "validity": {{"from": 0, "until": 100}}
            }}{context_extra}
        }}}}"#,
        d = b64(&[1; 32]),
        n = b64(&[2; 16]),
        g = b64(&[3; 16]),
        h = b64(&[4; 16]),
        s = b64(&[5; 32]),
    )
}

const CARRIERS: &str = r#""subject": {"type": "user", "id": "ignored", "properties": {"x": 1}}, "action": {"name": "read"}, "resource": {"type": "shop", "id": "items/1"}"#;

#[test]
fn a_request_decodes_into_the_core_terms() {
    let d = decode(body("", CARRIERS).as_bytes(), MAX).unwrap();
    let r = &d.request;
    assert_eq!(r.domain, Digest([1; 32]));
    assert_eq!(r.mode, Mode::Commit);
    assert_eq!(r.nonce, vec![2; 16]);
    assert_eq!(
        r.basis,
        ExerciseBasis::Holding(HoldingRef {
            grant: Id([3; 16]),
            holder: Id([4; 16]),
            since: 7
        })
    );
    assert_eq!(r.capacity, Capacity::Own);
    assert_eq!(r.intent.action.schema, Digest([5; 32]));
    assert_eq!(r.intent.resources[0].path, ["items", "1"]);
    assert_eq!(
        r.intent.params["limit"],
        ParamValue::Amount {
            value: 500,
            unit: String::from("EUR")
        }
    );
    assert_eq!(
        r.intent.params["tag"],
        ParamValue::Eq(EqValue::Bytes(vec![1, 2]))
    );
    assert!(d.ais.is_none() && r.payload.is_none());
}

// L1-ADP-12, L1-ADP-13
#[test]
fn proofs_and_the_continued_exercise_decode() {
    let extra = format!(
        r#", "proofs": [{{"claim": "{c}"}}, {{"claim_ref": "{r}"}}, {{"contribution": "{e}"}}], "exercise": "{e}""#,
        c = b64(&[9, 9]),
        r = b64(&[8; 16]),
        e = b64(&[7; 32]),
    );
    let d = decode(body(&extra, CARRIERS).as_bytes(), MAX).unwrap();
    assert_eq!(
        d.request.proofs,
        [
            ProofRef::Claim(vec![9, 9]),
            ProofRef::ClaimRef(Id([8; 16])),
            ProofRef::Contribution(Digest([7; 32])),
        ]
    );
    assert_eq!(d.request.exercise, Some(Digest([7; 32])));
    for bad in [
        r#", "proofs": []"#.to_owned(),
        r#", "proofs": [{"pin": "AA"}]"#.to_owned(),
        format!(
            r#", "proofs": [{}]"#,
            vec![r#"{"claim": "AA"}"#; 17].join(",")
        ),
    ] {
        assert!(
            decode(body(&bad, CARRIERS).as_bytes(), MAX).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn an_unknown_context_member_is_a_protocol_error() {
    let e = decode(body(r#", "hint": 1"#, CARRIERS).as_bytes(), MAX).unwrap_err();
    assert_eq!(e, AdpError("unknown-member"));
}

#[test]
fn the_carriers_must_name_the_intent() {
    let wrong = CARRIERS.replace("items/1", "items/2");
    assert_eq!(
        decode(body("", &wrong).as_bytes(), MAX).unwrap_err(),
        AdpError("carrier")
    );
    let no_subject = r#""action": {"name": "read"}, "resource": {"type": "shop", "id": "items/1"}"#;
    assert_eq!(
        decode(body("", no_subject).as_bytes(), MAX).unwrap_err(),
        AdpError("carrier")
    );
}

#[test]
fn json_outside_i_json_is_refused() {
    let dup = body("", CARRIERS).replace(
        r#""mode": "commit","#,
        r#""mode": "commit", "mode": "check","#,
    );
    assert_eq!(decode(dup.as_bytes(), MAX).unwrap_err(), AdpError("json"));
    let float = body("", CARRIERS).replace(r#""since": 7"#, r#""since": 7.0"#);
    assert_eq!(decode(float.as_bytes(), MAX).unwrap_err(), AdpError("json"));
    assert_eq!(
        decode(body("", CARRIERS).as_bytes(), 64).unwrap_err(),
        AdpError("json")
    );
}

#[test]
fn a_meta_payload_travels_as_dcbor() {
    let payload = Payload::GrantRevoke { grant: Id([6; 16]) };
    let extra = format!(r#", "payload": "{}""#, b64(&payload.to_bytes().unwrap()));
    let d = decode(body(&extra, CARRIERS).as_bytes(), MAX).unwrap();
    assert_eq!(d.request.payload, Some(payload));
    let bad = body(r#", "payload": "AQI""#, CARRIERS);
    assert_eq!(
        decode(bad.as_bytes(), MAX).unwrap_err(),
        AdpError("payload")
    );
}

#[test]
fn a_short_nonce_is_refused() {
    let short = body("", CARRIERS).replace(&b64(&[2; 16]), &b64(&[2; 8]));
    assert_eq!(
        decode(short.as_bytes(), MAX).unwrap_err(),
        AdpError("nonce")
    );
}

fn response(outcome: Outcome) -> Response {
    Response {
        decision: Decision {
            outcome,
            blockers: Vec::new(),
            unmet: Vec::new(),
            relied_on: vec![Id([7; 16])],
        },
        exercise: (outcome == Outcome::Allow).then_some(Digest([8; 32])),
        record: Some(12),
        replayed: false,
    }
}

#[test]
fn only_allow_is_true() {
    let allow = encode(&response(Outcome::Allow), Mode::Commit);
    assert_eq!(allow["decision"], true);
    assert_eq!(allow["context"]["outcome"], "allow");
    assert_eq!(allow["context"]["exercise"], b64(&[8; 32]));
    assert_eq!(allow["context"]["record"], 12);
    assert_eq!(allow["context"]["relied_on"][0], b64(&[7; 16]));
    for o in [Outcome::Deny, Outcome::RequireAction] {
        assert_eq!(encode(&response(o), Mode::Commit)["decision"], false);
    }
}

#[test]
fn check_is_advisory() {
    let r = encode(&response(Outcome::Allow), Mode::Check);
    assert_eq!(r["context"]["advisory"], true);
    assert!(
        encode(&response(Outcome::Allow), Mode::Commit)["context"]
            .get("advisory")
            .is_none()
    );
}
