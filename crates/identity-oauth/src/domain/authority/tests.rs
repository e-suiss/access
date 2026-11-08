#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_kernel::intent::ContextRefs;
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, Window,
};
use access_kernel::validity::{ProfileClass, ProfileVariant};

use super::*;

const RS: &str = "https://rs.example";

fn act(name: &str) -> ActionRef {
    ActionRef {
        namespace: String::from("shop"),
        name: String::from(name),
        major: 1,
        schema: Digest([4; 32]),
    }
}

fn rar(kind: &str, a: &ActionRef, extra: &str) -> String {
    format!(
        r#"{{"type":"{}","kind":"{kind}","schema":"{}"{extra}}}"#,
        action_type(a),
        digest_text(&a.schema)
    )
}

fn ais(kid: [u8; 32]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![(Value::Unsigned(KID), Value::Bytes(kid.to_vec()))]),
        Limits::CEILING,
    )
    .unwrap();
    let body = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(vec![1]),
            Value::Bytes(vec![0; 64]),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

fn exercise(actions: &[ActionRef], target: Option<IntentEnvelope>) -> TokenExercise {
    let payload = Payload::ProjectionIssue {
        bounds: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: actions.iter().cloned().collect(),
                    prefix: BTreeSet::new(),
                },
                resource: ResourceSelector::Structural(Structural {
                    namespace: String::from("shop"),
                    prefix: Vec::new(),
                    kind: None,
                    attrs: BTreeMap::new(),
                }),
                params: BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window { from: 0, until: 1 },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 0,
                downstream_holder_class: None,
            },
            requirements: BTreeSet::new(),
        },
        audience: BTreeSet::from([String::from(RS)]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    let mut action = act(PROJECTION_ISSUE);
    action.namespace = String::from(meta::NAMESPACE);
    TokenExercise {
        domain: Digest([1; 32]),
        nonce: vec![2; 16],
        intent: IntentEnvelope {
            action,
            resources: vec![access_kernel::model::ResourceRef {
                namespace: String::from("access.projection"),
                path: vec![String::from("rs")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from(PAYLOAD), payload.digest().unwrap())]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window { from: 0, until: 9 },
        },
        payload_bytes: payload.to_bytes().unwrap(),
        payload,
        basis: ExerciseBasis::Anchor(Id([3; 16])),
        capacity: Capacity::Own,
        ais: ais([5; 32]),
        target,
    }
}

// RFC 9396 §2, §9.13.5, P25
#[test]
fn details_are_typed_and_common_members_bind_nothing() {
    let read = act("read");
    let one = format!(
        "[{}]",
        rar("bounds", &read, r#","actions":["x"],"privileges":["y"]"#)
    );
    let (k, d) = parse_details(&one, RS).unwrap();
    assert_eq!(k, Kind::Bounds);
    assert_eq!(d.len(), 1);
    let at_rs = format!(
        "[{}]",
        rar("bounds", &read, r#","locations":["https://rs.example"]"#)
    );
    assert!(parse_details(&at_rs, RS).is_ok());
    for bad in [
        String::from("{}"),
        String::from("[]"),
        format!(
            "[{}]",
            rar("bounds", &read, r#","locations":["https://x.example"]"#)
        ),
        format!("[{}]", rar("other", &read, "")),
        format!(
            "[{},{}]",
            rar("bounds", &read, ""),
            rar("intent", &act("w"), r#","intent":"i""#)
        ),
        format!("[{}]", rar("intent", &read, "")),
        format!(
            "[{},{}]",
            rar("intent", &read, r#","intent":"a""#),
            rar("intent", &act("w"), r#","intent":"b""#)
        ),
        String::from(r#"[{"type":"shop:read:1","kind":"bounds"}]"#),
    ] {
        assert_eq!(
            parse_details(&bad, RS),
            Err(AuthorityError::Details),
            "{bad}"
        );
    }
}

// §9.9, CMP-1
#[test]
fn the_exercise_round_trips_and_nothing_else_parses() {
    let e = exercise(&[act("read")], None);
    let wire = encode_exercise(&e).unwrap();
    assert_eq!(parse_exercise(&wire).unwrap(), e);
    assert_eq!(parse_exercise(""), Err(AuthorityError::Exercise));
    assert_eq!(parse_exercise("!!"), Err(AuthorityError::Exercise));
    let extra = dcbor::encode(
        &Value::Map(vec![(Value::text("x"), Value::Unsigned(1))]),
        Limits::CEILING,
    )
    .unwrap();
    assert_eq!(
        parse_exercise(&access_kernel::json::b64url_encode(&extra)),
        Err(AuthorityError::Exercise)
    );
    assert_eq!(
        parse_exercise(&"A".repeat(MAX_EXERCISE + 1)),
        Err(AuthorityError::Exercise)
    );
}

// §9.9.3, §9.9.4, §9.13.5
#[test]
fn the_exercise_must_say_what_the_request_says() {
    let read = act("read");
    let e = exercise(std::slice::from_ref(&read), None);
    let d = Digest([1; 32]);
    let (k, details) = parse_details(&format!("[{}]", rar("bounds", &read, "")), RS).unwrap();
    let ok = check(&e, k, &details, RS, &d, &[5; 32]).unwrap();
    assert_eq!(ok.kind, Kind::Bounds);
    assert_eq!(
        check(&e, k, &details, "https://x.example", &d, &[5; 32]),
        Err(AuthorityError::Target)
    );
    assert_eq!(
        check(&e, k, &details, RS, &d, &[6; 32]),
        Err(AuthorityError::Holder)
    );
    assert_eq!(
        check(&e, k, &details, RS, &Digest([9; 32]), &[5; 32]),
        Err(AuthorityError::Exercise)
    );
    let two = exercise(&[read.clone(), act("write")], None);
    assert_eq!(
        check(&two, k, &details, RS, &d, &[5; 32]),
        Err(AuthorityError::Details)
    );
    let mut renamed = e.clone();
    renamed.intent.opaque.clear();
    assert_eq!(
        check(&renamed, k, &details, RS, &d, &[5; 32]),
        Err(AuthorityError::Exercise)
    );
    // §9.9.1
    let mut target = e.intent.clone();
    target.action = read.clone();
    target.opaque.clear();
    let digest = digest_text(&intent_digest(&target).unwrap());
    let it = exercise(std::slice::from_ref(&read), Some(target));
    let (ik, idetails) = parse_details(
        &format!(
            "[{}]",
            rar("intent", &read, &format!(r#","intent":"{digest}""#))
        ),
        RS,
    )
    .unwrap();
    assert_eq!(
        check(&it, ik, &idetails, RS, &d, &[5; 32]).unwrap().kind,
        Kind::Intent
    );
    let (wk, wrong) = parse_details(
        &format!("[{}]", rar("intent", &read, r#","intent":"sha-256:AAAA""#)),
        RS,
    )
    .unwrap();
    assert_eq!(
        check(&it, wk, &wrong, RS, &d, &[5; 32]),
        Err(AuthorityError::Details)
    );
    assert!(within(&details, &details));
    let (_, more) = parse_details(
        &format!(
            "[{},{}]",
            rar("bounds", &read, ""),
            rar("bounds", &act("w"), "")
        ),
        RS,
    )
    .unwrap();
    assert!(!within(&more, &details));
}
