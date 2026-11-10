use super::*;

fn answered(status: u16, body: &str) -> Reply {
    Reply::Answered {
        status,
        body: body.as_bytes().to_vec(),
    }
}

fn refused(o: &Outcome) -> Option<&Refusal> {
    match o {
        Outcome::Refused(r) => Some(r),
        Outcome::Proceed { .. } => None,
    }
}

// TN-135, MD-8, OP-151 m.3 (j)
#[test]
fn tn_135_md_8_hooks_fail_closed() {
    use HookPoint::{PostLogin, PreRegistration, TokenIssuance};
    use OnNoAnswer::{ContinueWithoutClaims, Refuse};
    for point in [PreRegistration, PostLogin, TokenIssuance] {
        for reply in [
            Reply::NoAnswer,
            answered(500, "{}"),
            answered(302, ""),
            answered(404, r#"{"decision":"allow"}"#),
        ] {
            assert_eq!(
                refused(&decide(point, Refuse, &reply)),
                Some(&Refusal::Unanswered),
                "{point:?} {reply:?}"
            );
        }
        for body in [
            "",
            "not json",
            "[]",
            r#"{"decision":"maybe"}"#,
            r#"{"claims":[]}"#,
        ] {
            assert_eq!(
                refused(&decide(point, Refuse, &answered(200, body))),
                Some(&Refusal::Violation),
                "{point:?} {body}"
            );
        }
    }
    assert_eq!(
        decide(TokenIssuance, ContinueWithoutClaims, &Reply::NoAnswer),
        Outcome::proceed()
    );
    assert_eq!(
        decide(TokenIssuance, ContinueWithoutClaims, &answered(503, "")),
        Outcome::proceed()
    );
    assert_eq!(
        refused(&decide(
            TokenIssuance,
            ContinueWithoutClaims,
            &answered(200, r#"{"claims":{"sub":"x"}}"#)
        )),
        Some(&Refusal::Violation)
    );
    let big = format!(
        r#"{{"decision":"allow","reason_code":"{}"}}"#,
        "a".repeat(MAX_ANSWER)
    );
    assert_eq!(
        refused(&decide(PostLogin, Refuse, &answered(200, &big))),
        Some(&Refusal::Violation)
    );
}

// TN-135, CI-2, OP-156 m.3 (r)
#[test]
fn a_call_point_risk_verdict_only_narrows() {
    let at = |body: &str| {
        decide(
            HookPoint::PostLogin,
            OnNoAnswer::Refuse,
            &answered(200, body),
        )
    };
    assert_eq!(
        at(r#"{"decision":"allow","risk":{"level":"low","reason_class":"none"}}"#),
        Outcome::proceed()
    );
    assert_eq!(
        at(r#"{"decision":"allow","risk":{"level":"high","reason_class":"bot"}}"#),
        Outcome::Refused(Refusal::Denied {
            reason_code: Some(String::from("risk-high"))
        })
    );
    assert_eq!(
        at(r#"{"decision":"deny","risk":{"level":"low","reason_class":"none"}}"#),
        Outcome::Refused(Refusal::Denied { reason_code: None })
    );
    assert_eq!(
        refused(&at(
            r#"{"decision":"allow","risk":{"level":"allow","reason_class":"none"}}"#
        )),
        Some(&Refusal::Violation)
    );
    assert_eq!(
        refused(&decide(
            HookPoint::PostLogin,
            OnNoAnswer::Refuse,
            &Reply::NoAnswer
        )),
        Some(&Refusal::Unanswered)
    );
}

// TN-135
#[test]
fn tn_135_refusing_points_only_refuse() {
    for point in [HookPoint::PreRegistration, HookPoint::PostLogin] {
        assert_eq!(
            decide(
                point,
                OnNoAnswer::Refuse,
                &answered(200, r#"{"decision":"allow"}"#)
            ),
            Outcome::proceed()
        );
        assert_eq!(
            decide(
                point,
                OnNoAnswer::Refuse,
                &answered(204, r#"{"decision":"deny","reason_code":"domain-blocked"}"#)
            ),
            Outcome::Refused(Refusal::Denied {
                reason_code: Some(String::from("domain-blocked"))
            })
        );
        for body in [
            r#"{"decision":"allow","claims":{"tier":"gold"}}"#,
            r#"{"decision":"deny","reason_code":"Not Allowed"}"#,
            r#"{"decision":"deny","reason_code":7}"#,
        ] {
            assert_eq!(
                refused(&decide(point, OnNoAnswer::Refuse, &answered(200, body))),
                Some(&Refusal::Violation),
                "{body}"
            );
        }
    }
}

// MUST-NEVER-18, TN-135, OP-150 m.11 (e), INV-12
#[test]
fn must_never_18_hook_claims_are_identity_only() {
    for name in RESERVED_CLAIMS.into_iter().chain(AUTHORITY_CLAIMS) {
        let body = format!(r#"{{"claims":{{"tier":"gold","{name}":"x"}}}}"#);
        assert_eq!(
            refused(&decide(
                HookPoint::TokenIssuance,
                OnNoAnswer::ContinueWithoutClaims,
                &answered(200, &body)
            )),
            Some(&Refusal::Violation),
            "{name}"
        );
    }
    for name in ["Tier", "1tier", "tier-x", "", &"a".repeat(65)] {
        assert!(!claim_allowed(name), "{name}");
    }
    let ok = decide(
        HookPoint::TokenIssuance,
        OnNoAnswer::Refuse,
        &answered(
            200,
            r#"{"claims":{"tier":"gold","seats":3,"beta":true,"regions":["eu","us"]}}"#,
        ),
    );
    let Outcome::Proceed { claims } = ok else {
        panic!("refused")
    };
    assert_eq!(claims.len(), 4);
    for body in [
        r#"{"claims":{"nested":{"a":1}}}"#,
        r#"{"claims":{"n":null}}"#,
        r#"{"claims":{"a":[{"b":1}]}}"#,
        r#"{"claims":{},"extra":1}"#,
    ] {
        assert_eq!(
            refused(&decide(
                HookPoint::TokenIssuance,
                OnNoAnswer::Refuse,
                &answered(200, body)
            )),
            Some(&Refusal::Violation),
            "{body}"
        );
    }
    let token = br#"{"iss":"https://id.example","sub":"s","tier":"keep"}"#;
    let mut extra = Map::new();
    extra.insert("tier".into(), "gold".into());
    extra.insert("plan".into(), "pro".into());
    extra.insert("sub".into(), "evil".into());
    let out: Value = serde_json::from_slice(&with_claims(token, &extra).unwrap()).unwrap();
    assert_eq!(out["sub"], "s");
    assert_eq!(out["tier"], "keep");
    assert_eq!(out["plan"], "pro");
}

// TN-135, §14.3
#[test]
fn tn_135_private_targets_are_refused() {
    for ok in [
        "https://hooks.shop.example/access",
        "https://hooks.shop.example/a?b=c",
    ] {
        assert!(check_target(ok, false).is_ok(), "{ok}");
    }
    for bad in [
        "http://hooks.shop.example/",
        "https://10.0.0.1/hook",
        "https://127.0.0.1/hook",
        "https://[::1]/hook",
        "https://169.254.169.254/latest",
        "https://user@hooks.shop.example/",
        "https://hooks.shop.example/#x",
        "https://localhost/hook",
        "https://hooks.internal/hook",
        "https://hooks.shop.example:8443/",
        "https://singlelabel/",
        "https://1.2.3.4.5/",
    ] {
        assert!(check_target(bad, false).is_err(), "{bad}");
    }
    assert!(check_target("https://hooks.internal/hook", true).is_ok());
    assert!(check_target("https://hooks.shop.example:8443/", true).is_ok());
    assert!(check_target("https://10.0.0.1/hook", true).is_err());
    let spec = HookSpec {
        point: HookPoint::PostLogin,
        url: String::from("https://hooks.shop.example/"),
        on_no_answer: OnNoAnswer::ContinueWithoutClaims,
        disclose: Vec::new(),
        signing: Signing::Ed25519,
    };
    assert_eq!(spec.check(false), Err(Invalid("on_no_answer")));
    let spec = HookSpec {
        disclose: vec![Disclosure::Email],
        on_no_answer: OnNoAnswer::Refuse,
        ..spec
    };
    assert_eq!(spec.check(false), Err(Invalid("disclose")));
}

// TN-135, OP-73
#[test]
fn tn_135_requests_carry_pseudonymous_ids_only() {
    let mut reg = Registration {
        id: [1; 16],
        point: HookPoint::PreRegistration,
        url: String::from("https://hooks.shop.example/"),
        on_no_answer: OnNoAnswer::Refuse,
        disclose: Vec::new(),
    };
    let call = Call::PreRegistration(PreRegistration {
        identifier_kinds: vec!["email"],
        email: Some(String::from("ada@shop.example")),
    });
    let body = |reg: &Registration, allow: bool| -> Value {
        serde_json::from_slice(&request_body(reg, &call, "c1", &[2; 16], 5, allow).unwrap())
            .unwrap()
    };
    let v = body(&reg, true);
    assert_eq!(v["type"], "urn:suiss:access:hook:pre_registration");
    assert_eq!(v["data"]["identifier_kinds"][0], "email");
    assert!(v["data"].get("email").is_none());
    reg.disclose = vec![Disclosure::Email];
    assert!(body(&reg, false)["data"].get("email").is_none());
    assert_eq!(body(&reg, true)["data"]["email"], "ada@shop.example");
    let h = request_headers("c1", 5, String::from("v1a,x"), &[1; 16]);
    let names: Vec<&str> = h.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "webhook-id",
            "webhook-timestamp",
            "webhook-signature",
            "hook-id",
            "hook-timestamp"
        ]
    );
}

// EI-25, OP-151 m.3 (j)
#[test]
fn ei_25_hook_changes_are_digested() {
    let spec = HookSpec {
        point: HookPoint::TokenIssuance,
        url: String::from("https://hooks.shop.example/a"),
        on_no_answer: OnNoAnswer::ContinueWithoutClaims,
        disclose: Vec::new(),
        signing: Signing::Ed25519,
    };
    let a = HookChange::Register {
        id: [1; 16],
        spec: spec.clone(),
    };
    let b = HookChange::Register {
        id: [1; 16],
        spec: HookSpec {
            url: String::from("https://hooks.shop.example/b"),
            ..spec
        },
    };
    let w = Window { from: 0, until: 10 };
    let (ia, ib) = (a.intent("shop", w).unwrap(), b.intent("shop", w).unwrap());
    assert_ne!(ia.opaque[CHANGE_PARAM], ib.opaque[CHANGE_PARAM]);
    assert_eq!(ia.action, ExtensionAction::HookRegister.action_ref());
    assert_eq!(
        ia.resources[0].path,
        ["shop", "hook", "01010101-0101-0101-0101-010101010101"]
    );
    let r = HookChange::Retire { id: [1; 16] };
    assert_eq!(r.action(), ExtensionAction::HookRetire);
}

// OP-151 m.10 (e), OP-149 m.23, MD-8
#[test]
fn extension_policy_is_closed_by_default_and_strict_when_stored() {
    let closed = ExtensionPolicy::from_stored(None).unwrap();
    assert_eq!(closed, ExtensionPolicy::default());
    assert!(!closed.private_allowed(true));
    let open = ExtensionPolicy {
        allow_private_targets: true,
        hook_disclosure: vec![Disclosure::Email],
    };
    assert!(open.private_allowed(true));
    assert!(!open.private_allowed(false));
    assert!(open.permits(&[Disclosure::Email]));
    let bytes = dcbor::encode(&open.to_value(), Limits::CEILING).unwrap();
    assert_eq!(ExtensionPolicy::from_stored(Some(&bytes)).unwrap(), open);
    let odd = Cbor::Map(vec![(
        Cbor::text("allow_private_targets"),
        Cbor::Bool(true),
    )]);
    let odd = dcbor::encode(&odd, Limits::CEILING).unwrap();
    assert!(ExtensionPolicy::from_stored(Some(&odd)).is_err());
    assert!(ExtensionPolicy::from_stored(Some(b"\xff")).is_err());
    let private = "https://hooks.shop.internal:8443/x";
    assert!(check_target(private, closed.private_allowed(true)).is_err());
    assert!(check_target(private, open.private_allowed(false)).is_err());
    assert!(check_target(private, open.private_allowed(true)).is_ok());
}
