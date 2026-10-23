use super::*;

const SCHEMA: &str = r"
entity Actor { tenant: String, assurance: Long };
entity Resource { tenant: String, kind: String, owner?: Actor };
type Ctx = { amount: Long, lineage_depth: Long, cited_claims: Set<String>, risk: Long, new_device: Bool, now: Long };
action transfer, read appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";

const MAIN: &str = r#"
@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };
@id("big-transfer") @require("rs-step-up")
forbid(principal, action == Action::"transfer", resource) when { context.amount > 10000 };
@id("risky") @require("rs-fresh-auth") forbid(principal, action, resource) when { context.risk >= 70 };
@id("deep-lineage") @undisclosed forbid(principal, action, resource) when { context.lineage_depth > 3 };
@id("no-kyc") @require("rs-claim-kyc")
forbid(principal, action == Action::"transfer", resource) unless { context.cited_claims.contains("kyc") };
"#;

const ERRORS: &str = r#"
@id("overflow") forbid(principal, action, resource) when { context.amount * 1000000000000 < 0 };
@id("owner-assurance") forbid(principal, action, resource) when { resource has owner && resource.owner.assurance < 1 };
"#;

fn engine(src: &str) -> Engine {
    Engine::compile(SCHEMA, src, Limits::default()).unwrap()
}

struct Req {
    action: &'static str,
    amount: i64,
    risk: i64,
    depth: i64,
    claims: &'static str,
    resource_tenant: &'static str,
    owner: bool,
}

impl Default for Req {
    fn default() -> Self {
        Self {
            action: "transfer",
            amount: 100,
            risk: 0,
            depth: 1,
            claims: r#"["kyc"]"#,
            resource_tenant: "t1",
            owner: false,
        }
    }
}

fn run(e: &Engine, r: &Req) -> Result<Outcome, InputRejected> {
    let context = format!(
        r#"{{"amount":{},"lineage_depth":{},"cited_claims":{},"risk":{},"new_device":false,"now":1790000000}}"#,
        r.amount, r.depth, r.claims, r.risk
    );
    let owner = if r.owner {
        r#","owner":{"__entity":{"type":"Actor","id":"o1"}}"#
    } else {
        ""
    };
    let entities = format!(
        r#"[{{"uid":{{"type":"Actor","id":"a1"}},"attrs":{{"tenant":"t1","assurance":2}},"parents":[]}},
            {{"uid":{{"type":"Actor","id":"o1"}},"attrs":{{"tenant":"t1","assurance":0}},"parents":[]}},
            {{"uid":{{"type":"Resource","id":"r1"}},"attrs":{{"tenant":"{}","kind":"order"{owner}}},"parents":[]}}]"#,
        r.resource_tenant
    );
    let action = format!(r#"Action::"{}""#, r.action);
    e.evaluate(&RequestJson {
        principal: r#"Actor::"a1""#,
        action: &action,
        resource: r#"Resource::"r1""#,
        context: &context,
        entities: &entities,
    })
}

fn require(refs: &[&str]) -> Outcome {
    Outcome::Require(refs.iter().map(|s| (*s).to_owned()).collect())
}

// OP-103 criterion 1
#[test]
fn permit_and_out_of_profile_policies_are_rejected() {
    let c = |src: &str| Engine::compile(SCHEMA, src, Limits::default()).err();
    assert_eq!(
        c(r#"@id("p") permit(principal, action, resource);"#),
        Some(CompileError::PermitNotAllowed)
    );
    assert_eq!(
        c(r#"@id("p") @require("rs-x") permit(principal, action, resource);"#),
        Some(CompileError::PermitNotAllowed)
    );
    assert_eq!(
        c(r#"@id("t") forbid(principal == ?principal, action, resource);"#),
        Some(CompileError::Template)
    );
    assert_eq!(
        c("forbid(principal, action, resource);"),
        Some(CompileError::BadId)
    );
    assert_eq!(
        c(
            r#"@id("a") forbid(principal, action, resource); @id("a") forbid(principal, action, resource);"#
        ),
        Some(CompileError::BadId)
    );
    assert_eq!(
        c(r#"@id("access-base-permit") forbid(principal, action, resource);"#),
        Some(CompileError::BadId)
    );
    assert_eq!(
        c(r#"@id("a") @require("step up") forbid(principal, action, resource);"#),
        Some(CompileError::BadAnnotation)
    );
    assert_eq!(
        c(r#"@id("a") @allow("x") forbid(principal, action, resource);"#),
        Some(CompileError::BadAnnotation)
    );
    assert_eq!(
        c(r#"@id("a") forbid(principal, action, resource) when { context.nope > 1 };"#),
        Some(CompileError::Validation)
    );
    assert_eq!(
        c(r#"@id("a") forbid(principal, action, resource) when { context.amount == "x" };"#),
        Some(CompileError::Validation)
    );
    assert_eq!(
        c("@id(\"a\") forbid(principal, action, resource"),
        Some(CompileError::Parse)
    );
}

// OP-103 criterion 2, OP-104 m.4
#[test]
fn outcomes_and_deny_overrides() {
    let e = engine(MAIN);
    assert_eq!(run(&e, &Req::default()), Ok(Outcome::NoObjection));
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 20_000,
                ..Req::default()
            }
        ),
        Ok(require(&["rs-step-up"]))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 20_000,
                risk: 80,
                ..Req::default()
            }
        ),
        Ok(require(&["rs-fresh-auth", "rs-step-up"]))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                claims: "[]",
                ..Req::default()
            }
        ),
        Ok(require(&["rs-claim-kyc"]))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                action: "read",
                claims: "[]",
                ..Req::default()
            }
        ),
        Ok(Outcome::NoObjection)
    );
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 20_000,
                resource_tenant: "t2",
                ..Req::default()
            }
        ),
        Ok(Outcome::Deny(Denial::Forbid {
            policies: vec!["cross-tenant".to_owned()],
            undisclosed: false
        }))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                depth: 5,
                resource_tenant: "t2",
                ..Req::default()
            }
        ),
        Ok(Outcome::Deny(Denial::Forbid {
            policies: vec!["cross-tenant".to_owned(), "deep-lineage".to_owned()],
            undisclosed: true
        }))
    );
}

// OP-103 criterion 3: plain Cedar skips an erroring forbid; the wrapper denies
#[test]
fn evaluation_errors_are_deny() {
    let e = engine(ERRORS);
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 10_000_000,
                ..Req::default()
            }
        ),
        Ok(Outcome::Deny(Denial::EvaluationError))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 1,
                owner: true,
                ..Req::default()
            }
        ),
        Ok(Outcome::Deny(Denial::Forbid {
            policies: vec!["owner-assurance".to_owned()],
            undisclosed: false
        }))
    );
    assert_eq!(
        run(
            &e,
            &Req {
                amount: 0,
                ..Req::default()
            }
        ),
        Ok(Outcome::NoObjection)
    );
}

// OP-104 m.5
#[test]
fn input_outside_schema_or_limits_is_rejected() {
    let e = engine(MAIN);
    let base = |context: &str, entities: &str| {
        e.evaluate(&RequestJson {
            principal: r#"Actor::"a1""#,
            action: r#"Action::"transfer""#,
            resource: r#"Resource::"r1""#,
            context,
            entities,
        })
    };
    assert_eq!(base(r#"{"amount":1}"#, "[]"), Err(InputRejected));
    assert_eq!(base("not json", "[]"), Err(InputRejected));
    let long = format!(
        r#"{{"amount":1,"lineage_depth":1,"cited_claims":["{}"],"risk":0,"new_device":false,"now":0}}"#,
        "x".repeat(257)
    );
    assert_eq!(base(&long, "[]"), Err(InputRejected));
    let float =
        r#"{"amount":1.5,"lineage_depth":1,"cited_claims":[],"risk":0,"new_device":false,"now":0}"#;
    assert_eq!(base(float, "[]"), Err(InputRejected));
    let many = format!(
        r#"{{"amount":1,"lineage_depth":1,"cited_claims":[{}],"risk":0,"new_device":false,"now":0}}"#,
        vec![r#""a""#; 65].join(",")
    );
    assert_eq!(base(&many, "[]"), Err(InputRejected));
    let unknown_action = e.evaluate(&RequestJson {
        principal: r#"Actor::"a1""#,
        action: r#"Action::"delete""#,
        resource: r#"Resource::"r1""#,
        context: "{}",
        entities: "[]",
    });
    assert_eq!(unknown_action, Err(InputRejected));
}

// OP-103 criterion 4, OP-104 m.2, m.3
#[test]
fn static_limits() {
    let c = |src: &str, limits: Limits| Engine::compile(SCHEMA, src, limits).err();
    let nested = format!(
        r#"@id("n") forbid(principal, action, resource) when {{ {}true{} }};"#,
        "(".repeat(40),
        ")".repeat(40)
    );
    assert_eq!(
        c(&nested, Limits::default()),
        Some(CompileError::NestingTooDeep)
    );
    let chain = (0..200)
        .map(|_| "context.risk > 1")
        .collect::<Vec<_>>()
        .join(" || ");
    let long = format!(r#"@id("l") forbid(principal, action, resource) when {{ {chain} }};"#);
    assert_eq!(
        c(&long, Limits::default()),
        Some(CompileError::TooManyTokens)
    );
    assert_eq!(
        c(&"x".repeat(64 * 1024 + 1), Limits::default()),
        Some(CompileError::SourceTooLarge)
    );
    let expensive = r#"@id("e") forbid(principal, action, resource) when { context.cited_claims.containsAll(["a"]) };"#;
    assert_eq!(
        c(expensive, Limits::default()),
        Some(CompileError::CostTooHigh)
    );
    assert_eq!(
        c(
            MAIN,
            Limits {
                policies: 4,
                ..Limits::default()
            }
        ),
        Some(CompileError::TooManyPolicies)
    );
    assert_eq!(
        c(
            MAIN,
            Limits {
                set_cost: 100,
                ..Limits::default()
            }
        ),
        Some(CompileError::CostTooHigh)
    );
    let deref = r#"@id("d") forbid(principal, action, resource) when { resource has owner && resource.owner.assurance < 1 };"#;
    assert_eq!(
        c(
            deref,
            Limits {
                deref: 0,
                ..Limits::default()
            }
        ),
        Some(CompileError::Validation)
    );
    let in_string = r#"@id("s") forbid(principal, action, resource) when { principal.tenant == "((((((((((((((((((((((((((((((((((" };"#;
    assert!(c(in_string, Limits::default()).is_none());
}

#[test]
fn deterministic() {
    let e = engine(MAIN);
    let r = Req {
        amount: 20_000,
        risk: 80,
        ..Req::default()
    };
    assert_eq!(run(&e, &r), run(&e, &r));
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn compile_never_panics(src in "[a-z@(){}\\[\\];,.\"=<>!&| 0-9]{0,200}") {
            let _ = Engine::compile(SCHEMA, &src, Limits::default());
        }

        #[test]
        fn no_positive_outcome(amount in -100_000_i64..100_000, risk in 0_i64..100, depth in 0_i64..10) {
            let e = engine(MAIN);
            let out = run(&e, &Req { amount, risk, depth, ..Req::default() });
            prop_assert!(matches!(out, Ok(Outcome::NoObjection | Outcome::Deny(_) | Outcome::Require(_))));
            if let Ok(Outcome::Require(refs)) = out {
                prop_assert!(!refs.is_empty());
            }
        }
    }
}
