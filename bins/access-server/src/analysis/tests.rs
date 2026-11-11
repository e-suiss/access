use super::*;

const NARROW: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };"#;
const NARROWER: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };
@id("no-agents") forbid(principal, action, resource) when { context.actor == "agent" };"#;

// OP-157 m.3 (n)
#[test]
fn only_a_proved_narrowing_or_equivalence_keeps_a_change_ct1() {
    let unknown = Change::Unknown(restriction_analysis::AnalysisError::Timeout);
    for (c, raises) in [
        (Change::Equivalent, false),
        (Change::Narrowing, false),
        (unknown, true),
    ] {
        assert_eq!(relation(&c).raises(true), raises, "{c:?}");
    }
    assert!(!PolicyRelation::Unknown.raises(false));
}

// OP-157 m.3 (n)
#[test]
fn without_an_analyzer_the_structural_rule_decides_alone() {
    let config = Config::default();
    assert!(!configured(&config).unwrap().wired());
}

// OP-105, OP-157 m.3 (n), Ek B 5660
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
async fn the_pinned_solver_answers_on_the_commit_paths_schema() {
    let path = std::env::var_os("ACCESS_CVC5").expect("ACCESS_CVC5");
    let smt = Smt::pinned(Path::new(&path)).unwrap();
    let schema = access_authority_core::restrict::SCHEMA;
    let answer =
        |old, new| tokio::time::timeout(Duration::from_secs(120), smt.compare(schema, old, new));
    assert_eq!(
        answer(NARROW, NARROWER).await.unwrap(),
        PolicyRelation::Narrowing
    );
    assert_eq!(
        answer(NARROWER, NARROW).await.unwrap(),
        PolicyRelation::Widening
    );
    assert!(answer(NARROWER, NARROW).await.unwrap().raises(true));
}
