use access_kernel::json::parse;
use access_kernel::model::Id;

use super::*;

// E41, OP-156 m.3 (t)
#[test]
fn a_gate_class_is_a_contribution_class_and_a_resource_is_bounded() {
    let j = |s: &str| parse(s.as_bytes(), 1024).unwrap();
    assert_eq!(gate_class(&j("\"approve\"")).unwrap(), "approve");
    assert_eq!(gate_class(&j("\"finance_approve2\"")).unwrap(), "finance_approve2");
    for bad in ["\"\"", "\"Approve\"", "\"2fa\"", "\"a-b\"", "1"] {
        assert!(gate_class(&j(bad)).is_err(), "{bad}");
    }
    assert!(gate_class(&j(&format!("\"{}\"", "a".repeat(65)))).is_err());
    assert!(resource(String::from("po:1182")).is_ok());
    assert!(resource(String::new()).is_err());
    assert!(resource("x".repeat(513)).is_err());
    assert!(resource(String::from("a\nb")).is_err());
}

// OP-156 m.3 (t)
#[test]
fn the_answer_names_parties_and_says_it_is_not_a_record() {
    let v = encode(&[Hit::Party(Id([1; 16])), Hit::Public], true);
    assert_eq!(v["parties"].as_array().unwrap().len(), 1);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["context"]["recorded"], false);
}
