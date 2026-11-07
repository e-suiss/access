#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use proptest::prelude::*;

use super::*;

const ATTRS: &[&str] = &["userName", "name.givenName", "active", "emails"];

fn cmp(attr: &'static str, op: Op, value: Value) -> Filter {
    Filter::Compare { attr, op, value }
}

// TN-112: the subset's operators, grouping and precedence (`and` binds tighter than `or`)
#[test]
fn the_subset_parses_with_scim_precedence() {
    assert_eq!(
        parse(r#"userName eq "bjensen""#, ATTRS).unwrap(),
        cmp("userName", Op::Eq, Value::Text("bjensen".into()))
    );
    assert_eq!(
        parse("emails pr", ATTRS).unwrap(),
        Filter::Present("emails")
    );
    assert_eq!(
        parse(r#"username SW "j" or active eq true and emails pr"#, ATTRS).unwrap(),
        Filter::Or(
            Box::new(cmp("userName", Op::Sw, Value::Text("j".into()))),
            Box::new(Filter::And(
                Box::new(cmp("active", Op::Eq, Value::Bool(true))),
                Box::new(Filter::Present("emails")),
            )),
        )
    );
    assert_eq!(
        parse(
            r#"(userName co "a" or userName ne null) and active eq false"#,
            ATTRS
        )
        .unwrap(),
        Filter::And(
            Box::new(Filter::Or(
                Box::new(cmp("userName", Op::Co, Value::Text("a".into()))),
                Box::new(cmp("userName", Op::Ne, Value::Null)),
            )),
            Box::new(cmp("active", Op::Eq, Value::Bool(false))),
        )
    );
    assert_eq!(
        parse(r#"name.givenName eq "a \"b\"""#, ATTRS).unwrap(),
        cmp("name.givenName", Op::Eq, Value::Text("a \"b\"".into()))
    );
}

// TN-112, §12.5.1 k.5: an unknown attribute is a 400, never ignored
#[test]
fn an_unknown_attribute_is_refused() {
    for f in [
        r#"password eq "x""#,
        "secret pr",
        r#"userName eq "a" or password eq "b""#,
        "(active eq true) and (nope eq 1)",
    ] {
        assert_eq!(parse(f, ATTRS), Err(FilterError::UnknownAttribute), "{f}");
    }
    assert_eq!(
        FilterError::UnknownAttribute.code(),
        "unknown-filter-attribute"
    );
}

// TN-112: anything outside the subset is a syntax error
#[test]
fn constructs_outside_the_subset_are_refused() {
    for f in [
        "",
        r#"userName gt "a""#,
        r#"not (userName eq "a")"#,
        r#"emails[type eq "work"]"#,
        r#"userName eq "a""#.trim_end_matches('"'),
        r#"(userName eq "a""#,
        r#"userName eq "a")"#,
        "userName eq",
        "active co true",
        r#"userName eq "a" and"#,
        "userName eq 01",
        r#"userName eq "\n""#,
        "userName\teq 1",
    ] {
        assert!(
            matches!(parse(f, ATTRS), Err(FilterError::Syntax)),
            "{f}: {:?}",
            parse(f, ATTRS)
        );
    }
}

// CR-10, OP-8: size, depth and term limits hold before recursion
#[test]
fn limits_are_enforced() {
    let deep = format!("{}active pr{}", "(".repeat(64), ")".repeat(64));
    assert_eq!(parse(&deep, ATTRS), Err(FilterError::TooComplex));
    let many = vec!["active pr"; MAX_TERMS + 1].join(" and ");
    assert_eq!(parse(&many, ATTRS), Err(FilterError::TooComplex));
    let long = format!(r#"userName eq "{}""#, "a".repeat(MAX_LEN));
    assert_eq!(parse(&long, ATTRS), Err(FilterError::TooComplex));
    let value = format!(r#"userName eq "{}""#, "a".repeat(MAX_VALUE + 1));
    assert_eq!(parse(&value, ATTRS), Err(FilterError::TooComplex));
}

proptest! {
    // CR-10: arbitrary input never panics
    #[test]
    fn arbitrary_input_never_panics(s in ".{0,300}") {
        let _ = parse(&s, ATTRS);
    }
}
