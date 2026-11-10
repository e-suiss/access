#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use proptest::prelude::*;

use super::*;

fn path(name: &str) -> AttrPath {
    AttrPath {
        urn: None,
        name: name.to_owned(),
        sub: None,
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

// IDP-23, OP-155 m.3 (g)
#[test]
fn the_rfc_examples_parse() {
    for f in [
        r#"userName eq "bjensen""#,
        r#"name.familyName co "O'Malley""#,
        r#"userName sw "J""#,
        r#"urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J""#,
        "title pr",
        r#"meta.lastModified gt "2011-05-13T04:42:34Z""#,
        r#"meta.lastModified ge "2011-05-13T04:42:34Z""#,
        r#"meta.lastModified lt "2011-05-13T04:42:34Z""#,
        r#"meta.lastModified le "2011-05-13T04:42:34Z""#,
        r#"title pr and userType eq "Employee""#,
        r#"title pr or userType eq "Intern""#,
        r#"schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User""#,
        r#"userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")"#,
        r#"userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")"#,
        r#"userType eq "Employee" and (emails.type eq "work")"#,
        r#"userType eq "Employee" and emails[type eq "work" and value co "@example.com"]"#,
        r#"emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]"#,
        "members[value eq \"2819c223\"]",
        "age gt 3.5e2",
    ] {
        parse(f).unwrap_or_else(|e| panic!("{f}: {e:?}"));
    }
}

// IDP-23
#[test]
fn and_binds_tighter_than_or() {
    let e = parse("a pr or b pr and c pr").unwrap();
    assert_eq!(
        e,
        Expr::Or(
            Box::new(Expr::Present(path("a"))),
            Box::new(Expr::And(
                Box::new(Expr::Present(path("b"))),
                Box::new(Expr::Present(path("c")))
            ))
        )
    );
}

// IDP-23
#[test]
fn paths_carry_their_urn_and_sub_attribute() {
    let e = parse(
        r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq "26118915""#,
    )
    .unwrap();
    assert_eq!(
        e,
        Expr::Compare {
            path: AttrPath {
                urn: Some(String::from(
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
                )),
                name: String::from("manager"),
                sub: Some(String::from("value")),
            },
            op: CompareOp::Eq,
            value: text("26118915"),
        }
    );
}

// IDP-23
#[test]
fn value_paths_and_patch_paths() {
    match parse(r#"emails[type eq "work"]"#).unwrap() {
        Expr::ValuePath { path: p, filter } => {
            assert_eq!(p, path("emails"));
            assert_eq!(
                *filter,
                Expr::Compare {
                    path: path("type"),
                    op: CompareOp::Eq,
                    value: text("work")
                }
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        parse_path("members").unwrap(),
        PatchPath::Attr(path("members"))
    );
    match parse_path(r#"addresses[type eq "work"].streetAddress"#).unwrap() {
        PatchPath::Value { path: p, sub, .. } => {
            assert_eq!(p, path("addresses"));
            assert_eq!(sub.as_deref(), Some("streetAddress"));
        }
        other @ PatchPath::Attr(_) => panic!("{other:?}"),
    }
    assert_eq!(
        parse_path("name.givenName").unwrap(),
        PatchPath::Attr(AttrPath {
            urn: None,
            name: String::from("name"),
            sub: Some(String::from("givenName")),
        })
    );
}

// CR-10, CR-40, Ek B 4810
#[test]
fn depth_33_is_refused_and_32_is_not() {
    let nested = |n: usize| format!("{}a pr{}", "(".repeat(n), ")".repeat(n));
    assert!(parse(&nested(MAX_DEPTH)).is_ok());
    assert_eq!(parse(&nested(MAX_DEPTH + 1)), Err(FilterError::TooComplex));
    let nots = |n: usize| format!("{}a pr{}", "not (".repeat(n), ")".repeat(n));
    assert_eq!(parse(&nots(MAX_DEPTH + 1)), Err(FilterError::TooComplex));
}

// CR-10
#[test]
fn length_terms_and_values_are_bounded() {
    let long = format!(r#"a eq "{}""#, "x".repeat(MAX_LEN));
    assert_eq!(parse(&long), Err(FilterError::TooComplex));
    let many = vec!["a pr"; MAX_TERMS + 1].join(" and ");
    assert_eq!(parse(&many), Err(FilterError::TooComplex));
}

// IDP-23
#[test]
fn malformed_filters_are_syntax_errors() {
    for f in [
        "",
        "a",
        "a eq",
        "a xx 1",
        "a co 1",
        "(a pr",
        "a pr)",
        "not a pr",
        r#"emails[type eq "work"[value pr]]"#,
        "emails.type[value pr]",
        "a eq 01",
        r#"a eq "unterminated"#,
        r#"a eq "bad \q escape""#,
        "1a pr",
        "and pr",
    ] {
        assert_eq!(parse(f), Err(FilterError::Syntax), "{f}");
    }
}

// IDP-23
#[test]
fn escapes_decode() {
    assert_eq!(
        parse(r#"a eq "q\"\\é""#).unwrap(),
        Expr::Compare {
            path: path("a"),
            op: CompareOp::Eq,
            value: text("q\"\\\u{e9}")
        }
    );
}

proptest! {
    // CR-10
    #[test]
    fn arbitrary_input_never_panics(s in ".{0,512}") {
        let _ = parse(&s);
        let _ = parse_path(&s);
    }
}
