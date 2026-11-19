use super::*;

fn ok(s: Scheme, raw: &str) -> Option<String> {
    s.normalize(raw)
}

// TN-158
#[test]
fn every_built_in_scheme_takes_its_numbers_and_refuses_the_rest() {
    assert_eq!(
        ok(Scheme::TrTckn, "100 000 001 46").as_deref(),
        Some("10000000146")
    );
    for bad in ["10000000147", "00000000146", "1000000014", "1000000014a"] {
        assert_eq!(ok(Scheme::TrTckn, bad), None, "{bad}");
    }
    assert_eq!(
        ok(Scheme::UsSsn, "123-45-6789").as_deref(),
        Some("123456789")
    );
    for bad in [
        "000-12-3456",
        "666-12-3456",
        "912-34-5678",
        "123-00-4567",
        "123-45-0000",
    ] {
        assert_eq!(ok(Scheme::UsSsn, bad), None, "{bad}");
    }
    assert_eq!(
        ok(Scheme::DeSteuerId, "86 095 742 719").as_deref(),
        Some("86095742719")
    );
    assert!(ok(Scheme::DeSteuerId, "65929970489").is_some());
    assert_eq!(ok(Scheme::DeSteuerId, "12345678901"), None);
    assert_eq!(
        ok(Scheme::GbNino, "ab 12 34 56 c").as_deref(),
        Some("AB123456C")
    );
    for bad in ["GB123456A", "DA123456A", "AB123456E", "AB12345C"] {
        assert_eq!(ok(Scheme::GbNino, bad), None, "{bad}");
    }
    assert_eq!(
        ok(Scheme::NlBsn, "111.222.333").as_deref(),
        Some("111222333")
    );
    assert_eq!(ok(Scheme::NlBsn, "111222334"), None);
    assert_eq!(ok(Scheme::NlBsn, "000000000"), None);
    assert_eq!(ok(Scheme::AzFin, "5ab7c9d").as_deref(), Some("5AB7C9D"));
    assert_eq!(ok(Scheme::AzFin, "5AB7C9"), None);
}

// TN-158
#[test]
fn a_generic_scheme_checks_only_length_and_characters() {
    let g = Scheme::generic(6, 10, Charset::Digits).unwrap();
    assert_eq!(ok(g, "123 456").as_deref(), Some("123456"));
    assert_eq!(ok(g, "12345"), None);
    assert_eq!(ok(g, "12345A"), None);
    let a = Scheme::generic(5, 5, Charset::Alphanumeric).unwrap();
    assert_eq!(ok(a, "ab12c").as_deref(), Some("AB12C"));
    assert_eq!(Scheme::generic(0, 5, Charset::Digits), None);
    assert_eq!(Scheme::generic(6, 5, Charset::Digits), None);
    assert_eq!(Scheme::generic(1, 33, Charset::Digits), None);
    assert_eq!(Scheme::built_in("tr-tckn"), Some(Scheme::TrTckn));
    assert_eq!(Scheme::built_in("xx"), None);
    assert_eq!(Scheme::parse("generic:6-10:digits"), Some(g));
    assert_eq!(Scheme::parse("generic:5-5:alnum"), Some(a));
    assert_eq!(Scheme::parse("generic:5-5:emoji"), None);
    assert_eq!(Scheme::parse("generic:0-5:digits"), None);
    assert_eq!(Scheme::parse("us-ssn"), Some(Scheme::UsSsn));
}

// TN-158
#[test]
fn a_page_shows_only_the_last_four_characters() {
    assert_eq!(masked("10000000146"), "*******0146");
    assert_eq!(masked("123"), "123");
}
