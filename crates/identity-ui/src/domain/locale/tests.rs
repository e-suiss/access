#![allow(clippy::unwrap_used, reason = "test code")]

use super::*;

fn catalogs() -> Catalogs {
    Catalogs::embedded().unwrap()
}

// TN-106, TN-108
#[test]
fn every_text_id_has_its_default_text_in_english_and_a_turkish_text() {
    let c = catalogs();
    let en = c.access("en").unwrap();
    let tr = c.access("tr").unwrap();
    for id in TextId::ALL {
        let k = key_of(id);
        assert_eq!(
            en.get(&k).map(String::as_str),
            Some(id.default_text()),
            "{k}"
        );
        assert!(tr.get(&k).is_some_and(|t| !t.is_empty()), "{k}");
    }
    assert_eq!(en.keys().collect::<Vec<_>>(), tr.keys().collect::<Vec<_>>());
}

// OP-153 m.3 (s), TN-108
#[test]
fn the_chain_runs_realm_locale_realm_language_access_locale_access_language_english() {
    let c = catalogs();
    let k = key_of(TextId::Continue);
    let mut realm = Overrides::new();
    realm.insert(
        String::from("tr-tr"),
        Messages::from([(k.clone(), String::from("İlerle"))]),
    );
    realm.insert(
        String::from("tr"),
        Messages::from([(k.clone(), String::from("Sürdür"))]),
    );
    c.check(&realm).unwrap();
    assert_eq!(c.pattern(&k, "tr-TR", Some(&realm)), Some("İlerle"));
    assert_eq!(c.pattern(&k, "tr-CY", Some(&realm)), Some("Sürdür"));
    assert_eq!(c.pattern(&k, "tr-CY", None), Some("Devam"));
    assert_eq!(c.pattern(&k, "de-DE", None), Some("Continue"));
    assert_eq!(c.pattern(&k, "not a tag", None), Some("Continue"));
    assert_eq!(c.pattern("no-such-key", "en", None), None);
}

// X35, XI-25
#[test]
fn a_protected_key_is_never_overridden() {
    let c = catalogs();
    let k = key_of(TextId::LoginFailed);
    assert!(c.is_protected(&k));
    let realm = Overrides::from([(
        String::from("en"),
        Messages::from([(k.clone(), String::from("Wrong password."))]),
    )]);
    assert_eq!(c.check(&realm), Err(LocaleError::Protected(k.clone())));
    assert_eq!(
        c.pattern(&k, "en", Some(&realm)),
        Some(TextId::LoginFailed.default_text())
    );
    let unknown = Overrides::from([(
        String::from("en"),
        Messages::from([(String::from("made-up"), String::from("x"))]),
    )]);
    assert_eq!(
        c.check(&unknown),
        Err(LocaleError::Unknown(String::from("made-up")))
    );
}

// TN-105
#[test]
fn the_parser_refuses_fluent_logic() {
    assert!(parse("a = { $n ->\n  [one] x\n *[other] y\n}").is_err());
    assert!(parse("-term = x").is_err());
    assert!(parse("a = x\n    .attr = y").is_err());
    assert!(parse("a = x\na = y").is_err());
    let m = parse("# c\na = one\n  two\n\nb = { $n } left").unwrap();
    assert_eq!(m["a"], "one two");
    let c = catalogs();
    assert_eq!(
        c.format("login-failed", "en", None, &[]).unwrap(),
        TextId::LoginFailed.default_text()
    );
}
