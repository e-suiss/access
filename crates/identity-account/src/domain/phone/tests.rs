use super::*;

fn tr() -> Option<Country> {
    country("tr")
}

// TN-156, OP-159 m.54 (b)
#[test]
fn a_turkish_number_reads_alike_however_it_is_typed() {
    for typed in [
        "0532 123 45 67",
        "05321234567",
        "532 123 45 67",
        "+90 532 123 45 67",
        "+905321234567",
        "0090 532 123 45 67",
        "(0532) 123-45-67",
        "+90 (532) 123.45.67",
    ] {
        assert_eq!(
            e164(typed, tr()).as_deref(),
            Some("+905321234567"),
            "{typed}"
        );
    }
}

// TN-156
#[test]
fn a_number_with_its_country_code_needs_no_default_country() {
    assert_eq!(
        e164("+49 30 1234567", None).as_deref(),
        Some("+49301234567")
    );
    assert_eq!(
        e164("+1 415 555 0100", tr()).as_deref(),
        Some("+14155550100")
    );
    assert_eq!(
        e164("0532 123 45 67", None),
        None,
        "a national number needs the country"
    );
    assert_eq!(
        e164("020 7946 0958", country("GB")).as_deref(),
        Some("+442079460958")
    );
}

// TN-156
#[test]
fn what_is_not_a_phone_number_is_refused() {
    for raw in [
        "ada@example.com",
        "ada",
        "123",
        "+",
        "0532 123 45 6",
        "0532 123 45 678",
        "+90 532 123 45 6",
        "+0 123 456 789",
        "+1234567890123456",
        "53a 123 45 67",
        "",
    ] {
        assert_eq!(e164(raw, tr()), None, "{raw:?}");
    }
    assert!(looks_like_phone("+90 532"));
    assert!(!looks_like_phone("ada@example.com"));
    assert!(!looks_like_phone("90+532"));
    assert_eq!(country("xx"), None);
}
