use super::*;

fn page() -> SignOut {
    SignOut {
        frames: vec![
            String::from("https://shop.example/fc?iss=x&sid=a"),
            String::from("https://mail.example/fc?iss=x&sid=b"),
        ],
        origins: vec![
            String::from("https://shop.example"),
            String::from("https://mail.example"),
        ],
        then: String::from("https://id.example/login/signed-out"),
        branding: None,
        overrides: None,
    }
}

// TN-150
#[test]
fn the_page_speaks_the_persons_language_and_names_no_app() {
    assert_eq!(locale(Some("tr-TR en"), Some("de")), "tr-tr");
    assert_eq!(locale(None, Some("de-DE;q=0.9, en")), "de-de");
    assert_eq!(locale(Some("!!"), Some("*")), "en");
    let tr = html(&page(), "tr-tr", "n0nce");
    assert!(tr.contains("<html lang=\"tr\" dir=\"ltr\">"), "{tr}");
    assert!(tr.contains("<h1>Çıkış yapılıyor</h1>"), "{tr}");
    assert!(tr.contains(">Devam</a>"), "{tr}");
    let en = html(&page(), "en", "n0nce");
    assert!(en.contains("<h1>Signing you out</h1>"), "{en}");
    assert!(html(&page(), "ar", "n").contains("dir=\"rtl\""));
    assert!(!en.contains("shop.example</"));
}

// TN-150, IDP-24
#[test]
fn the_page_waits_for_its_frames_and_never_longer_than_five_seconds() {
    let p = html(&page(), "en", "n0nce");
    assert!(p.contains("data-frames=\"2\""), "{p}");
    assert!(p.contains(
        "<meta http-equiv=\"refresh\" content=\"5;url=https://id.example/login/signed-out\">"
    ));
    assert!(p.contains("<a id=\"continue\" href=\"https://id.example/login/signed-out\">"));
    assert!(
        p.contains("<iframe hidden title=\"\" src=\"https://shop.example/fc?iss=x&amp;sid=a\">")
    );
    assert!(p.contains("<style nonce=\"n0nce\">") && p.contains("<script nonce=\"n0nce\">"));
    assert!(p.contains("role=\"status\""));
    let r = response(&page(), "en");
    let csp = r.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.starts_with("default-src 'none'; frame-src https://shop.example https://mail.example; style-src 'nonce-"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
}
