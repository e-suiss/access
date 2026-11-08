#![allow(clippy::unwrap_used, reason = "test code")]

use serde_json::json;

use super::*;

// TN-123 item 1
#[test]
fn writing_is_deterministic_and_reads_back() {
    let a = json!({"b": [{"z": 1, "a": "no"}, "x"], "a": {"y": true, "x": null}, "c": [], "d": {}});
    let mut reordered = Map::new();
    for k in ["d", "c", "b", "a"] {
        reordered.insert(k.to_owned(), a[k].clone());
    }
    let text = to_string(&a, Some("header"));
    assert_eq!(text, to_string(&Value::Object(reordered), Some("header")));
    assert_eq!(
        text,
        "# header\na:\n  x: null\n  y: true\nb:\n  - a: \"no\"\n    z: 1\n  - \"x\"\nc: []\nd: {}\n"
    );
    assert_eq!(from_str(&text).unwrap(), a);
}

#[test]
fn hand_edited_yaml_of_the_subset_is_read() {
    let text = "realm: acme   # the realm\nclients:\n- display_name: App\n  redirect_uris:\n    - https://app.example/cb\n  require_pushed_authorization_requests: false\ngroups: []\nsettings:\n  branding: {\"display_name\": \"Acme\"}\n  rp_id: 'acme.example'\n";
    let v = from_str(text).unwrap();
    assert_eq!(v["realm"], "acme");
    assert_eq!(
        v["clients"][0]["redirect_uris"][0],
        "https://app.example/cb"
    );
    assert_eq!(
        v["clients"][0]["require_pushed_authorization_requests"],
        false
    );
    assert_eq!(v["settings"]["branding"]["display_name"], "Acme");
    assert_eq!(v["settings"]["rp_id"], "acme.example");
}

#[test]
fn what_the_subset_does_not_cover_is_refused_with_its_line() {
    for (text, line) in [
        ("a: &x 1\n", 1),
        ("a: *x\n", 1),
        ("a: !!str 1\n", 1),
        ("a: |\n  text\n", 1),
        ("a: 1\n---\nb: 2\n", 2),
        ("a: yes\n", 1),
        ("a: 1.5\n", 1),
        ("a: 1\na: 2\n", 2),
        ("a:\n\tb: 1\n", 2),
        ("a: 1\n    b: 2\n", 2),
    ] {
        assert_eq!(from_str(text).unwrap_err().line, line, "{text}");
    }
}
