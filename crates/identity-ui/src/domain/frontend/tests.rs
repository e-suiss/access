use super::*;

fn query(request: &str, state: &str) -> ApproveQuery {
    ApproveQuery {
        request: String::from(request),
        redirect_uri: String::from("https://work.suiss.example/approved"),
        state: String::from(state),
    }
}

// OP-149 m.9: request is a 32-byte digest or a pushed request_uri; state is printable ASCII
#[test]
fn approval_parameters_are_checked() {
    let digest = b64url_encode(&[7; 32]);
    assert_eq!(
        approval_request(&query(&digest, "s1")),
        Ok(ApprovalRequest::Digest([7; 32]))
    );
    let uri = format!("{REQUEST_URI_PREFIX}abcdefghijklmnop0123");
    assert_eq!(
        approval_request(&query(&uri, "s1")),
        Ok(ApprovalRequest::RequestUri(uri.clone()))
    );
    for bad in [
        b64url_encode(&[7; 31]).as_str(),
        "not base64!",
        "urn:ietf:params:oauth:request_uri:short",
        "urn:ietf:params:oauth:request_uri:has space in it here",
    ] {
        assert_eq!(
            approval_request(&query(bad, "s1")),
            Err(ApproveRejection::Request),
            "{bad}"
        );
    }
    let long = "x".repeat(MAX_STATE + 1);
    for bad in ["", "tab\there", long.as_str(), "é"] {
        assert_eq!(
            approval_request(&query(&digest, bad)),
            Err(ApproveRejection::State)
        );
    }
}

// OP-149 m.9: the browser goes back with exercise, render_digest and the state unchanged
#[test]
fn the_redirect_carries_exercise_render_digest_and_state() {
    let to = approval_redirect("https://work.suiss.example/cb", &[1; 32], &[2; 32], "a b&c");
    assert_eq!(
        to,
        format!(
            "https://work.suiss.example/cb?exercise={}&render_digest={}&state=a%20b%26c",
            b64url_encode(&[1; 32]),
            b64url_encode(&[2; 32])
        )
    );
    let kept = approval_redirect("https://work.suiss.example/cb?x=1", &[1; 32], &[2; 32], "s");
    assert!(kept.starts_with("https://work.suiss.example/cb?x=1&exercise="));
}

// OP-65: times are RFC 3339 UTC; an intent validity keeps millisecond precision exactly
#[test]
fn times_round_trip_at_millisecond_precision() {
    let ms = 1_767_225_000_123;
    let text = rfc3339(ms);
    assert_eq!(text, "2025-12-31T23:50:00.123Z");
    assert_eq!(unix_ms(&text), Some(ms));
    assert_eq!(unix_ms("2025-12-31T23:50:00.1234Z"), None);
    assert_eq!(unix_ms("1969-12-31T23:59:59Z"), None);
    assert_eq!(unix_ms("yesterday"), None);
}
