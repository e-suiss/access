//! Unauthorized and missing answer alike (CR-40 m.2, m.3, SAI-43, Ek B 6236) through the real
//! ADP router, hardened as served, on the real core: a decision on a basis outside the caller's
//! disclosure scope and one on a basis that does not exist give the same status, outcome,
//! reason, structure and size class, and the padding never changes the content.

use super::*;

fn keys(v: &Json) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(String::new(), v)];
    while let Some((at, v)) = stack.pop() {
        if let Some(o) = v.as_object() {
            for (k, child) in o {
                stack.push((format!("{at}/{k}"), child));
            }
        }
        out.push(at);
    }
    out.sort();
    out
}

/// The parts of a decision answer that may differ between two requests: the request's own
/// nonce, record position and consistency token.
fn shape(v: &Json) -> Json {
    let mut v = v.clone();
    if let Some(c) = v.get_mut("context").and_then(Json::as_object_mut) {
        c.remove("nonce");
        c.remove("record");
        c.remove("decision_id");
        c.remove("consistency_token");
    }
    v
}

// CR-40 m.2, m.3, SAI-43, SI-14, DL-7, INV-27, OP-159 m.3 (s)
#[tokio::test]
async fn a_basis_outside_the_disclosure_scope_answers_like_a_missing_one() {
    let p = pdp("az-sai43").await;
    let intent = p.idp_intent(IdpAction::ClientRegister, "client").await;
    let stranger = Id(access_crypto::random::bytes::<16>().unwrap());
    let unseen = ExerciseBasis::Holding(HoldingRef {
        holder: stranger,
        ..p.audit
    });
    let missing = ExerciseBasis::Holding(HoldingRef {
        grant: Id(access_crypto::random::bytes::<16>().unwrap()),
        ..p.audit
    });
    let mut answers = Vec::new();
    for basis in [unseen, missing] {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let body = p.body(Mode::Check, &nonce, &intent, basis, PEP).await;
        answers.push(p.post("/access/v1/evaluation", &body).await);
    }
    let (a, b) = (&answers[0], &answers[1]);
    assert_eq!(a.status, b.status);
    let (va, vb) = (a.json(), b.json());
    assert_eq!(va["decision"], false, "{va}");
    assert_eq!(shape(&va), shape(&vb), "{va} {vb}");
    assert_eq!(keys(&va), keys(&vb));
    assert_eq!(a.body.len(), b.body.len());
    assert!(
        access_http::padding::CLASSES.contains(&a.body.len()),
        "{}",
        a.body.len()
    );
    assert_eq!(
        a.headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some(a.body.len().to_string().as_str())
    );
    let text = std::str::from_utf8(&a.body).unwrap();
    assert_eq!(
        serde_json::from_str::<Json>(text.trim_end()).unwrap(),
        va,
        "padding is whitespace after the JSON value"
    );
    assert!(text.trim_end().len() < text.len());
    p.w.domains.release().await;
}

// CR-40 m.3, INV-27
#[tokio::test]
async fn padding_never_reaches_an_answer_outside_the_sensitive_paths() {
    let p = pdp("az-pad-out").await;
    let a = p
        .send("/.well-known/authzen-configuration", Vec::new(), &[], None)
        .await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.body.trim_ascii_end().len(), a.body.len());
    p.w.domains.release().await;
}
