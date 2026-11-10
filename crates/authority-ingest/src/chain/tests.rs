use access_internal_api::claims::{Carrier, ClaimSubmission};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;

use super::*;

const NOW: u64 = 10_000_000;

fn fact(status: Status, checked_ms: u64, chain_exp_ms: u64) -> Fact {
    Fact {
        status,
        checked_ms,
        chain_exp_ms,
    }
}

// IDI-12, OP-155 m.3 (j)
#[test]
fn a_chain_that_does_not_hold_stops_the_issuer() {
    let fresh = fact(Status::Resolved, NOW - 1_000, NOW + 1_000);
    assert!(admits(&fresh, NOW));
    assert!(!admits(&fact(Status::Unresolved, NOW, NOW + 1_000), NOW));
    assert!(!admits(&fact(Status::Conflict, NOW, NOW + 1_000), NOW));
    assert!(!admits(&fact(Status::Pending, NOW, NOW + 1_000), NOW));
    assert!(
        !admits(
            &fact(Status::Resolved, NOW - FRESHNESS_MS - 1, NOW + 1_000),
            NOW
        ),
        "a check older than the freshness window"
    );
    assert!(admits(
        &fact(Status::Resolved, NOW - FRESHNESS_MS, NOW + 1_000),
        NOW
    ));
    assert!(!admits(&fact(Status::Resolved, NOW, NOW), NOW), "expired");
    assert_eq!(gate(&[], NOW), Ok(()), "an untracked issuer is not gated");
    assert_eq!(gate(&[fresh], NOW), Ok(()));
    assert_eq!(
        gate(&[fresh, fact(Status::Unresolved, NOW, NOW + 1)], NOW),
        Err(REFUSAL)
    );
    assert_eq!(REFUSAL.0, "claim-issuer-chain");
}

fn jws(payload: &str) -> Vec<u8> {
    format!(
        "{}.{}.{}",
        b64url_encode(br#"{"alg":"ES256"}"#),
        b64url_encode(payload.as_bytes()),
        b64url_encode(&[0_u8; 4])
    )
    .into_bytes()
}

#[test]
fn an_upstream_carrier_names_its_iss() {
    let s = ClaimSubmission {
        domain: Digest([1; 32]),
        carrier: Carrier::Oidc,
        claim: jws(r#"{"iss":"https://op.example","sub":"a"}"#),
        body: None,
        evidence: None,
    };
    assert_eq!(named(&s).entity.as_deref(), Some("https://op.example"));
    assert_eq!(named(&s).party, None);
    let garbage = ClaimSubmission {
        carrier: Carrier::Cose,
        claim: vec![1, 2, 3],
        ..s
    };
    assert_eq!(named(&garbage), Named::default());
}
