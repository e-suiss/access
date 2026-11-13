#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_authority_core::app::Response;
use access_internal_api::instances::core_action;
use access_kernel::combinator::{Capacity, Decision};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};

use super::*;

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: core_action("projection_issue"),
        resources: Vec::new(),
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 1 },
    }
}

fn request(
    resources: Vec<String>,
    kind: TokenKind,
    target: Option<IntentEnvelope>,
) -> TokenProjectionRequest {
    TokenProjectionRequest {
        domain: Digest([1; 32]),
        nonce: vec![7; 16],
        intent: intent(),
        payload: Payload::InstanceTerminate {
            instance: Id([3; 16]),
        }
        .to_bytes()
        .unwrap(),
        basis: ExerciseBasis::Anchor(Id([3; 16])),
        capacity: Capacity::Own,
        ais: vec![1],
        pep: String::from("access-identity"),
        issuer: String::from("https://id.example"),
        client_id: String::from("cli_x"),
        kind,
        target,
        confirmation: Confirmation::DpopJkt([4; 32]),
        resources,
        family: None,
        profile: access_internal_api::projections::TokenProfile::default(),
    }
}

fn response(outcome: Outcome) -> Response {
    Response {
        decision: Decision {
            outcome,
            blockers: Vec::new(),
            unmet: Vec::new(),
            relied_on: Vec::new(),
        },
        exercise: None,
        record: Some(9),
        replayed: false,
        basis_ref: None,
        consistency: None,
        receipt: None,
        signed_receipt: None,
        pap: None,
        signed_pap: None,
        pap_carried: None,
        ended: Vec::new(),
        explained: None,
        witnessed_through: None,
        ack: None,
        causal: None,
    }
}

// §9.9.3 rule 1, AG-8
#[test]
fn a_token_order_has_exactly_one_resource() {
    let one = vec![String::from("https://rs.example")];
    let o = order(request(one.clone(), TokenKind::Bounds, None)).unwrap();
    assert_eq!(o.audience, "https://rs.example");
    assert_eq!(o.confirmation, Cnf::Jkt([4; 32]));
    assert_eq!(o.incoming.request.mode, Mode::Commit);
    assert_eq!(
        order(request(Vec::new(), TokenKind::Bounds, None)).err(),
        Some("invalid-target")
    );
    let two = vec![
        String::from("https://a.example"),
        String::from("https://b.example"),
    ];
    assert_eq!(
        order(request(two, TokenKind::Bounds, None)).err(),
        Some("invalid-target")
    );
    // §9.9.1
    assert_eq!(
        order(request(one.clone(), TokenKind::Intent, None)).err(),
        Some("projection-authority")
    );
    assert_eq!(
        order(request(one, TokenKind::Bounds, Some(intent()))).err(),
        Some("projection-authority")
    );
}

// §9.9.5, K17, §16.7.1
#[test]
fn projections_answer_each_outcome() {
    assert!(matches!(
        answer(Projected::Decided(Box::new(response(Outcome::Deny)))),
        Ok(TokenProjection::Denied {
            position: Some(9),
            ..
        })
    ));
    assert!(matches!(
        answer(Projected::Decided(Box::new(response(
            Outcome::RequireAction
        )))),
        Ok(TokenProjection::RequireAction { .. })
    ));
    assert_eq!(
        answer(Projected::Refused(SIGNER_UNAVAILABLE)),
        Err(Unavailable(String::from(SIGNER_UNAVAILABLE)))
    );
    assert_eq!(
        answer(Projected::Refused("token-too-large")),
        Ok(TokenProjection::Refused {
            code: String::from("token-too-large")
        })
    );
}
