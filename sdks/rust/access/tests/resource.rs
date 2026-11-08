//! The resource server side (§9.9.3, §9.9.4, §10.4.3, §12.2.1, §13.4 U55, U60, §13.7.9,
//! L2-JOS-1 to L2-JOS-4, L2-STL-1 to L2-STL-3, OP-150 m.3 (d), (g), (s), m.9).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::collections::BTreeMap;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::ParamValue;
use access_kernel::model::{
    AuthoritySet, Binding as RequirementBinding, Bound, Consumption, Id, Independence, ProofKind,
    RequirementTerm, ResourceRef, ResourceSelector, Structural, SubjectSelector,
};
use access_kernel::verify::dpop::DpopError;
use access_kernel::verify::jws::ClaimError;
use access_kernel::verify::projection::{Kind, ProjectionError};
use access_sdk::authorize::Intent;
use access_sdk::resource::{
    ConfigError, Denied, FAST_HORIZON_MS, Keys, MAX_KEY_EPOCH_MS, MAX_TOKEN_BYTES, Presented,
    Profile, ResourceServer, TokenCapacity, Verified,
};
use access_sdk::transport::{Answer, Fault, FixedClock, Response};
use support::{
    BASIS_POS, Door, HOLDER_SEED, HOUR, NOW, OTHER_SEED, Open, REQUEST_URI, RS, TokenSpec, config,
    d, exercise, family, intent, intent_hash, introspection_body, jws, list_cwt, list_jwt,
    metadata, ok, proof, proof_with, server, signed_metadata, signed_metadata_by, status,
    text_digest,
};

fn present<'a>(token: &'a str, proof: Option<&'a str>) -> Presented<'a> {
    Presented {
        token,
        method: "POST",
        uri: REQUEST_URI,
        proof,
        certificate: None,
        content_position: None,
        satisfied: &[],
    }
}

fn verify(
    server: &ResourceServer,
    token: &str,
    proof: &str,
    memory: &support::Memory,
) -> Result<Verified<Door, Open>, Denied> {
    server.verify(
        &present(token, Some(proof)),
        &intent(),
        &FixedClock(NOW),
        &memory.ports(),
    )
}

// L2-JOS-1 to L2-JOS-4, §9.9.4 k.2, OP-150 m.9 (b), (d), (f): the RS reads its authority from
// RAR + cnf + ValidityContract
#[test]
fn a_dpop_bound_exact_intent_token_for_this_server_and_intent_is_verified() {
    let token = TokenSpec::intent_token().signed();
    let m = support::Memory::healthy();
    let v = verify(&server(Profile::Fast), &token, &proof(&token, "p-1"), &m).unwrap();
    assert_eq!(v.authority.kind, Kind::Intent);
    assert_eq!(v.authority.exercise, exercise());
    assert_eq!(v.authority.as_of, BASIS_POS);
    assert_eq!(v.authority.family, Some(family()));
    assert_eq!(v.authority.contract.digest, d(0x44));
    assert_eq!(v.authority.contract.horizon, NOW + 240_000);
    assert_eq!(v.authority.client_id, "c-1");
    assert_eq!(v.authority.introspected_as_of, None);
    assert_eq!(
        v.authority.capacity,
        TokenCapacity::Own {
            subject: "p-1".to_owned()
        }
    );
    assert_eq!(v.authority.actions.len(), 1);
    assert!(v.authority.actions[0].is(&support::action()));
    assert_eq!(v.authorized.intent(), &intent_hash());
    assert_eq!(v.authorized.exercise(), &exercise());
    assert_eq!(v.authorized.as_of(), BASIS_POS);
}

// §9.9.1 count = 1, OP-150 m.9 (j): exact-intent single use at the RS
#[test]
fn an_exact_intent_token_is_accepted_once() {
    let token = TokenSpec::intent_token().signed();
    let m = support::Memory::healthy();
    let s = server(Profile::Fast);
    assert!(verify(&s, &token, &proof(&token, "p-1"), &m).is_ok());
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-2"), &m).unwrap_err(),
        Denied::Reused
    );
    assert!(Denied::Reused.is_decision());
}

// §10.4.3 m.3, m.5, §13.4 U55, IDP-11, TN-30, MD-18: the RS keeps its own replay state
#[test]
fn a_replayed_dpop_proof_is_refused_and_a_dead_replay_store_refuses_too() {
    let token = TokenSpec::bounds_token().signed();
    let m = support::Memory::healthy();
    let s = server(Profile::Fast);
    let p = proof(&token, "p-1");
    assert!(verify(&s, &token, &p, &m).is_ok());
    assert_eq!(verify(&s, &token, &p, &m).unwrap_err(), Denied::DpopReplay);
    assert!(verify(&s, &token, &proof(&token, "p-2"), &m).is_ok());
    m.replay_down.set(true);
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-3"), &m).unwrap_err(),
        Denied::ReplayStore
    );
}

// §9.9.3 rule 2, §12.2.1, PI-11, TN-27, TN-28, TN-29: no bearer, the proof binds this request
#[test]
fn a_missing_mismatched_or_misbound_proof_is_refused() {
    let token = TokenSpec::intent_token().signed();
    let m = support::Memory::healthy();
    let s = server(Profile::Fast);
    let r = s.verify(
        &present(&token, None),
        &intent(),
        &FixedClock(NOW),
        &m.ports(),
    );
    assert_eq!(r.unwrap_err(), Denied::Confirmation("missing"));
    let other_key = proof_with(OTHER_SEED, &token, "p-1", "POST", REQUEST_URI, None);
    assert_eq!(
        verify(&s, &token, &other_key, &m).unwrap_err(),
        Denied::Projection(ProjectionError::Confirmation)
    );
    let other_uri = proof_with(
        HOLDER_SEED,
        &token,
        "p-1",
        "POST",
        "https://rs.example/doors/2",
        None,
    );
    assert_eq!(
        verify(&s, &token, &other_uri, &m).unwrap_err(),
        Denied::Dpop(DpopError::Uri)
    );
    let other_method = proof_with(HOLDER_SEED, &token, "p-1", "GET", REQUEST_URI, None);
    assert_eq!(
        verify(&s, &token, &other_method, &m).unwrap_err(),
        Denied::Dpop(DpopError::Method)
    );
    let other_token = proof_with(
        HOLDER_SEED,
        "another.token.here",
        "p-1",
        "POST",
        REQUEST_URI,
        None,
    );
    assert_eq!(
        verify(&s, &token, &other_token, &m).unwrap_err(),
        Denied::Dpop(DpopError::Ath)
    );
    *m.nonce_required.borrow_mut() = Some("n-1".to_owned());
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-9"), &m).unwrap_err(),
        Denied::DpopNonce
    );
    let with_nonce = proof_with(
        HOLDER_SEED,
        &token,
        "p-10",
        "POST",
        REQUEST_URI,
        Some("n-1"),
    );
    assert!(verify(&s, &token, &with_nonce, &m).is_ok());
}

// §9.9.3 rule 1, rule 7, AG-8, RFC 8707, TI-RT6: one audience, this one, this issuer, this domain
#[test]
fn tokens_for_another_audience_issuer_or_domain_are_refused() {
    let m = support::Memory::healthy();
    let s = server(Profile::Fast);
    let mut spec = TokenSpec::intent_token();
    spec.audience = "https://other.example".to_owned();
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "a-1"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Claims(ClaimError::Audience))
    );
    let mut spec = TokenSpec::intent_token();
    spec.aud_json = Some(format!(r#"["{RS}","https://other.example"]"#));
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "a-2"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Claims(ClaimError::Audience))
    );
    let mut spec = TokenSpec::intent_token();
    spec.issuer = "https://other-as.example".to_owned();
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "a-3"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Claims(ClaimError::Issuer))
    );
    let mut spec = TokenSpec::intent_token();
    spec.domain = d(2);
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "a-4"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Domain)
    );
    let mut spec = TokenSpec::intent_token();
    spec.contract_audience = r#""https://other.example""#.to_owned();
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "a-5"), &m).unwrap_err(),
        Denied::ContractAudience
    );
}

// OP-150 m.3 (s), §9.9.6: 8 KiB ceiling, checked before any port is touched
#[test]
fn a_token_over_8_kib_is_refused_before_anything_else() {
    let mut spec = TokenSpec::intent_token();
    spec.extra = format!(r#","pad":"{}""#, "x".repeat(MAX_TOKEN_BYTES));
    let token = spec.signed();
    assert!(token.len() > MAX_TOKEN_BYTES);
    let m = support::Memory::healthy();
    let r = verify(&server(Profile::Fast), &token, &proof(&token, "p-1"), &m);
    assert_eq!(r.unwrap_err(), Denied::TooLarge);
    assert_eq!(m.calls.get(), 0);
    assert!(m.seen.borrow().is_empty());
}

// §9.11.2, §13.11 EP-4, MD-6, MD-7, U36, U39: the domain's keys within key_epoch, default 1 h,
// ceiling 24 h
#[test]
fn the_keys_serve_within_the_key_epoch_and_every_fetch_fault_is_deny() {
    let token = TokenSpec::intent_token().signed();
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    *m.keys.borrow_mut() = Some(Keys::Cached {
        body: signed_metadata(),
        fetched_at: NOW - HOUR / 2,
    });
    assert!(verify(&s, &token, &proof(&token, "p-1"), &m).is_ok());
    *m.keys.borrow_mut() = Some(Keys::Cached {
        body: signed_metadata(),
        fetched_at: NOW - HOUR - 1,
    });
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-2"), &m).unwrap_err(),
        Denied::KeysStale
    );
    *m.keys.borrow_mut() = Some(Keys::Fetched(status(503)));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-3"), &m).unwrap_err(),
        Denied::KeysStatus(503)
    );
    *m.keys.borrow_mut() = Some(Keys::Fetched(Answer::Unanswered(Fault::Timeout)));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-4"), &m).unwrap_err(),
        Denied::KeysUnavailable(Fault::Timeout)
    );
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(b"{\"keys\":[]}".to_vec())));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-5"), &m).unwrap_err(),
        Denied::KeysMalformed
    );
    let mut c = config(Profile::Fast);
    c.key_epoch_ms = MAX_KEY_EPOCH_MS + 1;
    assert_eq!(ResourceServer::new(c).unwrap_err(), ConfigError::KeyEpoch);
    let mut c = config(Profile::Fast);
    c.key_epoch_ms = MAX_KEY_EPOCH_MS;
    assert!(ResourceServer::new(c).is_ok());
}

// L2-STL-1 to L2-STL-3, §9.12.4, PI-9, OP-150 m.7 (e), m.10: set bit, stale list, no list
#[test]
fn a_set_stale_unreadable_or_missing_status_list_is_deny() {
    let s = server(Profile::Fast);
    let token = TokenSpec::intent_token().signed();
    let m = support::Memory::healthy();
    *m.list.borrow_mut() = Some(ok(list_jwt(NOW / 1000 - 60, true)));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-1"), &m).unwrap_err(),
        Denied::Revoked
    );
    *m.list.borrow_mut() = Some(ok(list_jwt(NOW / 1000 - 1_000, false)));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-2"), &m).unwrap_err(),
        Denied::StatusStale
    );
    *m.list.borrow_mut() = Some(status(503));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-3"), &m).unwrap_err(),
        Denied::StatusStatus(503)
    );
    *m.list.borrow_mut() = Some(Answer::Unanswered(Fault::Timeout));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-4"), &m).unwrap_err(),
        Denied::StatusUnavailable(Fault::Timeout)
    );
    *m.list.borrow_mut() = Some(ok(b"not a list".to_vec()));
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-5"), &m).unwrap_err(),
        Denied::StatusSignature
    );
    // the CWT form under the domain's status-list key (OP-150 m.10 (b))
    *m.list.borrow_mut() = Some(Answer::Response(list_cwt(NOW / 1000 - 60, false)));
    assert!(verify(&s, &token, &proof(&token, "p-6"), &m).is_ok());
    *m.list.borrow_mut() = Some(Answer::Response(list_cwt(NOW / 1000 - 60, true)));
    let token2 = {
        let mut spec = TokenSpec::intent_token();
        spec.extra = r#","note":"second""#.to_owned();
        spec.signed()
    };
    assert_eq!(
        verify(&s, &token2, &proof(&token2, "p-7"), &m).unwrap_err(),
        Denied::Revoked
    );
    let mut without_excerpt = list_cwt(NOW / 1000 - 60, false);
    without_excerpt.key_excerpt = None;
    *m.list.borrow_mut() = Some(Answer::Response(without_excerpt));
    assert_eq!(
        verify(&s, &token2, &proof(&token2, "p-8"), &m).unwrap_err(),
        Denied::StatusKey
    );
    // the contract's Δ bounds the list's age (m.7 (e))
    let mut spec = TokenSpec::bounds_token();
    spec.max_staleness_ms = Some(30_000);
    let bounded = spec.signed();
    *m.list.borrow_mut() = Some(ok(list_jwt(NOW / 1000 - 60, false)));
    assert_eq!(
        verify(&s, &bounded, &proof(&bounded, "p-9"), &m).unwrap_err(),
        Denied::StatusStale
    );
    // no reference at all
    let mut spec = TokenSpec::intent_token();
    spec.status_json = None;
    let unreferenced = spec.signed();
    assert_eq!(
        verify(&s, &unreferenced, &proof(&unreferenced, "p-10"), &m).unwrap_err(),
        Denied::StatusMissing
    );
    // the contract's own reference must agree
    let mut spec = TokenSpec::intent_token();
    spec.contract_status_json = Some(format!(
        r#"{{"status_list":{{"idx":7,"uri":"{}"}}}}"#,
        support::LIST_URI
    ));
    let disagreeing = spec.signed();
    assert_eq!(
        verify(&s, &disagreeing, &proof(&disagreeing, "p-11"), &m).unwrap_err(),
        Denied::ContractStatus
    );
}

// §13.7.9, §9.9.3 rule 5, §13.4 G48, HL-22, U39, MD-7, MD-8, OP-150 m.3 (g): strict introspects
// every request, fast lives within 5 minutes and never learns of a revocation before its
// horizon, neither skips the signature
#[test]
fn the_strict_profile_introspects_every_request_and_the_fast_profile_bounds_the_horizon() {
    let token = TokenSpec::intent_token().signed();
    let strict = server(Profile::Strict);
    let m = support::Memory::healthy();
    let v = verify(&strict, &token, &proof(&token, "p-1"), &m).unwrap();
    assert_eq!(v.authority.introspected_as_of, Some(BASIS_POS + 5));
    assert!(strict.profile() == Profile::Strict && strict.audience() == RS);
    let faults = [
        (
            ok(introspection_body(&TokenSpec::intent_token(), false, 0)),
            Denied::Inactive,
        ),
        (status(500), Denied::IntrospectionStatus(500)),
        (status(503), Denied::IntrospectionStatus(503)),
        (
            Answer::Unanswered(Fault::Timeout),
            Denied::IntrospectionUnavailable(Fault::Timeout),
        ),
        (ok(b"garbage".to_vec()), Denied::IntrospectionMalformed),
        (
            ok(introspection_body(
                &TokenSpec::intent_token(),
                true,
                BASIS_POS - 1,
            )),
            Denied::IntrospectionStale,
        ),
    ];
    for (i, (answer, expected)) in faults.into_iter().enumerate() {
        let m = support::Memory::healthy();
        *m.introspection.borrow_mut() = Some(answer);
        let jti = format!("f-{i}");
        assert_eq!(
            verify(&strict, &token, &proof(&token, &jti), &m).unwrap_err(),
            expected
        );
    }
    let fast = server(Profile::Fast);
    let m = support::Memory::healthy();
    *m.introspection.borrow_mut() = Some(status(500));
    assert!(
        verify(&fast, &token, &proof(&token, "p-2"), &m).is_ok(),
        "fast does not introspect"
    );
    let mut spec = TokenSpec::intent_token();
    spec.exp_s = spec.iat_s + FAST_HORIZON_MS / 1000 + 1;
    spec.horizon_ms = spec.exp_s * 1000;
    let long = spec.signed();
    let m = support::Memory::healthy();
    assert_eq!(
        verify(&fast, &long, &proof(&long, "p-3"), &m).unwrap_err(),
        Denied::ProfileHorizon
    );
    // no profile skips the signature
    let mut tampered = token.clone();
    tampered.replace_range(tampered.len() - 4.., "AAAA");
    for s in [&strict, &fast] {
        let m = support::Memory::healthy();
        assert!(matches!(
            verify(s, &tampered, &proof(&tampered, "p-4"), &m).unwrap_err(),
            Denied::Projection(ProjectionError::Jws(_))
        ));
    }
}

// §9.9.4, P53, §9.9.4 k.1, P55: sub/act/may_act are hints with fixed shapes; reserved claims
// keep their shapes
#[test]
fn capacity_is_read_from_sub_and_act_and_reserved_claims_keep_their_shape() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let mut spec = TokenSpec::intent_token();
    spec.act =
        Some(r#"{"sub":"agent-9","iss":"https://as.example","act":{"sub":"agent-8"}}"#.to_owned());
    spec.detail_capacity = r#"{"for":"p-1"}"#.to_owned();
    spec.extra = r#","may_act":{"sub":"agent-7"}"#.to_owned();
    let token = spec.signed();
    let v = verify(&s, &token, &proof(&token, "p-1"), &m).unwrap();
    let TokenCapacity::For { principal, actors } = v.authority.capacity else {
        panic!("for");
    };
    assert_eq!(principal, "p-1");
    assert_eq!(actors.len(), 2);
    assert_eq!(actors[0].sub, "agent-9");
    assert_eq!(actors[0].iss.as_deref(), Some("https://as.example"));
    assert_eq!(actors[1].sub, "agent-8");
    assert!(v.authority.may_act);
    let mut spec = TokenSpec::intent_token();
    spec.act = Some(r#"{"sub":"agent-9"}"#.to_owned());
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-2"), &m).unwrap_err(),
        Denied::Claim("capacity")
    );
    for (extra, claim) in [
        (r#","scope":7"#, "scope"),
        (r#","act":"agent""#, "act"),
        (r#","may_act":"agent""#, "may_act"),
    ] {
        let mut spec = TokenSpec::intent_token();
        spec.extra = extra.to_owned();
        let token = spec.signed();
        assert_eq!(
            verify(&s, &token, &proof(&token, claim), &m).unwrap_err(),
            Denied::Claim(claim),
            "{claim}"
        );
    }
}

// §13.4 U60, §9.7A.3, P44, OP-150 m.3 (l): plain as_of in the projection
#[test]
fn a_projection_older_than_the_protected_content_is_refused() {
    let token = TokenSpec::bounds_token().signed();
    let m = support::Memory::healthy();
    let s = server(Profile::Fast);
    let mut p = present(&token, None);
    let first = proof(&token, "p-1");
    p.proof = Some(&first);
    p.content_position = Some(BASIS_POS + 1);
    assert_eq!(
        s.verify(&p, &intent(), &FixedClock(NOW), &m.ports())
            .unwrap_err(),
        Denied::Stale
    );
    let second = proof(&token, "p-2");
    p.proof = Some(&second);
    p.content_position = Some(BASIS_POS);
    assert!(
        s.verify(&p, &intent(), &FixedClock(NOW), &m.ports())
            .is_ok()
    );
}

// §9.9.3 rule 9, L24, RS-M8, RS-M10: the verified value carries no token to pass through
#[test]
fn a_verified_token_is_never_re_emitted() {
    let token = TokenSpec::intent_token().signed();
    let m = support::Memory::healthy();
    let v = verify(&server(Profile::Fast), &token, &proof(&token, "p-1"), &m).unwrap();
    let shown = format!("{v:?}");
    let (_, rest) = token.split_once('.').unwrap();
    let (payload, signature) = rest.split_once('.').unwrap();
    assert!(!shown.contains(payload));
    assert!(!shown.contains(signature));
    assert!(!shown.contains(&token));
}

// §9.9.1, §5.10: a bounds token names the action; without the action nothing is decided
#[test]
fn a_bounds_token_must_name_this_action() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let token = TokenSpec::bounds_token().signed();
    let v = verify(&s, &token, &proof(&token, "p-1"), &m).unwrap();
    assert_eq!(v.authority.kind, Kind::Bounds);
    let mut spec = TokenSpec::bounds_token();
    spec.action_type = "door:close:1".to_owned();
    let other = spec.signed();
    assert_eq!(
        verify(&s, &other, &proof(&other, "p-2"), &m).unwrap_err(),
        Denied::Bounds
    );
    let mut spec = TokenSpec::bounds_token();
    spec.schema = d(10);
    let other_schema = spec.signed();
    assert_eq!(
        verify(&s, &other_schema, &proof(&other_schema, "p-3"), &m).unwrap_err(),
        Denied::Bounds
    );
    let blind: Intent<Door, Open> = Intent::approved(intent_hash(), None);
    let r = s.verify(
        &present(&token, Some(&proof(&token, "p-4"))),
        &blind,
        &FixedClock(NOW),
        &m.ports(),
    );
    assert_eq!(r.unwrap_err(), Denied::Bounds);
    let mut spec = TokenSpec::intent_token();
    spec.intent = Digest([0x77; 32]);
    let other_intent = spec.signed();
    assert_eq!(
        verify(&s, &other_intent, &proof(&other_intent, "p-5"), &m).unwrap_err(),
        Denied::Intent
    );
}

// §9.9.3 rule 5, RFC 7662, OP-150 m.9 (i): an opaque token is only introspection, only strict
#[test]
fn an_opaque_token_is_verified_by_introspection_under_the_strict_profile_only() {
    let token = "opaque.handle";
    let m = support::Memory::healthy();
    assert_eq!(
        verify(&server(Profile::Fast), token, &proof(token, "p-1"), &m).unwrap_err(),
        Denied::Opaque
    );
    let strict = server(Profile::Strict);
    let v = verify(&strict, token, &proof(token, "p-2"), &m).unwrap();
    assert_eq!(v.authority.introspected_as_of, Some(BASIS_POS + 5));
    assert_eq!(v.authority.exercise, exercise());
    assert_eq!(
        verify(&strict, token, &proof(token, "p-3"), &m).unwrap_err(),
        Denied::Reused
    );
    *m.introspection.borrow_mut() =
        Some(ok(introspection_body(&TokenSpec::intent_token(), false, 0)));
    assert_eq!(
        verify(&strict, token, &proof(token, "p-4"), &m).unwrap_err(),
        Denied::Inactive
    );
    let mut spec = TokenSpec::intent_token();
    spec.jkt = support::kid(OTHER_SEED);
    *m.introspection.borrow_mut() = Some(ok(introspection_body(&spec, true, BASIS_POS)));
    assert_eq!(
        verify(&strict, token, &proof(token, "p-5"), &m).unwrap_err(),
        Denied::IntrospectionConfirmation
    );
}

// §9.16, OP-150 m.9 (d), m.10 (g): a family the RS learned was ended
#[test]
fn a_family_ended_by_a_received_event_is_refused_and_family_is_required() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let token = TokenSpec::intent_token().signed();
    m.ended.borrow_mut().insert(family());
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-1"), &m).unwrap_err(),
        Denied::FamilyEnded
    );
    let mut spec = TokenSpec::intent_token();
    spec.family = None;
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-2"), &m).unwrap_err(),
        Denied::Claim("family")
    );
    let mut spec = TokenSpec::intent_token();
    spec.access_contract = None;
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "p-3"), &m).unwrap_err(),
        Denied::Claim("access_contract")
    );
    assert_eq!(text_digest(&d(1)).len(), 8 + 43);
    let _ = Response::new(200, Vec::new());
}

// §10.4.5, §12.1.2, TI-RT6, MD-6 (supersedes OP-150 m.9 (b)'s thumbprint-only key rule): the
// token key resolves only through the domain's binding-signed Domain Metadata, for usage
// `token`, live at the token's `iat`; a realm JWKS key, another usage's key, a key outside its
// window, metadata the pinned binding keys did not sign, another domain's or an older one all
// verify nothing
#[test]
fn only_the_domains_token_key_live_at_iat_verifies_a_token() {
    let s = server(Profile::Fast);
    let spec = TokenSpec::intent_token();
    // a realm key, served as a JWKS: not Domain Metadata at all
    let m = support::Memory::healthy();
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(support::jwks_of(OTHER_SEED))));
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "k-1"), &m).unwrap_err(),
        Denied::KeysMalformed
    );
    // a realm key signing the same claims: not declared by the metadata
    let m = support::Memory::healthy();
    let realm_signed = jws(OTHER_SEED, "at+jwt", &spec.claims());
    assert!(matches!(
        verify(&s, &realm_signed, &proof(&realm_signed, "k-2"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Jws(_))
    ));
    // the domain's receipt and status-list keys: declared, but not for `token`
    for (i, seed) in [support::RECEIPT_SEED, support::LIST_SEED]
        .into_iter()
        .enumerate()
    {
        let other_usage = jws(seed, "at+jwt", &spec.claims());
        assert!(matches!(
            verify(
                &s,
                &other_usage,
                &proof(&other_usage, &format!("k-3-{i}")),
                &m
            )
            .unwrap_err(),
            Denied::Projection(ProjectionError::Jws(_))
        ));
    }
    // the token key, but the token says it was signed before the key's window
    let mut early = TokenSpec::intent_token();
    early.iat_s = (11 * HOUR) / 1000;
    let early = early.signed();
    assert_eq!(
        verify(&s, &early, &proof(&early, "k-4"), &m).unwrap_err(),
        Denied::TokenKey
    );
    assert!(Denied::TokenKey.is_decision());
}

// §10.4.5, CR-58, TI-RT5, TI-RT6: the metadata itself must come from a pinned binding key, for
// this domain, no older than the pinned one, and declare a token key
#[test]
fn metadata_from_another_binding_domain_or_time_verifies_nothing() {
    let s = server(Profile::Fast);
    let spec = TokenSpec::intent_token();
    let m = support::Memory::healthy();
    // metadata signed by a binding key the server does not pin
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata_by(
        OTHER_SEED,
        &metadata(),
    ))));
    let token = spec.signed();
    assert_eq!(
        verify(&s, &token, &proof(&token, "k-5"), &m).unwrap_err(),
        Denied::KeysMalformed
    );
    // another domain's metadata, signed by the pinned binding key
    let mut other_domain = metadata();
    other_domain.domain = d(2);
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata_by(
        support::BINDING_SEED,
        &other_domain,
    ))));
    assert_eq!(
        verify(&s, &token, &proof(&token, "k-6"), &m).unwrap_err(),
        Denied::KeysMalformed
    );
    // metadata older than the pinned one (TI-RT5)
    let mut older = metadata();
    older.issued_at -= 1;
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata_by(
        support::BINDING_SEED,
        &older,
    ))));
    assert_eq!(
        verify(&s, &token, &proof(&token, "k-7"), &m).unwrap_err(),
        Denied::KeysMalformed
    );
    // metadata that declares no token key
    let mut no_token_key = metadata();
    no_token_key.operational_keys.retain(|k| {
        !k.usage
            .contains(&access_kernel::verify::key_scope::KeyUsage::Token)
    });
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata_by(
        support::BINDING_SEED,
        &no_token_key,
    ))));
    assert_eq!(
        verify(&s, &token, &proof(&token, "k-8"), &m).unwrap_err(),
        Denied::TokenKey
    );
    // a status list signed by the token key or a realm key: only `status-list` keys sign lists
    for (i, seed) in [support::TOKEN_SEED, OTHER_SEED].into_iter().enumerate() {
        let m = support::Memory::healthy();
        *m.list.borrow_mut() = Some(ok(support::list_jwt_by(seed, NOW / 1000 - 60, false)));
        let token = spec.signed();
        assert_eq!(
            verify(&s, &token, &proof(&token, &format!("k-9-{i}")), &m).unwrap_err(),
            Denied::StatusSignature
        );
    }
    // a key whose window opens inside the token's `iat` second still signed it (JOSE times
    // are whole seconds, rounded down)
    let mut mid_second = metadata();
    for k in &mut mid_second.operational_keys {
        if k.usage
            .contains(&access_kernel::verify::key_scope::KeyUsage::Token)
        {
            k.valid_from = spec.iat_s * 1000 + 500;
        }
    }
    let m = support::Memory::healthy();
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(signed_metadata_by(
        support::BINDING_SEED,
        &mid_second,
    ))));
    let token = spec.signed();
    assert!(verify(&s, &token, &proof(&token, "k-10"), &m).is_ok());
    // the pinned metadata must be the configured domain's
    let mut c = config(Profile::Fast);
    c.metadata.domain = d(2);
    assert_eq!(ResourceServer::new(c).unwrap_err(), ConfigError::Domain);
}

fn bounds_token(set: AuthoritySet) -> String {
    let mut spec = TokenSpec::bounds_token();
    spec.bounds = Some(set);
    spec.signed()
}

fn door(path: &[&str], params: BTreeMap<String, ParamValue>) -> Intent<Door, Open> {
    let mut e = support::envelope();
    e.resources = vec![ResourceRef {
        namespace: "door".to_owned(),
        path: path.iter().map(|p| (*p).to_owned()).collect(),
        incarnation: 0,
    }];
    e.params = params;
    Intent::of(e).unwrap()
}

fn verify_for(
    s: &ResourceServer,
    token: &str,
    jti: &str,
    intent: &Intent<Door, Open>,
    satisfied: &[RequirementTerm],
    m: &support::Memory,
) -> Result<Verified<Door, Open>, Denied> {
    let p = proof(token, jti);
    let mut presented = present(token, Some(&p));
    presented.satisfied = satisfied;
    s.verify(&presented, intent, &FixedClock(NOW), &m.ports())
}

// §9.9.1, §5.3, OP-109 m.7, OP-150 m.9 (b), MD-8: a bounds token is evaluated with the Kernel's
// covers: a token for store A does not open a door in store B, a parameter outside its range
// is refused, and what the SDK cannot evaluate (no intent envelope, a party selector it only
// knows by pseudonym, details that differ from the contract's bounds) is refused
#[test]
fn a_bounds_token_covers_its_resource_scope_and_parameters_only() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let mut store_a = support::door_bounds();
    store_a.resource = ResourceSelector::Structural(Structural {
        namespace: "door".to_owned(),
        prefix: vec!["store-a".to_owned()],
        kind: None,
        attrs: BTreeMap::new(),
    });
    store_a.params = BTreeMap::from([(
        "amount".to_owned(),
        Bound::Range {
            min: None,
            max: Some(100),
            unit: "eur".to_owned(),
        },
    )]);
    let token = bounds_token(store_a.clone());
    let amount = |value| {
        BTreeMap::from([(
            "amount".to_owned(),
            ParamValue::Amount {
                value,
                unit: "eur".to_owned(),
            },
        )])
    };
    assert!(
        verify_for(
            &s,
            &token,
            "b-1",
            &door(&["store-a", "1"], amount(50)),
            &[],
            &m
        )
        .is_ok()
    );
    assert_eq!(
        verify_for(
            &s,
            &token,
            "b-2",
            &door(&["store-b", "1"], amount(50)),
            &[],
            &m
        )
        .unwrap_err(),
        Denied::Bounds
    );
    assert_eq!(
        verify_for(
            &s,
            &token,
            "b-3",
            &door(&["store-a", "1"], amount(150)),
            &[],
            &m
        )
        .unwrap_err(),
        Denied::Bounds
    );
    assert_eq!(
        verify_for(
            &s,
            &token,
            "b-4",
            &door(&["store-a", "1"], BTreeMap::new()),
            &[],
            &m
        )
        .unwrap_err(),
        Denied::Bounds
    );
    let blind: Intent<Door, Open> = Intent::approved(intent_hash(), Some(support::action()));
    assert_eq!(
        verify_for(&s, &token, "b-5", &blind, &[], &m).unwrap_err(),
        Denied::Unevaluable("intent")
    );
    let mut to_party = store_a.clone();
    to_party.recipient = Some(SubjectSelector::Party(Id([5; 16])));
    let token = bounds_token(to_party);
    assert_eq!(
        verify_for(
            &s,
            &token,
            "b-6",
            &door(&["store-a", "1"], amount(50)),
            &[],
            &m
        )
        .unwrap_err(),
        Denied::Unevaluable("bounds")
    );
}

// OP-150 m.9 (b), MD-8: every bounds detail repeats the contract's bounds, and a bounds token
// without readable bounds is refused
#[test]
fn bounds_details_must_repeat_readable_contract_bounds() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let amount = BTreeMap::from([(
        "amount".to_owned(),
        ParamValue::Amount {
            value: 50,
            unit: "eur".to_owned(),
        },
    )]);
    let mut store_a = support::door_bounds();
    store_a.resource = ResourceSelector::Structural(Structural {
        namespace: "door".to_owned(),
        prefix: vec!["store-a".to_owned()],
        kind: None,
        attrs: BTreeMap::new(),
    });
    let mut spec = TokenSpec::bounds_token();
    spec.bounds = Some(store_a);
    let claims = spec.claims().replacen(r#""store-a""#, r#""store-b""#, 1);
    let mismatched = jws(support::TOKEN_SEED, "at+jwt", &claims);
    assert_eq!(
        verify_for(
            &s,
            &mismatched,
            "b-7",
            &door(&["store-b", "1"], amount),
            &[],
            &m
        )
        .unwrap_err(),
        Denied::Claim("authorization_details")
    );
    let mut spec = TokenSpec::bounds_token();
    spec.bounds = None;
    let unbounded = spec.signed();
    assert_eq!(
        verify_for(&s, &unbounded, "b-8", &intent(), &[], &m).unwrap_err(),
        Denied::Unevaluable("bounds")
    );
}

// TN-44, RFC 9470, §12.2.3, Ek B 2293: a local requirement that is only the user's
// authentication strength or freshness answers `insufficient_user_authentication` with
// `max_age` and `acr_values`; one bound to the intent has no RFC 9470 answer
#[test]
fn an_unmet_authentication_term_is_an_rfc_9470_challenge() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let fresh = RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: "authentication".to_owned(),
        count: 1,
        binding: RequirementBinding::ActorInstance,
        freshness_ms: Some(299_500),
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::from([("aal".to_owned(), 2)]),
    };
    let mut spec = TokenSpec::bounds_token();
    spec.local_requirements_json = Some(format!("[{}]", support::value_json(&fresh.to_value())));
    let token = spec.signed();
    let denied = verify_for(&s, &token, "su-1", &intent(), &[], &m).unwrap_err();
    assert_eq!(
        denied,
        Denied::StepUp(access_sdk::resource::StepUp {
            max_age_s: 300,
            aal: Some(2)
        })
    );
    assert!(denied.is_decision());
    assert_eq!(
        denied.www_authenticate().unwrap(),
        "Bearer error=\"insufficient_user_authentication\", error_description=\"A fresher or stronger user authentication is required\", max_age=300, acr_values=\"http://idmanagement.gov/ns/assurance/aal/2\""
    );
    assert!(
        verify_for(
            &s,
            &token,
            "su-2",
            &intent(),
            std::slice::from_ref(&fresh),
            &m
        )
        .is_ok()
    );
    let bound = RequirementTerm {
        binding: RequirementBinding::IntentDigest,
        ..fresh
    };
    let mut spec = TokenSpec::bounds_token();
    spec.local_requirements_json = Some(format!("[{}]", support::value_json(&bound.to_value())));
    spec.extra = String::from(r#","note":"bound""#);
    let token = spec.signed();
    let denied = verify_for(&s, &token, "su-3", &intent(), &[], &m).unwrap_err();
    assert_eq!(denied, Denied::LocalRequirement);
    assert!(denied.www_authenticate().is_none());
}

// OP-150 m.8 (b), §9.12, MD-8: a contract's local requirement, such as an approval, must be one
// this server satisfied; an extension the SDK must understand is refused
#[test]
fn a_contract_local_requirement_this_server_did_not_satisfy_is_refused() {
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    let approval = RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: "approval".to_owned(),
        count: 1,
        binding: RequirementBinding::IntentDigest,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    };
    for (i, spec) in [TokenSpec::bounds_token(), TokenSpec::intent_token()]
        .into_iter()
        .enumerate()
    {
        let mut spec = spec;
        spec.local_requirements_json =
            Some(format!("[{}]", support::value_json(&approval.to_value())));
        spec.extra = format!(r#","note":"{i}""#);
        let token = spec.signed();
        assert_eq!(
            verify_for(&s, &token, &format!("l-{i}-1"), &intent(), &[], &m).unwrap_err(),
            Denied::LocalRequirement
        );
        assert!(
            verify_for(
                &s,
                &token,
                &format!("l-{i}-2"),
                &intent(),
                std::slice::from_ref(&approval),
                &m
            )
            .is_ok()
        );
    }
    assert!(Denied::LocalRequirement.is_decision());
    let mut spec = TokenSpec::bounds_token();
    spec.local_requirements_json = Some(r#"[{"proof_kind":"claim"}]"#.to_owned());
    let token = spec.signed();
    assert_eq!(
        verify_for(&s, &token, "l-3", &intent(), &[], &m).unwrap_err(),
        Denied::Unevaluable("local_requirements")
    );
    let mut spec = TokenSpec::bounds_token();
    spec.contract_audience = format!(r#""{RS}"],"must_understand":["x-ext""#);
    let token = spec.signed();
    assert_eq!(
        verify_for(&s, &token, "l-4", &intent(), &[], &m).unwrap_err(),
        Denied::Unevaluable("must_understand")
    );
}
