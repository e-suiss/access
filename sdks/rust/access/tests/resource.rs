//! The resource server side (§9.9.3, §9.9.4, §10.4.3, §12.2.1, §13.4 U55, U60, §13.7.9,
//! L2-JOS-1 to L2-JOS-4, L2-STL-1 to L2-STL-3, OP-150 m.3 (d), (g), (s), m.9).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use access_kernel::digest::Digest;
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
    d, exercise, family, intent, intent_hash, introspection_body, jwks, jwks_of, list_cwt,
    list_jwt, ok, proof, proof_with, server, status, text_digest,
};

fn present<'a>(token: &'a str, proof: Option<&'a str>) -> Presented<'a> {
    Presented {
        token,
        method: "POST",
        uri: REQUEST_URI,
        proof,
        certificate: None,
        content_position: None,
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

// §9.11.2, §13.11 EP-4, MD-6, MD-7, U36, U39: JWKS within key_epoch, default 1 h, ceiling 24 h
#[test]
fn the_jwks_serves_within_the_key_epoch_and_every_fetch_fault_is_deny() {
    let token = TokenSpec::intent_token().signed();
    let s = server(Profile::Fast);
    let m = support::Memory::healthy();
    *m.keys.borrow_mut() = Some(Keys::Cached {
        body: jwks(),
        fetched_at: NOW - HOUR / 2,
    });
    assert!(verify(&s, &token, &proof(&token, "p-1"), &m).is_ok());
    *m.keys.borrow_mut() = Some(Keys::Cached {
        body: jwks(),
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
    *m.keys.borrow_mut() = Some(Keys::Fetched(ok(jwks_of(OTHER_SEED))));
    assert!(matches!(
        verify(&s, &token, &proof(&token, "p-6"), &m).unwrap_err(),
        Denied::Projection(ProjectionError::Jws(_))
    ));
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
    *m.list.borrow_mut() = Some(ok(list_jwt(NOW / 1000 - 7_200, false)));
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
