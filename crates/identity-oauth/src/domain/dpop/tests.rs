use super::*;

const A: Jkt = Jkt([1; 32]);
const B: Jkt = Jkt([2; 32]);

// AG-38, OP-144, MD-3: ES256 and Ed25519 by RFC 9864 names; EdDSA is never announced
#[test]
fn signing_algorithms_use_fully_specified_names() {
    let values = DpopProfile::default().signing_alg_values();
    assert_eq!(values, ["Ed25519", "ES256"]);
    assert!(!values.contains(&"EdDSA"));
    let es_only = DpopProfile::new([Algorithm::Es256].into_iter().collect(), 5_000, 5_000).unwrap();
    assert_eq!(es_only.signing_alg_values(), ["ES256"]);
}

// MD-3, TN-28: the allowlist holds asymmetric, fully-specified algorithms only
#[test]
fn profile_rejects_other_algorithms_and_bad_windows() {
    for alg in [Algorithm::Esp256, Algorithm::MlDsa65] {
        assert_eq!(
            DpopProfile::new([alg].into_iter().collect(), 5_000, 5_000),
            Err(ProfileError::Algorithms)
        );
    }
    assert_eq!(
        DpopProfile::new(BTreeSet::new(), 5_000, 5_000),
        Err(ProfileError::Algorithms)
    );
    let allowed: BTreeSet<Algorithm> = [Algorithm::Ed25519].into_iter().collect();
    assert_eq!(
        DpopProfile::new(allowed.clone(), 0, 5_000),
        Err(ProfileError::Window)
    );
    assert_eq!(
        DpopProfile::new(allowed, 1, u64::MAX),
        Err(ProfileError::Window)
    );
}

// TN-30: replay TTL = proof lifetime + 2 × clock skew (5 s + 2 × 5 s = 15 s)
#[test]
fn replay_ttl_is_lifetime_plus_twice_the_skew() {
    let p = DpopProfile::new([Algorithm::Es256].into_iter().collect(), 5_000, 5_000).unwrap();
    assert_eq!(p.replay_ttl_ms(), Some(15_000));
    assert_eq!(DpopProfile::default().replay_ttl_ms(), Some(125_000));
}

// TN-29, IDP-11: AS answers 400, RS 401 with a DPoP challenge; state failure is 503
#[test]
fn failures_map_to_as_and_rs_responses() {
    let profile = DpopProfile::default();
    let nonce = Failure::UseNonce {
        nonce: String::from("n"),
    };
    assert_eq!(nonce.error(), "use_dpop_nonce");
    assert_eq!(nonce.status(Role::AuthorizationServer), 400);
    assert_eq!(nonce.status(Role::ResourceServer), 401);
    assert_eq!(nonce.nonce(), Some("n"));
    assert_eq!(
        nonce.challenge(Role::ResourceServer, &profile).as_deref(),
        Some(r#"DPoP error="use_dpop_nonce", algs="Ed25519 ES256""#)
    );
    assert_eq!(nonce.challenge(Role::AuthorizationServer, &profile), None);
    let invalid = Failure::InvalidProof {
        step: Step::Jti,
        code: "dpop-replay",
    };
    assert_eq!(invalid.error(), "invalid_dpop_proof");
    assert_eq!(invalid.status(Role::ResourceServer), 401);
    assert_eq!(invalid.nonce(), None);
    assert_eq!(Failure::Unavailable.status(Role::ResourceServer), 503);
    assert_eq!(
        Failure::Unavailable.challenge(Role::ResourceServer, &profile),
        None
    );
}

// TN-31, RFC 9449 §10: dpop_jkt binds the code to the key
#[test]
fn dpop_jkt_binds_the_authorization_code() {
    assert_eq!(authorization_request_jkt(None), Ok(None));
    assert_eq!(authorization_request_jkt(Some(&A.text())), Ok(Some(A)));
    for bad in ["", "AAAA", "not base64", &format!("{}=", A.text())] {
        assert_eq!(
            authorization_request_jkt(Some(bad)),
            Err(BindingError::Malformed),
            "{bad}"
        );
    }
    assert_eq!(BindingError::Malformed.error(), "invalid_request");
    assert_eq!(check_code_exchange(None, None), Ok(()));
    assert_eq!(check_code_exchange(None, Some(A)), Ok(()));
    assert_eq!(check_code_exchange(Some(A), Some(A)), Ok(()));
    assert_eq!(
        check_code_exchange(Some(A), None),
        Err(BindingError::ProofRequired)
    );
    assert_eq!(
        check_code_exchange(Some(A), Some(B)),
        Err(BindingError::KeyMismatch)
    );
}

// TN-31, §10.4.3 m.4: a public client's refresh token is bound to its DPoP key; a confidential
// client's is not
#[test]
fn public_client_refresh_tokens_are_key_bound() {
    assert_eq!(refresh_binding(ClientType::Public, Some(A)), Ok(Some(A)));
    assert_eq!(
        refresh_binding(ClientType::Public, None),
        Err(BindingError::ProofRequired)
    );
    assert_eq!(refresh_binding(ClientType::Confidential, Some(A)), Ok(None));
    assert_eq!(refresh_binding(ClientType::Confidential, None), Ok(None));
    assert_eq!(check_refresh(Some(A), Some(A)), Ok(()));
    assert_eq!(
        check_refresh(Some(A), Some(B)),
        Err(BindingError::KeyMismatch)
    );
    assert_eq!(
        check_refresh(Some(A), None),
        Err(BindingError::ProofRequired)
    );
    assert_eq!(check_refresh(None, None), Ok(()));
}

// TN-27, PI-11: an identity plane access token is DPoP- or mTLS-bound, never bearer
#[test]
fn access_tokens_are_never_bearer() {
    assert_eq!(
        access_token_confirmation(Some(A), Some([9; 32])),
        Ok(Confirmation::Jkt(A.0))
    );
    assert_eq!(
        access_token_confirmation(None, Some([9; 32])),
        Ok(Confirmation::X5tS256([9; 32]))
    );
    assert_eq!(
        access_token_confirmation(None, None),
        Err(BindingError::ProofRequired)
    );
}
