use super::*;

// CR-19, CR-25, CR-26
#[test]
fn the_realm_policy_is_coherent() {
    assert_eq!(check(&Policy::REALM), Ok(()));
    assert_eq!(check(&Policy::AUTHORITY), Err(PolicyError::Lifetime));
}

// CR-25, CR-26, CR-27
#[test]
fn broken_policies_are_refused() {
    let p = Policy::REALM;
    let short_retain = Policy {
        retain_ms: TOKEN_MAX_MS - 1,
        ..p
    };
    assert_eq!(check(&short_retain), Err(PolicyError::Retention));
    let short_lead = Policy {
        publish_lead_ms: JWKS_CACHE_MS - 1,
        ..p
    };
    assert_eq!(check(&short_lead), Err(PolicyError::Lead));
    let short_window = Policy {
        window_ms: p.lifetime_ms + p.lifetime_ms / 5 + p.publish_lead_ms,
        ..p
    };
    assert_eq!(check(&short_window), Err(PolicyError::Window));
    let huge = Policy {
        lifetime_ms: u64::MAX,
        ..p
    };
    assert_eq!(check(&huge), Err(PolicyError::Window));
}

// CR-25
#[test]
fn the_cache_header_matches_the_cache_time() {
    assert!(CACHE_CONTROL.contains("max-age=300"));
    assert!(CACHE_CONTROL.contains("stale-while-revalidate=600"));
    assert_eq!(JWKS_CACHE_MS, (300 + 600) * 1000);
}

// MD-3, CR-41 m.3, OP-159 m.3 (o)
#[test]
fn akp_keys_are_published_only_at_their_exact_length() {
    let alg = suiss_crypto::cose::Algorithm::MlDsa65;
    let short = PublicKey::MlDsa(alg, vec![0; 1951]);
    assert_eq!(jwks([(&[0; 32], &short)]), Err(JoseError::Key));
    let (signer, _) = suiss_crypto::signer::MlDsaSigner::generate(alg).unwrap();
    let key = suiss_crypto::signer::Signer::public_key(&signer);
    assert!(
        jwks([(&[1; 32], &key)])
            .unwrap()
            .contains(r#""kty":"AKP","alg":"ML-DSA-65""#)
    );
    assert_eq!(jwks([]).as_deref(), Ok(r#"{"keys":[]}"#));
}
