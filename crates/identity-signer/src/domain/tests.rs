use super::*;

// CR-19, CR-25, CR-26: the realm defaults pass; the authority's hour-long keys do not
#[test]
fn the_realm_policy_is_coherent() {
    assert_eq!(check(&Policy::REALM), Ok(()));
    assert_eq!(check(&Policy::AUTHORITY), Err(PolicyError::Lifetime));
}

// CR-25, CR-26, CR-27: each rule refuses a policy that breaks it
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

// CR-25: the header the JWKS is served with declares the cache time the lead accounts for
#[test]
fn the_cache_header_matches_the_cache_time() {
    assert!(CACHE_CONTROL.contains("max-age=300"));
    assert!(CACHE_CONTROL.contains("stale-while-revalidate=600"));
    assert_eq!(JWKS_CACHE_MS, (300 + 600) * 1000);
}

// MD-3: an AKP key makes the document fail rather than be published
#[test]
fn akp_keys_are_refused() {
    let key = PublicKey::MlDsa(suiss_crypto::cose::Algorithm::MlDsa65, vec![0; 1952]);
    assert_eq!(jwks([(&[0; 32], &key)]), Err(JoseError::Key));
    assert_eq!(jwks([]).as_deref(), Ok(r#"{"keys":[]}"#));
}
