use super::*;

const LIGHT: Argon2Params = Argon2Params {
    m_kib: 64,
    t: 1,
    p: 1,
};

// IDP-3, OP-146
#[test]
fn policy_counts_characters_after_nfkc() {
    assert_eq!(
        Password::new("short").err(),
        Some(PasswordRejected::TooShort { min: 8 })
    );
    assert!(Password::new("ﬁﬁﬁ").is_err());
    assert!(Password::new("ﬁﬁﬁﬁ").is_ok());
    assert!(Password::new(&"é".repeat(MAX_CHARS)).is_ok());
    assert_eq!(
        Password::new(&"a".repeat(MAX_CHARS + 1)).err(),
        Some(PasswordRejected::TooLong { max: MAX_CHARS })
    );
    assert!(Password::new("password").is_ok());
    assert!(Password::presented(&"a".repeat(MAX_LOGIN_BYTES + 1)).is_none());
    assert!(Password::presented("x").is_some());
}

// OP-146 m.5 (j)
#[test]
fn compatibility_forms_hash_alike() {
    let a = Password::new("Ｐａｓｓｗｏｒｄ１").unwrap();
    let b = Password::new("Password1").unwrap();
    let salt = [7; 16];
    let ha = hash(&LIGHT, &a, &salt).unwrap();
    assert!(verify(&b, &ha, &LIGHT).unwrap().matched);
}

// CR-36, CR-37, U69
#[test]
fn phc_round_trip_and_rehash() {
    let pw = Password::new("correct horse").unwrap();
    let h = hash(&LIGHT, &pw, &[1; 16]).unwrap();
    assert!(h.expose().starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
    assert_eq!(stored_params(h.expose()).unwrap(), Some(LIGHT));
    let v = verify(&pw, &h, &Argon2Params::CANONICAL).unwrap();
    assert_eq!(
        v,
        Verification {
            matched: true,
            rehash: true
        }
    );
    let v = verify(&Password::new("wrong horse").unwrap(), &h, &LIGHT).unwrap();
    assert_eq!(
        v,
        Verification {
            matched: false,
            rehash: false
        }
    );
    assert_eq!(
        verify(&pw, &Secret::new("$2b$10$abc".to_owned()), &LIGHT),
        Err(HashFailure::Malformed)
    );
}

// CR-36, OP-33
#[test]
fn realms_only_raise() {
    assert_eq!(
        Argon2Params::CANONICAL,
        Argon2Params {
            m_kib: 7168,
            t: 5,
            p: 1
        }
    );
    assert!(Argon2Params::for_realm(7168, 4, 1).is_err());
    assert!(Argon2Params::for_realm(4096, 5, 1).is_err());
    assert!(Argon2Params::for_realm(19 * 1024, 5, 1).is_ok());
}

// CR-36, OP-146
#[test]
fn semaphore_size() {
    let c = Argon2Params::CANONICAL;
    assert_eq!(permits(8, None, &c), 8);
    assert_eq!(permits(8, Some(70 * 1024 * 1024), &c), 5);
    assert_eq!(permits(2, Some(1 << 40), &c), 2);
    assert_eq!(permits(8, Some(1024), &c), 1);
    assert_eq!(permits(0, None, &c), 1);
}

fn salt() -> [u8; 16] {
    access_crypto::random::bytes::<16>().unwrap()
}

// CR-15, CR-36, IDP-3, OP-158
#[test]
fn a_fips_realm_hashes_with_pbkdf2_not_argon2() {
    let pw = Password::new("correct horse battery").unwrap();
    let fips = HashPolicy::of(HashProfile::Standard, true);
    let phc = hash_with(&fips, &pw, &salt()).unwrap();
    assert!(
        phc.expose().starts_with("$pbkdf2-sha256$i=600000$"),
        "{}",
        phc.expose()
    );
    assert!(!access_crypto::legacy_hash::is_argon2(phc.expose()));
    let v = verify_with(&pw, &phc, &fips).unwrap();
    assert!(v.matched && !v.rehash);
    let wrong = Password::new("correct horse battery!").unwrap();
    assert!(!verify_with(&wrong, &phc, &fips).unwrap().matched);
    let argon = HashPolicy::Argon2(LIGHT);
    let back = verify_with(&pw, &phc, &argon).unwrap();
    assert!(back.matched && back.rehash);
    let weak = HashPolicy::Pbkdf2 { iterations: 1_000 };
    let fewer = hash_with(&weak, &pw, &salt()).unwrap();
    let v = verify_with(&pw, &fewer, &fips).unwrap();
    assert!(v.matched && v.rehash);
}

// CR-15, CR-37
#[test]
fn an_argon2_hash_moves_to_pbkdf2_when_fips_is_turned_on() {
    let pw = Password::new("correct horse battery").unwrap();
    let phc = hash(&LIGHT, &pw, &salt()).unwrap();
    let v = verify_with(&pw, &phc, &HashPolicy::of(HashProfile::Standard, true)).unwrap();
    assert!(v.matched && v.rehash);
    assert!(
        verify_with(
            &pw,
            &Secret::new("$2b$10$x".into()),
            &HashPolicy::Argon2(LIGHT)
        )
        .is_err()
    );
}

// OP-33, OP-158, §10.2.1
#[test]
fn the_argon2_profile_may_only_be_raised() {
    assert_eq!(
        HashProfile::Standard.raise_to(HashProfile::HighMemory),
        Ok(HashProfile::HighMemory)
    );
    assert_eq!(
        HashProfile::HighMemory.raise_to(HashProfile::HighMemory),
        Ok(HashProfile::HighMemory)
    );
    assert_eq!(
        HashProfile::HighMemory.raise_to(HashProfile::Standard),
        Err(ProfileDowngrade)
    );
    assert_eq!(ProfileDowngrade.code(), "hash-profile-downgrade");
    let high = HashProfile::HighMemory.argon2();
    assert_eq!((high.m_kib, high.t, high.p), (2 * 1024 * 1024, 1, 4));
    assert!(HashProfile::Standard.argon2().weaker_than(&high) || high.t < 5);
    for p in [HashProfile::Standard, HashProfile::HighMemory] {
        assert_eq!(HashProfile::parse(p.name()), Some(p));
    }
    assert_eq!(HashProfile::parse("low"), None);
}
