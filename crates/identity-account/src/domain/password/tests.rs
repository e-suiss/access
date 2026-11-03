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

// CR-36, CR-37
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
