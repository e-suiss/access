//! AS-17, SA-T12, R-4, OP-159 m.3 (gg) red team regression: LDAP injection against the gateway
//! and access-server's real edge router over mutual TLS 1.3, on a real PostgreSQL. A bind DN or
//! a filter value carrying filter syntax is a literal, never a wildcard; a filter beyond the
//! channel's bounds is refused, never truncated; a credential attribute is never returned.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use ldap3_proto::proto::{LdapFilter, LdapResultCode, LdapSearchScope, LdapSubstringFilter};
use support::{code, eq, ldaps, values, world};

const PEOPLE: &str = "ou=people,o=corp";

// AS-17, IDP-16
#[tokio::test]
async fn as_17_a_bind_dn_with_filter_syntax_is_a_literal_name() {
    let w = world(102).await;
    let ada = w.person("ada").await;
    let _bob = w.person("bob").await;
    let (_, token) = w.app_password(ada).await;
    for dn in [
        "uid=*,ou=people,o=corp",
        "uid=ada)(|(uid=*),ou=people,o=corp",
        "uid=ada*,ou=people,o=corp",
        "uid=*)(uid=*))(|(uid=*,ou=people,o=corp",
        "uid=bob,ou=people,o=corp",
    ] {
        let mut c = ldaps(&w, None).await;
        assert_eq!(
            c.bind(dn, &token).await,
            LdapResultCode::InvalidCredentials,
            "{dn}"
        );
    }
    let mut c = ldaps(&w, None).await;
    assert_ne!(
        c.bind("uid=ada\\00,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("login.ldap.failed")),
        "{audit:?}"
    );
}

// AS-17, IDP-16, §10.6.3
#[tokio::test]
async fn as_17_filter_values_with_filter_syntax_match_nothing_extra() {
    let w = world(103).await;
    let ada = w.person("ada").await;
    let _bob = w.person("bob").await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    for value in [
        "*",
        "ada)(uid=*",
        "*)(|(objectClass=*",
        "ada\0",
        "ada)(|(mail=*)",
    ] {
        let (hits, done) = c
            .search(
                PEOPLE,
                LdapSearchScope::Subtree,
                eq("uid", value),
                &["uid"],
                Vec::new(),
            )
            .await;
        assert!(hits.is_empty(), "{value:?} matched {hits:?}");
        if !value.contains('\0') {
            assert_eq!(code(&done), LdapResultCode::Success, "{value:?}");
        }
    }
    let (one, _) = c
        .search(
            PEOPLE,
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &["uid"],
            Vec::new(),
        )
        .await;
    assert_eq!(one.len(), 1);
    let sub = LdapFilter::Substring(
        String::from("uid"),
        LdapSubstringFilter {
            initial: Some(String::from("a)(uid=")),
            any: vec![],
            final_: None,
        },
    );
    let (hits, _) = c
        .search(PEOPLE, LdapSearchScope::Subtree, sub, &["uid"], Vec::new())
        .await;
    assert!(hits.is_empty(), "{hits:?}");
}

// AS-17, R-4, SAI-2
#[tokio::test]
async fn as_17_a_filter_past_the_channel_bounds_is_refused_not_truncated() {
    let w = world(104).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    let mut deep = eq("uid", "ada");
    for _ in 0..20 {
        deep = LdapFilter::And(vec![deep]);
    }
    let (hits, done) = c
        .search(PEOPLE, LdapSearchScope::Subtree, deep, &["uid"], Vec::new())
        .await;
    assert!(hits.is_empty());
    assert_ne!(code(&done), LdapResultCode::Success);
    let wide = LdapFilter::Or((0..300).map(|i| eq("uid", &format!("u{i}"))).collect());
    let (hits, done) = c
        .search(PEOPLE, LdapSearchScope::Subtree, wide, &["uid"], Vec::new())
        .await;
    assert!(hits.is_empty());
    assert_ne!(code(&done), LdapResultCode::Success);
}

// AS-17, IDP-16
#[tokio::test]
async fn as_17_credential_attributes_are_never_returned() {
    let w = world(105).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    let (hits, done) = c
        .search(
            PEOPLE,
            LdapSearchScope::Subtree,
            LdapFilter::Present(String::from("userPassword")),
            &["userPassword", "*", "+"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    for e in &hits {
        assert!(values(e, "userPassword").is_empty(), "{e:?}");
    }
    let (all, _) = c
        .search(
            PEOPLE,
            LdapSearchScope::Subtree,
            LdapFilter::Present(String::from("objectClass")),
            &["*", "+", "userPassword", "authPassword"],
            Vec::new(),
        )
        .await;
    assert!(!all.is_empty());
    for e in &all {
        assert!(values(e, "userPassword").is_empty(), "{e:?}");
        assert!(values(e, "authPassword").is_empty(), "{e:?}");
    }
}
