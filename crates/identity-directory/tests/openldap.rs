//! §10.6.4, IDP-17, OP-155 m.3 (n), Ek B 4664: the pull against an AD-shaped `OpenLDAP` that CI's
//! `edge-interop` job starts (`scripts/ci/edge-env.sh`); run with `--ignored` there.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::assert_is_empty,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_crypto::Secret;
use access_identity_directory::adapters::Source;
use access_identity_directory::domain::{Change, GroupIssuer, change, memberships, watermark};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by scripts/ci/edge-env.sh"))
}

fn source() -> Source {
    Source {
        addr: var("ACCESS_TEST_LDAP_ADDR"),
        server_name: var("ACCESS_TEST_LDAP_SERVER_NAME"),
        roots_pem: std::fs::read(var("ACCESS_TEST_LDAP_CA")).unwrap(),
        bind_dn: var("ACCESS_TEST_LDAP_BIND_DN"),
        password: Secret::new(var("ACCESS_TEST_LDAP_BIND_PASSWORD")),
        base: var("ACCESS_TEST_LDAP_BASE"),
    }
}

// §10.6.4, IDP-17, OP-155 m.3 (g), (n)
#[tokio::test]
#[ignore = "needs the AD-shaped OpenLDAP of CI job edge-interop"]
async fn an_incremental_pull_reads_people_and_groups_above_the_watermark() {
    let s = source();
    let all: Vec<Change> = s
        .changes(0)
        .await
        .unwrap()
        .iter()
        .filter_map(change)
        .collect();
    let people = all
        .iter()
        .filter(|c| matches!(c, Change::Person { .. }))
        .count();
    assert_eq!(people, 2, "{all:?}");
    assert_eq!(watermark(0, &all), 103);
    let later: Vec<Change> = s
        .changes(102)
        .await
        .unwrap()
        .iter()
        .filter_map(change)
        .collect();
    assert_eq!(later.len(), 1, "{later:?}");
    assert!(matches!(&later[0], Change::Group { name, .. } if name == "staff"));
    let mut realm = BTreeMap::new();
    realm.insert(
        String::from("staff"),
        GroupIssuer {
            issuer: String::from("upstream:corp-ad"),
            accepted: false,
        },
    );
    assert!(memberships("corp-ad", &all, &realm).is_empty());
    let mut wrong = source();
    wrong.password = Secret::new(String::from("not-the-password"));
    assert!(wrong.changes(0).await.is_err());
}
