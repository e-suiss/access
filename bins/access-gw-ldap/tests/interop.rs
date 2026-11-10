//! OP-155 m.3 (n), (q), Ek B 4664: the `OpenLDAP` command-line clients (`ldapsearch`,
//! `ldapwhoami`, `ldappasswd`) against the gateway's real LDAPS listener and access-server's real
//! edge router on a real PostgreSQL. CI's `edge-interop` job installs the clients and runs these
//! with `--ignored`; they need no container.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::process::{Command, Output};

use support::{World, world};

fn ca_file(w: &World) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("access-gw-ldap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("ca-{}.pem", w.ldaps.port()));
    std::fs::write(&path, w.ca_pem.as_bytes()).unwrap();
    path
}

async fn run(w: &World, program: &'static str, args: Vec<String>) -> Output {
    let ca = ca_file(w);
    tokio::task::spawn_blocking(move || {
        Command::new(program)
            .args(args)
            .env("LDAPTLS_CACERT", ca)
            .env("LDAPTLS_REQCERT", "demand")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn uri(w: &World) -> String {
    format!("ldaps://127.0.0.1:{}", w.ldaps.port())
}

fn s(v: &str) -> String {
    String::from(v)
}

// §10.6.3, IDP-16, OP-155 m.3 (n)
#[tokio::test]
#[ignore = "needs the OpenLDAP clients; CI job edge-interop"]
async fn openldap_clients_bind_page_and_change_the_app_password() {
    let w = world(101).await;
    let ada = w.person("ada").await;
    for u in ["bob", "cem", "dia"] {
        w.person(u).await;
    }
    let (_, token) = w.app_password(ada).await;
    let who = run(
        &w,
        "ldapwhoami",
        vec![
            s("-x"),
            s("-H"),
            uri(&w),
            s("-D"),
            s("dn=token"),
            s("-w"),
            token.clone(),
        ],
    )
    .await;
    assert!(who.status.success(), "{who:?}");
    assert_eq!(
        String::from_utf8_lossy(&who.stdout).trim(),
        "dn:uid=ada,ou=people,o=corp"
    );
    let search = run(
        &w,
        "ldapsearch",
        vec![
            s("-x"),
            s("-LLL"),
            s("-H"),
            uri(&w),
            s("-D"),
            s("uid=ada,ou=people,o=corp"),
            s("-w"),
            token.clone(),
            s("-b"),
            s("ou=people,o=corp"),
            s("-E"),
            s("pr=2/noprompt"),
            s("(objectClass=posixAccount)"),
            s("uid"),
            s("memberOf"),
        ],
    )
    .await;
    assert!(search.status.success(), "{search:?}");
    let text = String::from_utf8_lossy(&search.stdout);
    assert_eq!(text.matches("dn: uid=").count(), 4, "{text}");
    let anonymous = run(
        &w,
        "ldapsearch",
        vec![
            s("-x"),
            s("-LLL"),
            s("-H"),
            uri(&w),
            s("-b"),
            s("o=corp"),
            s("(uid=ada)"),
        ],
    )
    .await;
    assert_eq!(anonymous.status.code(), Some(50), "{anonymous:?}");
    let dse = run(
        &w,
        "ldapsearch",
        vec![
            s("-x"),
            s("-LLL"),
            s("-H"),
            uri(&w),
            s("-b"),
            s(""),
            s("-s"),
            s("base"),
            s("+"),
        ],
    )
    .await;
    assert!(String::from_utf8_lossy(&dse.stdout).contains("namingContexts: o=corp"));
    let digest = run(
        &w,
        "ldapwhoami",
        vec![
            s("-H"),
            uri(&w),
            s("-Y"),
            s("DIGEST-MD5"),
            s("-U"),
            s("ada"),
            s("-w"),
            s("x"),
        ],
    )
    .await;
    assert!(!digest.status.success(), "{digest:?}");
    let passwd = run(
        &w,
        "ldappasswd",
        vec![
            s("-x"),
            s("-H"),
            uri(&w),
            s("-D"),
            s("dn=token"),
            s("-w"),
            token.clone(),
            s("-a"),
            token.clone(),
        ],
    )
    .await;
    assert!(passwd.status.success(), "{passwd:?}");
    let fresh = String::from_utf8_lossy(&passwd.stdout)
        .trim()
        .strip_prefix("New password: ")
        .map(String::from)
        .unwrap();
    let old = run(
        &w,
        "ldapwhoami",
        vec![
            s("-x"),
            s("-H"),
            uri(&w),
            s("-D"),
            s("dn=token"),
            s("-w"),
            token,
        ],
    )
    .await;
    assert_eq!(old.status.code(), Some(49), "{old:?}");
    let new = run(
        &w,
        "ldapwhoami",
        vec![
            s("-x"),
            s("-H"),
            uri(&w),
            s("-D"),
            s("dn=token"),
            s("-w"),
            fresh,
        ],
    )
    .await;
    assert!(new.status.success(), "{new:?}");
}
