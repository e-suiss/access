//! OP-155 m.3 (n), §10.6.3, IDP-16, IDI-11, OP-153 m.3 (gg): the LDAP gateway against
//! access-server's real edge router over mutual TLS 1.3, on a real PostgreSQL. An LDAP client
//! speaks to the gateway's real listeners with the same codec. Keys, certificates and app
//! passwords are made at run time.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::expect_used,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::assert_is_empty,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use access_identity_account::ports::AccountTx as _;
use access_identity_x509::testing::{Ca, LeafSpec, OcspAnswer, Status};
use access_store::identity::TenantTx;
use bytes::BytesMut;
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindCred, LdapBindRequest, LdapExtendedRequest, LdapFilter,
    LdapMatchingRuleAssertion, LdapModifyDNRequest, LdapOp, LdapPasswordModifyRequest,
    LdapResultCode, LdapSearchScope, OID_WHOAMI, SaslCredentials,
};
use rustls::pki_types::ServerName;
use support::{ADMIN, Client, OCSP, code, eq, ldaps, now_s, paged, tls_config, values, world};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

// §10.6.3, IDP-16, OP-155 m.3 (n)
#[tokio::test]
async fn an_app_password_binds_and_reads_the_directory_tree() {
    let w = world(81).await;
    let ada = w.person("ada").await;
    let bob = w.person("bob").await;
    w.group("staff", &[ada]).await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let (_, who) = c
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from(OID_WHOAMI),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    let LdapOp::ExtendedResponse(x) = &who.op else {
        panic!("{who:?}")
    };
    assert_eq!(
        x.value.as_deref(),
        Some(b"dn:uid=ada,ou=people,o=corp".as_slice())
    );
    let (people, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::Subtree,
            eq("objectClass", "posixAccount"),
            &["uid", "uidNumber", "memberOf", "mail"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    assert_eq!(people.len(), 2);
    let a = people
        .iter()
        .find(|e| e.dn == "uid=ada,ou=people,o=corp")
        .unwrap();
    assert_eq!(values(a, "mail"), vec![String::from("ada@corp.example")]);
    assert_eq!(
        values(a, "memberOf"),
        vec![String::from("cn=staff,ou=groups,o=corp")]
    );
    let n: u32 = values(a, "uidNumber")[0].parse().unwrap();
    assert!(n >= 65_536);
    let (groups, _) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            LdapFilter::And(vec![
                eq("objectClass", "groupOfNames"),
                eq("objectClass", "posixGroup"),
            ]),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        values(&groups[0], "member"),
        vec![String::from("uid=ada,ou=people,o=corp")]
    );
    let chain = LdapFilter::Extensible(LdapMatchingRuleAssertion {
        matching_rule: Some(String::from("1.2.840.113556.1.4.1941")),
        type_: Some(String::from("memberOf")),
        match_value: String::from("CN=Staff,OU=Groups,O=Corp"),
        dn_attributes: false,
    });
    let (hits, _) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            chain,
            &["uid"],
            Vec::new(),
        )
        .await;
    assert_eq!(hits.len(), 1);
    assert_eq!(values(&hits[0], "uid"), vec![String::from("ada")]);
    let (schema, done) = c
        .search(
            "cn=Subschema",
            LdapSearchScope::Base,
            LdapFilter::Present(String::from("objectClass")),
            &["attributeTypes", "objectClasses"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    let types = values(&schema[0], "attributeTypes");
    assert!(types.iter().any(|t| t.contains("NAME 'memberOf'")));
    assert!(types.iter().any(|t| t.contains("NAME 'uidNumber'")));
    let classes = values(&schema[0], "objectClasses");
    assert!(classes.iter().any(|t| t.contains("NAME 'posixGroup'")));
    // IDP-16
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("uid=ada,ou=people,o=corp", &token).await,
        LdapResultCode::Success
    );
    assert_eq!(
        d.bind("uid=bob,ou=people,o=corp", &token).await,
        LdapResultCode::InvalidCredentials
    );
    let _ = bob;
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("login.ldap.succeeded")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("login.ldap.failed")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("credential.ldap.issued")),
        "{audit:?}"
    );
    assert!(
        outbox.iter().any(|k| k.ends_with("authentication")),
        "{outbox:?}"
    );
    assert!(
        outbox
            .iter()
            .any(|k| k == "relay.message.ldap_credential_changed.v1"),
        "{outbox:?}"
    );
}

// IDP-16, §10.6.3
#[tokio::test]
async fn a_primary_password_never_binds() {
    let w = world(82).await;
    let ada = w.person("ada").await;
    let primary = String::from("correct horse battery staple 1");
    {
        let mut tx = w.tx().await;
        let phc = w
            .hasher
            .hash(
                &access_identity_account::domain::password::Password::new(&primary).unwrap(),
                [3; 16],
            )
            .await
            .unwrap();
        access_identity_account::app::accounts::store_password(
            &mut tx,
            &w.realm(),
            ada,
            phc.expose(),
            &ADMIN,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let mut c = ldaps(&w, None).await;
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", &primary).await,
        LdapResultCode::InvalidCredentials
    );
    assert_eq!(
        c.bind("dn=token", &primary).await,
        LdapResultCode::InvalidCredentials
    );
    let (_, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &[],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
}

// §10.6.3, Ek B 4975, 5049
#[tokio::test]
async fn anonymous_reads_only_the_root_dse() {
    let w = world(83).await;
    w.person("ada").await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("", "").await, LdapResultCode::Success);
    let (dse, done) = c
        .search(
            "",
            LdapSearchScope::Base,
            LdapFilter::Present(String::from("objectClass")),
            &["+"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::Success);
    assert_eq!(
        values(&dse[0], "namingContexts"),
        vec![String::from("o=corp")]
    );
    assert_eq!(
        values(&dse[0], "supportedSASLMechanisms"),
        vec![String::from("EXTERNAL")]
    );
    assert!(values(&dse[0], "supportedControl").contains(&String::from("1.2.840.113556.1.4.319")));
    let (none, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &[],
            Vec::new(),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    let (_, done) = c
        .search(
            "cn=Subschema",
            LdapSearchScope::Base,
            LdapFilter::Present(String::from("objectClass")),
            &["+"],
            Vec::new(),
        )
        .await;
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    assert_eq!(
        c.bind("uid=ada,ou=people,o=corp", "").await,
        LdapResultCode::UnwillingToPerform
    );
    for mechanism in ["DIGEST-MD5", "SCRAM-SHA-256", "PLAIN", "GSSAPI"] {
        let (_, m) = c
            .call(
                LdapOp::BindRequest(LdapBindRequest {
                    dn: String::new(),
                    cred: LdapBindCred::SASL(SaslCredentials {
                        mechanism: String::from(mechanism),
                        credentials: Vec::new(),
                    }),
                }),
                Vec::new(),
            )
            .await;
        assert_eq!(
            code(&m),
            LdapResultCode::AuthMethodNotSupported,
            "{mechanism}"
        );
    }
    let (_, m) = c
        .call(
            LdapOp::BindRequest(LdapBindRequest {
                dn: String::new(),
                cred: LdapBindCred::SASL(SaslCredentials {
                    mechanism: String::from("EXTERNAL"),
                    credentials: Vec::new(),
                }),
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::InappropriateAuthentication);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.bind.refused")),
        "{audit:?}"
    );
}

// IDP-16, Ek B 5048
#[tokio::test]
async fn writes_answer_unwilling_to_perform() {
    let w = world(84).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let (_, m) = c
        .call(
            LdapOp::AddRequest(LdapAddRequest {
                dn: String::from("uid=eve,ou=people,o=corp"),
                attributes: Vec::new(),
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (_, m) = c
        .call(
            LdapOp::DelRequest(String::from("uid=ada,ou=people,o=corp")),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (_, m) = c
        .call(
            LdapOp::ModifyDNRequest(LdapModifyDNRequest {
                dn: String::from("uid=ada,ou=people,o=corp"),
                newrdn: String::from("uid=eve"),
                deleteoldrdn: true,
                new_superior: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.write.refused")),
        "{audit:?}"
    );
}

// IDP-16, Ek B 4797
#[tokio::test]
async fn a_plain_bind_without_tls_needs_confidentiality() {
    let w = world(85).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let tcp = TcpStream::connect(w.starttls).await.unwrap();
    let mut c = Client {
        s: tcp,
        buf: BytesMut::new(),
        id: 0,
    };
    assert_eq!(
        c.bind("dn=token", &token).await,
        LdapResultCode::ConfidentialityRequired
    );
    let (_, m) = c
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from("1.3.6.1.4.1.1466.20037"),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let tls = tokio_rustls::TlsConnector::from(tls_config(&w, None))
        .connect(ServerName::try_from("localhost").unwrap(), c.s)
        .await
        .unwrap();
    let mut t = Client {
        s: tls,
        buf: BytesMut::new(),
        id: c.id,
    };
    assert_eq!(t.bind("dn=token", &token).await, LdapResultCode::Success);
    let mut s = ldaps(&w, None).await;
    let (_, m) = s
        .call(
            LdapOp::ExtendedRequest(LdapExtendedRequest {
                name: String::from("1.3.6.1.4.1.1466.20037"),
                value: None,
            }),
            Vec::new(),
        )
        .await;
    assert_eq!(code(&m), LdapResultCode::OperationsError);
}

// §10.6.3, OP-155 m.3 (n)
#[tokio::test]
async fn paged_results_refuse_a_tampered_cookie() {
    let w = world(86).await;
    let ada = w.person("ada").await;
    for u in ["bob", "cem", "dia", "eli"] {
        w.person(u).await;
    }
    let (_, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let page = |cookie: Vec<u8>| vec![LdapControl::SimplePagedResults { size: 2, cookie }];
    let filter = || eq("objectClass", "person");
    let (first, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(Vec::new()),
        )
        .await;
    assert_eq!(first.len(), 2);
    let cookie = paged(&done).unwrap();
    assert!(!cookie.is_empty() && cookie.len() <= 256);
    let (second, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(cookie.clone()),
        )
        .await;
    assert_eq!(second.len(), 2);
    assert_ne!(first[0].dn, second[0].dn);
    let (third, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(paged(&done).unwrap()),
        )
        .await;
    assert_eq!(third.len(), 1);
    assert_eq!(paged(&done), Some(Vec::new()));
    let mut forged = cookie.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (none, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            filter(),
            &["uid"],
            page(forged),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::UnwillingToPerform);
    let (none, done) = c
        .search(
            "ou=people,o=corp",
            LdapSearchScope::OneLevel,
            eq("uid", "bob"),
            &["uid"],
            page(cookie),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::UnwillingToPerform);
}

// GHSA-qcxq-75wr-5cm8, OP-125, Ek B 5102
#[tokio::test]
async fn hostile_ber_is_refused_before_decoding() {
    let w = world(87).await;
    let mut inner = vec![0x04, 0x00];
    for _ in 0..5000 {
        let mut next = vec![0x30, 0x83];
        next.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_be_bytes()[1..]);
        next.extend_from_slice(&inner);
        inner = next;
    }
    let mut c = ldaps(&w, None).await;
    c.s.write_all(&inner).await.unwrap();
    assert!(c.recv().await.is_none());
    let mut d = ldaps(&w, None).await;
    d.s.write_all(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    assert!(d.recv().await.is_none());
    let mut e = ldaps(&w, None).await;
    assert_eq!(e.bind("", "").await, LdapResultCode::Success);
    let (audit, _) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.ldap.ber.refused")),
        "{audit:?}"
    );
}

// §10.6.3, Ek B 4799
#[tokio::test]
async fn password_modify_replaces_only_the_ldap_credential() {
    let w = world(88).await;
    let ada = w.person("ada").await;
    let (_, token) = w.app_password(ada).await;
    let (_, other) = w.app_password(ada).await;
    let before = w.epoch(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    let modify = |old: Option<&str>, new: Option<&str>| {
        LdapOp::ExtendedRequest(
            LdapPasswordModifyRequest {
                user_identity: None,
                old_password: old.map(String::from),
                new_password: new.map(String::from),
            }
            .into(),
        )
    };
    let (_, m) = c
        .call(modify(Some(&token), Some("chosen")), Vec::new())
        .await;
    assert_eq!(code(&m), LdapResultCode::UnwillingToPerform);
    let guess = format!("{}x", &token[..token.len() - 1]);
    let (_, m) = c.call(modify(Some(&guess), None), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::InvalidCredentials);
    let (_, m) = c.call(modify(Some(&token), None), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let LdapOp::ExtendedResponse(x) = &m.op else {
        panic!("{m:?}")
    };
    let fresh = ldap3_proto::proto::LdapPasswordModifyResponse::try_from(x)
        .unwrap()
        .gen_password
        .unwrap();
    assert_ne!(fresh, token);
    assert!(w.epoch(ada).await > before);
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("dn=token", &token).await,
        LdapResultCode::InvalidCredentials
    );
    assert_eq!(d.bind("dn=token", &fresh).await, LdapResultCode::Success);
    assert_eq!(d.bind("dn=token", &other).await, LdapResultCode::Success);
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("credential.ldap.rotated")),
        "{audit:?}"
    );
    assert!(
        outbox
            .iter()
            .filter(|k| k.ends_with("authenticator_binding"))
            .count()
            >= 3,
        "{outbox:?}"
    );
}

// §10.6.3, Ek B 4798
#[tokio::test]
async fn sasl_external_binds_with_an_accepted_certificate() {
    let w = world(89).await;
    w.person("ada").await;
    let now = now_s();
    let root = Ca::root_at("Corp Root", now);
    let leaf = root.leaf(&LeafSpec {
        cn: "Ada",
        email: Some("ada@corp.example"),
        ocsp: Some(OCSP),
        ..LeafSpec::default()
    });
    {
        let mut tx = TenantTx::begin(&w.db.app, w.tenant, w.corp).await.unwrap();
        let b = w.bound(&mut tx, "idp.realm.certificate_login").await;
        tx.put_certificate_login(
            &b,
            &access_store::certificate::CertificateLoginRow {
                enabled: true,
                rule: String::from("san_email"),
                anchors: vec![root.der.clone()],
                piv_policies: Vec::new(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let external = || {
        LdapOp::BindRequest(LdapBindRequest {
            dn: String::new(),
            cred: LdapBindCred::SASL(SaslCredentials {
                mechanism: String::from("EXTERNAL"),
                credentials: Vec::new(),
            }),
        })
    };
    let mut c = ldaps(&w, Some(&leaf)).await;
    let (_, m) = c.call(external(), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::InvalidCredentials);
    w.responders.0.lock().unwrap().insert(
        String::from(OCSP),
        root.ocsp(&leaf.der, &OcspAnswer::current_at(Status::Good, now), None),
    );
    let mut d = ldaps(&w, Some(&leaf)).await;
    let (_, m) = d.call(external(), Vec::new()).await;
    assert_eq!(code(&m), LdapResultCode::Success);
    let (hits, _) = d
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &["uid"],
            Vec::new(),
        )
        .await;
    assert_eq!(hits.len(), 1);
}

// §10.6.3
#[tokio::test]
async fn a_revoked_app_password_reads_nothing() {
    let w = world(90).await;
    let ada = w.person("ada").await;
    let (id, token) = w.app_password(ada).await;
    let mut c = ldaps(&w, None).await;
    assert_eq!(c.bind("dn=token", &token).await, LdapResultCode::Success);
    w.revoke(ada, id).await;
    let (none, done) = c
        .search(
            "o=corp",
            LdapSearchScope::Subtree,
            eq("uid", "ada"),
            &["uid"],
            Vec::new(),
        )
        .await;
    assert!(none.is_empty());
    assert_eq!(code(&done), LdapResultCode::InsufficentAccessRights);
    let mut d = ldaps(&w, None).await;
    assert_eq!(
        d.bind("dn=token", &token).await,
        LdapResultCode::InvalidCredentials
    );
}
