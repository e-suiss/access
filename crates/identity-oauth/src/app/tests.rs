#![allow(clippy::unused_async_trait_impl, reason = "fakes of async ports")]

use std::sync::Mutex;

use access_store::identity::{RealmId, TenantId};

use super::*;
use crate::domain::issuer::Issuer;

struct Rows {
    realms: Vec<RealmEntry>,
    hosts: Vec<(&'static str, usize)>,
    down: bool,
}

impl Directory for Rows {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        if self.down {
            return Err(Unavailable);
        }
        Ok(self
            .hosts
            .iter()
            .find(|(h, _)| *h == host)
            .and_then(|(_, i)| self.realms.get(*i).cloned()))
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<RealmEntry>, Unavailable> {
        if self.down {
            return Err(Unavailable);
        }
        Ok(self.realms.iter().find(|r| r.slug == slug).cloned())
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        if self.down {
            return Err(Unavailable);
        }
        Ok(self.realms.clone())
    }

    async fn facts(&self, realm: &RealmEntry) -> Result<crate::ports::Facts, Unavailable> {
        let n = realm.realm.as_bytes()[0];
        Ok(crate::ports::Facts {
            public_sub_clients: u64::from(n == 3),
            domain: Some([n; 32]),
        })
    }
}

#[derive(Default)]
struct FakeKeys {
    down: bool,
    empty: bool,
    asked: Mutex<Vec<[u8; 16]>>,
}

impl Keys for FakeKeys {
    async fn ping(&self) -> Result<(), Unavailable> {
        if self.down { Err(Unavailable) } else { Ok(()) }
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        if self.down {
            return Err(Unavailable);
        }
        self.asked.lock().unwrap().push(*realm.as_bytes());
        if self.empty {
            return Ok(String::from(EMPTY_JWKS));
        }
        Ok(format!(
            r#"{{"keys":[{{"kid":"{}"}}]}}"#,
            realm.as_bytes()[0]
        ))
    }
}

fn realm(n: u8, slug: &str, issuer: &str) -> RealmEntry {
    RealmEntry {
        tenant: TenantId::from_bytes([n; 16]),
        realm: RealmId::from_bytes([n; 16]),
        slug: slug.to_owned(),
        issuer: Issuer::parse(issuer).unwrap(),
    }
}

fn rows() -> Rows {
    Rows {
        realms: vec![
            realm(1, "acme", "https://acme.id.example"),
            realm(2, "beta", "https://id.example/realms/beta"),
            realm(3, "gamma", "https://gamma.id.example"),
        ],
        hosts: vec![
            ("acme.id.example", 0),
            ("gamma.id.example", 2),
            ("stale.id.example", 2),
        ],
        down: false,
    }
}

fn service() -> Discovery<Rows, FakeKeys> {
    Discovery::new(rows(), FakeKeys::default())
}

fn issuer_of(reply: &Reply) -> String {
    let Reply::Metadata(doc) = reply else {
        panic!("{reply:?}");
    };
    let v: serde_json::Value = serde_json::from_str(doc).unwrap();
    v["issuer"].as_str().unwrap().to_owned()
}

// TN-10, §17.9.6, OP-132 m.3
#[tokio::test]
async fn host_selects_the_realm_and_the_row_names_the_issuer() {
    let s = service();
    for authority in ["acme.id.example", "ACME.ID.EXAMPLE", "acme.id.example:443"] {
        let reply = s
            .serve(Document::OpenIdConfiguration, authority, None)
            .await;
        assert_eq!(issuer_of(&reply), "https://acme.id.example", "{authority}");
        let Reply::Metadata(doc) = reply else {
            panic!()
        };
        assert!(
            doc.contains(r#""issuer":"https://acme.id.example""#),
            "{doc}"
        );
    }
    let as_meta = s
        .serve(Document::AuthorizationServer, "acme.id.example", None)
        .await;
    assert_eq!(issuer_of(&as_meta), "https://acme.id.example");
}

// §17.9.6
#[tokio::test]
async fn unknown_or_mismatched_hosts_find_no_realm() {
    let s = service();
    for authority in [
        "nope.id.example",
        "stale.id.example",
        "acme.id.example:8443",
        "acme.id.example:x",
        "[::1]:443",
        "",
    ] {
        for doc in [
            Document::OpenIdConfiguration,
            Document::AuthorizationServer,
            Document::ProtectedResource,
            Document::Jwks,
        ] {
            assert_eq!(
                s.serve(doc, authority, None).await,
                Reply::NotFound,
                "{authority}"
            );
        }
    }
}

// TN-10
#[tokio::test]
async fn path_issuers_resolve_by_slug_on_their_origin() {
    let s = service();
    let r = s
        .serve(Document::OpenIdConfiguration, "id.example", Some("beta"))
        .await;
    assert_eq!(issuer_of(&r), "https://id.example/realms/beta");
    for (authority, slug) in [
        ("other.example", Some("beta")),
        ("acme.id.example", Some("acme")),
        ("id.example", Some("nope")),
        ("id.example", Some("BAD!")),
        ("id.example", None),
    ] {
        assert_eq!(
            s.serve(Document::Jwks, authority, slug).await,
            Reply::NotFound,
            "{authority} {slug:?}"
        );
    }
}

// CR-19, CMP-22b
#[tokio::test]
async fn jwks_is_the_realms_own_and_fails_closed() {
    let s = service();
    assert_eq!(
        s.serve(Document::Jwks, "gamma.id.example", None).await,
        Reply::Jwks(String::from(r#"{"keys":[{"kid":"3"}]}"#))
    );
    let down = Discovery::new(
        rows(),
        FakeKeys {
            down: true,
            ..FakeKeys::default()
        },
    );
    assert_eq!(
        down.serve(Document::Jwks, "gamma.id.example", None).await,
        Reply::Unavailable
    );
    let no_db = Discovery::new(
        Rows {
            down: true,
            ..rows()
        },
        FakeKeys::default(),
    );
    assert_eq!(
        no_db
            .serve(Document::OpenIdConfiguration, "acme.id.example", None)
            .await,
        Reply::Unavailable
    );
}

// OP-138, §17.9.7, CMP-22b
#[tokio::test]
async fn startup_checks_fail_fast() {
    let base = RealmBase::parse("https://id.example").unwrap();
    let s = service();
    assert_eq!(s.check(&base).await, Ok(3));
    assert_eq!(s.keys.asked.lock().unwrap().len(), 3);
    let other = RealmBase::parse("https://login.example").unwrap();
    assert_eq!(
        s.check(&other).await,
        Err(StartupError::Issuer(String::from("acme")))
    );
    let mut renamed = rows();
    renamed.realms[1] = realm(2, "beta", "https://id.example/realms/gamma");
    assert_eq!(
        Discovery::new(renamed, FakeKeys::default())
            .check(&base)
            .await,
        Err(StartupError::Issuer(String::from("beta")))
    );
    let down = Discovery::new(
        rows(),
        FakeKeys {
            down: true,
            ..FakeKeys::default()
        },
    );
    assert_eq!(down.check(&base).await, Err(StartupError::Signer));
    let empty = Discovery::new(
        rows(),
        FakeKeys {
            empty: true,
            ..FakeKeys::default()
        },
    );
    assert_eq!(
        empty.check(&base).await,
        Err(StartupError::Jwks(String::from("acme")))
    );
    let no_db = Discovery::new(
        Rows {
            down: true,
            ..rows()
        },
        FakeKeys::default(),
    );
    assert_eq!(no_db.check(&base).await, Err(StartupError::Directory));
}

fn metadata_of(reply: &Reply) -> serde_json::Value {
    let Reply::Metadata(doc) = reply else {
        panic!("{reply:?}");
    };
    serde_json::from_str(doc).unwrap()
}

// MD-10, IDP-24
#[tokio::test]
async fn public_sub_is_declared_only_where_a_client_opted_in() {
    let s = service();
    let acme = metadata_of(
        &s.serve(Document::OpenIdConfiguration, "acme.id.example", None)
            .await,
    );
    assert_eq!(
        acme["subject_types_supported"],
        serde_json::json!(["pairwise"])
    );
    let gamma = metadata_of(
        &s.serve(Document::OpenIdConfiguration, "gamma.id.example", None)
            .await,
    );
    assert_eq!(
        gamma["subject_types_supported"],
        serde_json::json!(["pairwise", "public"])
    );
}

// §9.15.1 k.2, MD-5, P60
#[tokio::test]
async fn as_metadata_refers_to_the_governing_domain_metadata() {
    let plain = metadata_of(
        &service()
            .serve(Document::AuthorizationServer, "acme.id.example", None)
            .await,
    );
    assert!(plain.get(metadata::DOMAIN_METADATA_MEMBER).is_none());
    let s = service().with_suiss(suiss::Settings {
        region: String::from("eu"),
        relay: String::from("https://relay.example"),
        management_api: String::from("https://manage.example"),
        api_base: String::from("https://api.example"),
        products: std::collections::BTreeMap::new(),
    });
    let doc = metadata_of(
        &s.serve(Document::AuthorizationServer, "acme.id.example", None)
            .await,
    );
    assert_eq!(
        doc[metadata::DOMAIN_METADATA_MEMBER],
        format!(
            "https://api.example/.well-known/access-domain-metadata/sha-256:{}",
            access_kernel::json::b64url_encode(&[1; 32])
        )
    );
}
