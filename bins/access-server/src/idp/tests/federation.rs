//! The chain gate of chain-constrained issuers on the real ingest path (IDI-12, OP-155 m.3 (j)):
//! the realm issuer's Claims stop while its tracked chain does not hold and flow again once it
//! does, with no Acceptance written in between.

use std::collections::BTreeMap;

use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::{AuthFacts, Bind, authentication};
use access_internal_api::claims::ClaimVerdict;
use access_kernel::claim::body::AuthMethod;
use access_store::issuer::{issuer_instance, realm_issuer};
use access_store::oidf::{ChainState, set_issuer_state, track_issuer};

use super::claims::courier;
use super::*;

const ENTITY: &str = "https://issuer.federation.example";

fn verdict(i: &Issued) -> Option<&ClaimVerdict> {
    match i {
        Issued::Answered { verdict, .. } => Some(verdict),
        Issued::Unplaced(_) => None,
    }
}

fn refused_by_chain(i: &Issued) -> bool {
    matches!(verdict(i), Some(ClaimVerdict::Rejected { code }) if code == "claim-issuer-chain")
}

fn admitted(i: &Issued) -> bool {
    matches!(verdict(i), Some(ClaimVerdict::Admitted { .. }))
}

// IDI-12, IDP-20, OP-155 m.3 (j), §9.13.8 k.4
#[tokio::test]
async fn a_lost_chain_cuts_the_issuer_and_its_return_resumes_it() {
    let w = World::new().await;
    let (t, r, d) = w.realm("oidf-gate").await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let issuer = realm_issuer(&mut tx).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let key = w.keys.open_issuer(r, issuer).await.unwrap();
    let domain = DomainId::from_bytes(d.0);
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let instance = issuer_instance(&mut tx, &domain, &thumbprint(&key))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        w.admin().register_issuer(t, r).await.unwrap(),
        Some(instance)
    );
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let alice = tx
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx, &alice, &ALICE.0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    let c = courier(&w);
    let login = |at: u64| {
        authentication(AuthFacts {
            subject: alice,
            method: AuthMethod::Webauthn,
            auth_time: at,
            assurance: BTreeMap::from([(String::from("aal"), 1)]),
            webauthn: None,
            evidence: None,
            bind: Bind::None,
        })
    };
    assert!(admitted(&c.issue(t, r, &login(NOW - 9)).await.unwrap()));
    let realm = (*t.as_bytes(), *r.as_bytes());
    track_issuer(&w.db.app, &domain, realm, ENTITY, Some(issuer), NOW)
        .await
        .unwrap();
    let head = w.plane.domains.head(d).await.unwrap();
    assert!(
        refused_by_chain(&c.issue(t, r, &login(NOW - 8)).await.unwrap()),
        "a tracked issuer whose chain never resolved"
    );
    assert_eq!(
        w.plane.domains.head(d).await.unwrap(),
        head,
        "a cut Claim is not recorded"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW + 3_600_000,
    )
    .await
    .unwrap();
    assert!(admitted(&c.issue(t, r, &login(NOW - 7)).await.unwrap()));
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Unresolved,
        None,
        NOW,
        0,
    )
    .await
    .unwrap();
    let head = w.plane.domains.head(d).await.unwrap();
    assert!(refused_by_chain(
        &c.issue(t, r, &login(NOW - 6)).await.unwrap()
    ));
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Conflict,
        None,
        NOW,
        NOW + 1,
    )
    .await
    .unwrap();
    assert!(refused_by_chain(
        &c.issue(t, r, &login(NOW - 5)).await.unwrap()
    ));
    assert_eq!(
        w.plane.domains.head(d).await.unwrap(),
        head,
        "the cut writes nothing, the Acceptance least of all"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW,
    )
    .await
    .unwrap();
    assert!(
        refused_by_chain(&c.issue(t, r, &login(NOW - 4)).await.unwrap()),
        "an expired chain"
    );
    set_issuer_state(
        &w.db.app,
        &domain,
        ENTITY,
        ChainState::Resolved,
        Some("https://ta.example"),
        NOW,
        NOW + 3_600_000,
    )
    .await
    .unwrap();
    assert!(
        admitted(&c.issue(t, r, &login(NOW - 3)).await.unwrap()),
        "the chain is back: input resumes with the same Acceptance"
    );
}

mod admin {
    use access_identity_admin::domain::Invalid;
    use access_identity_admin::domain::federation::{FederationChange, Subordinate};

    use super::*;

    const TA: &str = "https://ta.federation.example";

    fn jwks() -> String {
        String::from(r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"AA","y":"AA"}]}"#)
    }

    async fn settings(
        w: &World,
        t: TenantId,
        r: RealmId,
    ) -> access_store::oidf::FederationSettingsRow {
        let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
        let s = tx.federation_settings().await.unwrap();
        tx.commit().await.unwrap();
        s
    }

    async fn anchors(w: &World, t: TenantId, r: RealmId) -> Vec<(String, bool)> {
        let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
        let a = tx.trust_anchors().await.unwrap();
        tx.commit().await.unwrap();
        a.into_iter().map(|a| (a.entity_id, a.live)).collect()
    }

    async fn apply(w: &World, at: (TenantId, RealmId), d: Digest, c: FederationChange, n: u8) {
        let hours = if c.action().reserved() { 48 } else { 1 };
        let p = proposal(at, Change::Federation(c), n, idp_anchor(d), hours);
        written(&exercise(w, &p, ROOT_KEY).await.unwrap());
    }

    async fn refused(
        w: &World,
        at: (TenantId, RealmId),
        d: Digest,
        c: FederationChange,
    ) -> Invalid {
        let p = proposal(at, Change::Federation(c), 99, idp_anchor(d), 1);
        match w.admin().prepare(&p).await {
            Err(AdminError::Invalid(i)) => i,
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("prepared"),
        }
    }

    // OP-155 m.3 (a), (j), IDP-19, §10.7.1 rule 7
    #[tokio::test]
    async fn federation_is_off_until_each_action_turns_it_on() {
        let w = World::new().await;
        let (t, r, d) = w.realm("oidf-admin").await;
        onboard(&w.plane, d, ROOT, ROOT_KEY).await;
        let s = settings(&w, t, r).await;
        assert!(!s.enabled && !s.ta_enabled && !s.registration_open);
        assert_eq!(
            refused(&w, (t, r), d, FederationChange::Registration(true)).await,
            Invalid::Federation
        );
        let hints = vec![String::from(TA)];
        apply(
            &w,
            (t, r),
            d,
            FederationChange::Enable {
                authority_hints: hints.clone(),
            },
            2,
        )
        .await;
        apply(&w, (t, r), d, FederationChange::Registration(true), 3).await;
        let sub = Subordinate {
            entity_id: String::from("https://rp.federation.example"),
            jwks: jwks(),
            metadata_policy: None,
        };
        apply(&w, (t, r), d, FederationChange::TaEnable(vec![sub]), 4).await;
        let s = settings(&w, t, r).await;
        assert!(s.enabled && s.ta_enabled && s.registration_open);
        assert_eq!(s.authority_hints, hints);
        let add = FederationChange::TrustAnchorAdd {
            entity_id: String::from(TA),
            jwks: jwks(),
        };
        assert!(add.action().reserved());
        apply(&w, (t, r), d, add, 5).await;
        assert_eq!(anchors(&w, t, r).await, vec![(String::from(TA), true)]);
        let remove = FederationChange::TrustAnchorRemove(String::from(TA));
        apply(&w, (t, r), d, remove.clone(), 6).await;
        assert_eq!(anchors(&w, t, r).await, vec![(String::from(TA), false)]);
        assert_eq!(refused(&w, (t, r), d, remove).await, Invalid::NoTrustAnchor);
        apply(&w, (t, r), d, FederationChange::Disable, 8).await;
        let s = settings(&w, t, r).await;
        assert!(!s.enabled && !s.ta_enabled && !s.registration_open);
    }

    /// The realm signer as the discovery routes reach it.
    struct Federated<'a>(&'a Opened);

    #[expect(clippy::unused_async_trait_impl, reason = "a fake of an async port")]
    impl access_identity_oauth::ports::Keys for Federated<'_> {
        async fn ping(&self) -> Result<(), access_identity_oauth::ports::Unavailable> {
            Ok(())
        }

        async fn jwks(
            &self,
            _: RealmId,
        ) -> Result<String, access_identity_oauth::ports::Unavailable> {
            Err(access_identity_oauth::ports::Unavailable)
        }

        async fn federation_jwks(
            &self,
            realm: RealmId,
        ) -> Result<String, access_identity_oauth::ports::Unavailable> {
            match self.0.ask(SignerRequest::FederationJwks(SignerRealm(
                *realm.as_bytes(),
            ))) {
                SignerResponse::Jwks(d) => Ok(d),
                _ => Err(access_identity_oauth::ports::Unavailable),
            }
        }

        async fn sign_federation(
            &self,
            realm: RealmId,
            typ: &str,
            payload: &[u8],
            at: u64,
        ) -> Result<String, access_identity_oauth::ports::Unavailable> {
            match self.0.ask(SignerRequest::SignFederation {
                realm: SignerRealm(*realm.as_bytes()),
                typ: String::from(typ),
                payload: payload.to_vec(),
                at,
            }) {
                SignerResponse::Signed { token, .. } => Ok(token),
                _ => Err(access_identity_oauth::ports::Unavailable),
            }
        }
    }

    async fn get(router: &axum::Router, host: &str, path: &str) -> (u16, String, String) {
        use tower::ServiceExt as _;
        let r = router
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .header(axum::http::header::HOST, host)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = r.status().as_u16();
        let ct = r
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (status, ct, String::from_utf8(body.to_vec()).unwrap())
    }

    // IDP-19, OP-155 m.3 (j), §10.7.1, MD-6, Ek B 4748, 5083
    #[tokio::test]
    async fn a_leaf_publishes_its_entity_configuration_with_its_federation_key() {
        use access_identity_oauth::adapters::PgDirectory;
        let w = World::new().await;
        let (t, r, d) = w.realm("oidf-leaf").await;
        onboard(&w.plane, d, ROOT, ROOT_KEY).await;
        let real_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let real_now = u64::try_from(real_now).unwrap();
        let keys: &'static Opened = Box::leak(Box::default());
        keys.at(real_now);
        let entry = access_store::tenancy::route_by_slug(&w.db.router, "oidf-leaf")
            .await
            .unwrap()
            .unwrap();
        let issuer = entry.issuer.clone();
        let rest = issuer.strip_prefix("https://").unwrap();
        let host = rest.split('/').next().unwrap().to_owned();
        let path = format!(
            "{}/.well-known/openid-federation",
            rest.strip_prefix(host.as_str()).unwrap()
        );
        let router = access_http::realm::router(access_identity_oauth::app::Discovery::new(
            PgDirectory::new(w.db.router.clone()).with_facts(w.db.app.clone()),
            Federated(keys),
        ));
        let (status, _, _) = get(&router, &host, &path).await;
        assert_eq!(status, 404, "a realm that is no leaf publishes nothing");
        apply(
            &w,
            (t, r),
            d,
            FederationChange::Enable {
                authority_hints: vec![String::from(TA)],
            },
            2,
        )
        .await;
        let (status, ct, jwt) = get(&router, &host, &path).await;
        assert_eq!(status, 200, "{jwt}");
        assert_eq!(ct, "application/entity-statement+jwt");
        let ec =
            access_identity_oidf::statement::verify_configuration(&jwt, &issuer, real_now).unwrap();
        assert_eq!(ec.authority_hints, vec![String::from(TA)]);
        assert!(ec.metadata_of("openid_provider").is_some());
        let entity = ec.metadata_of("federation_entity").unwrap();
        assert!(
            entity.get("federation_fetch_endpoint").is_none()
                && entity.get("federation_list_endpoint").is_none(),
            "a leaf serves no fetch or list"
        );
        let open = SignerRequest::Open {
            realm: SignerRealm(*r.as_bytes()),
            alg: access_crypto::jose::JwsAlg::Es256,
        };
        assert_eq!(keys.ask(open), SignerResponse::Opened);
        let SignerResponse::Jwks(jose) = keys.ask(SignerRequest::Jwks(SignerRealm(*r.as_bytes())))
        else {
            panic!("no realm keys");
        };
        let kid = ec.jwks.first().unwrap().kid.clone().unwrap();
        assert!(
            !jose.contains(&kid),
            "the token key never signs an entity statement"
        );
        apply(&w, (t, r), d, FederationChange::Registration(true), 3).await;
        let (_, _, jwt) = get(&router, &host, &path).await;
        let ec =
            access_identity_oidf::statement::verify_configuration(&jwt, &issuer, real_now).unwrap();
        let op = ec.metadata_of("openid_provider").unwrap();
        assert_eq!(
            op.get("client_registration_types_supported"),
            Some(&access_kernel::json::Json::Array(vec![
                access_kernel::json::Json::Str(String::from("automatic"))
            ]))
        );
        assert!(
            op.get("federation_registration_endpoint").is_none(),
            "no explicit registration endpoint is served"
        );
        // IDP-19, §10.7.1 rule 1, Ek B 4749, 5000
        let base = path.trim_end_matches("/.well-known/openid-federation");
        let list = format!("{base}/federation/list");
        let fetch = format!("{base}/federation/fetch?sub=https%3A%2F%2Frp.federation.example");
        assert_eq!(
            get(&router, &host, &list).await.0,
            404,
            "the role is off by default"
        );
        assert_eq!(get(&router, &host, &fetch).await.0, 404);
        let sub = Subordinate {
            entity_id: String::from("https://rp.federation.example"),
            jwks: access_crypto::jose::output::to_string(
                &access_identity_oidf::testing::Key::new("rp")
                    .unwrap()
                    .jwks(),
            ),
            metadata_policy: Some(String::from(
                r#"{"openid_relying_party":{"grant_types":{"subset_of":["authorization_code"]}}}"#,
            )),
        };
        apply(&w, (t, r), d, FederationChange::TaEnable(vec![sub]), 4).await;
        let (status, _, ids) = get(&router, &host, &list).await;
        assert_eq!(status, 200);
        assert_eq!(ids, r#"["https://rp.federation.example"]"#);
        let (status, ct, statement) = get(&router, &host, &fetch).await;
        assert_eq!(status, 200, "{statement}");
        assert_eq!(ct, "application/entity-statement+jwt");
        let s = access_identity_oidf::statement::verify_statement(&statement, &ec.jwks, real_now)
            .unwrap();
        assert_eq!(
            (s.iss.as_str(), s.sub.as_str()),
            (issuer.as_str(), "https://rp.federation.example")
        );
        assert!(s.metadata_policy.is_some());
        let (_, _, jwt) = get(&router, &host, &path).await;
        let ec =
            access_identity_oidf::statement::verify_configuration(&jwt, &issuer, real_now).unwrap();
        let entity = ec.metadata_of("federation_entity").unwrap();
        assert!(entity.get("federation_fetch_endpoint").is_some());
        assert!(
            entity.get("federation_resolve_endpoint").is_none()
                && entity
                    .get("federation_trust_mark_status_endpoint")
                    .is_none(),
            "only served endpoints are declared"
        );
        // OP-155 m.3 (j)
        let unknown = format!("{base}/federation/fetch?sub=https%3A%2F%2Fother.example");
        let itself = format!(
            "{base}/federation/fetch?sub={}",
            urlencoding(issuer.as_str())
        );
        let without_sub = format!("{base}/federation/fetch");
        for (url, status, error) in [
            (&unknown, 404, "not_found"),
            (&itself, 400, "invalid_request"),
            (&without_sub, 400, "invalid_request"),
        ] {
            let (got, ct, body) = get(&router, &host, url).await;
            assert_eq!(
                (got, ct.as_str()),
                (status, "application/json"),
                "{url}: {body}"
            );
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["error"], error, "{url}");
            assert!(body["error_description"].is_string());
        }
    }

    fn urlencoding(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    /// Federation documents served in process, by URL.
    #[derive(Default)]
    struct Served(std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>);

    impl Served {
        fn serve(&self, url: &str, status: u16, body: &str) {
            self.0
                .lock()
                .unwrap()
                .insert(String::from(url), (status, String::from(body)));
        }
    }

    impl access_identity_oauth::ports::oauth::ClientDocuments for Served {
        fn vet<'a>(&'a self, _: &'a str) -> access_identity_oauth::ports::oauth::Fetch<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn fetch<'a>(
            &'a self,
            _: RealmId,
            url: &'a str,
            _: &'a str,
            _: usize,
        ) -> access_identity_oauth::ports::oauth::Fetch<
            'a,
            access_identity_oauth::ports::oauth::Fetched,
        > {
            let (status, body) = self
                .0
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .unwrap_or((404, String::new()));
            Box::pin(async move {
                Ok(access_identity_oauth::ports::oauth::Fetched {
                    status,
                    max_age_s: None,
                    content_type: None,
                    body: body.into_bytes(),
                })
            })
        }
    }

    // IDI-12, IDP-20, OP-155 m.3 (j), §9.13.8 k.4, §10.7.1, Ek B 4754
    #[tokio::test]
    async fn a_trust_anchor_revocation_cuts_the_issuer_until_its_chain_returns() {
        use access_identity_oauth::adapters::oidf::refresh_issuers;
        use access_identity_oidf::testing::Entity;
        let w = World::new().await;
        let (t, r, d) = w.realm("oidf-idi12").await;
        onboard(&w.plane, d, ROOT, ROOT_KEY).await;
        access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
            .await
            .unwrap();
        let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
        let issuer = realm_issuer(&mut tx).await.unwrap().unwrap();
        tx.commit().await.unwrap();
        let key = w.keys.open_issuer(r, issuer).await.unwrap();
        let domain = DomainId::from_bytes(d.0);
        let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
        let instance = issuer_instance(&mut tx, &domain, &thumbprint(&key))
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            w.admin().register_issuer(t, r).await.unwrap(),
            Some(instance)
        );
        onboard(&w.plane, d, ALICE, ALICE_KEY).await;
        let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
        let alice = tx
            .insert_subject("active", "realm-kek:1", &[9; 40])
            .await
            .unwrap();
        assert!(
            access_store::idp::bind_subject_party(&mut tx, &alice, &ALICE.0)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        let ta = Entity::new(TA).unwrap();
        let leaf = Entity::new(ENTITY).unwrap();
        apply(
            &w,
            (t, r),
            d,
            FederationChange::Enable {
                authority_hints: Vec::new(),
            },
            2,
        )
        .await;
        let anchor = FederationChange::TrustAnchorAdd {
            entity_id: String::from(TA),
            jwks: access_crypto::jose::output::to_string(&ta.key.jwks()),
        };
        apply(&w, (t, r), d, anchor, 3).await;
        let (iat, exp) = (NOW - 1_000, NOW + 3_600_000);
        let meta = |s: &str| access_kernel::json::parse(s.as_bytes(), 1 << 16).unwrap();
        let ta_meta = meta(&format!(
            r#"{{"federation_entity":{{"federation_fetch_endpoint":"{}"}}}}"#,
            ta.fetch_endpoint()
        ));
        let leaf_meta =
            meta(r#"{"openid_provider":{"issuer":"https://issuer.federation.example"}}"#);
        let fetch = format!(
            "{}?sub={}",
            ta.fetch_endpoint(),
            ENTITY.replace(':', "%3A").replace('/', "%2F")
        );
        let docs = Served::default();
        docs.serve(
            &format!("{TA}/.well-known/openid-federation"),
            200,
            &ta.config(&[], &ta_meta, iat, exp),
        );
        docs.serve(
            &format!("{ENTITY}/.well-known/openid-federation"),
            200,
            &leaf.config(&[TA], &leaf_meta, iat, exp),
        );
        let statement = ta.about(&leaf, None, iat, exp);
        docs.serve(&fetch, 200, &statement);
        track_issuer(
            &w.db.app,
            &domain,
            (*t.as_bytes(), *r.as_bytes()),
            ENTITY,
            Some(issuer),
            NOW,
        )
        .await
        .unwrap();
        let c = courier(&w);
        let login = |at: u64| {
            authentication(AuthFacts {
                subject: alice,
                method: AuthMethod::Webauthn,
                auth_time: at,
                assurance: BTreeMap::from([(String::from("aal"), 1)]),
                webauthn: None,
                evidence: None,
                bind: Bind::None,
            })
        };
        let done = refresh_issuers(&w.db.app, &docs, &domain, NOW)
            .await
            .unwrap();
        assert_eq!(done.resolved, 1, "{done:?}");
        assert!(admitted(&c.issue(t, r, &login(NOW - 9)).await.unwrap()));
        docs.serve(&fetch, 404, "");
        let done = refresh_issuers(&w.db.app, &docs, &domain, NOW)
            .await
            .unwrap();
        assert_eq!(
            done.unresolved, 1,
            "the anchor no longer vouches for the issuer"
        );
        let head = w.plane.domains.head(d).await.unwrap();
        assert!(
            refused_by_chain(&c.issue(t, r, &login(NOW - 8)).await.unwrap()),
            "the next Claim of that issuer is not ingested"
        );
        assert_eq!(
            w.plane.domains.head(d).await.unwrap(),
            head,
            "nothing is recorded: the Acceptance stands, untouched"
        );
        docs.serve(&fetch, 200, &statement);
        let done = refresh_issuers(&w.db.app, &docs, &domain, NOW)
            .await
            .unwrap();
        assert_eq!(done.resolved, 1);
        assert!(
            admitted(&c.issue(t, r, &login(NOW - 7)).await.unwrap()),
            "the chain is back: the Claim flows again under the same Acceptance"
        );
    }
}
