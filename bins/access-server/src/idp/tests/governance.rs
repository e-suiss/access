//! Realm governance through `idp.*` Exercises (MD-14, TN-106, TN-118, §13.2): branding, the
//! realm's JOSE key policy, decided rotation and the emergency drop of a compromised key, each
//! committed in the governing domain and then applied to the identity signer.

use std::collections::BTreeSet;

use access_identity_admin::app::jwks_kids;
use access_identity_admin::domain::{
    Attribute, Branding, CUTOFF_MARGIN_MS, ClaimName, Color, Invalid,
};
use access_store::idp::{branding, key_changes};

use super::*;

const LEAD: u64 = Policy::REALM.publish_lead_ms;
const MINUTE: u64 = 60_000;

fn kids(w: &World, realm: RealmId) -> Vec<[u8; 32]> {
    let doc = w.block_jwks(realm);
    jwks_kids(&doc)
}

impl World {
    fn block_jwks(&self, realm: RealmId) -> String {
        match self
            .keys
            .ask(SignerRequest::Jwks(SignerRealm(*realm.as_bytes())))
        {
            SignerResponse::Jwks(doc) => doc,
            other => panic!("{other:?}"),
        }
    }
}

fn brand(logo: &str) -> Branding {
    Branding {
        display_name: Some(String::from("Acme")),
        logo_uri: Some(String::from(logo)),
        primary_color: Some(Color::parse("#0a3d62").unwrap()),
        background_color: None,
        csp_origins: BTreeSet::from([String::from("https://cdn.acme.example")]),
    }
}

// §13.4 G54, G53, MD-14, MD-9, OP-149 m.16 (a), OP-63
#[tokio::test]
async fn idp_commits_carry_the_sessions_actor_binding() {
    // L0-META-7, INV-2, PI-7
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("bound").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let root_subject = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    let alice_subject = t
        .insert_subject("staged", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    let nobody = t
        .insert_subject("staged", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    for (s, party) in [(root_subject, ROOT), (alice_subject, ALICE)] {
        assert!(
            access_store::idp::bind_subject_party(&mut t, &s, &party.0)
                .await
                .unwrap()
        );
    }
    t.commit().await.unwrap();
    let mapper = |nonce, subject| Proposal {
        subject: Some(subject),
        ..proposal(
            (tenant, realm),
            Change::MapperSet {
                claim: ClaimName::parse("nick").unwrap(),
                source: Some(Attribute::parse("nickname").unwrap()),
            },
            nonce,
            idp_anchor(d),
            1,
        )
    };
    for (nonce, s) in [(1, alice_subject), (2, nobody)] {
        assert!(matches!(
            exercise(&w, &mapper(nonce, s), ROOT_KEY).await,
            Err(AdminError::Refused(code)) if code == "actor-binding"
        ));
    }
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        access_store::idp::mappers(&mut t).await.unwrap(),
        Vec::new()
    );
    t.commit().await.unwrap();
    written(
        &exercise(&w, &mapper(3, root_subject), ROOT_KEY)
            .await
            .unwrap(),
    );
}

// TN-106, MD-14, K06
#[tokio::test]
async fn branding_changes_through_commit() {
    // §12.4.2, E34, EI-25
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("brand").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let good = brand("https://cdn.acme.example/logo.svg");
    let p = proposal(
        (tenant, realm),
        Change::Branding(good.clone()),
        1,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &p, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let stored = branding(&mut t).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        stored,
        dcbor::encode(&good.to_value(), Limits::CEILING).unwrap()
    );
    let outside = proposal(
        (tenant, realm),
        Change::Branding(brand("https://evil.example/logo.svg")),
        2,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&outside).await,
        Err(AdminError::Invalid(Invalid::Branding))
    ));
}

// §9.9.6, P55, PI-8, S-1, INV-33
#[tokio::test]
async fn claim_mappers_stay_inside_the_profile() {
    // MD-14, TN-117
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("mapper").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    for claim in ["roles", "groups", "permissions", "scope", "cnf"] {
        assert_eq!(ClaimName::parse(claim), Err(Invalid::Claim), "{claim}");
    }
    assert_eq!(Attribute::parse("is_admin"), Err(Invalid::Attribute));
    let p = proposal(
        (tenant, realm),
        Change::MapperSet {
            claim: ClaimName::parse("display_name").unwrap(),
            source: Some(Attribute::parse("name").unwrap()),
        },
        1,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &p, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        access_store::idp::mappers(&mut t).await.unwrap(),
        vec![(String::from("display_name"), String::from("name"))]
    );
}

// CR-59, SAI-46, CR-25, OP-146 m.16 (m)
#[tokio::test]
async fn a_new_realm_signs_tokens_at_once() {
    let w = World::new().await;
    let (_, realm, _) = w.realm("fresh").await;
    let signer_realm = SignerRealm(*realm.as_bytes());
    let SignerResponse::Signed { kid, token } = w.keys.ask(SignerRequest::Sign {
        realm: signer_realm,
        typ: String::from("at+jwt"),
        payload: br#"{"sub":"u1"}"#.to_vec(),
        at: 0,
    }) else {
        panic!("the new realm signed nothing");
    };
    assert_eq!(token.split('.').count(), 3);
    let listed = kids(&w, realm);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0], kid);
    let early = LEAD - MINUTE;
    w.keys.at(early);
    assert_eq!(
        w.keys.ask(SignerRequest::Rotate {
            realm: signer_realm,
            retire: kid,
        }),
        SignerResponse::Error(String::from("signer-no-backup"))
    );
    w.keys.at(LEAD);
    assert!(matches!(
        w.keys.ask(SignerRequest::Rotate {
            realm: signer_realm,
            retire: kid,
        }),
        SignerResponse::Rekeyed(_)
    ));
    assert_ne!(kids(&w, realm)[0], kid);
}

// §13.2, §13.7.1, §13.7.7, SEC9, MD-7
#[tokio::test]
async fn a_compromised_key_is_dropped_at_once() {
    // CR-23, CR-27, OP-73, X11, SI-4
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("stolen").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    w.keys.at(LEAD);
    let active = kids(&w, realm)[0];
    let at = 5 * 24 * 3_600_000;
    let p = proposal(
        (tenant, realm),
        Change::KeyDrop {
            kid: active,
            compromised_at: Some(at),
        },
        1,
        idp_anchor(d),
        1,
    );
    let prepared = w.admin().prepare(&p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    );
    written(&w.admin().apply(&p, ais.clone()).await.unwrap());
    assert!(!kids(&w, realm).contains(&active));
    assert!(matches!(
        w.admin().apply(&p, ais).await.unwrap(),
        Applied::AlreadyWritten { .. }
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let changes = key_changes(&mut t).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].action, "idp.realm.key_drop");
    assert_eq!(changes[0].kid, Some(active));
    assert_eq!(changes[0].cutoff_at, Some(at - CUTOFF_MARGIN_MS));
    // CR-27, TN-41
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let signals = t.outbox_kinds().await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        signals
            .iter()
            .filter(|k| *k == "signal.credential_compromise")
            .count(),
        1
    );
    let unknown = proposal(
        (tenant, realm),
        Change::KeyDrop {
            kid: [0; 32],
            compromised_at: None,
        },
        2,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&unknown).await,
        Err(AdminError::Invalid(Invalid::NoKey))
    ));
}

// TN-118, MD-6, CR-25, CR-26, §13.7.1
#[tokio::test]
async fn a_rotation_and_a_policy_are_decided() {
    // SAI-46, TN-118
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("rotate").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    w.keys.at(LEAD);
    w.keys.at(2 * LEAD + MINUTE);
    let before = kids(&w, realm);
    let active = before[0];
    let rotate = proposal(
        (tenant, realm),
        Change::KeyRotate { retire: active },
        1,
        idp_anchor(d),
        48,
    );
    written(&exercise(&w, &rotate, ROOT_KEY).await.unwrap());
    let after = kids(&w, realm);
    assert_ne!(after[0], active);
    assert!(after.contains(&active));
    let mut faster = Policy::REALM;
    faster.lifetime_ms = 30 * 24 * 3_600_000;
    faster.window_ms = 60 * 24 * 3_600_000;
    written(
        &exercise(
            &w,
            &proposal(
                (tenant, realm),
                Change::KeyPolicy(faster),
                2,
                idp_anchor(d),
                48,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut bad = Policy::REALM;
    bad.publish_lead_ms = 0;
    assert!(matches!(
        w.admin()
            .prepare(&proposal(
                (tenant, realm),
                Change::KeyPolicy(bad),
                3,
                idp_anchor(d),
                48,
            ))
            .await,
        Err(AdminError::Invalid(Invalid::KeyPolicy))
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let actions: Vec<String> = key_changes(&mut t)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.action)
        .collect();
    assert_eq!(actions, ["idp.realm.key_rotate", "idp.realm.key_policy"]);
}

// TN-18, IDP-5, OP-153 m.3 (u), m.22 (j), m.25 (f)
#[tokio::test]
async fn related_origins_hold_five_labels_under_verified_domains() {
    use access_identity_admin::domain::RelatedOrigins;
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("related").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let list = |hosts: &[&str]| RelatedOrigins {
        origins: hosts.iter().map(|h| format!("https://{h}")).collect(),
    };
    let six = list(&[
        "a.one.example",
        "b.two.example",
        "c.three.example",
        "d.four.example",
        "e.five.example",
        "f.six.example",
    ]);
    let p = proposal(
        (tenant, realm),
        Change::RelatedOrigins(six),
        1,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&p).await,
        Err(AdminError::Invalid(Invalid::RelatedOrigins))
    ));
    let unverified = proposal(
        (tenant, realm),
        Change::RelatedOrigins(list(&["shop.acme-brand.example"])),
        2,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&unverified).await,
        Err(AdminError::Invalid(Invalid::RelatedOrigins))
    ));
    let malformed = proposal(
        (tenant, realm),
        Change::RelatedOrigins(RelatedOrigins {
            origins: BTreeSet::from([String::from("http://shop.acme.example/path")]),
        }),
        3,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&malformed).await,
        Err(AdminError::Invalid(Invalid::RelatedOrigins))
    ));
    let none = proposal(
        (tenant, realm),
        Change::RelatedOrigins(RelatedOrigins::default()),
        4,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &none, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        access_store::idp::related_origins(&mut t).await.unwrap(),
        Vec::<String>::new()
    );
    t.commit().await.unwrap();

    // OP-153 m.25 (f)
    let six_under_one_suffix = proposal(
        (tenant, realm),
        Change::RelatedOrigins(list(&[
            "a.one.co.uk",
            "b.two.co.uk",
            "c.three.co.uk",
            "d.four.co.uk",
            "e.five.co.uk",
            "f.six.co.uk",
        ])),
        5,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&six_under_one_suffix).await,
        Err(AdminError::Invalid(Invalid::RelatedOrigins))
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let org = t.insert_org([0x0b; 16], "Acme", &[0x0b; 32]).await.unwrap();
    for (n, domain) in ["acme.co.uk", "acme-brand.example"].into_iter().enumerate() {
        let n = u8::try_from(n).unwrap();
        let claim = t
            .insert_domain_claim(org, domain, "dns_txt", &[n; 32])
            .await
            .unwrap();
        assert!(
            t.verify_domain(claim, 86_400, &[2; 32], &[3; 32])
                .await
                .unwrap()
        );
    }
    t.commit().await.unwrap();
    let brands = list(&[
        "shop.acme.co.uk",
        "www.acme.co.uk",
        "shop.acme-brand.example",
    ]);
    let stored = proposal(
        (tenant, realm),
        Change::RelatedOrigins(brands.clone()),
        6,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &stored, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        access_store::idp::related_origins(&mut t).await.unwrap(),
        brands.origins.into_iter().collect::<Vec<_>>()
    );
    t.commit().await.unwrap();
}

// X35, XI-25, OP-153 m.3 (s)
#[tokio::test]
async fn a_protected_message_is_never_overridden() {
    use access_identity_admin::domain::LocaleOverrides;
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("locale").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let set = |locale: &str, key: &str, text: &str| LocaleOverrides {
        texts: std::collections::BTreeMap::from([(
            String::from(locale),
            std::collections::BTreeMap::from([(String::from(key), String::from(text))]),
        )]),
    };
    for (n, refused) in [
        set("tr", "login-failed", "Hesap bulunamadı"),
        set("en", "recovery-cooling", "Recovery is instant"),
        set("en", "no-such-key", "x"),
        set("en", "action-continue", "Go { $x }"),
        set("e n", "action-continue", "Go"),
    ]
    .into_iter()
    .enumerate()
    {
        let p = proposal(
            (tenant, realm),
            Change::LocaleOverrides(refused),
            u8::try_from(n).unwrap() + 1,
            idp_anchor(d),
            1,
        );
        assert!(
            matches!(
                w.admin().prepare(&p).await,
                Err(AdminError::Invalid(Invalid::LocaleOverrides))
            ),
            "{n}"
        );
    }
    let ok = set("tr", "action-continue", "İlerle");
    let p = proposal(
        (tenant, realm),
        Change::LocaleOverrides(ok.clone()),
        9,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &p, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let stored = access_store::idp::locale_overrides(&mut t)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        stored,
        dcbor::encode(&ok.to_value(), Limits::CEILING).unwrap()
    );
}

async fn records(w: &World, d: Digest) -> usize {
    let last = u64::try_from(i64::MAX).unwrap();
    access_store::authority::read_log(&w.db.app, &DomainId::from_bytes(d.0), 0, last)
        .await
        .unwrap()
        .len()
}

// §10.1.7, MD-14, TN-118, CR-27, OP-157 m.3 (x), (gg), Ek B 5676
#[tokio::test]
async fn a_scheduled_rotation_writes_no_exercise_and_its_policy_is_a_reserved_exercise() {
    use access_internal_api::idp::IdpAction;
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("scheduled").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let before = records(&w, d).await;
    let first = kids(&w, realm)[0];

    let ours = SignerRealm(*realm.as_bytes());
    let day = 86_400_000;
    let mut rotated = Vec::new();
    let mut now = LEAD;
    while now <= Policy::REALM.lifetime_ms * 5 / 2 {
        w.keys.now.store(now, std::sync::atomic::Ordering::SeqCst);
        let report = w.keys.signer.lock().unwrap().round(now, 7);
        assert!(report.troubled.is_empty(), "{now}");
        rotated.extend(
            report
                .rotated()
                .filter(|(r, _)| **r == ours)
                .map(|(_, kid)| *kid),
        );
        now += day;
    }
    assert!(rotated.len() >= 2, "{rotated:?}");
    assert_eq!(
        access_identity_signer::service::AUDIT_EVENT_ROTATED,
        "signer.rotated"
    );
    let current = kids(&w, realm);
    assert_ne!(current[0], first);
    assert!(rotated.contains(&current[0]));
    assert_eq!(records(&w, d).await, before, "no Exercise, no record");
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(key_changes(&mut t).await.unwrap().len(), 0);
    t.commit().await.unwrap();

    // MD-14, §13.7.1
    let mut slower = Policy::REALM;
    slower.lifetime_ms = 120 * day;
    slower.window_ms = 240 * day;
    let change = Change::KeyPolicy(slower);
    assert!(change.action().reserved());
    assert!(IdpAction::RealmKeyPolicy.schema().reserved);
    assert!(IdpAction::RealmKeyRotate.schema().reserved);
    let by_alice = proposal((tenant, realm), change.clone(), 1, idp_anchor(d), 48);
    assert!(!matches!(
        exercise(&w, &by_alice, ALICE_KEY).await,
        Ok(Applied::Written { .. } | Applied::AlreadyWritten { .. })
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(key_changes(&mut t).await.unwrap().len(), 0);
    t.commit().await.unwrap();
    let by_root = proposal((tenant, realm), change, 2, idp_anchor(d), 48);
    let at = records(&w, d).await;
    written(&exercise(&w, &by_root, ROOT_KEY).await.unwrap());
    assert!(records(&w, d).await > at);
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let actions: Vec<String> = key_changes(&mut t)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.action)
        .collect();
    t.commit().await.unwrap();
    assert_eq!(actions, ["idp.realm.key_policy"]);
    // OP-155 m.3 (o), OP-157 m.3 (x)
    for a in [IdpAction::GatewayKeytabPolicy, IdpAction::SamlCertPolicy] {
        assert!(!a.schema().reserved, "{a:?}");
    }
    assert!(IdpAction::GatewayKeytabEmergency.schema().reserved);
    assert!(IdpAction::SamlCertEmergency.schema().reserved);
}

/// A Grant to `holder` on the realm's `idp.*` resources over `actions`.
fn idp_grant(
    d: Digest,
    slug: &str,
    holder: Id,
    actions: access_kernel::model::ActionSet,
) -> Payload {
    use access_kernel::model::{
        AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, ResourceSelector,
        Structural, SubjectSelector,
    };
    Payload::GrantIssue(access_kernel::meta::GrantContent {
        basis: access_kernel::meta::GrantBasis::Anchor(meta::object_id(
            &d,
            kind::ANCHOR,
            IDP_ANCHOR,
        )),
        holder: SubjectSelector::Party(holder),
        authority: CanonicalAuthority {
            authority: AuthoritySet {
                actions,
                resource: ResourceSelector::Structural(Structural {
                    namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
                    prefix: vec![String::from(slug)],
                    kind: None,
                    attrs: std::collections::BTreeMap::new(),
                }),
                params: std::collections::BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: u64::MAX / 2,
                },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms::default(),
            requirements: BTreeSet::new(),
        },
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    })
}

/// The root's core meta-action write `payload` on the idp anchor.
fn root_write(d: Digest, nonce: u8, payload: Payload) -> access_internal_api::idp::Submission {
    let intent = access_kernel::intent::IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: meta::core_action(payload.action()),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::from([(
            String::from(meta::PAYLOAD_PARAM),
            payload.digest().unwrap(),
        )]),
        recipient: None,
        purpose: None,
        context: access_kernel::intent::ContextRefs::default(),
        validity: Window {
            from: NOW,
            until: NOW + HOUR,
        },
    };
    let digest = intent_digest(&intent).unwrap();
    access_internal_api::idp::Submission {
        domain: d,
        nonce: vec![nonce; 16],
        ais: sign(&statement(d, &[nonce; 16], digest, idp_anchor(d)), ROOT_KEY),
        intent,
        payload: Some(Box::new(payload)),
        basis: idp_anchor(d),
        capacity: Capacity::Own,
        contributions: Vec::new(),
        pep: String::from(PEP),
        actor: None,
    }
}

// §8.17.9.8, TN-117, X20, OP-157 m.3 (t), m.19 (d), Ek B 5453
#[tokio::test]
async fn a_claim_mapper_is_reserved_and_a_namespace_grant_does_not_reach_it() {
    use access_internal_api::idp::IdpAction;
    use access_kernel::meta::HoldingRef;
    use access_kernel::model::ActionSet;
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("mapper-reserved").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let alice = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &alice, &ALICE.0)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let mapper = IdpAction::MapperSet;
    let catalog = access_internal_api::idp::spp(mapper.namespace(), ROOT).catalog_digest();
    let held = |nonce: u8, actions: ActionSet| {
        let w = &w;
        async move {
            let applied = w
                .admin()
                .meta(
                    (tenant, realm),
                    root_write(d, nonce, idp_grant(d, "mapper-reserved", ALICE, actions)),
                )
                .await;
            let Ok(Applied::Written {
                exercise, position, ..
            }) = applied
            else {
                panic!("the root's Grant was not written: {applied:?}");
            };
            ExerciseBasis::Holding(HoldingRef {
                grant: meta::object_id(&exercise, kind::GRANT, 0),
                holder: ALICE,
                since: position,
            })
        }
    };
    let set = |nonce: u8, basis: ExerciseBasis| Proposal {
        subject: Some(alice),
        ..proposal(
            (tenant, realm),
            Change::MapperSet {
                claim: ClaimName::parse("nick").unwrap(),
                source: Some(Attribute::parse("nickname").unwrap()),
            },
            nonce,
            basis,
            1,
        )
    };

    // L0-ALG-30, §13.7.1
    let namespace = held(
        0x40,
        ActionSet {
            exact: BTreeSet::new(),
            prefix: BTreeSet::from([(String::from(mapper.namespace()), catalog)]),
        },
    )
    .await;
    assert!(!matches!(
        exercise(&w, &set(0x41, namespace), ALICE_KEY).await,
        Ok(Applied::Written { .. } | Applied::AlreadyWritten { .. })
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        access_store::idp::mappers(&mut t).await.unwrap(),
        Vec::new()
    );
    t.commit().await.unwrap();

    let named = held(
        0x42,
        ActionSet {
            exact: BTreeSet::from([mapper.action_ref()]),
            prefix: BTreeSet::new(),
        },
    )
    .await;
    written(&exercise(&w, &set(0x43, named), ALICE_KEY).await.unwrap());
    assert!(IdpAction::MapperSet.reserved());
}
