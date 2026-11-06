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

// §13.4 G54, MD-14, OP-149 m.16 (a), OP-63: an idp.* change asked for in a realm subject's
// session commits only when a live Instance of the Party that subject is bound to signed it;
// another Party's key, or a subject bound to no Party, is refused before anything is decided
#[tokio::test]
async fn idp_commits_carry_the_sessions_actor_binding() {
    // L0-META-7, INV-2, PI-7
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("bound").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let root_subject = t
        .insert_subject("staged", "realm-kek:1", &[9; 40])
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

// TN-106, MD-14, K06: a realm's branding is data written only by an idp.realm.branding
// Exercise; a logo outside its CSP origins is refused before anything is decided
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

// §9.9.6, P55, PI-8, S-1, INV-33: a claim mapper takes a standard profile attribute and never
// defines a claim only an authority projection carries
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

// CR-59, SAI-46, CR-25, OP-146 m.16 (m): a realm created through the admin path signs a token
// with its founding key the moment it is open, with no schedule round and no clock advance; the
// JWKS already lists that key first and a published backup, which waits the full lead
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

// §13.2, §13.7.1, §13.7.7, SEC9, MD-7: a compromised realm key is dropped by a narrowing
// idp.realm.key_drop Exercise; it leaves the JWKS at once, the drop records the issuer cutoff
// 24 hours before the compromise, a retry changes nothing, and a key the realm does not
// publish is refused
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

// TN-118, MD-6, CR-25, CR-26, §13.7.1: a manual rotation and a new rotation policy are
// reserved idp.realm Exercises; the rotation makes the published backup sign and keeps the old
// key in the JWKS, and a policy the realm may not take is refused before anything is decided
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
