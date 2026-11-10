//! The SCIM client as a Claim source on the real commit path (OP-155 m.3 (g), INV-16, §9.13.8
//! k.7, §10.1.2): a client registered by `idp.scim.client_register` has its own issuer Party;
//! its `member` Claim over the SCIM channel is recorded but selects nobody until the domain
//! establishes a `subject-selection` Acceptance of that issuer, and nothing it sends writes a
//! Grant.

use access_identity_admin::domain::scim::ScimChange;
use access_identity_scim::app::claims::{Courier as ScimCourier, Issued as ScimIssued, member};
use access_internal_api::claims::{ClaimVerdict, Quarantine};
use access_internal_api::idp::Verdict;
use access_kernel::intent::IntentEnvelope;

use super::claims::At;
use super::*;
use crate::ingest::PgSubmissions;

impl access_identity_scim::app::Clock for At {
    fn now_ms(&self) -> u64 {
        NOW
    }
}

fn meta_intent(payload: &Payload) -> IntentEnvelope {
    IntentEnvelope {
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
    }
}

async fn establish(w: &World, d: Digest, nonce: u8, content: Value) -> Verdict {
    let payload = Payload::AcceptanceEstablish(content);
    let intent = meta_intent(&payload);
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let digest = intent_digest(&intent).unwrap();
    let ais = sign(&statement(d, &[nonce; 16], digest, basis), ROOT_KEY);
    w.plane
        .commit(
            access_authority_core::domain::Request {
                domain: d,
                mode: access_kernel::combinator::Mode::Commit,
                nonce: vec![nonce; 16],
                intent,
                payload: Some(payload),
                basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais,
            (String::from(PEP), None),
        )
        .await
        .unwrap()
}

fn selection(issuer: [u8; 16]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), Id(issuer).to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::SUBJECT_SELECTION),
        ),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(access_identity_scim::app::claims::MEMBER)]),
        ),
        (
            Value::text("subject"),
            access_kernel::model::SubjectSelector::Public.to_value(),
        ),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

async fn member_entry(w: &World, d: Digest, subject: Id, claim: Id) -> bool {
    let rows = access_store::authority::state_of(
        &w.db.app,
        &DomainId::from_bytes(d.0),
        &[access_kernel::claim::member_key(
            access_identity_scim::app::claims::MEMBER,
            &subject,
            &claim,
        )],
    )
    .await
    .unwrap();
    rows.iter().any(|r| r.value.is_some())
}

// INV-16, §9.13.8 k.7, §13.7.1, IDP-23, OP-155 m.3 (g), (gg), Ek B 4821, 4822, 4926, 5059
#[tokio::test]
async fn a_scim_membership_selects_only_through_a_subject_selection_acceptance() {
    let w = World::new().await;
    let (t, r, d) = w.realm_with("scim-select", Some(0)).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let register = proposal(
        (t, r),
        Change::Scim(ScimChange::ClientRegister {
            name: String::from("hr"),
            profile: None,
        }),
        0x61,
        idp_anchor(d),
        1,
    );
    let applied = exercise(&w, &register, ROOT_KEY).await.unwrap();
    assert!(
        matches!(
            &applied,
            Applied::Written {
                secret: Some(_),
                ..
            }
        ),
        "{applied:?}"
    );
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let client = access_store::scim::client(&mut tx, "hr")
        .await
        .unwrap()
        .unwrap();
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
    assert_ne!(client.issuer, ROOT.0);

    let courier = ScimCourier {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        ingest: access_authority_ingest::app::Ingest::new(
            w.plane.domains.clone(),
            PgSubmissions(w.db.app.clone()),
            At,
        ),
        clock: At,
    };
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let group = [0x42; 16];
    let unaccepted = courier
        .issue((t, r), "hr", &member(alice, "hr", group, NOW, false))
        .await
        .unwrap();
    let ScimIssued::Answered(ClaimVerdict::Quarantined { claim, reason, .. }) = unaccepted else {
        panic!("{unaccepted:?}");
    };
    assert_eq!(reason, Quarantine::SourceNotAccepted);
    assert!(!member_entry(&w, d, ALICE, claim).await);

    // §13.7.1, INV-16
    let v = establish(&w, d, 0x72, selection(client.issuer)).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    let accepted = courier
        .issue((t, r), "hr", &member(alice, "hr", group, NOW + 1, false))
        .await
        .unwrap();
    let ScimIssued::Answered(ClaimVerdict::Admitted { claim, .. }) = accepted else {
        panic!("{accepted:?}");
    };
    assert!(member_entry(&w, d, ALICE, claim).await);

    let retire = proposal(
        (t, r),
        Change::Scim(ScimChange::ClientRetire(String::from("hr"))),
        0x62,
        idp_anchor(d),
        1,
    );
    assert!(matches!(
        exercise(&w, &retire, ROOT_KEY).await.unwrap(),
        Applied::Written { secret: None, .. }
    ));
    assert_eq!(
        courier
            .issue((t, r), "hr", &member(alice, "hr", group, NOW + 2, true))
            .await
            .unwrap(),
        ScimIssued::Unplaced("client-retired")
    );
}
