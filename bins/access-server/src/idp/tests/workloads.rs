//! Workload and attestation Acceptances on the real commit path (OP-154 m.3 (d), (r), (s),
//! AG-30, AG-31, L21, U20): a trust domain is accepted by the domain root's actor-binding
//! Acceptance of its issuer id and by nothing else; a new realm accepts its issuer's workload
//! bindings for actor binding and its runtime attestations as predicate input; an attester's
//! Acceptance admits only the classes it lists.

use access_identity_account::domain::claims::{runtime_attestation, workload_binding};
use access_identity_admin::app::workloads::trust_domain;
use access_identity_attest::domain::runtime::RuntimeClass;
use access_identity_attest::domain::workload::{Scheme, trust_domain_issuer};
use access_identity_oauth::ports::oauth::WorkloadTrust as _;
use access_internal_api::idp::Verdict;
use access_kernel::claim::body::Workload;
use access_kernel::intent::IntentEnvelope;

use super::claims::courier;
use super::*;

const AGENT: Id = Id([0x0d; 16]);

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

/// The root's `acceptance_establish` of `content` on the meta anchor.
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

fn issuer_gate(issuer: Id, use_: &str, classes: &[&str]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
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

// OP-154 m.3 (r), AG-30, L25, §11.12, Ek B 4133, 4489, 4546
#[tokio::test]
async fn a_trust_domain_is_accepted_by_the_roots_actor_binding_acceptance_alone() {
    let w = World::new().await;
    let (_, _, d) = w.realm_with("trust", Some(0)).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let acme = trust_domain_issuer(Scheme::Spiffe, "acme.example");
    let beta = trust_domain_issuer(Scheme::Spiffe, "beta.example");
    assert!(!w.plane.accepted(d.0, acme).await.unwrap());
    let v = establish(&w, d, 0x71, trust_domain(Scheme::Spiffe, "acme.example")).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    assert!(w.plane.accepted(d.0, acme).await.unwrap());
    assert!(!w.plane.accepted(d.0, beta).await.unwrap());
    assert!(
        !w.plane
            .accepted(d.0, trust_domain_issuer(Scheme::Wimse, "acme.example"))
            .await
            .unwrap()
    );
    let other_use = issuer_gate(
        Id(beta),
        access_kernel::claim::PREDICATE_INPUT,
        &["identity_binding_workload"],
    );
    let v = establish(&w, d, 0x72, other_use).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    assert!(!w.plane.accepted(d.0, beta).await.unwrap());
}

// AG-31, §11.12.4, Ek B 4545
#[tokio::test]
async fn an_attester_signing_a_class_outside_its_acceptance_is_ignored() {
    let w = World::new().await;
    let (_, _, d) = w.realm_with("attester", Some(0)).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let attester = Id([0x7a; 16]);
    let gate = issuer_gate(
        attester,
        access_kernel::claim::PREDICATE_INPUT,
        &["attestation_runtime"],
    );
    let v = establish(&w, d, 0x73, gate).await;
    assert!(matches!(v, Verdict::Committed(_)), "{v:?}");
    let use_ = access_kernel::claim::PREDICATE_INPUT;
    let accepted = |class: &'static str| {
        let domains = w.plane.domains.clone();
        async move {
            domains
                .issuer_accepted(d, attester, (use_, class))
                .await
                .unwrap()
        }
    };
    assert!(accepted("attestation_runtime").await);
    assert!(!accepted("posture_device").await);
    assert!(!accepted("identity_binding_workload").await);
}

// OP-154 m.3 (d), (s), §5.9, L21, U20, Ek B 4200, 4262, 4324, 4524, 4547
#[tokio::test]
async fn the_realm_issuer_binds_workloads_and_runtime_attestations_as_claims() {
    let w = World::new().await;
    let (t, r, d) = w.realm("bindings").await;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    w.admin().register_issuer(t, r).await.unwrap();
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let c = courier(&w);
    let key = thumbprint(&public(0x5e));
    let binding = workload_binding(
        AGENT.0,
        Workload {
            uri: String::from("spiffe://acme.example/agent/mail/w1"),
            thumbprint: key,
        },
        b"jwt-svid",
        NOW,
    );
    let issued = c.issue(t, r, &binding).await.unwrap();
    assert!(
        matches!(
            issued,
            access_identity_account::app::claims::Issued::Answered {
                verdict: access_internal_api::claims::ClaimVerdict::Admitted { .. },
                ..
            }
        ),
        "{issued:?}"
    );
    let runtime = RuntimeClass::Tpm.digest();
    let attested = runtime_attestation(AGENT.0, [0x5f; 16], runtime, NOW);
    let issued = c.issue(t, r, &attested).await.unwrap();
    assert!(
        matches!(
            issued,
            access_identity_account::app::claims::Issued::Answered {
                verdict: access_internal_api::claims::ClaimVerdict::Admitted { .. },
                ..
            }
        ),
        "{issued:?}"
    );
    let p = attested
        .prepare(&access_identity_account::domain::claims::Placement {
            domain: d,
            issuer: Id([0; 16]),
            subject: AGENT,
            instance: None,
            supersedes: None,
            now: NOW,
        })
        .unwrap();
    assert_eq!(p.statement.bound_instance, Some(Id([0x5f; 16])));
    assert_eq!(
        p.statement.value,
        Some(access_kernel::model::EqValue::Bytes(runtime.to_vec()))
    );
}
