//! The Pay, Commerce and Serve seams on the real server path (§7.9.9, §7.9.10, E21, F9, U62,
//! MUST-NEVER-7, PI-14, OP-156 m.3 (b), (u)). Each product is a twin of `access-product-twin` on
//! the public crates alone, with its own Party, issuer key and Acceptance. It publishes its
//! schema, issues its Claims, asks Access as its own PEP and keeps its own domain truth: money,
//! holds and settlement for Pay, orders for Commerce, shifts for Serve. Access holds only the
//! authority.

use access_kernel::claim::Statement as ClaimStatement;
use access_kernel::claim::body::{Body, Class, body_digest};
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, adp_body};
use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use access_product_twin::twin::Signed;

use super::*;

mod commerce;
mod pay;
mod serve;

/// A product's seam in its own deployment, its schema published and accepted by the root.
struct Product {
    s: Seam,
    schema: Schema,
}

impl Product {
    async fn open(label: &str, product: &str) -> Self {
        let s = Seam::open(label, product).await;
        let schema = schema(product);
        s.twin.publish_schema(&s.domain, &schema).await.unwrap();
        s.accept_schema(&schema).await;
        Self { s, schema }
    }

    fn action(&self, name: &str) -> ActionRef {
        self.schema.action(name).unwrap()
    }

    /// The root accepts `issuer`'s Claims of `classes` for `use_`; the Acceptance's digest.
    async fn accept_from(&self, issuer: Id, use_: &str, classes: &[&str]) -> Digest {
        let mut classes = classes.to_vec();
        classes.sort_by_key(|c| (c.len(), *c));
        let content = Value::Map(vec![
            (Value::text("issuer"), issuer.to_value()),
            (Value::text("use"), Value::text(use_)),
            (
                Value::text("classes"),
                Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
            ),
        ]);
        let digest = access_kernel::claim::acceptance_digest(&content);
        self.s.root(Payload::AcceptanceEstablish(content)).await;
        digest
    }

    /// `actor`'s statement for `envelope` on `basis`, carried by the twin to the evaluation
    /// endpoint as its PEP, with `proofs`: the decision body as Access answered it.
    async fn evaluate(
        &self,
        actor: &Actor,
        envelope: &IntentEnvelope,
        basis: ExerciseBasis,
        proofs: Vec<Json>,
    ) -> Json {
        let request = self.s.request(actor, envelope.clone(), basis, Vec::new());
        let digest = intent_digest(envelope).unwrap();
        let mut body: Json = serde_json::from_str(
            &adp_body(&ExerciseRequest {
                domain: &self.s.domain,
                mode: Mode::Commit,
                nonce: &request.nonce,
                intent: &digest,
                envelope: Some(envelope),
                actor: &SdkActor::Statement(request.ais),
                basis: &basis,
                capacity: Capacity::Own,
                pep: TWIN_PEP,
                exercise: None,
            })
            .unwrap(),
        )
        .unwrap();
        if !proofs.is_empty() {
            body["context"]["proofs"] = Json::Array(proofs);
        }
        let Answer::Response(r) = self
            .s
            .listener
            .send(
                access_product_twin::wire::call(
                    access_product_twin::Method::Post,
                    access_product_twin::wire::EVALUATION,
                    &[],
                    body.to_string().into_bytes(),
                )
                .unwrap(),
            )
            .await
        else {
            panic!("no answer");
        };
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        schedule(&self.s.signer);
        serde_json::from_slice(&r.body).unwrap()
    }
}

/// A Claim statement about `subject` of `class` with `value`, valid for `for_ms` from now; the
/// domain and issuer are filled by whoever signs it.
fn statement(subject: Id, class: &str, value: Option<EqValue>, for_ms: u64) -> ClaimStatement {
    let now = now_ms();
    ClaimStatement {
        domain: Digest([0; 32]),
        issuer: Id([0; 16]),
        subject,
        class: String::from(class),
        value,
        issued_at: now,
        validity: Window {
            from: now - 60_000,
            until: now + for_ms,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    }
}

/// The product's own Claim about `subject` of `class` with `value` for `for_ms`, its body beside
/// it.
fn signed(subject: Id, class: &str, (value, body): (EqValue, Vec<u8>), for_ms: u64) -> Signed {
    Signed::with_body(
        Issue {
            subject,
            class: String::from(class),
            value: Some(value),
            for_ms,
            resource: None,
        },
        body,
    )
}

/// The value and body bytes of a product-seam Claim of `class` (L2-CLB-1, `product-seam.cddl`):
/// `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR([class, body]))`.
fn seam_body(class: &str, body: &Value) -> (EqValue, Vec<u8>) {
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(class), body.clone()]),
        Limits::CEILING,
    )
    .unwrap();
    (
        EqValue::Bytes(context_digest("access/claim-body/v1", &tagged).0.to_vec()),
        dcbor::encode(body, Limits::CEILING).unwrap(),
    )
}

/// The value and body bytes of a Kernel-tabled Claim body.
fn tabled_body(body: &Body) -> (EqValue, Vec<u8>) {
    let class = match body {
        Body::Authentication(_) => Class::Authentication,
        Body::EffectAttestation(_) => Class::EffectAttestation,
        Body::VerifierProfile(_) => Class::VerifierProfile,
        _ => panic!("not a seam body"),
    };
    let v = body.to_value();
    (
        EqValue::Bytes(body_digest(class, &v).unwrap().to_vec()),
        dcbor::encode(&v, Limits::CEILING).unwrap(),
    )
}

/// An amount in kuruş as the `amount` parameter.
fn amount(kurus: i64) -> BTreeMap<String, ParamValue> {
    BTreeMap::from([(
        String::from("amount"),
        ParamValue::Amount {
            value: kurus,
            unit: String::from("try"),
        },
    )])
}

/// At most `max` kuruş per use.
fn at_most(max: i64) -> BTreeMap<String, Bound> {
    BTreeMap::from([(
        String::from("amount"),
        Bound::Range {
            min: Some(0),
            max: Some(max),
            unit: String::from("try"),
        },
    )])
}

/// An authority budget of `capacity` kuruş over the Grant's life.
fn budget(capacity: u64) -> BTreeSet<BudgetTerm> {
    BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Amount(String::from("try")),
        capacity,
        window: BudgetWindow::Total,
    }])
}

/// The decision's `outcome` and the classes of its blockers.
fn blocked(v: &Json) -> (String, Vec<String>) {
    let outcome = v["context"]["outcome"].as_str().unwrap_or("").to_owned();
    let classes = v["context"]["blockers"]
        .as_array()
        .map(|b| {
            b.iter()
                .filter_map(|x| x["class"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    (outcome, classes)
}
mod surfaces;
