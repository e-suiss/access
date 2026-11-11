//! A product's Exercise at the ADP (§9.5, L1-ADP-5 to L1-ADP-12, OP-149 m.29 (b)): a `commit`
//! of an intent the test user's device Instance signs, sent to `POST /access/v1/evaluation`
//! with the PEP certificate, and the decision it gets back.

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::Id;
use access_kernel::verify::key_scope::thumbprint;
use serde_json::{Value, json};
use suiss_crypto::signer::{Signer, sign_sign1};

use crate::ClientError;
use crate::dpop::{now_ms, random_text};
use crate::http::Http;

/// The PEP name a client certificate gives its holder: the base64url SHA-256 of the leaf.
#[must_use]
pub fn pep_name(leaf_der: &[u8]) -> String {
    b64url_encode(&suiss_crypto::digest::sha256(leaf_der))
}

/// A `commit` of `intent` by the Party's device Instance.
pub struct Exercise<'a> {
    /// The deployment's API base, e.g. `https://access-server:8443`.
    pub api_base: &'a str,
    /// The governing domain.
    pub domain: Digest,
    /// The actor Party.
    pub party: Id,
    /// The Exercise nonce, 16 to 64 bytes.
    pub nonce: &'a [u8],
    /// The intent, as the Kernel reads it.
    pub intent: &'a IntentEnvelope,
    /// The intent, as the product wrote it (`context.intent`).
    pub intent_json: &'a Value,
    /// The actor's holding of the Grant.
    pub basis: HoldingRef,
    /// Whose behalf the actor acts on: its own, or `For` the person a support Grant names.
    pub capacity: Capacity,
    /// Proof objects (L1-ADP-12), such as `{"contribution": "<exercise>"}`.
    pub proofs: Vec<Value>,
    /// The PEP certificate's leaf, DER.
    pub pep_leaf_der: &'a [u8],
    /// The device Instance key that signs the AIS.
    pub device: &'a dyn Signer,
}

/// A holding basis in the ADP JSON encoding.
#[must_use]
pub fn holding_json(h: &HoldingRef) -> Value {
    json!({
        "holding": {
            "grant": b64url_encode(&h.grant.0),
            "holder": b64url_encode(&h.holder.0),
            "since": h.since,
        }
    })
}

/// The AIS of `statement` under `device` (L2-SIG-1): a tagged `COSE_Sign1` with the key's
/// thumbprint as `kid`.
///
/// # Errors
/// [`ClientError`].
pub fn ais(device: &dyn Signer, statement: &Statement) -> Result<Vec<u8>, ClientError> {
    let payload = statement.to_bytes().map_err(|_| ClientError::Encode)?;
    sign_sign1(
        device,
        thumbprint(&device.public_key()),
        CONTENT_TYPE,
        &payload,
    )
    .map_err(|e| ClientError::Key(format!("ais: {}", e.code())))
}

/// The evaluation body (L1-ADP-5): the `AuthZEN` carriers and the `context` with the request.
///
/// # Errors
/// [`ClientError`].
pub fn body(e: &Exercise<'_>) -> Result<Value, ClientError> {
    let digest = intent_digest(e.intent).map_err(|_| ClientError::Encode)?;
    let first = e.intent.resources.first().ok_or(ClientError::Encode)?;
    let statement = Statement {
        domain: e.domain,
        nonce: e.nonce.to_vec(),
        intent: digest,
        mode: Mode::Commit,
        pep: pep_name(e.pep_leaf_der),
        capacity: e.capacity,
        basis: ExerciseBasis::Holding(e.basis),
        iat: now_ms(),
        exercise: None,
    };
    let mut context = json!({
        "domain": b64url_encode(&e.domain.0),
        "mode": "commit",
        "nonce": b64url_encode(e.nonce),
        "intent": e.intent_json,
        "basis": holding_json(&e.basis),
        "capacity": match e.capacity {
            Capacity::Own => json!("own"),
            Capacity::For(p) => json!({ "for": b64url_encode(&p.0) }),
        },
        "ais": b64url_encode(&ais(e.device, &statement)?),
    });
    if let (false, Some(c)) = (e.proofs.is_empty(), context.as_object_mut()) {
        c.insert(String::from("proofs"), Value::Array(e.proofs.clone()));
    }
    Ok(json!({
        "subject": { "type": "access_party", "id": b64url_encode(&e.party.0) },
        "action": { "name": e.intent.action.name },
        "resource": { "type": first.namespace, "id": first.path.join("/") },
        "context": context,
    }))
}

/// Commits the Exercise and returns the decision as the ADP answered it (L1-ADP-10).
///
/// # Errors
/// [`ClientError`]; anything but a decision is [`ClientError::Unexpected`].
pub async fn commit(http: &Http, e: &Exercise<'_>) -> Result<Value, ClientError> {
    let body = body(e)?.to_string();
    let key = random_text::<16>()?;
    let r = http
        .request(
            "POST",
            &format!("{}/access/v1/evaluation", e.api_base),
            &[("Idempotency-Key", key.as_str())],
            Some(("application/json", body.as_bytes())),
        )
        .await?;
    if r.status == 200 {
        Ok(r.json())
    } else {
        Err(ClientError::Unexpected {
            step: "evaluation",
            status: r.status,
            body: r.text(),
        })
    }
}

/// The outcome a decision carries: `allow`, `deny` or `require_action`.
#[must_use]
pub fn outcome(decision: &Value) -> Option<&str> {
    decision
        .get("context")
        .and_then(|c| c.get("outcome"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use std::collections::BTreeMap;

    use access_kernel::intent::ContextRefs;
    use access_kernel::json::b64url_decode;
    use access_kernel::model::{ActionRef, ResourceRef, Window};
    use access_kernel::verify::cose::KeySet;
    use suiss_crypto::signer::SoftSigner;

    use super::*;

    // L1-ADP-5, L1-ADP-8, L2-SIG-1, OP-141 m.18 (b)
    #[test]
    fn the_evaluation_body_carries_a_signed_commit() {
        let (device, _) = SoftSigner::generate_ed25519().unwrap();
        let intent = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: ActionRef {
                namespace: "work".into(),
                name: "commit".into(),
                major: 1,
                schema: Digest([1; 32]),
            },
            resources: vec![ResourceRef {
                namespace: "work".into(),
                path: vec!["ledgers".into(), "main".into()],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window { from: 1, until: 2 },
        };
        let leaf = [0x11_u8; 20];
        let e = Exercise {
            api_base: "https://access-server:8443",
            domain: Digest([2; 32]),
            party: Id([3; 16]),
            nonce: &[4; 16],
            intent: &intent,
            intent_json: &json!({ "as": "written" }),
            basis: HoldingRef {
                grant: Id([5; 16]),
                holder: Id([3; 16]),
                since: 7,
            },
            capacity: Capacity::Own,
            proofs: vec![json!({ "contribution": b64url_encode(&[6; 32]) })],
            pep_leaf_der: &leaf,
            device: &device,
        };
        let b = body(&e).unwrap();
        assert_eq!(b["action"]["name"], "commit");
        assert_eq!(b["resource"]["type"], "work");
        assert_eq!(b["resource"]["id"], "ledgers/main");
        assert_eq!(b["context"]["mode"], "commit");
        assert_eq!(b["context"]["intent"]["as"], "written");
        assert_eq!(b["context"]["basis"]["holding"]["since"], 7);
        assert_eq!(
            b["context"]["proofs"][0]["contribution"],
            b64url_encode(&[6; 32])
        );
        let ais = b64url_decode(b["context"]["ais"].as_str().unwrap()).unwrap();
        let key = device.public_key();
        let mut keys = KeySet::default();
        keys.insert(thumbprint(&key), key).unwrap();
        keys.allowed
            .insert(access_kernel::verify::cose::Algorithm::Ed25519);
        let verified = access_kernel::verify::cose::verify_sign1(
            &access_kernel::verify::PureBackend,
            &ais,
            &keys,
            CONTENT_TYPE,
        )
        .unwrap();
        let statement = Statement::from_bytes(&verified.payload).unwrap();
        assert_eq!(statement.pep, pep_name(&leaf));
        assert_eq!(statement.intent, intent_digest(&intent).unwrap());
        assert_eq!(statement.nonce, vec![4; 16]);
        assert_eq!(statement.basis, ExerciseBasis::Holding(e.basis));
        assert_eq!(
            outcome(&json!({ "decision": false, "context": { "outcome": "require_action" } })),
            Some("require_action")
        );
    }
}
