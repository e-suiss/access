//! Meta-action writes from the console end to end (OP-151 m.20 (b), OP-152 m.7 (d), Ek B 3097,
//! 3098, 3100): the BFF drafts each write with its payload, the browser signs the commit and the
//! BFF forwards it to the real decision point, which records it on the domain's log.

use access_http::adp::payload::{authority_set_to_json, canonical_authority_to_json};
use access_internal_api::idp::IdpAction;
use access_kernel::meta::{self as kmeta, ExerciseBasis, kind};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, Window,
};

use super::*;

/// What a committed write answered.
pub(super) struct Written {
    pub(super) status: StatusCode,
    pub(super) body: serde_json::Value,
}

impl Console {
    /// The browser's read proof for the draft route.
    pub(super) fn draft_proof(&self) -> String {
        let basis = ExerciseBasis::Anchor(kmeta::object_id(&self.domain, kind::ANCHOR, IDP_ANCHOR));
        self.browser.ais(
            self.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, "/console/api/intents"),
            Mode::Check,
            basis,
        )
    }

    /// Drafts `ask` through the BFF.
    pub(super) async fn draft(&self, ask: &serde_json::Value) -> (StatusCode, serde_json::Value) {
        let (r, body) = send(
            &self.management,
            self.browser
                .request(&Method::POST, "/console/api/intents", "x")
                .header("x-access-ais", self.draft_proof())
                .body(Body::from(ask.to_string()))
                .unwrap(),
        )
        .await;
        (
            r.status(),
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Drafts the meta write `name` with `payload`, signs its commit on `basis` in the browser
    /// and sends it through the BFF to ADP.
    pub(super) async fn meta_write(
        &self,
        name: &str,
        payload: serde_json::Value,
        basis: ExerciseBasis,
    ) -> Written {
        let (status, draft) = self
            .draft(&serde_json::json!({
                "action": { "namespace": "access", "name": name, "major": 1 },
                "payload": payload,
                "mode": "commit",
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "{name}: {draft}");
        let digest = envelope_digest(draft["envelope"].as_str().unwrap());
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let ais = self.browser.ais_for(
            crate::console::CONSOLE_PEP,
            self.domain,
            &nonce,
            digest,
            Mode::Commit,
            basis,
        );
        let resource = &draft["intent"]["resources"][0];
        let body = serde_json::json!({
            "subject": { "type": "access_party", "id": b64url_encode(&self.root.0) },
            "action": { "name": name },
            "resource": {
                "type": resource["namespace"],
                "id": resource["path"][0],
            },
            "context": {
                "domain": b64url_encode(&self.domain.0),
                "mode": "commit",
                "nonce": b64url_encode(&nonce),
                "intent": draft["intent"],
                "payload": draft["payload"],
                "basis": basis_json(basis),
                "capacity": "own",
                "ais": ais,
            },
        });
        let (r, out) = send(
            &self.management,
            self.browser
                .request(&Method::POST, "/console/api/proxy/adp/evaluation", "x")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        Written {
            status: r.status(),
            body: serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
        }
    }

    pub(super) fn idp_anchor(&self) -> ExerciseBasis {
        ExerciseBasis::Anchor(kmeta::object_id(&self.domain, kind::ANCHOR, IDP_ANCHOR))
    }

    pub(super) fn meta_anchor(&self) -> ExerciseBasis {
        ExerciseBasis::Anchor(kmeta::meta_anchor(&self.domain))
    }
}

pub(super) fn basis_json(b: ExerciseBasis) -> serde_json::Value {
    match b {
        ExerciseBasis::Anchor(a) => serde_json::json!({ "anchor": b64url_encode(&a.0) }),
        ExerciseBasis::Public(g) => serde_json::json!({ "public": b64url_encode(&g.0) }),
        ExerciseBasis::Holding(h) => serde_json::json!({ "holding": {
            "grant": b64url_encode(&h.grant.0),
            "holder": b64url_encode(&h.holder.0),
            "since": h.since,
        } }),
    }
}

/// A role over `actions` on the realm's `idp` resources.
pub(super) fn role(actions: &[IdpAction]) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: actions.iter().map(|a| a.action_ref()).collect(),
            prefix: std::collections::BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
            prefix: vec![String::from("acme")],
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        params: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

pub(super) fn canonical(set: AuthoritySet) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: set,
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: now() + 86_400_000,
            },
            conditions: std::collections::BTreeSet::new(),
            budget: std::collections::BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements: std::collections::BTreeSet::new(),
    }
}

pub(super) fn exercise_of(w: &Written) -> Digest {
    let b = b64url_decode(w.body["context"]["exercise"].as_str().unwrap()).unwrap();
    Digest(<[u8; 32]>::try_from(b.as_slice()).unwrap())
}

// OP-151 m.20 (b), OP-152 m.7 (d), TN-110, C28, X20, Ek B 3097, 3098
#[tokio::test]
async fn the_console_defines_a_role_and_moves_its_delegation_through_the_sequencer() {
    let c = console("mgmt-meta", true).await;
    let before = c.w.domains.head(c.domain).await.unwrap().0;
    let v1 = role(&[IdpAction::AccountSuspend, IdpAction::AccountReactivate]);
    let define = |set: &AuthoritySet| {
        serde_json::json!({ "authority_set_define": {
            "name": "helpdesk",
            "authority": authority_set_to_json(set).unwrap(),
        } })
    };
    let w = c
        .meta_write("authority_set_define", define(&v1), c.meta_anchor())
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    assert_eq!(w.body["decision"], true, "{}", w.body);
    let v2 = role(&[IdpAction::AccountSuspend]);
    let w = c
        .meta_write("authority_set_define", define(&v2), c.meta_anchor())
        .await;
    assert_eq!(w.body["decision"], true, "{}", w.body);

    let idp = kmeta::object_id(&c.domain, kind::ANCHOR, IDP_ANCHOR);
    let issue = serde_json::json!({ "grant_issue": {
        "basis": { "anchor": b64url_encode(&idp.0) },
        "holder": { "party": b64url_encode(&c.root.0) },
        "authority": canonical_authority_to_json(&canonical(v1.clone())).unwrap(),
        "named": {
            "name": "helpdesk",
            "version": 1,
            "digest": b64url_encode(&kmeta::authority_set_digest(&v1).0),
        },
    } });
    let w = c.meta_write("grant_issue", issue, c.idp_anchor()).await;
    assert_eq!(w.body["decision"], true, "{}", w.body);
    let grant: Id = kmeta::object_id(&exercise_of(&w), kind::GRANT, 0);

    // X20
    let amend = |set: &AuthoritySet, version: u64| {
        serde_json::json!({ "grant_amend": {
            "grant": b64url_encode(&grant.0),
            "authority": canonical_authority_to_json(&canonical(set.clone())).unwrap(),
            "agency": ["own"],
            "named": {
                "name": "helpdesk",
                "version": version,
                "digest": b64url_encode(&kmeta::authority_set_digest(set).0),
            },
        } })
    };
    let w = c
        .meta_write("grant_amend", amend(&v2, 2), c.idp_anchor())
        .await;
    assert_eq!(w.body["decision"], true, "{}", w.body);
    // INV-10, XI-4
    let w = c
        .meta_write("grant_amend", amend(&v1, 1), c.idp_anchor())
        .await;
    assert_eq!(w.body["context"]["outcome"], "require_action", "{}", w.body);
    assert!(
        w.body["context"]["blockers"][0]["remediation"]["wait_until"].is_u64(),
        "{}",
        w.body
    );

    let revoke = serde_json::json!({ "grant_revoke": { "grant": b64url_encode(&grant.0) } });
    let w = c
        .meta_write("grant_revoke", revoke.clone(), c.idp_anchor())
        .await;
    assert_eq!(w.body["decision"], true, "{}", w.body);
    let after = c.w.domains.head(c.domain).await.unwrap().0;
    assert!(after > before, "{after} > {before}");

    // TN-110
    let (status, draft) = c
        .draft(&serde_json::json!({
            "action": { "namespace": "access", "name": "grant_amend", "major": 1 },
            "payload": revoke,
            "mode": "commit",
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(draft["code"], "intent-payload-not-allowed");
}
