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

impl Console {
    /// A `check` context for the drafted `ask`, signed in the browser on `basis`.
    pub(super) async fn check_context(
        &self,
        ask: &serde_json::Value,
        basis: ExerciseBasis,
    ) -> serde_json::Value {
        let (status, draft) = self.draft(ask).await;
        assert_eq!(status, StatusCode::OK, "{draft}");
        let digest = envelope_digest(draft["envelope"].as_str().unwrap());
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let ais = self.browser.ais_for(
            crate::console::CONSOLE_PEP,
            self.domain,
            &nonce,
            digest,
            Mode::Check,
            basis,
        );
        serde_json::json!({
            "domain": b64url_encode(&self.domain.0),
            "mode": "check",
            "nonce": b64url_encode(&nonce),
            "intent": draft["intent"],
            "basis": basis_json(basis),
            "capacity": "own",
            "ais": ais,
        })
    }

    /// One search page of `kind` through the BFF, as the browser asks it.
    pub(super) async fn search(&self, kind: &str, query: serde_json::Value) -> serde_json::Value {
        let ask = serde_json::json!({
            "action": { "namespace": "access", "name": "read", "major": 1 },
            "resources": [{ "namespace": "access.search", "path": [kind] }],
            "mode": "check",
        });
        let mut context = self.check_context(&ask, self.meta_anchor()).await;
        context["query"] = query;
        let (r, out) = send(
            &self.management,
            self.browser
                .request(
                    &Method::POST,
                    &format!("/console/api/proxy/adp/search/{kind}"),
                    "x",
                )
                .body(Body::from(
                    serde_json::json!({ "context": context }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{kind}: {}",
            String::from_utf8_lossy(&out)
        );
        serde_json::from_slice(&out).unwrap()
    }

    pub(super) async fn post(&self, path: &str, body: &serde_json::Value) -> Written {
        let (r, out) = send(
            &self.management,
            self.browser
                .request(&Method::POST, path, "x")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        Written {
            status: r.status(),
            body: serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
        }
    }
}

// §8.17.9.2, C28, E11, IA-2, IA-5, OP-152 m.7 (b), E17, XI-3, Ek B 3097, 3100, 3010, 3013, 3080
#[tokio::test]
async fn the_management_reads_answer_from_the_real_decision_point() {
    let c = console("mgmt-reads", true).await;
    let v1 = role(&[IdpAction::AccountSuspend]);
    let w = c
        .meta_write(
            "authority_set_define",
            serde_json::json!({ "authority_set_define": {
                "name": "helpdesk",
                "authority": authority_set_to_json(&v1).unwrap(),
            } }),
            c.meta_anchor(),
        )
        .await;
    assert_eq!(w.body["decision"], true, "{}", w.body);

    let roles = c.search("roles", serde_json::json!({})).await;
    assert_eq!(
        roles["results"][0]["roles"],
        serde_json::json!([{ "name": "helpdesk", "latest": 1 }])
    );
    let r = c
        .search("role", serde_json::json!({ "name": "helpdesk" }))
        .await;
    let version = &r["results"][0];
    assert_eq!(version["version"], 1);
    assert_eq!(version["authority"], authority_set_to_json(&v1).unwrap());
    assert!(version["not_included"]["reserved"].is_array());

    // §8.17.9.2
    let admin = AuthoritySet {
        actions: ActionSet {
            exact: [
                "grant_amend",
                "grant_revoke",
                "acceptance_amend",
                "anchor_amend",
            ]
            .into_iter()
            .map(kmeta::core_action)
            .collect(),
            prefix: std::collections::BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("access.grant"),
            prefix: Vec::new(),
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        params: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
    };
    let issue = serde_json::json!({ "grant_issue": {
        "basis": { "anchor": b64url_encode(&kmeta::meta_anchor(&c.domain).0) },
        "holder": { "party": b64url_encode(&c.root.0) },
        "authority": canonical_authority_to_json(&canonical(admin)).unwrap(),
    } });
    let w = c.meta_write("grant_issue", issue, c.meta_anchor()).await;
    assert_eq!(w.body["decision"], true, "{}", w.body);
    let grant = kmeta::object_id(&exercise_of(&w), kind::GRANT, 0);
    let view = c
        .search(
            "admin-grant",
            serde_json::json!({ "grant": b64url_encode(&grant.0) }),
        )
        .await;
    let view = &view["results"][0];
    let names = |list: &serde_json::Value| -> Vec<String> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|l| l["action"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(names(&view["actions"]), ["grant_amend", "grant_revoke"]);
    assert_eq!(
        names(&view["reserved"]),
        ["anchor_amend", "acceptance_amend"]
    );

    // IA-5, OP-152 m.7 (b)
    assert!(c.w.domains.derive().await.is_empty());
    let holdings = c.search("holdings", serde_json::json!({})).await;
    let held = holdings["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["grant"] == b64url_encode(&grant.0))
        .cloned()
        .unwrap();
    assert_eq!(held["holder"], b64url_encode(&c.root.0));
    let since = held["since"].as_u64().unwrap();
    let probe = serde_json::json!({
        "action": { "namespace": "access", "name": "grant_revoke", "major": 1 },
        "resources": [{ "namespace": "access.grant", "path": ["acme"] }],
        "mode": "check",
    });
    let (_, draft) = c.draft(&probe).await;
    let set = serde_json::json!({
        "domain": b64url_encode(&c.domain.0),
        "intent": draft["intent"],
        "basis": { "holding": {
            "grant": b64url_encode(&grant.0),
            "holder": b64url_encode(&c.root.0),
            "since": since,
        } },
        "capacity": "own",
    });
    let e = c
        .post(
            "/console/api/proxy/adp/eligibility:check",
            &serde_json::json!({ "subject": b64url_encode(&c.root.0), "set": set }),
        )
        .await;
    assert_eq!(e.status, StatusCode::OK, "{}", e.body);
    assert_eq!(e.body["eligible"], true, "{}", e.body);

    // IA-2
    let changes = c.search("changes", serde_json::json!({})).await;
    let rows = changes["results"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|r| r["kind"] == "authority_set" && r["id"] == "helpdesk" && r["version"] == 1),
        "{changes}"
    );
    assert!(
        rows.iter().any(|r| r["kind"] == "grant"
            && r["id"] == b64url_encode(&grant.0)
            && r["own"] == true),
        "{changes}"
    );
    assert!(rows.iter().all(|r| r.get("action_required").is_none()));

    // E17, XI-3
    let bulk = c
        .search(
            "bulk-impact",
            serde_json::json!({ "revoke": [b64url_encode(&grant.0)] }),
        )
        .await;
    let bulk = &bulk["results"][0];
    assert_eq!(bulk["type"], "bulk_impact");
    assert_eq!(bulk["aftermath"]["grants_ending"], 1);
    assert_eq!(bulk["items"].as_array().unwrap().len(), 1);
}

// §8.17.10.2, X21, E10, E12, L1-ADP-18, Ek B 3104, 3105, 3106, 3107
#[tokio::test]
async fn a_publisher_publishes_and_sees_pending_acceptance_without_an_accept() {
    let c = console("mgmt-publish", true).await;
    let namespace = "idp.account";
    let package = serde_json::json!({
        "namespace": namespace,
        "catalog_version": access_internal_api::idp::CATALOG_VERSION + 1,
        "actions": [{ "name": "suspend", "major": 1, "effect_class": "reversible" }],
        "classes": [],
    });
    let ask = serde_json::json!({
        "action": { "namespace": "access", "name": "publish", "major": 1 },
        "resources": [{ "namespace": "access.publication", "path": [namespace] }],
        "package": package,
        "mode": "check",
    });
    let before = c.w.domains.head(c.domain).await.unwrap().0;
    let domains = serde_json::json!([b64url_encode(&c.domain.0)]);
    let anonymous = serde_json::json!({
        "context": {
            "domain": b64url_encode(&c.domain.0),
            "mode": "check",
            "nonce": b64url_encode(&[7; 16]),
            "intent": c.draft(&ask).await.1["intent"],
            "basis": basis_json(c.meta_anchor()),
            "capacity": "own",
        },
        "package": package,
        "domains": domains,
    });
    let w = c
        .post("/console/api/proxy/adp/publications", &anonymous)
        .await;
    assert_eq!(w.status, StatusCode::UNAUTHORIZED, "{}", w.body);

    // E12
    let mut unmappable = package.clone();
    unmappable["actions"][0]["params"] = serde_json::json!({ "note": "text" });
    unmappable["classes"] =
        serde_json::json!([{ "action": "suspend", "parameter": "note", "class": "recipient" }]);
    let mut wrong = ask.clone();
    wrong["package"] = unmappable.clone();
    let context = c.check_context(&wrong, c.meta_anchor()).await;
    let w = c
        .post(
            "/console/api/proxy/adp/publications",
            &serde_json::json!({ "context": context, "package": unmappable, "domains": domains }),
        )
        .await;
    assert_eq!(w.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", w.body);
    assert_eq!(w.body["warnings"][0]["reason"], "affects_recipient");

    let context = c.check_context(&ask, c.meta_anchor()).await;
    let w = c
        .post(
            "/console/api/proxy/adp/publications",
            &serde_json::json!({ "context": context, "package": package, "domains": domains }),
        )
        .await;
    assert_eq!(w.status, StatusCode::CREATED, "{}", w.body);
    assert_eq!(w.body["publisher"], b64url_encode(&c.root.0));
    assert_eq!(w.body["existing_grants_unchanged"], true);
    let fingerprint = w.body["fingerprint"].clone();

    // X21
    let status_ask = serde_json::json!({
        "action": { "namespace": "access", "name": "read", "major": 1 },
        "resources": [{ "namespace": "access.publication", "path": [namespace] }],
        "mode": "check",
    });
    let context = c.check_context(&status_ask, c.meta_anchor()).await;
    let s = c
        .post(
            "/console/api/proxy/adp/publications:status",
            &serde_json::json!({ "context": context, "fingerprint": fingerprint, "domains": domains }),
        )
        .await;
    assert_eq!(s.status, StatusCode::OK, "{}", s.body);
    assert_eq!(s.body["pending_acceptance"], domains);
    assert_eq!(s.body["accepted_in"], serde_json::json!([]));
    let offers = c
        .search(
            "schema-publications",
            serde_json::json!({ "namespace": namespace }),
        )
        .await;
    assert_eq!(offers["results"][0]["standing"], "pending_acceptance");
    assert_eq!(c.w.domains.head(c.domain).await.unwrap().0, before);
}
