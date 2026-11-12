//! The `AuthZEN` 1.0 PDP checklist (§9.5.1, P35, OP-155 m.3 (q), Ek B 5075) and ADP CBOR (Ek B
//! 5076) through the real ADP router, hardened as the server serves it, on the real sequencer,
//! store and authority signer: an admin-created realm whose root acts with its own key, one test
//! per checklist item.

use access_http::adp::adapters::{Discovery, Pep, router as adp_router};
use access_http::adp::app::Service;
use access_http::{Limits, harden};
use access_internal_api::idp::IdpAction;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::ResourceRef;
use access_sdk::authorize::{Actor, ExerciseRequest, adp_body};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
use serde_json::{Value as Json, json};
use tower::ServiceExt as _;

use super::*;

mod pep_token;

/// The PEP the TLS layer names by its certificate (OP-141 m.18 (b)).
pub(super) const PEP: &str = "authzen-pep";

const ISSUER: &str = "https://access.test";

const SLUG: &str = "authzen";

/// A realm, its root and the ADP router over its domain.
pub(super) struct Pdp {
    pub(super) w: World,
    pub(super) domain: Digest,
    pub(super) root: HsmSigner,
    pub(super) party: Id,
    pub(super) adp: axum::Router,
    /// The root's holding of its audit Grant.
    pub(super) audit: HoldingRef,
    _signer: AuthoritySigner,
}

/// The realm `authzen`, created by the admin path with the bootstrap root as founder, the root
/// onboarded and holding a Grant to read the audit stream; the ADP router hardened as served.
pub(super) async fn pdp(label: &str) -> Pdp {
    pdp_timed(label, None).await
}

/// [`pdp`] whose realm has the CT3 time-lock `ct3_delay_s`; a test domain's is zero
/// (OP-153 m.7 (a)).
pub(super) async fn pdp_timed(label: &str, ct3_delay_s: Option<u64>) -> Pdp {
    pdp_with(
        label,
        ct3_delay_s,
        Arc::new(access_authority_core::ports::NoAnalysis),
    )
    .await
}

/// [`pdp_timed`] with `analysis` behind the `policy.set` analysis port (OP-159 m.3 (aa)).
pub(super) async fn pdp_with(
    label: &str,
    ct3_delay_s: Option<u64>,
    analysis: Arc<dyn access_authority_core::ports::PolicyAnalysis>,
) -> Pdp {
    let (w, signer) = World::open_analysed(label, true, None, fresh().await.unwrap(), analysis);
    let signer = signer.unwrap();
    schedule(&signer);
    let (tenant, created) = w.admin_realm_timed(SLUG, ct3_delay_s).await;
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    let declared = DeclaredTargets::default();
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
        console: None,
    };
    schedule(&signer);
    bootstrap
        .onboard(tenant, created.realm, created.domain, &root, party)
        .await
        .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let since = bootstrap
        .commit_meta(
            created.domain,
            &root,
            &nonce,
            Payload::GrantIssue(audit_grant(&created.domain, party)),
            party,
        )
        .await
        .unwrap();
    let audit = HoldingRef {
        grant: meta::object_id(
            &meta::exercise_id(&created.domain, &nonce).unwrap(),
            kind::GRANT,
            0,
        ),
        holder: party,
        since,
    };
    assert!(w.domains.derive().await.is_empty());
    schedule(&signer);
    let limits = Limits::default();
    let adp = harden(
        adp_router(
            Service::new(w.domains.clone(), limits.max_body_bytes),
            Discovery {
                issuer: String::from(ISSUER),
            },
        ),
        limits,
    );
    Pdp {
        domain: created.domain,
        w,
        root,
        party,
        adp,
        audit,
        _signer: signer,
    }
}

/// The root's Grant to read the audit stream, under the meta-anchor.
fn audit_grant(domain: &Digest, party: Id) -> GrantContent {
    grant_of(
        domain,
        party,
        authority(
            BTreeSet::from([meta::core_action("read")]),
            "access.audit",
            BTreeSet::new(),
        ),
    )
}

/// A sent request's status, headers and body.
pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

impl Answer {
    pub(super) fn json(&self) -> Json {
        serde_json::from_slice(&self.body).unwrap_or(Json::Null)
    }
}

impl Pdp {
    pub(super) async fn now(&self) -> u64 {
        server_time(&self.w.db.app).await.unwrap()
    }

    /// An `idp` action of the root on `kind` in this realm, under the IDP anchor.
    pub(super) async fn idp_intent(&self, action: IdpAction, kind: &str) -> IntentEnvelope {
        let at = Moment::at(self.now().await);
        IntentEnvelope {
            provenance: BTreeMap::new(),
            action: action.action_ref(),
            resources: vec![ResourceRef {
                namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
                path: vec![String::from(SLUG), String::from(kind)],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: at.validity,
        }
    }

    /// A search reader's intent: `access.read` on `access.search/<kind>`.
    pub(super) async fn search_intent(&self, kind: &str) -> IntentEnvelope {
        let mut i = self.idp_intent(IdpAction::ClientRegister, kind).await;
        i.action = meta::core_action("read");
        i.resources = vec![ResourceRef {
            namespace: String::from("access.search"),
            path: vec![String::from(kind)],
            incarnation: 0,
        }];
        i
    }

    pub(super) fn idp_basis(&self) -> ExerciseBasis {
        ExerciseBasis::Anchor(meta::object_id(&self.domain, kind::ANCHOR, IDP_ANCHOR))
    }

    /// The root's ADP body for `intent` in `mode` on `basis`, its AIS naming `pep`.
    pub(super) async fn body(
        &self,
        mode: Mode,
        nonce: &[u8],
        intent: &IntentEnvelope,
        basis: ExerciseBasis,
        pep: &str,
    ) -> Json {
        let digest = intent_digest(intent).unwrap();
        let ais = sign(
            &self.root,
            &Statement {
                domain: self.domain,
                nonce: nonce.to_vec(),
                intent: digest,
                mode,
                pep: String::from(pep),
                capacity: Capacity::Own,
                basis,
                iat: self.now().await,
                exercise: None,
            },
        )
        .unwrap();
        let body = adp_body(&ExerciseRequest {
            domain: &self.domain,
            mode,
            nonce,
            intent: &digest,
            envelope: Some(intent),
            actor: &Actor::Statement(ais),
            basis: &basis,
            capacity: Capacity::Own,
            pep,
            exercise: None,
        })
        .unwrap();
        serde_json::from_str(&body).unwrap()
    }

    /// An evaluation body of the root's `ClientRegister` on the IDP anchor, `mode`, fresh nonce.
    pub(super) async fn allowed(&self, mode: Mode) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let intent = self.idp_intent(IdpAction::ClientRegister, "client").await;
        self.body(mode, &nonce, &intent, self.idp_basis(), PEP)
            .await
    }

    /// The same action on a basis that does not cover it: the audit Grant.
    pub(super) async fn denied(&self, mode: Mode) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let intent = self.idp_intent(IdpAction::ClientRegister, "client").await;
        let basis = ExerciseBasis::Holding(self.audit);
        self.body(mode, &nonce, &intent, basis, PEP).await
    }

    /// A search body of `kind` read by the root with `query`.
    pub(super) async fn search(&self, kind: &str, query: Json) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let intent = self.search_intent(kind).await;
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.domain));
        let mut body = self.body(Mode::Check, &nonce, &intent, basis, PEP).await;
        body["context"]["query"] = query;
        body
    }

    /// Sends `bytes` to `path` as the PEP `pep` with `headers`.
    pub(super) async fn send(
        &self,
        path: &str,
        bytes: Vec<u8>,
        headers: &[(&str, &str)],
        pep: Option<&str>,
    ) -> Answer {
        let mut b = HttpRequest::post(path);
        if bytes.is_empty() {
            b = HttpRequest::get(path);
        }
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            && !bytes.is_empty()
        {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(Body::from(bytes)).unwrap();
        if let Some(p) = pep {
            req.extensions_mut().insert(Pep(String::from(p)));
        }
        let r = self.adp.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
        Answer {
            status,
            headers,
            body,
        }
    }

    /// The nonce row the decision on `body` recorded.
    pub(super) async fn recorded(&self, body: &Json) -> access_store::authority::NonceRow {
        let nonce =
            access_kernel::json::b64url_decode(body["context"]["nonce"].as_str().unwrap()).unwrap();
        find_nonce(&self.w.db.app, &DomainId::from_bytes(self.domain.0), &nonce)
            .await
            .unwrap()
            .unwrap()
    }

    pub(super) async fn post(&self, path: &str, body: &Json) -> Answer {
        self.send(path, body.to_string().into_bytes(), &[], Some(PEP))
            .await
    }
}

// §9.5.1 m.1, L1-ADP-1, L1-ADP-2, Ek B 5075
#[tokio::test]
async fn authzen_1_evaluation_commits_through_the_real_core() {
    let p = pdp("az-evaluation").await;
    let before = p.w.domains.head(p.domain).await.unwrap().0;
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(v["context"]["outcome"], "allow", "{v}");
    assert!(v["context"]["exercise"].is_string(), "{v}");
    assert!(p.w.domains.head(p.domain).await.unwrap().0 > before);
    let check = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Check).await)
        .await
        .json();
    assert_eq!(check["decision"], true, "{check}");
    assert_eq!(check["context"]["advisory"], true, "{check}");
    p.w.domains.release().await;
}

// §9.5.1 m.2, OP-141 m.22 (a), §9.7.1, Ek B 5075
#[tokio::test]
async fn authzen_2_evaluations_answer_each_item_under_three_semantics() {
    let p = pdp("az-evaluations").await;
    let one = p.allowed(Mode::Check).await;
    let allow = one["context"].clone();
    let deny = p.denied(Mode::Check).await["context"].clone();
    let batch = |semantic: &str, items: &[&Json]| {
        json!({
            "subject": one["subject"],
            "action": one["action"],
            "resource": one["resource"],
            "options": { "evaluations_semantic": semantic },
            "evaluations": items.iter().map(|c| json!({ "context": c })).collect::<Vec<_>>(),
        })
    };
    let all = p
        .post(
            "/access/v1/evaluations",
            &batch("execute_all", &[&allow, &deny]),
        )
        .await
        .json();
    let decisions: Vec<_> = all["evaluations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["decision"].clone())
        .collect();
    assert_eq!(decisions, vec![json!(true), json!(false)], "{all}");
    let first_deny = p
        .post(
            "/access/v1/evaluations",
            &batch("deny_on_first_deny", &[&deny, &allow]),
        )
        .await
        .json();
    assert_eq!(
        first_deny["evaluations"][0]["decision"], false,
        "{first_deny}"
    );
    assert_eq!(
        first_deny["evaluations"][1],
        json!({ "evaluated": false }),
        "{first_deny}"
    );
    let first_permit = p
        .post(
            "/access/v1/evaluations",
            &batch("permit_on_first_permit", &[&allow, &deny]),
        )
        .await
        .json();
    assert_eq!(first_permit["evaluations"][0]["decision"], true);
    assert_eq!(
        first_permit["evaluations"][1],
        json!({ "evaluated": false })
    );
    p.w.domains.release().await;
}

/// The root's search of `kind` with `query`, its hits.
async fn hits(p: &Pdp, kind: &str, query: Json) -> Json {
    let a = p
        .post(
            &format!("/access/v1/search/{kind}"),
            &p.search(kind, query).await,
        )
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{kind}: {v}");
    v
}

fn read_action() -> Json {
    let a = meta::core_action("read");
    json!({
        "namespace": a.namespace,
        "name": a.name,
        "major": a.major,
        "schema": b64url_encode(&a.schema.0),
    })
}

// §9.5.1 m.3, L1-ADP-16, OP-141 m.22 (b), Ek B 5075
#[tokio::test]
async fn authzen_3_resource_search_lists_what_the_reader_reaches() {
    let p = pdp("az-search-resource").await;
    let v = hits(
        &p,
        "resource",
        json!({ "party": b64url_encode(&p.party.0), "action": read_action() }),
    )
    .await;
    assert!(
        v.to_string().contains("access.audit"),
        "the root's audit Grant is listed: {v}"
    );
    p.w.domains.release().await;
}

// §9.5.1 m.4, L1-ADP-16, OP-141 m.22 (c), Ek B 5075
#[tokio::test]
async fn authzen_4_subject_search_lists_who_may_act() {
    let p = pdp("az-search-subject").await;
    let v = hits(
        &p,
        "subject",
        json!({
            "action": read_action(),
            "resource": { "namespace": "access.audit", "path": [SLUG] },
        }),
    )
    .await;
    assert!(
        v.to_string().contains(&b64url_encode(&p.party.0)),
        "the root is listed: {v}"
    );
    p.w.domains.release().await;
}

// §9.5.1 m.5, L1-ADP-16, Ek B 5075
#[tokio::test]
async fn authzen_5_action_search_lists_what_the_reader_may_do() {
    let p = pdp("az-search-action").await;
    let v = hits(
        &p,
        "action",
        json!({
            "party": b64url_encode(&p.party.0),
            "resource": { "namespace": "access.audit", "path": [SLUG] },
        }),
    )
    .await;
    assert!(v.to_string().contains("\"read\""), "read is listed: {v}");
    p.w.domains.release().await;
}

// §9.5.1 m.6, L1-ADP-11, AP-15, MD-3, Ek B 5075
#[tokio::test]
async fn authzen_6_discovery_names_the_pdp_and_carries_signed_metadata() {
    let p = pdp("az-discovery").await;
    let a = p
        .send("/.well-known/authzen-configuration", Vec::new(), &[], None)
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["policy_decision_point"], ISSUER);
    assert_eq!(
        v["access_evaluation_endpoint"],
        format!("{ISSUER}/access/v1/evaluation")
    );
    let caps = v["capabilities"].as_array().unwrap();
    for c in [
        "urn:suiss:access:adp:1",
        "urn:suiss:access:explain:1",
        "urn:suiss:access:consistency-token:1",
        "urn:suiss:access:adp-cbor:1",
    ] {
        assert!(caps.contains(&json!(c)), "{c}: {v}");
    }
    let text = access_kernel::foreign::domain_text(&p.domain);
    let a = p
        .send(
            &format!("/.well-known/authzen-configuration/{text}"),
            Vec::new(),
            &[],
            None,
        )
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["policy_decision_point"], format!("{ISSUER}/{text}"));
    let signed =
        access_kernel::json::b64url_decode(v["signed_metadata"].as_str().unwrap()).unwrap();
    let served = p
        .send(
            &format!("/.well-known/access-domain-metadata/{text}"),
            Vec::new(),
            &[],
            None,
        )
        .await;
    assert_eq!(served.status, StatusCode::OK);
    assert_eq!(served.body, signed);
    p.w.domains.release().await;
}

// §9.5.1 m.7, R2, INV-26, Ek B 5075
#[tokio::test]
async fn authzen_7_a_refusal_is_200_false_and_a_protocol_error_is_400() {
    let p = pdp("az-refusal").await;
    let a = p
        .post("/access/v1/evaluation", &p.denied(Mode::Commit).await)
        .await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], false, "{v}");
    assert_eq!(v["context"]["outcome"], "deny", "{v}");
    let after_deny = p.w.domains.head(p.domain).await.unwrap().0;
    let mut missing = p.allowed(Mode::Commit).await;
    missing["context"].as_object_mut().unwrap().remove("basis");
    let a = p.post("/access/v1/evaluation", &missing).await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.json());
    assert_eq!(a.headers[header::CONTENT_TYPE], "application/problem+json");
    let a = p
        .send(
            "/access/v1/evaluation",
            p.allowed(Mode::Commit).await.to_string().into_bytes(),
            &[],
            None,
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        p.w.domains.head(p.domain).await.unwrap().0,
        after_deny,
        "a protocol error and an unauthenticated PEP record nothing"
    );
    p.w.domains.release().await;
}

// §9.5.1 m.8, L1-ADP-4, Ek B 5075
#[tokio::test]
async fn authzen_8_the_request_id_is_echoed() {
    let p = pdp("az-request-id").await;
    let a = p
        .send(
            "/access/v1/evaluation",
            p.allowed(Mode::Check).await.to_string().into_bytes(),
            &[("x-request-id", "req-5075")],
            Some(PEP),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.headers["x-request-id"], "req-5075");
    let refused = p
        .send(
            "/access/v1/evaluation",
            b"{}".to_vec(),
            &[("x-request-id", "req-5075-bad")],
            Some(PEP),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.headers["x-request-id"], "req-5075-bad");
    p.w.domains.release().await;
}

// §9.5.1 m.9, L1-ADP-9, R7, P34, Ek B 5075
#[tokio::test]
async fn authzen_9_unknown_carrier_members_are_ignored_and_access_members_are_not() {
    let p = pdp("az-unknown").await;
    let mut body = p.allowed(Mode::Check).await;
    body["subject"]["properties"] = json!({ "department": "ops" });
    body["action"]["properties"] = json!({ "vendor": true });
    body["evaluation_hint"] = json!("ignored");
    let a = p.post("/access/v1/evaluation", &body).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.json());
    assert_eq!(a.json()["decision"], true);
    let mut must = p.allowed(Mode::Check).await;
    must["context"]["must_understand_this"] = json!(1);
    let a = p.post("/access/v1/evaluation", &must).await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.json());
    assert_eq!(a.json()["code"], "unknown-member");
    p.w.domains.release().await;
}

// §9.5.1 m.10, L1-ADP-2, OP-141 m.18 (b), OP-155 m.3 (q), Ek B 5075
#[tokio::test]
async fn authzen_10_only_an_authenticated_pep_is_heard() {
    let p = pdp("az-pep").await;
    let body = p.allowed(Mode::Check).await.to_string().into_bytes();
    let anonymous = p
        .send("/access/v1/evaluation", body.clone(), &[], None)
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.json()["code"], "pep-unauthenticated");
    let keyed = p
        .send(
            "/access/v1/evaluation",
            body.clone(),
            &[("x-api-key", "not-a-pep-credential")],
            None,
        )
        .await;
    assert_eq!(keyed.status, StatusCode::UNAUTHORIZED);
    let other = p
        .send(
            "/access/v1/evaluation",
            body.clone(),
            &[],
            Some("other-pep"),
        )
        .await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST, "{}", other.json());
    let heard = p.send("/access/v1/evaluation", body, &[], Some(PEP)).await;
    assert_eq!(heard.status, StatusCode::OK);
    p.w.domains.release().await;
}

// §9.5.1 m.11, RFC 7493, E12, Ek B 5075
#[tokio::test]
async fn authzen_11_only_i_json_is_read() {
    let p = pdp("az-ijson").await;
    let good = p.allowed(Mode::Check).await.to_string();
    let float = good.replacen("\"major\":1", "\"major\":1.0", 1);
    assert_ne!(float, good);
    let duplicate = good.replacen("{\"subject\"", "{\"subject\":{},\"subject\"", 1);
    assert_ne!(duplicate, good);
    let lone = good.replacen("\"client\"", "\"\\ud800\"", 1);
    assert_ne!(lone, good);
    for (name, body) in [("float", float), ("duplicate", duplicate), ("lone", lone)] {
        let a = p
            .send("/access/v1/evaluation", body.into_bytes(), &[], Some(PEP))
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{name}: {}", a.json());
    }
    p.w.domains.release().await;
}

// §9.5.1 m.12, §14.6, CR-10, Ek B 5075
#[tokio::test]
async fn authzen_12_oversized_and_deep_bodies_are_refused() {
    let p = pdp("az-dos").await;
    let mut big = p.allowed(Mode::Check).await;
    big["subject"]["properties"] = json!({ "pad": "x".repeat(Limits::default().max_body_bytes) });
    let a = p.post("/access/v1/evaluation", &big).await;
    assert_eq!(a.status, StatusCode::PAYLOAD_TOO_LARGE);
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let mut nested = p.allowed(Mode::Check).await.to_string();
    nested.insert_str(1, &format!("\"pad\":{deep},"));
    let a = p
        .send("/access/v1/evaluation", nested.into_bytes(), &[], Some(PEP))
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST);
    let a = p
        .send(
            "/access/v1/evaluation",
            b"{\"subject\":".to_vec(),
            &[],
            Some(PEP),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST);
    p.w.domains.release().await;
}

// §9.5.1 m.13, §9.6.1, P41, OP-141 m.38, Ek B 5075
#[tokio::test]
async fn authzen_13_reason_user_and_reason_admin_are_apart() {
    let p = pdp("az-reasons").await;
    let body = p.denied(Mode::Commit).await;
    let denied = p.post("/access/v1/evaluation", &body).await.json();
    assert_eq!(denied["decision"], false, "{denied}");
    assert_eq!(
        denied["context"]["reason_user"],
        json!(["no-covering-authority"]),
        "{denied}"
    );
    assert!(denied["context"].get("reason_admin").is_none(), "{denied}");
    let record = p.recorded(&body).await.decision_pos;
    let mut explain = body;
    explain["context"]["record"] = json!(record);
    explain["context"]["scope"] = json!("audit");
    let a = p.post("/access/v1/explain", &explain).await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["context"]["kind"], "recorded", "{v}");
    assert!(v["context"]["reason_admin"].is_object(), "{v}");
    p.w.domains.release().await;
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut h, b| {
        let _ = write!(h, "{b:02x}");
        h
    })
}

// OP-155 m.3 (q), §9.5.1, Ek B 5076
#[tokio::test]
async fn the_cbor_and_json_forms_give_the_same_decision_record() {
    use access_http::adp::cbor::{CONTENT_TYPE as CBOR, cbor_body};
    let p = pdp("az-cbor").await;
    let body = p.allowed(Mode::Commit).await;
    let cbor = cbor_body(body.to_string().as_bytes()).unwrap();
    let first = p
        .send(
            "/access/v1/evaluation",
            cbor,
            &[("content-type", CBOR)],
            Some(PEP),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.headers[header::CONTENT_TYPE], CBOR);
    let read =
        serde_json::from_slice::<Json>(&access_http::adp::cbor::json_body(&first.body).unwrap())
            .unwrap();
    assert_eq!(read["decision"], true, "{read}");
    let row = p.recorded(&body).await;
    let envelope = p.w.domains.head(p.domain).await.unwrap().0;
    let intent = access_http::adp::domain::decode(body.to_string().as_bytes(), 1 << 16)
        .unwrap()
        .request
        .intent;
    assert_eq!(row.intent_digest, intent_digest(&intent).unwrap().0);
    let log = access_store::authority::read_log(
        &p.w.db.app,
        &DomainId::from_bytes(p.domain.0),
        row.decision_pos,
        row.decision_pos,
    )
    .await
    .unwrap();
    let again = p.post("/access/v1/evaluation", &body).await;
    let json = again.json();
    assert_eq!(again.status, StatusCode::OK, "{json}");
    assert_eq!(json["context"]["replayed"], true, "{json}");
    assert_eq!(json["context"]["exercise"], read["context"]["exercise"]);
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, envelope);
    let replayed = p.recorded(&body).await;
    assert_eq!(replayed.decision_pos, row.decision_pos);
    let relog = access_store::authority::read_log(
        &p.w.db.app,
        &DomainId::from_bytes(p.domain.0),
        replayed.decision_pos,
        replayed.decision_pos,
    )
    .await
    .unwrap();
    assert_eq!(hex(&relog[0].leaf_hash), hex(&log[0].leaf_hash));
    let asked = p
        .send(
            "/access/v1/evaluation",
            p.allowed(Mode::Check).await.to_string().into_bytes(),
            &[("accept", CBOR)],
            Some(PEP),
        )
        .await;
    assert_eq!(asked.headers[header::CONTENT_TYPE], CBOR);
    let refused = p
        .send(
            "/access/v1/evaluation",
            vec![0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02],
            &[("content-type", CBOR)],
            Some(PEP),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.json()["code"], "cbor-key-order");
    p.w.domains.release().await;
}
