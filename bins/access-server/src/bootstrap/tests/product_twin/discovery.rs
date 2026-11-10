//! Shadow agent discovery on the real server path (AG-39, AG-43, OP-156 m.4 Q20, OP-153 m.3
//! (gg)). A discovery connector is a product twin built on the public crates alone: it reads the
//! recorded Google Workspace and Microsoft Graph answers and issues each application's access as
//! a `discovered_app` Claim with its body, through Claim Ingest, under its own issuer key. The
//! root accepts its Claims; the `discovery` search then names the applications no live agent or
//! system Party accounts for, for the domain's auditors alone, and changes nothing.

use access_product_twin::Signed;
use access_product_twin::discovery::{AppGrant, CLASS, Connector, parse};
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, adp_body};
use serde_json::{Value as Json, json};
use suiss_crypto::signer::Signer;

use super::*;

fn example(name: &str) -> Json {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/discovery")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

impl Seam {
    /// The connector reports `grant` as an access of `subject`.
    async fn report(&self, subject: Id, grant: &AppGrant) {
        let (body, value) = grant.encoded().unwrap();
        let issued = self
            .twin
            .issue_signed(
                &self.domain,
                Signed::with_body(
                    Issue {
                        subject,
                        class: String::from(CLASS),
                        value: Some(EqValue::Bytes(value.to_vec())),
                        for_ms: 3_600_000,
                        resource: None,
                    },
                    body,
                ),
            )
            .await
            .unwrap();
        assert_eq!(issued.disposition, "admit", "{issued:?}");
        schedule(&self.signer);
    }

    /// The `discovery` search as `key`'s Party, through the public ADP route.
    async fn discovery<S: Signer>(&self, key: &S, unregistered: bool) -> Vec<Json> {
        let envelope = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: meta::core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.search"),
                path: vec![String::from("discovery")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: window(),
        };
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.domain));
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let digest = intent_digest(&envelope).unwrap();
        let ais = sign_sign1(
            key,
            thumbprint(&key.public_key()),
            CONTENT_TYPE,
            &Statement {
                domain: self.domain,
                nonce: nonce.clone(),
                intent: digest,
                mode: Mode::Check,
                pep: String::from(TWIN_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now_ms(),
                exercise: None,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let body = adp_body(&ExerciseRequest {
            domain: &self.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &SdkActor::Statement(ais),
            basis: &basis,
            capacity: Capacity::Own,
            pep: TWIN_PEP,
            exercise: None,
        })
        .unwrap();
        let mut context = serde_json::from_str::<Json>(&body).unwrap()["context"].clone();
        context["query"] = json!({ "unregistered": unregistered });
        let answer = self
            .listener
            .raw(
                "POST",
                "/access/v1/search/discovery",
                json!({ "context": context }).to_string().into_bytes(),
            )
            .await;
        let Answer::Response(r) = answer else {
            panic!("{answer:?}");
        };
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v: Json = serde_json::from_slice(&r.body).unwrap();
        v["results"].as_array().unwrap().clone()
    }
}

// AG-39, AG-43, OP-156 m.4 Q20, Ek B 4390
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_discovery_search_names_the_applications_no_agent_accounts_for() {
    let s = Seam::open("seam-discovery", "connector").await;
    s.accept_claims("predicate-input", &[CLASS]).await;
    let person = s.actor().await;
    let google = parse(
        Connector::GoogleWorkspace,
        &example("google-workspace-tokens.json"),
    )
    .unwrap();
    let graph = parse(
        Connector::MicrosoftGraph,
        &example("microsoft-graph-grants.json"),
    )
    .unwrap();
    for g in google.iter().chain(&graph) {
        s.report(person.party, g).await;
    }
    s.report(s.party, &google[0]).await;

    let all = s.discovery(&s.root, false).await;
    assert_eq!(all.len(), 4, "{all:?}");
    let registered: Vec<&str> = all
        .iter()
        .filter(|r| r["registered"] == true)
        .map(|r| r["app"].as_str().unwrap())
        .collect();
    assert_eq!(
        registered,
        ["100000000001-registered.apps.googleusercontent.com"]
    );
    let shadow = s.discovery(&s.root, true).await;
    assert_eq!(shadow.len(), 3, "{shadow:?}");
    let inbox = shadow
        .iter()
        .find(|r| r["name"] == "Inbox Autopilot")
        .unwrap();
    assert_eq!(inbox["connector"], "google-workspace");
    assert_eq!(inbox["advisory"], true);
    assert!(
        inbox["scopes"]
            .as_array()
            .unwrap()
            .contains(&json!("https://mail.google.com/"))
    );

    // AG-43
    assert_eq!(s.discovery(&person.key, false).await.len(), 0);
    s.only_public();
}
