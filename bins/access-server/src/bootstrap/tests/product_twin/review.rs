//! Access reviews on the real server path (IDP-39 (1), (3), LFP-18, XI-19, §8.17.12, OP-157 m.3
//! (w), OP-153 m.3 (gg), Ek B 5566, 5577): the IGA and PAM twins, built on the public crates,
//! against inventory hygiene and JIT elevation. A hygiene mark is a suggestion that changes
//! nothing; a JIT activation never gets an ALLOW without its approval threshold.

use access_kernel::meta::{HoldingRef, MandateEnvelope};
use access_kernel::model::{Binding, Consumption, DelegationTerms, Independence, WhileCondition};
use access_product_twin::review::hygiene;
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, adp_body};
use access_store::authority::read_head;
use access_store::scope::DomainId;
use serde_json::{Value as Json, json};

use super::*;

/// The approval class a JIT elevation's threshold needs.
const JIT_CLASS: &str = "pam_approve";

fn pam_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/seams/pam")
}

async fn head(s: &Seam) -> u64 {
    read_head(&s.w.db.sequencer, &DomainId::from_bytes(s.domain.0))
        .await
        .unwrap()
        .pos
}

/// `who`'s own inventory answer, read with its own `check` statement over the public search.
async fn inventory(s: &Seam, who: &Actor) -> Vec<Json> {
    let search = IntentEnvelope {
        provenance: BTreeMap::new(),
        action: meta::core_action("read"),
        resources: vec![ResourceRef {
            namespace: String::from("access.search"),
            path: vec![String::from("inventory")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: window(),
    };
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&s.domain));
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let digest = intent_digest(&search).unwrap();
    let ais = Seam::ais(
        &who.key,
        &Statement {
            domain: s.domain,
            nonce: nonce.clone(),
            intent: digest,
            mode: Mode::Check,
            pep: String::from(TWIN_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now_ms(),
            exercise: None,
        },
    );
    let body = adp_body(&ExerciseRequest {
        domain: &s.domain,
        mode: Mode::Check,
        nonce: &nonce,
        intent: &digest,
        envelope: Some(&search),
        actor: &SdkActor::Statement(ais),
        basis: &basis,
        capacity: Capacity::Own,
        pep: TWIN_PEP,
        exercise: None,
    })
    .unwrap();
    let mut body: Json = serde_json::from_str(&body).unwrap();
    body["context"]["query"] = json!({ "party": b64url_encode(&who.party.0) });
    let Answer::Response(r) = s
        .listener
        .raw(
            "POST",
            "/access/v1/search/inventory",
            body.to_string().into_bytes(),
        )
        .await
    else {
        panic!("no answer");
    };
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v: Json = serde_json::from_slice(&r.body).unwrap();
    v["results"].as_array().unwrap().clone()
}

/// A small application whose records a manager delegates.
const LEDGER: &str = r#"
product = "Ledger"
namespace = "ledger"
catalog_version = 1
truth = ["entry"]

[[actions]]
name = "read"
major = 1
effect_class = "none"
resource_types = ["entry"]
"#;

// XI-19, §8.17.12, OP-157 m.3 (w), OP-153 m.3 (gg), Ek B 5566
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hygiene_marks_expiring_and_broad_delegations_and_a_read_changes_nothing() {
    let s = Seam::open("seam-hygiene", "iga").await;
    let app = Schema::parse(LEDGER).unwrap();
    s.twin.publish_schema(&s.domain, &app).await.unwrap();
    s.accept_schema(&app).await;
    let read = app.action("read").unwrap();
    let manager = s.actor().await;
    let member = s.actor().await;
    let mut to_manager = canonical(
        std::slice::from_ref(&read),
        structural("ledger.entry", &[]),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    to_manager.delegation = DelegationTerms {
        depth: 2,
        downstream_holder_class: None,
    };
    let (team, since) = s
        .grant(SubjectSelector::Party(manager.party), to_manager)
        .await;
    let basis = holding(team, manager.party, since);
    let now = server_time(&s.w.db.app).await.unwrap();
    let give = |resource: ResourceSelector, until: u64, depth: u64| {
        let mut a = canonical(
            std::slice::from_ref(&read),
            resource,
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        a.constraints.validity = Window { from: 0, until };
        a.delegation.depth = depth;
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Holding(HoldingRef {
                grant: team,
                holder: manager.party,
                since,
            }),
            holder: SubjectSelector::Party(member.party),
            authority: a,
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        })
    };
    let issued = |e: Digest| meta::object_id(&e, kind::GRANT, 0);
    let (quiet, _) = s
        .own_commit(
            &manager,
            basis,
            give(structural("ledger.entry", &["q-1"]), u64::MAX, 0),
        )
        .await;
    let (ending, _) = s
        .own_commit(
            &manager,
            basis,
            give(
                structural("ledger.entry", &["q-2"]),
                now + 2 * 86_400_000,
                0,
            ),
        )
        .await;
    let (any, _) = s
        .own_commit(
            &manager,
            basis,
            give(structural("ledger.entry", &[]), u64::MAX, 0),
        )
        .await;
    let (onward, _) = s
        .own_commit(
            &manager,
            basis,
            give(structural("ledger.entry", &["q-3"]), u64::MAX, 1),
        )
        .await;
    let (quiet, ending, any, onward) = (issued(quiet), issued(ending), issued(any), issued(onward));

    let before = head(&s).await;
    let rows = inventory(&s, &manager).await;
    let marks = hygiene(&rows);
    let of = |g: Id| marks.iter().find(|m| m.grant == b64url_encode(&g.0));
    assert!(of(quiet).is_none(), "{marks:?}");
    assert!(of(ending).unwrap().expiring);
    assert!(!of(ending).unwrap().broad);
    assert!(of(any).unwrap().broad);
    assert!(of(onward).unwrap().broad);
    assert!(
        marks.iter().all(|m| !m.unused),
        "a delegation issued now was not idle for 90 days: {marks:?}"
    );
    assert!(
        !marks.iter().any(|m| m.grant == b64url_encode(&team.0)),
        "the manager's own holding is no delegation of the manager's"
    );

    // XI-19
    let hub = access_experience::domain::hub::hygiene::rows(&rows, ("d", None));
    assert_eq!(
        hub.iter()
            .map(|r| (r.kind.as_str(), r.count))
            .collect::<Vec<_>>(),
        [("expiring", 1), ("broad", 2)]
    );
    assert!(hub.iter().all(|r| r.suggestion == "hygiene.suggestion"));
    assert_eq!(head(&s).await, before, "a hygiene read changes nothing");
    let again = hygiene(&inventory(&s, &member).await);
    assert!(
        again.is_empty(),
        "the member's own holdings are not its delegations: {again:?}"
    );
    assert_eq!(head(&s).await, before);
    s.only_public();
}

/// How Teleport's access request plugin maps a request to an Access intent and back
/// (`teleport.toml`).
#[derive(serde::Deserialize)]
struct Teleport {
    recorded: String,
    action: String,
    resource_namespace: String,
    resource_path: Vec<String>,
    allow: Reply,
    refuse: Reply,
}

#[derive(serde::Deserialize)]
struct Reply {
    set: String,
    to: String,
}

impl Teleport {
    fn load() -> Self {
        figment::Figment::from(figment::providers::Toml::file(
            pam_dir().join("teleport.toml"),
        ))
        .extract()
        .unwrap()
    }

    fn request(&self) -> Json {
        serde_json::from_slice(&std::fs::read(pam_dir().join(&self.recorded)).unwrap()).unwrap()
    }

    fn host(&self, request: &Json) -> Vec<String> {
        self.resource_path
            .iter()
            .map(|p| request.pointer(p).unwrap().as_str().unwrap().to_owned())
            .collect()
    }
}

// IDP-39 (1), §2.5, §4.5, §8.17.12, OP-157 m.3 (w), OP-153 m.3 (gg), Ek B 5577
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_jit_activation_gets_no_allow_without_its_approval_threshold() {
    let s = Seam::open("seam-jit", "pam").await;
    let pam = Schema::parse(&std::fs::read_to_string(pam_dir().join("pam.toml")).unwrap()).unwrap();
    s.twin.publish_schema(&s.domain, &pam).await.unwrap();
    s.accept_schema(&pam).await;
    let open = pam.action("open").unwrap();
    let alice = s.actor().await;
    let approver = s.actor().await;
    let teleport = Teleport::load();
    assert_eq!(teleport.action, "pam.session.open");
    let mut request = teleport.request();
    let host = teleport.host(&request);
    let path: Vec<&str> = host.iter().map(String::as_str).collect();

    // §8.17.12
    let threshold = RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(JIT_CLASS),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    };
    let (standing, since) = s
        .grant(
            SubjectSelector::Party(alice.party),
            canonical(
                std::slice::from_ref(&open),
                structural(&teleport.resource_namespace, &[path[0]]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::from([threshold]),
            ),
        )
        .await;
    s.grant(
        SubjectSelector::Party(approver.party),
        canonical(
            &[meta::core_action(access_kernel::contribution::ACTION)],
            structural(access_kernel::contribution::NAMESPACE, &[JIT_CLASS]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
    )
    .await;
    let basis = holding(standing, alice.party, since);
    let session = || {
        envelope(
            open.clone(),
            (teleport.resource_namespace.as_str(), path.as_slice()),
            BTreeMap::new(),
        )
    };

    // IDP-39 (1)
    let asked = s
        .twin
        .ask(&s.domain, &s.request(&alice, session(), basis, Vec::new()))
        .await;
    assert!(refused(&asked, Refusal::RequireAction), "{asked:?}");
    *request.pointer_mut(&teleport.refuse.set).unwrap() = Json::from(teleport.refuse.to.as_str());
    assert_ne!(
        request.pointer(&teleport.allow.set).unwrap(),
        teleport.allow.to.as_str(),
        "Teleport opens nothing without Access's ALLOW"
    );

    // §8.17.12
    let kid = access_kernel::verify::key_scope::thumbprint(&alice.key.public_key());
    let instance =
        s.w.domains
            .lookup_keys(
                s.domain,
                &[kid],
                access_authority_core::keys::AsOf::Head,
                false,
            )
            .await
            .unwrap()
            .lookup
            .keys
            .into_iter()
            .find(|k| k.kid == kid)
            .unwrap()
            .instance;
    let now = server_time(&s.w.db.app).await.unwrap();
    let mut activation = canonical(
        std::slice::from_ref(&open),
        structural(&teleport.resource_namespace, &[path[0]]),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    activation.constraints.validity = Window {
        from: now - 60_000,
        until: now + 1_800_000,
    };
    s.own_commit(
        &alice,
        ExerciseBasis::Anchor(alice.anchor),
        Payload::MandateBind {
            instance,
            envelope: MandateEnvelope {
                authority: activation.authority,
                constraints: activation.constraints,
                requirements: BTreeSet::new(),
                pin: Some(HoldingRef {
                    grant: standing,
                    holder: alice.party,
                    since,
                }),
                origins: access_kernel::combinator::Origins::default(),
            },
        },
    )
    .await;
    let activated = s
        .twin
        .ask(&s.domain, &s.request(&alice, session(), basis, Vec::new()))
        .await;
    assert!(
        refused(&activated, Refusal::RequireAction),
        "the activation never lifts the threshold: {activated:?}"
    );

    // G30
    let forged = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &alice,
                session(),
                basis,
                vec![Proof::Recorded(Id(
                    access_crypto::random::bytes::<16>().unwrap()
                ))],
            ),
        )
        .await;
    assert!(forged.is_err(), "{forged:?}");

    // E22
    let elsewhere = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &alice,
                envelope(
                    open.clone(),
                    (teleport.resource_namespace.as_str(), &["staging", "db-1"]),
                    BTreeMap::new(),
                ),
                basis,
                Vec::new(),
            ),
        )
        .await;
    assert!(
        !refused(&elsewhere, Refusal::RequireAction) && elsewhere.is_err(),
        "{elsewhere:?}"
    );
    s.only_public();
}

/// `who`'s Instance on the seam's domain.
async fn instance_of(s: &Seam, who: &Actor) -> Id {
    let kid = access_kernel::verify::key_scope::thumbprint(&who.key.public_key());
    s.w.domains
        .lookup_keys(
            s.domain,
            &[kid],
            access_authority_core::keys::AsOf::Head,
            false,
        )
        .await
        .unwrap()
        .lookup
        .keys
        .into_iter()
        .find(|k| k.kid == kid)
        .unwrap()
        .instance
}

/// A PAM session for a JIT test: the action, its host and the authority over it.
struct Session {
    open: ActionRef,
    namespace: String,
    host: Vec<String>,
}

impl Session {
    fn authority(&self) -> CanonicalAuthority {
        canonical(
            std::slice::from_ref(&self.open),
            structural(&self.namespace, &[self.host[0].as_str()]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
    }

    fn envelope(&self) -> IntentEnvelope {
        let path: Vec<&str> = self.host.iter().map(String::as_str).collect();
        envelope(
            self.open.clone(),
            (self.namespace.as_str(), path.as_slice()),
            BTreeMap::new(),
        )
    }

    /// A standing Grant to `who` without a threshold: the basis and its holding.
    async fn standing(&self, s: &Seam, who: &Actor) -> (ExerciseBasis, HoldingRef) {
        let (grant, since) = s
            .grant(SubjectSelector::Party(who.party), self.authority())
            .await;
        let pin = HoldingRef {
            grant,
            holder: who.party,
            since,
        };
        (holding(grant, who.party, since), pin)
    }

    /// `who` binds its Instance to the session's authority pinned to `pin`, within `constraints`.
    async fn bind(&self, s: &Seam, who: &Actor, pin: HoldingRef, constraints: ConstraintSet) {
        let instance = instance_of(s, who).await;
        s.own_commit(
            who,
            ExerciseBasis::Anchor(who.anchor),
            Payload::MandateBind {
                instance,
                envelope: MandateEnvelope {
                    authority: self.authority().authority,
                    constraints,
                    requirements: BTreeSet::new(),
                    pin: Some(pin),
                    origins: access_kernel::combinator::Origins::default(),
                },
            },
        )
        .await;
    }

    async fn ask(
        &self,
        s: &Seam,
        who: &Actor,
        basis: ExerciseBasis,
    ) -> Result<access_sdk::authorize::Authorized<(), ()>, Denied> {
        s.twin
            .ask(
                &s.domain,
                &s.request(who, self.envelope(), basis, Vec::new()),
            )
            .await
    }
}

fn within(from: u64, until: u64) -> ConstraintSet {
    ConstraintSet {
        validity: Window { from, until },
        conditions: BTreeSet::new(),
        budget: BTreeSet::new(),
    }
}

// INV-5, C14, C27, L0-EVAL-16b, §8.17.12, OP-157 m.3 (w), m.19 (a), OP-153 m.3 (gg), Ek B 5577
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_activation_mandate_bounds_the_session_by_its_window_budget_and_conditions() {
    let s = Seam::open("s-jit-window", "pam").await;
    let pam = Schema::parse(&std::fs::read_to_string(pam_dir().join("pam.toml")).unwrap()).unwrap();
    s.twin.publish_schema(&s.domain, &pam).await.unwrap();
    s.accept_schema(&pam).await;
    let teleport = Teleport::load();
    let request = teleport.request();
    let session = Session {
        open: pam.action("open").unwrap(),
        namespace: teleport.resource_namespace.clone(),
        host: teleport.host(&request),
    };
    let now = server_time(&s.w.db.app).await.unwrap();

    // INV-5, C14
    let alice = s.actor().await;
    let (basis, pin) = session.standing(&s, &alice).await;
    assert!(
        session.ask(&s, &alice, basis).await.is_ok(),
        "the standing Grant alone acts"
    );
    session
        .bind(&s, &alice, pin, within(now - 120_000, now - 60_000))
        .await;
    let expired = session.ask(&s, &alice, basis).await;
    assert!(
        refused(&expired, Refusal::Deny),
        "an expired activation is not read as no Mandate: {expired:?}"
    );

    // C27
    let bob = s.actor().await;
    let (basis, pin) = session.standing(&s, &bob).await;
    let mut once = within(now - 60_000, now + 1_800_000);
    once.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 1,
        window: BudgetWindow::Total,
    }]);
    session.bind(&s, &bob, pin, once).await;
    assert!(session.ask(&s, &bob, basis).await.is_ok());
    let spent = session.ask(&s, &bob, basis).await;
    assert!(refused(&spent, Refusal::Deny), "{spent:?}");

    // L0-EVAL-4
    let carol = s.actor().await;
    let (basis, pin) = session.standing(&s, &carol).await;
    let mut held = within(now - 60_000, now + 1_800_000);
    held.conditions = BTreeSet::from([WhileCondition::ClaimHeld {
        class: String::from("pam_on_call"),
        subject: SubjectSelector::Party(carol.party),
        acceptance: Digest(access_crypto::random::bytes::<32>().unwrap()),
    }]);
    session.bind(&s, &carol, pin, held).await;
    let lapsed = session.ask(&s, &carol, basis).await;
    assert!(refused(&lapsed, Refusal::Deny), "{lapsed:?}");
    s.only_public();
}
