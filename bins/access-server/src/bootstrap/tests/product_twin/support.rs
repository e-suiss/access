//! Support access on the real server path (MD-9, TN-70…TN-73, U57, INV-4, OP-157 m.3 (c)–(g)):
//! the case system twin, the support Grant templates and their twelve invariants. Lanes V1 and V2
//! fill it.
//!
//! The case system is a product twin built on the public crates alone: it pairs as its own Party
//! with its own issuer key, and its `support_case` Claims count only through the root's
//! `predicate-input` Acceptance. The person gives support access with their own `grant.issue` on
//! their own self-anchor; the operator acts with their own Instance key, `For` the person, through
//! a PEP, on the real sequencer, store and `SoftHSM`.

use access_authority_core::app::templates::support::{
    self as templates, AMENDED, CASE_REQUIRED, Give, NOT_OWN, OUT_OF_SCOPE, PASSES_ON,
    PROTECTED_ACTION, TOO_LONG, Template,
};
use access_internal_api::idp::IdpAction;
use access_kernel::claim::{PREDICATE_INPUT, acceptance_digest};
use access_kernel::json::b64url_encode;
use access_kernel::model::{PurposeRef, WhileCondition};
use access_product_twin::case::{CLASS, CaseEvent, CaseSystem, Vendor};
use access_sdk::authorize::{Actor as SdkActor, Authorized, ExerciseRequest, adp_body};
use serde_json::{Value as Json, json};

use super::*;

/// The case system twin's own registered name: the `system` of every case ref it states.
const SYSTEM: &str = "acme-desk";

/// A deployment whose realm accepts the case system twin's `support_case` Claims.
struct Desk {
    s: Seam,
    system: CaseSystem,
    acceptance: Digest,
}

type Asked = Result<Authorized<(), ()>, Denied>;

impl Desk {
    async fn open(label: &str) -> Self {
        let s = Seam::open(label, SYSTEM).await;
        let content = Value::Map(vec![
            (Value::text("issuer"), s.party.to_value()),
            (Value::text("use"), Value::text(PREDICATE_INPUT)),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text(CLASS)]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
            ),
        ]);
        let acceptance = acceptance_digest(&content);
        s.root(Payload::AcceptanceEstablish(content)).await;
        Self {
            s,
            system: CaseSystem {
                name: String::from(SYSTEM),
                vendor: Vendor::Zendesk,
            },
            acceptance,
        }
    }

    fn case(&self, id: &str) -> Digest {
        self.system.case_ref(id).unwrap()
    }

    /// The case system states that case `id` about `subject` is `open`, as its recorded vendor
    /// event says.
    async fn state(&self, subject: Id, id: &str, open: bool) {
        let event = CaseEvent {
            case: String::from(id),
            open,
        };
        let claim = self.system.claim(subject, &event, 3_600_000).unwrap();
        let issued = self
            .s
            .twin
            .issue_signed(&self.s.domain, claim)
            .await
            .unwrap();
        assert_eq!(issued.disposition, "admit", "{issued:?}");
        schedule(&self.s.signer);
    }

    async fn give(
        &self,
        person: &Actor,
        operator: Id,
        (template, actions, minutes): (Template, &[IdpAction], u64),
        case: &str,
    ) -> Give {
        let now = server_time(&self.s.w.db.app).await.unwrap();
        Give {
            template,
            subject: person.party,
            anchor: person.anchor,
            holder: SubjectSelector::Party(operator),
            case: self.case(case),
            acceptance: self.acceptance,
            actions: actions.iter().copied().collect(),
            validity: Window {
                from: now,
                until: now + minutes * 60_000,
            },
        }
    }

    /// `actor`'s own commit of `payload` on `basis`: the Exercise and position, or the decision
    /// that refused it.
    async fn commit(
        &self,
        actor: &Actor,
        basis: ExerciseBasis,
        payload: Payload,
    ) -> Result<(Digest, u64), Box<Verdict>> {
        let now = server_time(&self.s.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, actor.party, validity).unwrap();
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let ais = Seam::ais(
            &actor.key,
            &Statement {
                domain: self.s.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            },
        );
        MetaExercises::lead(&self.s.w.plane, self.s.domain)
            .await
            .unwrap();
        let verdict = Box::pin(MetaExercises::meta(
            &self.s.w.plane,
            Request {
                domain: self.s.domain,
                mode: Mode::Commit,
                nonce,
                intent,
                payload: Some(payload),
                basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais,
            String::from(IDENTITY_PEP),
        ))
        .await
        .unwrap();
        schedule(&self.s.signer);
        match verdict {
            Verdict::Committed(c) => Ok((c.exercise, c.position)),
            other => Err(Box::new(other)),
        }
    }

    /// The person gives `content` on their own self-anchor: the support Grant's holding for
    /// `operator`.
    async fn issue(
        &self,
        person: &Actor,
        content: GrantContent,
    ) -> Result<ExerciseBasis, Box<Verdict>> {
        let operator = match &content.holder {
            SubjectSelector::Party(p) => *p,
            _ => Id([0; 16]),
        };
        let (exercise, since) = self
            .commit(
                person,
                ExerciseBasis::Anchor(person.anchor),
                Payload::GrantIssue(content),
            )
            .await?;
        Ok(holding(
            meta::object_id(&exercise, kind::GRANT, 0),
            operator,
            since,
        ))
    }

    /// The operator's `action` on the person's account `For` them on `basis`, naming `case`,
    /// asked by the PEP; the intent asked about.
    async fn act(
        &self,
        operator: &Actor,
        person: &Actor,
        action: IdpAction,
        case: Digest,
        basis: ExerciseBasis,
    ) -> (Asked, IntentEnvelope) {
        let mut envelope = envelope(
            action.action_ref(),
            (templates::RESOURCES, &[&hex(&person.party), "settings"]),
            BTreeMap::new(),
        );
        envelope.purpose = Some(PurposeRef::Case(case));
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let capacity = Capacity::For(person.party);
        let ais = Seam::ais(
            &operator.key,
            &Statement {
                domain: self.s.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&envelope).unwrap(),
                mode: Mode::Commit,
                pep: String::from(TWIN_PEP),
                capacity,
                basis,
                iat: now_ms(),
                exercise: None,
            },
        );
        let request = access_product_twin::Request {
            ais,
            envelope: envelope.clone(),
            nonce,
            basis,
            capacity,
            proofs: Vec::new(),
        };
        let r = self.s.twin.ask(&self.s.domain, &request).await;
        schedule(&self.s.signer);
        (r, envelope)
    }

    /// The root's commit of `payload` on the meta-anchor: the refusal's subcode, if refused.
    async fn root_try(&self, payload: Payload) -> Option<String> {
        let now = server_time(&self.s.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, self.s.root_party, validity).unwrap();
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.s.domain));
        let ais = sign_sign1(
            &self.s.root,
            thumbprint(&self.s.root.public_key()),
            CONTENT_TYPE,
            &Statement {
                domain: self.s.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        MetaExercises::lead(&self.s.w.plane, self.s.domain)
            .await
            .unwrap();
        let verdict = Box::pin(MetaExercises::meta(
            &self.s.w.plane,
            Request {
                domain: self.s.domain,
                mode: Mode::Commit,
                nonce,
                intent,
                payload: Some(payload),
                basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais,
            String::from(IDENTITY_PEP),
        ))
        .await
        .unwrap();
        schedule(&self.s.signer);
        match verdict {
            Verdict::Committed(_) => None,
            other => Some(subcode(&other)),
        }
    }

    /// The `kind` hub search about `who`'s own Party, as `who`, through the public ADP route.
    async fn hub(&self, kind: &str, who: &Actor) -> Vec<Json> {
        let envelope = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: meta::core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.search"),
                path: vec![String::from(kind)],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: window(),
        };
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.s.domain));
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let digest = intent_digest(&envelope).unwrap();
        let ais = sign_sign1(
            &who.key,
            thumbprint(&who.key.public_key()),
            CONTENT_TYPE,
            &Statement {
                domain: self.s.domain,
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
            domain: &self.s.domain,
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
        context["query"] = json!({ "party": b64url_encode(&who.party.0) });
        let answer = self
            .s
            .listener
            .raw(
                "POST",
                &format!("/access/v1/search/{kind}"),
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

    async fn read(
        &self,
        operator: &Actor,
        person: &Actor,
        case: &str,
        basis: ExerciseBasis,
    ) -> Asked {
        self.act(
            operator,
            person,
            IdpAction::AccountRead,
            self.case(case),
            basis,
        )
        .await
        .0
    }
}

/// The subcode of the blocker a refused meta-action names.
fn subcode(v: &Verdict) -> String {
    match v {
        Verdict::NotAllowed { decision, .. } => decision
            .blockers
            .iter()
            .find_map(|b| b.subcode.clone())
            .unwrap_or_default(),
        other => format!("{other:?}"),
    }
}

// MD-9, TN-70, TN-73, U57, MUST-NEVER-19, §8.16, OP-157 m.3 (c), (e), Ek B 5410, 5505, 5511, 5517
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn support_access_is_the_persons_own_grant_held_by_an_open_case() {
    let d = Desk::open("support-held").await;
    let person = d.s.actor().await;
    let operator = d.s.actor().await;

    // §8.16
    let none = d
        .read(
            &operator,
            &person,
            "4411",
            ExerciseBasis::Anchor(person.anchor),
        )
        .await;
    assert!(none.is_err(), "{none:?}");

    let give = d
        .give(
            &person,
            operator.party,
            (
                Template::Session,
                &[IdpAction::AccountRead, IdpAction::AccountProfileUpdate],
                60,
            ),
            "4411",
        )
        .await;
    let basis = d.issue(&person, give.grant().unwrap()).await.unwrap();

    // OP-157 m.3 (e)
    let unheld = d.read(&operator, &person, "4411", basis).await;
    assert!(matches!(unheld, Err(Denied::Refused(_))), "{unheld:?}");

    d.state(person.party, "4411", true).await;
    let (allowed, intent) = d
        .act(
            &operator,
            &person,
            IdpAction::AccountProfileUpdate,
            d.case("4411"),
            basis,
        )
        .await;
    let mut done = Vec::new();
    ProductTwin::enforce(allowed.unwrap(), &intent, || done.push("profile")).unwrap();
    assert_eq!(done, ["profile"]);

    // TN-73
    let other_case = d.read(&operator, &person, "5000", basis).await;
    assert!(other_case.is_err(), "{other_case:?}");
    let stranger = d.s.actor().await;
    d.state(stranger.party, "4411", true).await;
    let elsewhere = d.read(&operator, &stranger, "4411", basis).await;
    assert!(elsewhere.is_err(), "{elsewhere:?}");
    let not_holder = d.read(&stranger, &person, "4411", basis).await;
    assert!(not_holder.is_err(), "{not_holder:?}");

    // §8.16
    let (protected, _) = d
        .act(
            &operator,
            &person,
            IdpAction::AccountEmailChange,
            d.case("4411"),
            basis,
        )
        .await;
    assert!(protected.is_err(), "{protected:?}");

    // OP-157 m.3 (e)
    d.state(person.party, "4411", false).await;
    let closed = d.read(&operator, &person, "4411", basis).await;
    assert!(closed.is_err(), "{closed:?}");
    d.state(person.party, "4411", true).await;
    let reopened = d.read(&operator, &person, "4411", basis).await;
    assert!(
        reopened.is_err(),
        "a closed case never holds again: {reopened:?}"
    );
    d.s.only_public();
}

// U57, §8.16, TN-72, INV-4, OP-157 m.3 (c), Ek B 5507, 5508, 5509, 5510, 5512, 5516, 5520
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_template_shape_of_support_access_is_ever_written() {
    let d = Desk::open("support-shape").await;
    let person = d.s.actor().await;
    let operator = d.s.actor().await;
    let read = (Template::Session, &[IdpAction::AccountRead][..], 30);
    let refused = |r: Result<ExerciseBasis, Box<Verdict>>, reason: &str| {
        let v = r.expect_err(reason);
        assert_eq!(subcode(&v), reason, "{v:?}");
    };

    // §8.16, Ek B 5510
    let mut protected = d.give(&person, operator.party, read, "4411").await;
    protected.actions.insert(IdpAction::AccountEmailChange);
    assert_eq!(protected.grant(), Err(PROTECTED_ACTION));
    let mut content = d
        .give(&person, operator.party, read, "4411")
        .await
        .grant()
        .unwrap();
    content
        .authority
        .authority
        .actions
        .exact
        .insert(IdpAction::AccountSigninMethodChange.action_ref());
    refused(d.issue(&person, content).await, PROTECTED_ACTION);

    // §8.16, U57
    let long = d
        .give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountProfileUpdate], 61),
            "4411",
        )
        .await;
    let mut content = long.grant().unwrap_or_else(|_| {
        let mut ok = long.clone();
        ok.validity.until = ok.validity.from + 60 * 60_000;
        let mut c = ok.grant().unwrap();
        c.authority.constraints.validity = long.validity;
        c
    });
    refused(d.issue(&person, content.clone()).await, TOO_LONG);
    let standing = d
        .give(
            &person,
            operator.party,
            (Template::Standing, &[], 24 * 60),
            "4411",
        )
        .await;
    assert!(d.issue(&person, standing.grant().unwrap()).await.is_ok());

    // §8.16, Ek B 5516
    content.authority.constraints.validity.until =
        content.authority.constraints.validity.from + 60_000;
    content.authority.delegation.depth = 1;
    refused(d.issue(&person, content.clone()).await, PASSES_ON);

    // TN-73, §8.16, Ek B 5511
    content.authority.delegation.depth = 0;
    content.authority.authority.purpose = None;
    refused(d.issue(&person, content.clone()).await, CASE_REQUIRED);
    content.authority.authority.purpose =
        Some(BTreeSet::from([PurposeRef::Code(String::from("support"))]));
    refused(d.issue(&person, content.clone()).await, CASE_REQUIRED);

    // TN-72, §5.7, Ek B 5520
    let employee = d.s.actor().await;
    let mut reach = d
        .give(&person, operator.party, read, "4411")
        .await
        .grant()
        .unwrap();
    reach.agency = BTreeSet::from([Capacity::For(employee.party)]);
    let r = d.issue(&person, reach.clone()).await;
    assert_eq!(
        subcode(&r.unwrap_err()),
        "meta-agency",
        "the person gives only For themselves"
    );
    reach.agency = BTreeSet::from([Capacity::For(person.party)]);
    reach.authority.constraints.conditions = BTreeSet::from([WhileCondition::ClaimHeld {
        class: String::from(CLASS),
        subject: SubjectSelector::Party(employee.party),
        acceptance: d.acceptance,
    }]);
    let ResourceSelector::Structural(s) = &mut reach.authority.authority.resource else {
        panic!("structural");
    };
    s.prefix = vec![hex(&employee.party)];
    let r = d.issue(&person, reach).await;
    assert!(
        r.is_err(),
        "the person's self-anchor never reaches another account: {r:?}"
    );

    // MD-9
    let root_given = d
        .give(&person, operator.party, read, "4411")
        .await
        .grant()
        .unwrap();
    let mut by_root = root_given.clone();
    by_root.basis = GrantBasis::Anchor(meta::meta_anchor(&d.s.domain));
    let refusal = d.root_try(Payload::GrantIssue(by_root)).await;
    assert!(
        matches!(refusal.as_deref(), Some("meta-agency" | NOT_OWN)),
        "the root never gives support access for the person: {refusal:?}"
    );

    // §8.16
    let basis = d.issue(&person, root_given.clone()).await.unwrap();
    let ExerciseBasis::Holding(h) = basis else {
        panic!("holding");
    };
    let mut longer = root_given.authority.clone();
    longer.constraints.validity.until += 60_000;
    let amended = d
        .commit(
            &person,
            ExerciseBasis::Anchor(person.anchor),
            Payload::GrantAmend {
                grant: h.grant,
                authority: longer,
                agency: root_given.agency.clone(),
                named: None,
            },
        )
        .await;
    assert_eq!(subcode(&amended.unwrap_err()), AMENDED);

    // INV-4, §8.16, Ek B 5509
    let own = canonical(
        &[IdpAction::AccountRead.action_ref()],
        structural(templates::RESOURCES, &[]),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    let (own_grant, since) = d.s.grant(SubjectSelector::Party(operator.party), own).await;
    d.state(person.party, "4411", true).await;
    let own_basis = holding(own_grant, operator.party, since);
    let r = d.read(&operator, &person, "4411", own_basis).await;
    assert!(
        matches!(r, Err(Denied::Refused(_))),
        "the operator's own authority is never a basis for acting for the person: {r:?}"
    );
    assert!(d.read(&operator, &person, "4411", basis).await.is_ok());

    // §8.16, OP-157 m.3 (c), (n)
    d.s.root(Payload::PolicySet {
        policy: None,
        content: access_authority_core::restrict::patterns::support_protected().unwrap(),
        defaults: Some(access_kernel::meta::PolicyDefaults {
            ct3_delay_s: None,
            mapping_probation_days: None,
            approval_surfaces: None,
            breakglass_review_h: None,
            support_max_min: Some(20),
        }),
    })
    .await;
    assert!(
        d.read(&operator, &person, "4411", basis).await.is_ok(),
        "support-protected forbids only the protected actions"
    );
    let half = d.give(&person, operator.party, read, "4411").await;
    refused(d.issue(&person, half.grant().unwrap()).await, TOO_LONG);
    let short = d
        .give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountRead], 20),
            "4411",
        )
        .await;
    assert!(d.issue(&person, short.grant().unwrap()).await.is_ok());
    assert_eq!(
        d.give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountSuspend], 20),
            "4411"
        )
        .await
        .grant(),
        Err(OUT_OF_SCOPE)
    );
}

// §8.16, U57, TN-71, X37, OP-157 m.3 (c), Ek B 5507, 5513, 5518, 5609
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_support_ends_only_the_operators_access_and_every_use_names_the_operator() {
    use access_authority_core::app::hub::Group;
    let d = Desk::open("support-revoke").await;
    let person = d.s.actor().await;
    let operator = d.s.actor().await;
    d.state(person.party, "4411", true).await;
    let give = d
        .give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountRead], 30),
            "4411",
        )
        .await;
    let basis = d.issue(&person, give.grant().unwrap()).await.unwrap();
    let ExerciseBasis::Holding(h) = basis else {
        panic!("holding");
    };
    let (allowed, _) = d
        .act(
            &operator,
            &person,
            IdpAction::AccountRead,
            d.case("4411"),
            basis,
        )
        .await;
    let allowed = allowed.unwrap();

    // §8.16, TN-71
    let exercise = b64url_encode(&allowed.exercise().0);
    let uses = d.hub("activity", &person).await;
    let used = uses
        .iter()
        .find(|u| u["exercise"] == exercise.as_str())
        .unwrap_or_else(|| panic!("{uses:?}"));
    let grant = b64url_encode(&h.grant.0);
    assert_eq!(used["by_viewer"], false);
    assert_eq!(used["basis"]["grant"], grant.as_str());
    let mine = d.hub("activity", &operator).await;
    let theirs = mine
        .iter()
        .find(|u| u["exercise"] == exercise.as_str())
        .unwrap_or_else(|| panic!("{mine:?}"));
    assert_eq!(
        theirs["by_viewer"], true,
        "the operator's own Instance acted"
    );
    assert_eq!(theirs["instance"], used["instance"]);
    let rows = d.hub("inventory", &person).await;
    let row = rows
        .iter()
        .find(|r| r["grant"] == grant.as_str())
        .unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(row["groups"], json!([Group::ActingForYou.word()]));

    // §8.16
    d.commit(
        &person,
        ExerciseBasis::Anchor(person.anchor),
        Payload::GrantRevoke { grant: h.grant },
    )
    .await
    .unwrap();
    let ended = d.read(&operator, &person, "4411", basis).await;
    assert!(ended.is_err(), "{ended:?}");
    let again = d
        .give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountRead], 30),
            "4411",
        )
        .await;
    assert!(
        d.issue(&person, again.grant().unwrap()).await.is_ok(),
        "the person's own Instance and key act as before"
    );
}

const ISSUER: &str = "https://access.test/realms/seams";
const RS: &str = "https://support.access.test/api";

/// The operator's `projection.issue` of `authority` for [`RS`] in `capacity` on `basis`,
/// decided and signed by the authority plane over `SoftHSM`.
async fn token(
    d: &Desk,
    operator: &Actor,
    authority: &CanonicalAuthority,
    (capacity, basis): (Capacity, ExerciseBasis),
) -> access_internal_api::projections::TokenProjection {
    use access_internal_api::projections::{
        Confirmation, Projections as _, TokenKind, TokenProfile, TokenProjectionRequest,
    };
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let now = server_time(&d.s.w.db.app).await.unwrap();
    let mut bounds = authority.clone();
    bounds.constraints.validity = Window {
        from: now.max(authority.constraints.validity.from),
        until: now + 120_000,
    };
    let payload = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([String::from(RS)]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, operator.party, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let ais = Seam::ais(
        &operator.key,
        &Statement {
            domain: d.s.domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity,
            basis,
            iat: now,
            exercise: None,
        },
    );
    let issued =
        d.s.w
            .plane
            .issue(TokenProjectionRequest {
                domain: d.s.domain,
                nonce,
                intent,
                payload: payload.to_bytes().unwrap(),
                basis,
                capacity,
                ais,
                pep: String::from(IDENTITY_PEP),
                issuer: String::from(ISSUER),
                client_id: String::from("support-console"),
                kind: TokenKind::Bounds,
                target: None,
                confirmation: Confirmation::DpopJkt(thumbprint(&operator.key.public_key())),
                resources: vec![String::from(RS)],
                family: None,
                profile: TokenProfile::default(),
            })
            .await
            .unwrap();
    schedule(&d.s.signer);
    issued
}

// §8.16, §9.9.4, §11.21.3, MD-9, P53, TN-70, TNI-13, L22, OP-157 m.3 (d), Ek B 5430, 5436, 5506
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_support_token_names_the_person_as_subject_and_the_operator_as_act() {
    use access_internal_api::projections::TokenProjection;
    let d = Desk::open("support-token").await;
    let person = d.s.actor().await;
    let operator = d.s.actor().await;
    d.state(person.party, "4411", true).await;
    let give = d
        .give(
            &person,
            operator.party,
            (Template::Session, &[IdpAction::AccountRead], 30),
            "4411",
        )
        .await;
    let content = give.grant().unwrap();
    let basis = d.issue(&person, content.clone()).await.unwrap();
    // TNI-13, P53
    let issued = token(
        &d,
        &operator,
        &content.authority,
        (Capacity::For(person.party), basis),
    )
    .await;
    let TokenProjection::Issued(t) = issued else {
        panic!("{issued:?}");
    };
    let header: Json = serde_json::from_slice(
        &access_kernel::json::b64url_decode(t.token.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["typ"], "at+jwt");
    let claims: Json = serde_json::from_slice(
        &access_kernel::json::b64url_decode(t.token.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let act = &claims["act"];
    assert!(act["sub"].is_string(), "{claims}");
    assert_ne!(claims["sub"], act["sub"], "{claims}");
    assert_eq!(details_capacity(&claims), claims["sub"], "{claims}");
    assert!(
        act.get("act").is_none(),
        "support passes on to no one: {claims}"
    );
    let details = claims["authorization_details"].as_array().unwrap();
    assert!(
        details
            .iter()
            .all(|x| x["type"] == "idp.account:read:1" && x["kind"] == "bounds"),
        "{claims}"
    );
    assert_eq!(
        details[0]["purpose"],
        json!([{ "case": format!("sha-256:{}", b64url_encode(&d.case("4411").0)) }]),
        "{claims}"
    );

    // MD-9, §8.16
    let own = token(&d, &operator, &content.authority, (Capacity::Own, basis)).await;
    assert!(!matches!(own, TokenProjection::Issued(_)), "{own:?}");
    d.state(person.party, "4411", false).await;
    let closed = token(
        &d,
        &operator,
        &content.authority,
        (Capacity::For(person.party), basis),
    )
    .await;
    assert!(
        matches!(&closed, TokenProjection::Denied { decision, .. }
            if decision.blockers.iter().any(|b| b.subcode.as_deref() == Some(templates::CASE_CLOSED))),
        "{closed:?}"
    );
}

fn details_capacity(claims: &Json) -> Json {
    claims["authorization_details"][0]["capacity"]["for"].clone()
}
