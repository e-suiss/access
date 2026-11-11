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
    let activity = d.hub("activity", &person).await;
    let used = activity
        .iter()
        .find(|u| u["exercise"] == exercise.as_str())
        .unwrap_or_else(|| panic!("{activity:?}"));
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

/// Support access as people see and use it, through the Frontend API on the real router (OP-157
/// m.3 (f), (g), TN-137): the operator asks, the person's own device gives exactly what was
/// asked, the operator acts through a PEP, the person sees who did what and ends it.
mod front {
    use access_identity_account::adapters::pg::PgAccounts;
    use access_identity_account::app::accounts::{change_status, create};
    use access_identity_account::app::{Actor as Who, Realm};
    use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
    use access_identity_account::domain::status::AccountStatus;
    use access_identity_admin::domain::Change;
    use access_identity_admin::domain::support::CaseSystemChange;
    use access_identity_ui::app::Hosted;
    use access_kernel::json::b64url_decode;
    use access_store::identity::{RealmId, TenantId};
    use axum::http::Method;

    use super::*;

    const WHO: Who<'static> = Who {
        actor: "test",
        correlation: "support",
    };

    const HOST: &str = "access.test";

    /// The realm's Frontend API with the support routes, as `main` mounts them, and the realm.
    pub(super) struct Front {
        app: axum::Router,
        pub(super) tenant: TenantId,
        pub(super) realm: RealmId,
        pub(super) ids: Arc<access_crypto::opaque_id::IdKey>,
    }

    pub(super) struct Person {
        pub(super) actor: Actor,
        pub(super) subject: [u8; 16],
        pub(super) cookie: String,
    }

    pub(super) async fn front(d: &Desk) -> Front {
        use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
        use access_identity_account::app::hasher::{Hasher, HasherConfig};
        use access_identity_account::app::local::LocalLimiter;
        use access_identity_account::app::login::LoginGate;
        use access_identity_account::domain::password::Argon2Params;
        use access_identity_account::domain::throttle::ThrottlePolicy;
        use access_identity_oauth::adapters::PgDirectory;
        use access_identity_oauth::app::Discovery as RealmDiscovery;
        use access_identity_session::domain::session::SessionPolicy;
        use access_identity_ui::adapters::Outbox;
        let w = &d.s.w;
        let route = access_store::tenancy::routes(&w.db.router)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.slug == SLUG)
            .unwrap();
        let hosted = Arc::new(Hosted {
            kits: crate::login::HsmKits::new(
                crate::login::RealmKeks::new(Arc::clone(&w.keys)),
                w.db.router.clone(),
                w.db.app.clone(),
                SessionPolicy::DEFAULT,
            ),
            db: w.db.app.clone(),
            products: w.db.reader.clone(),
            clock: SystemClock,
            messages: Outbox,
            gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
            hasher: Hasher::new(HasherConfig::sized(
                Argon2Params::CANONICAL,
                cores(),
                cgroup_memory_budget(),
            )),
            redirect_to: String::from("/"),
            hooks: Arc::new(access_identity_hooks::ports::NoHooks),
            risk: access_identity_session::app::RiskServices::without_sources(),
            signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        });
        let app = access_http::login::support_router(
            RealmDiscovery::new(
                PgDirectory::new(w.db.router.clone()),
                SignerKeys::new(w.identity_signer.clone()),
            ),
            hosted,
            w.plane.clone(),
            String::from(IDENTITY_PEP),
        );
        Front {
            app,
            tenant: route.tenant,
            realm: route.realm,
            ids: crate::ids::CellIds::new(w.keys.clone()).key().unwrap(),
        }
    }

    impl Front {
        async fn tx(&self, d: &Desk) -> TenantTx {
            TenantTx::begin(&d.s.w.db.app, self.tenant, self.realm)
                .await
                .unwrap()
        }

        /// An active account of the realm bound to a new Party of its own, with a fresh session.
        pub(super) async fn person(&self, d: &Desk, address: &str, name: Option<&str>) -> Person {
            let actor = d.s.actor().await;
            let ids = crate::ids::CellIds::new(d.s.w.keys.clone()).key().unwrap();
            let v = crate::login::RealmKeks::new(d.s.w.keys.clone())
                .vault(self.realm)
                .unwrap();
            let realm = Realm {
                tenant: self.tenant,
                realm: self.realm,
                kek: &*v.kek,
                ids: &ids,
            };
            let db = PgAccounts::sealed(d.s.w.db.app.clone(), v.clone());
            let email = Identifier::new(IdentifierKind::Email, address).unwrap();
            let subject = create(&db, &realm, &[email], &WHO).await.unwrap();
            for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
                change_status(&db, &realm, subject, to, &WHO).await.unwrap();
            }
            let mut t = self.tx(d).await;
            access_store::idp::bind_subject_party(&mut t, &subject, &actor.party.0)
                .await
                .unwrap();
            if let Some(n) = name {
                access_identity_account::app::vault::set_profile(&mut t, &v, subject, "name", n)
                    .await
                    .unwrap();
            }
            let value: [u8; 32] = access_crypto::random::bytes().unwrap();
            let at = now_ms();
            t.insert_session(&access_store::sessions::NewSession {
                cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
                subject,
                session_epoch: 0,
                keep_signed_in: false,
                created_ms: i64::try_from(at).unwrap(),
                auth_time_ms: i64::try_from(at).unwrap(),
                idle_ms: 3_600_000,
                expires_ms: i64::try_from(at + 3_600_000).unwrap(),
                assurance: &serde_json::to_vec(
                    &access_identity_session::domain::assurance::vector(&[
                        access_identity_session::domain::assurance::Factor::password(at),
                    ]),
                )
                .unwrap(),
            })
            .await
            .unwrap();
            t.commit().await.unwrap();
            Person {
                actor,
                subject,
                cookie: b64url_encode(&value),
            }
        }

        /// `p` founds the support organization `name`.
        pub(super) async fn org(&self, d: &Desk, p: &Person, name: &str) {
            let mut t = self.tx(d).await;
            let party: [u8; 16] = access_crypto::random::bytes().unwrap();
            let exercise: [u8; 32] = access_crypto::random::bytes().unwrap();
            let org = t.insert_org(party, name, &exercise).await.unwrap();
            t.insert_membership(
                org,
                p.subject,
                access_store::orgs::Source::Founder,
                true,
                None,
            )
            .await
            .unwrap();
            t.commit().await.unwrap();
        }

        pub(super) fn account(&self, p: &Person) -> String {
            self.ids
                .encode(access_identity_account::app::SUBJECT_PREFIX, p.subject)
                .unwrap()
        }

        /// The root's `idp.*` change.
        pub(super) async fn change(&self, d: &Desk, change: Change) {
            let declared = DeclaredTargets::default();
            let b = d.s.bootstrap(&declared);
            let ids = cell_ids(&d.s.w.db.app, &d.s.w.keys).await.unwrap();
            Box::pin(b.change(
                &b.admin(&ids, None),
                (self.tenant, self.realm),
                d.s.domain,
                &d.s.root,
                change,
            ))
            .await
            .unwrap();
            schedule(&d.s.signer);
        }

        /// The case system twin registered as the realm's support case system.
        pub(super) async fn register(&self, d: &Desk) {
            let body = json!({ "name": SYSTEM, "issuer": b64url_encode(&d.s.party.0),
                               "provider": "zendesk", "format": "product-seam/v1" });
            self.change(
                d,
                Change::CaseSystem(CaseSystemChange::register(&body).unwrap()),
            )
            .await;
        }

        pub(super) async fn send(
            &self,
            method: Method,
            path: &str,
            who: &Person,
            body: Option<Json>,
            extra: &[(&str, String)],
        ) -> (u16, Json) {
            let mut b = HttpRequestOf::builder()
                .method(method.clone())
                .uri(format!("/realms/{SLUG}{path}"))
                .header(header::HOST, HOST)
                .header(
                    header::COOKIE,
                    format!("__Host-access-session={}", who.cookie),
                );
            if method != Method::GET {
                b = b
                    .header(header::ORIGIN, format!("https://{HOST}"))
                    .header("sec-fetch-site", "same-origin")
                    .header(
                        "idempotency-key",
                        b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
                    )
                    .header(header::CONTENT_TYPE, "application/json");
            }
            for (k, v) in extra {
                b = b.header(*k, v);
            }
            let req = b
                .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
                .unwrap();
            let r = self.app.clone().oneshot(req).await.unwrap();
            let status = r.status().as_u16();
            let bytes = to_bytes(r.into_body(), 1 << 22).await.unwrap();
            let v = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
            (status, v)
        }

        pub(super) async fn audited(&self, d: &Desk) -> Vec<String> {
            let mut t = self.tx(d).await;
            let rows = t.audit_page(None, 1_000).await.unwrap();
            t.commit().await.unwrap();
            rows.into_iter().map(|r| r.event_type).collect()
        }
    }

    /// `who`'s own signed Exercise of `intent` (and `payload`) on `basis` in `capacity`, as the
    /// routes carry it.
    pub(super) fn signed(
        d: &Desk,
        who: &Actor,
        (intent, payload): (&IntentEnvelope, Option<&Payload>),
        basis: ExerciseBasis,
        capacity: Capacity,
    ) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let ais = Seam::ais(
            &who.key,
            &Statement {
                domain: d.s.domain,
                nonce: nonce.clone(),
                intent: intent_digest(intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity,
                basis,
                iat: now_ms(),
                exercise: None,
            },
        );
        let basis = match basis {
            ExerciseBasis::Anchor(a) => json!({ "anchor": b64url_encode(&a.0) }),
            ExerciseBasis::Holding(h) => json!({ "holding": {
                "grant": b64url_encode(&h.grant.0),
                "holder": b64url_encode(&h.holder.0),
                "since": h.since,
            } }),
            ExerciseBasis::Public(_) => Json::Null,
        };
        let mut v = json!({
            "nonce": b64url_encode(&nonce),
            "intent": b64url_encode(&intent.to_bytes().unwrap()),
            "basis": basis,
            "ais": b64url_encode(&ais),
        });
        if let Some(p) = payload {
            v["payload"] = Json::from(b64url_encode(&p.to_bytes().unwrap()));
        }
        v
    }

    /// The person signs the `give` draft of request `row` as it came, or changed by `edit`.
    pub(super) fn give_body(
        d: &Desk,
        p: &Person,
        row: &Json,
        edit: impl FnOnce(&mut GrantContent),
    ) -> Json {
        let give = &row["give"];
        let mut payload =
            Payload::from_bytes(&b64url_decode(give["payload"].as_str().unwrap()).unwrap())
                .unwrap();
        let Payload::GrantIssue(c) = &mut payload else {
            panic!("{give}");
        };
        edit(c);
        let now = now_ms();
        let intent = self_signed_intent(
            &payload,
            p.actor.party,
            Window {
                from: now - 60_000,
                until: now + 600_000,
            },
        )
        .unwrap();
        signed(
            d,
            &p.actor,
            (&intent, Some(&payload)),
            ExerciseBasis::Anchor(p.actor.anchor),
            Capacity::Own,
        )
    }

    pub(super) fn holding_of(v: &Json) -> ExerciseBasis {
        let h = &v["basis"]["holding"];
        ExerciseBasis::Holding(HoldingRef {
            grant: Id(b64url_decode(h["grant"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()),
            holder: Id(b64url_decode(h["holder"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()),
            since: h["since"].as_u64().unwrap(),
        })
    }

    pub(super) async fn ask(
        f: &Front,
        operator: &Person,
        person: &Person,
        (case, scope, minutes): (&str, &str, u32),
    ) -> (u16, Json) {
        f.send(
            Method::POST,
            "/v1/support/requests",
            operator,
            Some(json!({ "subject": f.account(person), "case_system": SYSTEM,
                         "case": case, "scope": scope, "minutes": minutes })),
            &[],
        )
        .await
    }

    pub(super) async fn incoming(f: &Front, person: &Person) -> Vec<Json> {
        let (status, v) = f
            .send(Method::GET, "/v1/support/requests", person, None, &[])
            .await;
        assert_eq!(status, 200, "{v}");
        v["requests"].as_array().unwrap().clone()
    }

    pub(super) fn path_of(id: &Json, rest: &str) -> String {
        format!("/v1/support/requests/{}{rest}", id.as_str().unwrap())
    }
}

use front::{ask, give_body, holding_of, incoming, path_of, signed};

// TN-137 (1), §8.16, XI-7, SI-21, X37, U57, OP-157 m.3 (f), Ek B 5459, 5513, 5514, 5524, 5526,
// OP-157 m.3 (f), Ek B 5529, 5609, 5613
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one support access from request to revoke"
)]
async fn support_access_is_asked_given_used_seen_and_revoked_on_the_persons_own_page() {
    use axum::http::Method;
    let d = Desk::open("support-front").await;
    let f = front::front(&d).await;
    f.register(&d).await;
    let person = f.person(&d, "ayse@access.test", Some("Ayşe K.")).await;
    let operator = f.person(&d, "mehmet@access.test", Some("Mehmet Y.")).await;

    // OP-157 m.3 (f)
    let (status, got) = ask(&f, &operator, &person, ("4411", "read", 30)).await;
    assert_eq!(
        (status, got["code"].as_str()),
        (403, Some("support-operator-required")),
        "{got}"
    );
    f.org(&d, &operator, "Acme Support").await;
    let (status, got) = ask(&f, &operator, &person, ("4411", "profile", 61)).await;
    assert_eq!(status, 400, "{got}");
    let (status, asked) = ask(&f, &operator, &person, ("4411", "read", 30)).await;
    assert_eq!(status, 201, "{asked}");
    assert_eq!(asked["state"], "waiting");
    assert_eq!(asked["organization"], "Acme Support");
    let invites = identity_events_until(
        &d.s.w.db,
        "relay.message.support_access_request.v1",
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;
    assert_eq!(invites.len(), 1);

    // XI-7
    let (_, mine) = f
        .send(Method::GET, "/v1/support/requests", &operator, None, &[])
        .await;
    assert_eq!(mine["sent"][0]["state"], "waiting", "{mine}");
    assert!(mine["sent"][0].get("give").is_none(), "{mine}");
    assert!(mine["requests"].as_array().unwrap().is_empty(), "{mine}");
    let rows = incoming(&f, &person).await;
    let row = &rows[0];
    assert_eq!(row["operator"], "Mehmet Y.", "{row}");
    assert!(row["give"].is_object(), "{row}");
    assert_eq!(row["give"]["pep"], IDENTITY_PEP, "{row}");
    let taken = give_body(&d, &operator, row, |_| {});
    let (status, got) = f
        .send(
            Method::POST,
            &path_of(&row["id"], "/give"),
            &operator,
            Some(taken),
            &[],
        )
        .await;
    assert_eq!(
        (status, got["code"].as_str()),
        (404, Some("support-request-unknown")),
        "{got}"
    );

    // §8.16
    let drafted = Payload::from_bytes(
        &access_kernel::json::b64url_decode(row["give"]["payload"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let Payload::GrantIssue(drafted) = drafted else {
        panic!("{row}");
    };
    let template = Give {
        template: Template::Session,
        subject: person.actor.party,
        anchor: person.actor.anchor,
        holder: SubjectSelector::Party(operator.actor.party),
        case: d.case("4411"),
        acceptance: d.acceptance,
        actions: BTreeSet::from([IdpAction::AccountRead]),
        validity: drafted.authority.constraints.validity,
    };
    assert_eq!(
        template.grant().unwrap(),
        drafted,
        "the draft is V1's template"
    );
    let wider = give_body(&d, &person, row, |c| {
        c.authority
            .authority
            .actions
            .exact
            .insert(IdpAction::AccountProfileUpdate.action_ref());
    });
    let (status, got) = f
        .send(
            Method::POST,
            &path_of(&row["id"], "/give"),
            &person,
            Some(wider),
            &[],
        )
        .await;
    assert_eq!(status, 400, "only what was asked is given: {got}");

    // TN-137 (1)
    let body = give_body(&d, &person, row, |_| {});
    let (status, given) = f
        .send(
            Method::POST,
            &path_of(&row["id"], "/give"),
            &person,
            Some(body),
            &[],
        )
        .await;
    assert_eq!(status, 201, "{given}");
    assert_eq!(given["state"], "active");
    assert_eq!(given["read_only"], true);
    let basis = holding_of(&given);
    let notices = identity_events_until(
        &d.s.w.db,
        "relay.message.support_access_notice.v1",
        |q| !q.is_empty(),
        "the granted notice",
    )
    .await;
    assert_eq!(notices.len(), 1);
    assert!(
        f.audited(&d)
            .await
            .contains(&String::from("support.access_granted"))
    );

    // TN-137 (4), Ek B 5529
    d.state(person.actor.party, "4411", true).await;
    let (read, _) = d
        .act(
            &operator.actor,
            &person.actor,
            IdpAction::AccountRead,
            d.case("4411"),
            basis,
        )
        .await;
    let read = read.unwrap();
    let (write, _) = d
        .act(
            &operator.actor,
            &person.actor,
            IdpAction::AccountProfileUpdate,
            d.case("4411"),
            basis,
        )
        .await;
    assert!(write.is_err(), "view only: {write:?}");

    // §8.16, X37, XI-17, Ek B 5613
    let (status, access) = f
        .send(Method::GET, "/v1/me/support-access", &person, None, &[])
        .await;
    assert_eq!(status, 200, "{access}");
    let given_row = &access["access"][0];
    assert_eq!(given_row["operator"], "Mehmet Y.");
    assert_eq!(given_row["organization"], "Acme Support");
    assert_eq!(given_row["case"], "4411");
    assert_eq!(given_row["revoke"]["pep"], IDENTITY_PEP, "{given_row}");
    let activity = d.hub("activity", &person.actor).await;
    let exercise = b64url_encode(&read.exercise().0);
    let used = activity
        .iter()
        .find(|u| u["exercise"] == exercise.as_str())
        .unwrap_or_else(|| panic!("{activity:?}"));
    assert_eq!(
        used["by_viewer"], false,
        "the action is the operator's, never the person's"
    );
    assert_eq!(
        used["basis"]["grant"],
        given_row["basis"]["holding"]["grant"]
    );
    let (status, theirs) = f
        .send(Method::GET, "/v1/me/support-access", &operator, None, &[])
        .await;
    assert_eq!(status, 200);
    assert!(
        theirs["access"].as_array().unwrap().is_empty(),
        "only the person's own view"
    );

    // §8.16, Ek B 5513, 5609
    let ExerciseBasis::Holding(held) = basis else {
        panic!("holding");
    };
    let revoke = Payload::GrantRevoke { grant: held.grant };
    let now = now_ms();
    let intent = self_signed_intent(
        &revoke,
        person.actor.party,
        Window {
            from: now - 60_000,
            until: now + 600_000,
        },
    )
    .unwrap();
    let body = signed(
        &d,
        &person.actor,
        (&intent, Some(&revoke)),
        ExerciseBasis::Anchor(person.actor.anchor),
        Capacity::Own,
    );
    let grant = b64url_encode(&held.grant.0);
    let (status, ended) = f
        .send(
            Method::POST,
            &format!("/v1/me/support-access/{grant}/revoke"),
            &person,
            Some(body),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{ended}");
    assert_eq!(ended["state"], "revoked");
    let after = d.read(&operator.actor, &person.actor, "4411", basis).await;
    assert!(after.is_err(), "{after:?}");
    let notices = identity_events_until(
        &d.s.w.db,
        "relay.message.support_access_notice.v1",
        |q| q.len() >= 2,
        "the revoked notice",
    )
    .await;
    assert_eq!(notices.len(), 2);
    let audited = f.audited(&d).await;
    for e in [
        "support.access_requested",
        "support.access_granted",
        "support.access_ended",
    ] {
        assert!(audited.iter().any(|a| a == e), "{e}: {audited:?}");
    }
    let mut tx = TenantTx::begin(&d.s.w.db.app, f.tenant, f.realm)
        .await
        .unwrap();
    let kek = crate::login::RealmKeks::new(d.s.w.keys.clone())
        .vault(f.realm)
        .unwrap()
        .kek;
    let again = access_identity_account::app::support::revoked(
        &mut tx,
        (&*kek, &f.ids),
        (
            &access_identity_account::adapters::system::SystemEntropy,
            &access_identity_account::adapters::system::SystemClock,
        ),
        (held.grant.0, now_ms()),
        SLUG,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(!again, "an end is announced once");
}

// §8.16, XI-7, OP-157 m.3 (c), (f), Ek B 5524, 5525
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_only_invites_and_a_person_who_blocks_support_gets_none() {
    use axum::http::Method;
    let d = Desk::open("support-block").await;
    let f = front::front(&d).await;
    f.register(&d).await;
    let person = f.person(&d, "ayse@access.test", None).await;
    let operator = f.person(&d, "mehmet@access.test", None).await;
    f.org(&d, &operator, "Acme Support").await;

    // §8.16
    let (status, got) = f
        .send(
            Method::PUT,
            "/v1/me/support-block",
            &person,
            Some(json!({ "blocked": true })),
            &[],
        )
        .await;
    assert_eq!(
        (status, got["blocked"].as_bool()),
        (200, Some(true)),
        "{got}"
    );
    let (status, got) = ask(&f, &operator, &person, ("4411", "read", 30)).await;
    assert_eq!(
        (status, got["code"].as_str()),
        (409, Some("support-blocked")),
        "{got}"
    );
    let (status, _) = f
        .send(
            Method::PUT,
            "/v1/me/support-block",
            &person,
            Some(json!({ "blocked": false })),
            &[],
        )
        .await;
    assert_eq!(status, 200);

    // XI-7
    let (status, asked) = ask(&f, &operator, &person, ("4411", "read", 30)).await;
    assert_eq!(status, 201, "{asked}");
    let (status, got) = f
        .send(
            Method::POST,
            &path_of(&asked["id"], "/decline"),
            &operator,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (status, got["code"].as_str()),
        (404, Some("support-request-unknown")),
        "{got}"
    );
    let (status, got) = f
        .send(
            Method::POST,
            &path_of(&asked["id"], "/decline"),
            &person,
            None,
            &[],
        )
        .await;
    assert_eq!(
        (status, got["state"].as_str()),
        (200, Some("declined")),
        "{got}"
    );
    let rows = incoming(&f, &person).await;
    assert_eq!(rows[0]["state"], "declined");
    assert!(
        rows[0].get("give").is_none(),
        "a declined request gives nothing"
    );
    let body = json!({ "nonce": "AA", "intent": "AA", "basis": { "anchor": "AA" }, "ais": "AA" });
    let (status, _) = f
        .send(
            Method::POST,
            &path_of(&asked["id"], "/give"),
            &person,
            Some(body),
            &[],
        )
        .await;
    assert_eq!(status, 404);
}

// §8.16, TN-74, INV-30, OP-157 m.3 (g), Ek B 5519
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one artifact from upload to its own Grant"
)]
async fn a_support_artifact_is_redacted_on_upload_and_read_only_under_its_own_grant() {
    use access_identity_admin::domain::Change;
    use access_identity_admin::domain::support::ArtifactPolicy;
    use axum::http::Method;
    let d = Desk::open("support-artifact").await;
    let f = front::front(&d).await;
    f.register(&d).await;
    let person = f.person(&d, "ayse@access.test", None).await;
    let operator = f.person(&d, "mehmet@access.test", None).await;
    f.org(&d, &operator, "Acme Support").await;
    let (_, asked) = ask(&f, &operator, &person, ("4411", "read", 30)).await;
    let token = format!(
        "{}.{}.{}",
        b64url_encode(br#"{"alg":"ES256"}"#),
        b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
        b64url_encode(&access_crypto::random::bytes::<32>().unwrap())
    );
    let cookie = b64url_encode(&access_crypto::random::bytes::<24>().unwrap());
    let har = json!({ "log": { "entries": [{ "request": {
        "url": "https://app.test/me",
        "headers": [
            { "name": "Authorization", "value": format!("Bearer {token}") },
            { "name": "Cookie", "value": format!("__Host-session={cookie}") }
        ],
        "cookies": [{ "name": "__Host-session", "value": cookie }]
    } }] } })
    .to_string();
    let upload_intent = |case: Digest| {
        let mut e = envelope(
            IdpAction::AccountArtifactUpload.action_ref(),
            (
                templates::RESOURCES,
                &[&hex(&person.actor.party), "artifacts"],
            ),
            BTreeMap::from([(
                String::from("case"),
                ParamValue::Eq(EqValue::Text(access_identity_account::app::support::hex(
                    &case.0,
                ))),
            )]),
        );
        e.purpose = Some(PurposeRef::Case(case));
        e
    };
    let upload = |content_type: &str, content: &str| {
        let intent = upload_intent(d.case("4411"));
        json!({
            "request": asked["id"],
            "content_type": content_type,
            "content": content,
            "exercise": signed(&d, &person.actor, (&intent, None),
                ExerciseBasis::Anchor(person.actor.anchor), Capacity::Own),
        })
    };

    // OP-157 m.3 (g)
    let (status, got) = f
        .send(
            Method::POST,
            "/v1/support/artifacts",
            &person,
            Some(upload("application/har+json", &har)),
            &[],
        )
        .await;
    assert_eq!(
        (status, got["code"].as_str()),
        (409, Some("support-artifacts-closed")),
        "{got}"
    );
    f.change(
        &d,
        Change::SupportArtifactPolicy(Some(ArtifactPolicy {
            max_bytes: 1 << 20,
            retention_days: 30,
        })),
    )
    .await;
    // TN-74, OP-157 m.3 (g)
    let (status, got) = f
        .send(
            Method::POST,
            "/v1/support/artifacts",
            &person,
            Some(upload("image/png", "x")),
            &[],
        )
        .await;
    assert_eq!(
        (status, got["code"].as_str()),
        (415, Some("artifact-format-refused")),
        "{got}"
    );
    let (status, _) = f
        .send(
            Method::POST,
            "/v1/support/artifacts",
            &person,
            Some(upload("video/mp4", "x")),
            &[("content-type", String::from("video/mp4"))],
        )
        .await;
    assert_eq!(status, 415);
    let (status, kept) = f
        .send(
            Method::POST,
            "/v1/support/artifacts",
            &person,
            Some(upload("application/har+json", &har)),
            &[],
        )
        .await;
    assert_eq!(status, 201, "{kept}");
    assert!(kept["redactions"].as_u64().unwrap() >= 3, "{kept}");
    assert!(
        f.audited(&d)
            .await
            .contains(&String::from("support.artifact_uploaded"))
    );
    let artifact = kept["id"].as_str().unwrap().to_owned();
    let id: [u8; 16] = access_kernel::json::b64url_decode(&artifact)
        .unwrap()
        .try_into()
        .unwrap();
    let mut tx = TenantTx::begin(&d.s.w.db.app, f.tenant, f.realm)
        .await
        .unwrap();
    let row = tx.support_artifact(id).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    let (_, _, sealed) = row.sealed.clone().unwrap();
    assert!(!sealed.windows(cookie.len()).any(|w| w == cookie.as_bytes()));

    // TN-74
    let read_intent = || {
        let case = d.case("4411");
        let mut e = envelope(
            IdpAction::AccountArtifactRead.action_ref(),
            (
                templates::RESOURCES,
                &[
                    &hex(&person.actor.party),
                    "artifacts",
                    &access_identity_account::app::support::hex(&id),
                ],
            ),
            BTreeMap::from([(
                String::from("case"),
                ParamValue::Eq(EqValue::Text(access_identity_account::app::support::hex(
                    &case.0,
                ))),
            )]),
        );
        e.purpose = Some(PurposeRef::Case(case));
        e
    };
    let header = |basis: ExerciseBasis| {
        let s = signed(
            &d,
            &operator.actor,
            (&read_intent(), None),
            basis,
            Capacity::For(person.actor.party),
        );
        vec![(
            access_http::login::SUPPORT_EXERCISE_HEADER,
            b64url_encode(s.to_string().as_bytes()),
        )]
    };
    let path = format!("/v1/support/artifacts/{artifact}");
    let (status, got) = f.send(Method::GET, &path, &operator, None, &[]).await;
    assert_eq!(
        (status, got["code"].as_str()),
        (403, Some("support-artifact-denied")),
        "{got}"
    );
    let rows = incoming(&f, &person).await;
    let (status, read_access) = f
        .send(
            Method::POST,
            &path_of(&rows[0]["id"], "/give"),
            &person,
            Some(give_body(&d, &person, &rows[0], |_| {})),
            &[],
        )
        .await;
    assert_eq!(status, 201, "{read_access}");
    d.state(person.actor.party, "4411", true).await;
    let (status, got) = f
        .send(
            Method::GET,
            &path,
            &operator,
            None,
            &header(holding_of(&read_access)),
        )
        .await;
    assert_eq!(
        (status, got["code"].as_str()),
        (403, Some("support-artifact-denied")),
        "a support Grant to view the account never reads artifacts: {got}"
    );
    let (status, asked) = ask(&f, &operator, &person, ("4411", "artifacts", 30)).await;
    assert_eq!(status, 201, "{asked}");
    let rows = incoming(&f, &person).await;
    let row = rows.iter().find(|r| r["id"] == asked["id"]).unwrap();
    assert_eq!(row["give"]["template"], "support.artifacts", "{row}");
    let (status, files) = f
        .send(
            Method::POST,
            &path_of(&row["id"], "/give"),
            &person,
            Some(give_body(&d, &person, row, |_| {})),
            &[],
        )
        .await;
    assert_eq!(status, 201, "{files}");
    let (status, got) = f
        .send(
            Method::GET,
            &path,
            &operator,
            None,
            &header(holding_of(&files)),
        )
        .await;
    assert_eq!(status, 200, "{got}");
    let text = got["content"].as_str().unwrap();
    assert!(!text.contains(&token) && !text.contains(&cookie), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    assert_eq!(got["media_type"], "application/json");
    assert!(
        f.audited(&d)
            .await
            .contains(&String::from("support.artifact_read"))
    );
}

// TN-72, TN-137 (3), §8.16, OP-157 m.3 (c), Ek B 5528
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_organization_gives_support_access_to_its_own_resources_only() {
    let d = Desk::open("support-org").await;
    let org = d.s.actor().await;
    let employee = d.s.actor().await;
    let operator = d.s.actor().await;
    let give = d
        .give(
            &org,
            operator.party,
            (Template::Org, &[IdpAction::AccountRead], 30),
            "7001",
        )
        .await;
    let basis = d.issue(&org, give.grant().unwrap()).await.unwrap();
    d.state(org.party, "7001", true).await;
    assert!(d.read(&operator, &org, "7001", basis).await.is_ok());
    d.state(employee.party, "7001", true).await;
    let reached = d.read(&operator, &employee, "7001", basis).await;
    assert!(
        reached.is_err(),
        "an employee's own account is reached only with the employee's Grant: {reached:?}"
    );
}

// §8.16,, SI-21, OP-157 m.3 (f), Ek B 5514
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn support_access_that_reaches_its_end_ends_and_the_person_is_told() {
    use axum::http::Method;
    let d = Desk::open("support-ends").await;
    let f = front::front(&d).await;
    f.register(&d).await;
    let person = f.person(&d, "ayse@access.test", None).await;
    let operator = f.person(&d, "mehmet@access.test", Some("Mehmet Y.")).await;
    f.org(&d, &operator, "Acme Support").await;
    let (_, asked) = ask(&f, &operator, &person, ("4411", "read", 5)).await;
    let rows = incoming(&f, &person).await;
    let (status, given) = f
        .send(
            Method::POST,
            &path_of(&rows[0]["id"], "/give"),
            &person,
            Some(give_body(&d, &person, &rows[0], |_| {})),
            &[],
        )
        .await;
    assert_eq!(status, 201, "{given} {asked}");
    let kek = crate::login::RealmKeks::new(d.s.w.keys.clone())
        .vault(f.realm)
        .unwrap()
        .kek;
    let sweep = |at: u64| {
        let kek = Arc::clone(&kek);
        let ids = Arc::clone(&f.ids);
        let db = d.s.w.db.app.clone();
        let (tenant, realm) = (f.tenant, f.realm);
        async move {
            let mut t = TenantTx::begin(&db, tenant, realm).await.unwrap();
            let n = access_identity_account::app::support::sweep(
                &mut t,
                (&*kek, &ids),
                (
                    &access_identity_account::adapters::system::SystemEntropy,
                    &access_identity_account::adapters::system::SystemClock,
                ),
                at,
                SLUG,
            )
            .await
            .unwrap();
            t.commit().await.unwrap();
            n
        }
    };
    assert_eq!(sweep(now_ms()).await, 0);
    assert_eq!(sweep(now_ms() + 6 * 60_000).await, 1);
    assert_eq!(
        sweep(now_ms() + 7 * 60_000).await,
        0,
        "no silent extension, one end"
    );
    let (_, access) = f
        .send(Method::GET, "/v1/me/support-access", &person, None, &[])
        .await;
    assert_eq!(access["access"][0]["state"], "ended", "{access}");
    let notices = identity_events_until(
        &d.s.w.db,
        "relay.message.support_access_notice.v1",
        |q| q.len() >= 2,
        "the ended notice",
    )
    .await;
    assert_eq!(notices.len(), 2);
}
