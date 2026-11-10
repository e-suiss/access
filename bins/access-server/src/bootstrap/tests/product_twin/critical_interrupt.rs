//! The critical interrupt Grant on the real server path (E48, INV-4, OP-156 m.3 (c), Ek B
//! 4494): Relay is a product twin of the public crates, its `relay.interrupt.critical` action
//! accepted by the domain's root. Only the person's own Grant on the person's self-anchor lets a
//! personal agent interrupt; the agent cannot give it to itself or widen it, nobody else can
//! give it for the person, and Relay asks Access live at delivery, so a revoked Grant stops the
//! next interrupt.

use super::*;

/// `actor`'s own meta-Exercise of `payload` on `basis`, decided and not panicking: the verdict.
async fn attempt(
    s: &Seam,
    actor: &Actor,
    basis: ExerciseBasis,
    payload: Payload,
) -> access_internal_api::idp::Verdict {
    let now = server_time(&s.w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, actor.party, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let ais = Seam::ais(
        &actor.key,
        &Statement {
            domain: s.domain,
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
    MetaExercises::lead(&s.w.plane, s.domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &s.w.plane,
        Request {
            domain: s.domain,
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
    )
    .await
    .unwrap();
    schedule(&s.signer);
    verdict
}

fn issued(v: &access_internal_api::idp::Verdict) -> bool {
    matches!(v, access_internal_api::idp::Verdict::Committed(_))
}

fn interrupt_grant(action: &ActionRef, basis: Id, holder: Id, prefix: &[&str]) -> Payload {
    Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(basis),
        holder: SubjectSelector::Party(holder),
        authority: canonical(
            std::slice::from_ref(action),
            structural("access.party", prefix),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    })
}

// E48, INV-4, OP-156 m.3 (c), OP-153 m.3 (gg), Ek B 4494
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "one person's interrupt Grant from issue to revocation"
)]
async fn only_the_persons_own_scoped_grant_lets_an_agent_interrupt_and_relay_asks_live() {
    let s = Seam::open("seam-relay", "relay").await;
    let relay = schema("relay");
    s.twin.publish_schema(&s.domain, &relay).await.unwrap();
    s.accept_schema(&relay).await;
    let critical = relay.action("critical").unwrap();
    let person = s.actor().await;
    let agent = s.actor().await;
    let stranger = s.actor().await;
    let me = hex(&person.party);
    let from_mom = [me.as_str(), "interrupt", "from", "mom"];
    let interrupt = |from: &str| {
        envelope(
            critical.clone(),
            ("access.party", &[&me, "interrupt", "from", from]),
            BTreeMap::new(),
        )
    };

    // E48: without a Grant the agent cannot interrupt
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &agent,
                interrupt("mom"),
                ExerciseBasis::Anchor(person.anchor),
                Vec::new(),
            ),
        )
        .await;
    assert!(r.is_err(), "{r:?}");

    // INV-4: the agent cannot give the Grant to itself on the person's self-anchor or its own
    let to_itself = attempt(
        &s,
        &agent,
        ExerciseBasis::Anchor(person.anchor),
        interrupt_grant(&critical, person.anchor, agent.party, &from_mom),
    )
    .await;
    assert!(!issued(&to_itself), "{to_itself:?}");
    let on_its_own = attempt(
        &s,
        &agent,
        ExerciseBasis::Anchor(agent.anchor),
        interrupt_grant(&critical, agent.anchor, agent.party, &from_mom),
    )
    .await;
    assert!(!issued(&on_its_own), "{on_its_own:?}");
    // E48: nobody gives it for the person
    let for_someone_else = attempt(
        &s,
        &stranger,
        ExerciseBasis::Anchor(person.anchor),
        interrupt_grant(&critical, person.anchor, agent.party, &from_mom),
    )
    .await;
    assert!(!issued(&for_someone_else), "{for_someone_else:?}");
    let from_its_anchor = attempt(
        &s,
        &stranger,
        ExerciseBasis::Anchor(stranger.anchor),
        interrupt_grant(&critical, stranger.anchor, agent.party, &from_mom),
    )
    .await;
    assert!(
        !issued(&from_its_anchor),
        "a stranger's own anchor does not cover the person: {from_its_anchor:?}"
    );

    // E48: the person's explicit, scoped Grant
    let (exercise, since) = s
        .own_commit(
            &person,
            ExerciseBasis::Anchor(person.anchor),
            interrupt_grant(&critical, person.anchor, agent.party, &from_mom),
        )
        .await;
    let grant = meta::object_id(&exercise, kind::GRANT, 0);
    let basis = holding(grant, agent.party, since);
    let mom = interrupt("mom");
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, mom.clone(), basis, Vec::new()),
        )
        .await
        .unwrap();
    let mut delivered = Vec::new();
    ProductTwin::enforce(allowed, &mom, || delivered.push("mom")).unwrap();
    assert_eq!(delivered, ["mom"]);
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, interrupt("boss"), basis, Vec::new()),
        )
        .await;
    assert!(
        matches!(r, Err(Denied::Refused(Refusal::Deny))),
        "the scope holds: {r:?}"
    );

    // INV-4: holding it, the agent still cannot widen it
    let wider = attempt(
        &s,
        &agent,
        basis,
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Holding(HoldingRef {
                grant,
                holder: agent.party,
                since,
            }),
            holder: SubjectSelector::Party(agent.party),
            authority: canonical(
                std::slice::from_ref(&critical),
                structural("access.party", &[&me, "interrupt"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        }),
    )
    .await;
    assert!(!issued(&wider), "{wider:?}");

    // E48: Relay asks at delivery, so the person's revocation stops the next interrupt
    s.own_commit(
        &person,
        ExerciseBasis::Anchor(person.anchor),
        Payload::GrantRevoke { grant },
    )
    .await;
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, interrupt("mom"), basis, Vec::new()),
        )
        .await;
    assert!(r.is_err(), "{r:?}");
    s.only_public();
}
