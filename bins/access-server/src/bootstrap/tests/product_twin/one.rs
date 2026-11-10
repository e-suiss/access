//! The One seam on the real server path (§7.3, §7.9.6, E24, INV-4, OP-156 m.3 (w), OP-153
//! m.3 (gg)). Suiss One is a product twin built on the public crates alone: it pairs as a
//! platform product, so its Party and Instance key are its own, and the domain's root accepts
//! its schema with its own Exercise. The person gives One a Grant for themself (`FOR(user)`);
//! One acts only within it, never as itself, never past it, and never gives itself a Grant.

use super::*;

/// One's request for `envelope` on `basis` in `capacity`, signed with its own Instance key and
/// with the twin, One itself, as PEP.
fn own_request(
    s: &Seam,
    key: &SoftSigner,
    envelope: IntentEnvelope,
    basis: ExerciseBasis,
    capacity: Capacity,
) -> access_product_twin::Request {
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let ais = Seam::ais(
        key,
        &Statement {
            domain: s.domain,
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
    access_product_twin::Request {
        ais,
        envelope,
        nonce,
        basis,
        capacity,
        proofs: Vec::new(),
    }
}

fn message(action: &ActionRef, person: &Actor, conversation: &str, to: Id) -> IntentEnvelope {
    envelope(
        action.clone(),
        ("access.party", &[&hex(&person.party), conversation]),
        BTreeMap::from([(String::from("recipient"), ParamValue::Subject(to))]),
    )
}

// §7.3, §7.9.6, E24, INV-4, OP-156 m.3 (w), Ek B 5264
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_acts_for_the_person_only_within_what_the_person_gave_it() {
    let (s, key) = Seam::open_keyed("seam-one", "one").await;
    let one = schema("one");
    let published = s.twin.publish_schema(&s.domain, &one).await.unwrap();
    assert!(
        !s.twin
            .accepted(&s.domain, "one", &published.fingerprint)
            .await
            .unwrap()
    );
    // E24
    s.accept_schema(&one).await;
    assert!(
        s.twin
            .accepted(&s.domain, "one", &published.fingerprint)
            .await
            .unwrap()
    );
    let send = one.action("message").unwrap();
    let person = s.actor().await;
    let friend = s.actor().await;
    let stranger = s.actor().await;

    // §7.9.6.1
    let (exercise, since) = s
        .own_commit(
            &person,
            ExerciseBasis::Anchor(person.anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(person.anchor),
                holder: SubjectSelector::Party(s.party),
                authority: canonical(
                    std::slice::from_ref(&send),
                    structural("access.party", &[&hex(&person.party)]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::For(person.party)]),
                named: None,
            }),
        )
        .await;
    let grant = meta::object_id(&exercise, kind::GRANT, 0);
    let basis = holding(grant, s.party, since);

    let mut delivered = Vec::new();
    let first = message(&send, &person, "c-1", friend.party);
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &own_request(&s, &key, first.clone(), basis, Capacity::For(person.party)),
        )
        .await
        .unwrap();
    ProductTwin::enforce(allowed, &first, || delivered.push("c-1")).unwrap();
    schedule(&s.signer);

    // §7.9.6.2
    let r = s
        .twin
        .ask(
            &s.domain,
            &own_request(
                &s,
                &key,
                message(&send, &person, "c-2", friend.party),
                basis,
                Capacity::Own,
            ),
        )
        .await;
    assert!(r.is_err(), "{r:?}");

    // §7.9.6.3
    let r = s
        .twin
        .ask(
            &s.domain,
            &own_request(
                &s,
                &key,
                message(&send, &stranger, "c-3", friend.party),
                basis,
                Capacity::For(stranger.party),
            ),
        )
        .await;
    assert!(r.is_err(), "{r:?}");

    // INV-4, §7.9.6.3
    let to_itself = s
        .twin
        .attempt(
            &s.domain,
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(person.anchor),
                holder: SubjectSelector::Party(s.party),
                authority: canonical(
                    std::slice::from_ref(&send),
                    structural("access.party", &[]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::For(person.party)]),
                named: None,
            }),
            ExerciseBasis::Anchor(person.anchor),
        )
        .await
        .unwrap();
    assert!(!to_itself.took_effect(), "{to_itself:?}");
    let onward = s
        .twin
        .attempt(
            &s.domain,
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Holding(HoldingRef {
                    grant,
                    holder: s.party,
                    since,
                }),
                holder: SubjectSelector::Party(s.party),
                authority: canonical(
                    std::slice::from_ref(&send),
                    structural("access.party", &[&hex(&person.party)]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::For(person.party)]),
                named: None,
            }),
            basis,
        )
        .await
        .unwrap();
    assert!(!onward.took_effect(), "{onward:?}");

    // §7.9.6.3, §7.9.7.2
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
            &own_request(
                &s,
                &key,
                message(&send, &person, "c-4", friend.party),
                basis,
                Capacity::For(person.party),
            ),
        )
        .await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(delivered, ["c-1"]);
    s.only_public();
}
