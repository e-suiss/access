//! SYNC-DERIVED rows in the commit of their record (OP-158 m.17 (g), §16.5.1, G43, SI-7) on the
//! real store: with every write after a commit failing, as a crash between the commit and a later
//! write would, a published list still never leaves out a holding its record ended, and a
//! verifier's contracts and reports still decide what it is issued next.

use access_authority_core::adapters::{Projected, TokenAuthority};
use access_authority_core::status::adapters::{PgLists, SignerSocket, open_family};
use access_authority_core::status::{Publisher, list_uri};
use access_kernel::status::lookup;
use access_store::projections::Family;
use access_store::testing::{fail_derived_after_commit, unapplied_end};

use super::*;

// G43, §9.9.3 k.6, P50, SI-7, OP-158 m.17 (g), Ek B 6145
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the injected failure, the ending record, its list, then the guard"
)]
async fn g43_a_list_never_leaves_out_a_holding_its_record_ended() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("s3-holder-end");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let uri = list_uri(API, &d, 0);
    let issue = |nonce, family| {
        token_order(
            d,
            nonce,
            vec![action("shop", "read")],
            RS,
            60_000,
            TokenAuthority::Bounds,
            family,
        )
    };
    let issued = async |order| match a.project(&order).await.unwrap() {
        Projected::Issued(t) => t,
        other => panic!("{other:?}"),
    };
    issued(issue(90, None)).await;
    issued(issue(91, None)).await;
    let publisher = Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket.clone()),
    );
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let family = || Family {
        family: access_crypto::random::bytes().unwrap(),
        client_id: String::from("cli_x"),
        holder: access_crypto::random::bytes().unwrap(),
        root_exercise: access_crypto::random::bytes().unwrap(),
        status: None,
        revoked_pos: None,
    };
    let open = async |f: &Family| {
        open_family(&db.sequencer, API, d, f)
            .await
            .unwrap()
            .unwrap()
            .1
    };
    let revoke = async |f: &Family, pos| {
        assert!(
            access_store::projections::revoke_family(
                &db.sequencer,
                &DomainId::from_bytes(d.0),
                &f.family,
                pos
            )
            .await
            .unwrap()
        );
    };
    let other = family();
    let other_idx = open(&other).await;

    fail_derived_after_commit(&db).await.unwrap();
    let instance = meta::object_id(&meta::exercise_id(&d, &[2; 16]).unwrap(), kind::INSTANCE, 0);
    let anchor = ExerciseBasis::Anchor(meta::object_id(
        &meta::exercise_id(&d, &[1; 16]).unwrap(),
        kind::ANCHOR,
        0,
    ));
    let terminate = incoming(
        meta_request(d, 92, anchor, Payload::InstanceTerminate { instance }),
        ROOT_KEY,
    );
    let ended = a.exercise(&terminate).await;
    let pos = head_of(&db, d).await;
    revoke(&other, pos).await;
    // G43
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let (t, raw) = published_bits(&db, d, &uri).await;
    assert_eq!(t.as_of, pos);
    assert!(lookup(&t, &raw, &entry(&uri, other_idx)).unwrap());
    assert!(
        lookup(&t, &raw, &entry(&uri, 0)).unwrap() && lookup(&t, &raw, &entry(&uri, 1)).unwrap(),
        "a list signed at the ending record carries the bits of the holding it ended"
    );
    let ended = ended.unwrap();
    allowed(&ended);
    assert_eq!(ended.record, Some(pos));

    // OP-158 m.17 (g)
    let held = family();
    open(&held).await;
    unapplied_end(&db, d.0, pos, held.holder).await.unwrap();
    let extra = family();
    open(&extra).await;
    revoke(&extra, pos).await;
    assert!(
        publisher.publish(d, NOW).await.is_err(),
        "no list is signed while an ending record leaves a holding on it live"
    );
    assert_eq!(
        published_bits(&db, d, &uri).await.0,
        t,
        "the last list stays the last one"
    );
}

// SI-7, SEC14, TI-4, §16.5.1, §16.5.2, §13.7.2, OP-158 m.17 (g), Ek B 6151
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one verifier's contract, overdue denial and report, in order"
)]
async fn si_7_a_verifiers_contracts_and_reports_are_written_with_their_records() {
    use access_authority_core::app::projection::policy;
    use access_authority_core::restrict::derived::verifier_contracts_key;
    use access_internal_api::claims::ClaimVerdict;
    use access_kernel::report::Report;
    use access_kernel::validity::ProfileVariant as V;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let clock = Movable::at(NOW);
    let a = moving_process(&db, d, clock.clone());
    onboard_process(&a, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read")], 50).await;
    let hour = 3_600_000;
    let lone = "lone.example";
    let body = access_kernel::claim::body::Body::VerifierProfile(verifier_profile(lone, true));
    admitted(
        &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
            .await
            .unwrap()
            .verdict,
    );
    let key = verifier_contracts_key(lone);
    let version = async || {
        access_store::authority::versions(
            &db.app,
            &DomainId::from_bytes(d.0),
            std::slice::from_ref(&key),
        )
        .await
        .unwrap()[0]
    };
    let at = async |nonce: u8, variant: V, now: u64| {
        let mut request = meta_request(
            d,
            nonce,
            holding,
            projection(
                vec![action("shop", "read")],
                &[lone],
                variant,
                (now, now + hour),
                None,
                None,
            ),
        );
        request.intent.validity = Window {
            from: now,
            until: now + hour,
        };
        a.exercise(&incoming_at(request, ALICE_KEY, now)).await
    };

    fail_derived_after_commit(&db).await.unwrap();
    let issued = at(10, V::CheckpointedOffline, NOW).await;
    let overdue = NOW + hour + 24 * hour + 1;
    clock.set(overdue);
    // SEC14
    let refused = at(11, V::OnlineStrict, overdue).await.unwrap();
    policy_denied(&refused, policy::UNREPORTED);
    let issued = issued.unwrap();
    allowed(&issued);
    // §16.5.2, TI-4
    assert_eq!(version().await, issued.record.unwrap());

    let pap = access_kernel::pap::Pap::from_bytes(&issued.pap.unwrap()).unwrap();
    let contract = contract_digest(&pap);
    let report = Report {
        verifier_profile: *access_verifier::profile::LocalProfile::new(verifier_profile(
            lone, true,
        ))
        .unwrap()
        .digest(),
        verifier_instance: None,
        exercise: pap.projection_exercise,
        contract,
        period: Window {
            from: NOW,
            until: NOW + hour,
        },
        previous: None,
        first_seq: 0,
        entries: Vec::new(),
        head: access_kernel::report::seed(&pap.projection_exercise, &contract).unwrap(),
        slice_unused: BTreeSet::new(),
        profile_version: 1,
    };
    let value = access_kernel::claim::body::body_digest(
        access_kernel::claim::body::Class::OfflineExerciseReport,
        &report.to_value(),
    )
    .unwrap();
    let reported = a
        .ingest(&report_claim(
            d,
            "offline_exercise_report",
            value,
            report.to_bytes().unwrap(),
            overdue,
        ))
        .await
        .unwrap();
    let ClaimVerdict::Admitted { position, .. } = reported.verdict else {
        panic!("{:?}", reported.verdict);
    };
    assert_eq!(version().await, position);
    let rec = a.reconciliation(d, pap.projection_exercise).await.unwrap();
    assert_eq!(rec.len(), 1);
    assert!(rec[0].bound && rec[0].continuous && rec[0].late, "{rec:?}");
    allowed(&at(12, V::OnlineStrict, overdue).await.unwrap());
    fold_check(&db.sequencer, d).await.unwrap();
}
