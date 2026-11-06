//! Subject resolution (OP-149 A11) and allowed Exercises (OP-149 m.9) against the real
//! authority plane and identity store.

use access_http::product::ports::{Sector, SubjectQuery, Subjects as _};

use super::*;
use crate::product::PgSubjects;

// OP-149 A11, MD-10: a realm's Party resolves to the pairwise sub one of its clients sees and
// back; the sub is the one the client's tokens carry, assigned once; what does not resolve is
// left out, and the answer carries the governing domain's consistency token
#[tokio::test]
async fn parties_resolve_to_a_clients_pairwise_sub_and_back() {
    // OP-141 m.22 (f), OP-149 m.16 (a)
    let w = World::new().await;
    let (t, r, d) = w.realm("acme").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let c = new_client(&w).await;
    let p = proposal(
        (t, r),
        Change::ClientRegister(c.clone()),
        3,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &p, ROOT_KEY).await.unwrap());
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let subject = tx
        .insert_subject("staged", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut tx, &subject, &ALICE.0)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let s = PgSubjects {
        app: w.db.app.clone(),
        domains: w.plane.domains.clone(),
    };
    let ask = |q| {
        s.resolve(
            *t.as_bytes(),
            *r.as_bytes(),
            Sector::RealmClient(c.id.as_str()),
            q,
        )
    };
    let found = ask(SubjectQuery::Parties(vec![ALICE.0, [4; 16]]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.pairs.len(), 1);
    let (party, sub) = found.pairs[0].clone();
    assert_eq!((party, sub.len()), (ALICE.0, 43));
    assert_ne!(found.consistency, "");
    let again = ask(SubjectQuery::Parties(vec![ALICE.0]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.pairs[0].1, sub, "assigned once");
    let mut t2 = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let sector = c_uuid(&w, t, r, &c).await;
    let stored = t2
        .pairwise(subject, sector, &b64url(&[1; 32]))
        .await
        .unwrap();
    t2.commit().await.unwrap();
    assert_eq!(stored, sub, "the sub the client's tokens carry");
    let back = ask(SubjectQuery::Subs(vec![sub.clone(), b64url(&[7; 32])]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.pairs, vec![(ALICE.0, sub)]);
    assert!(
        s.resolve(
            *t.as_bytes(),
            *r.as_bytes(),
            Sector::RealmClient("cli_nobody"),
            SubjectQuery::Parties(vec![ALICE.0])
        )
        .await
        .unwrap()
        .is_none()
    );
}

async fn c_uuid(w: &World, t: TenantId, r: RealmId, c: &Client) -> [u8; 16] {
    let mut tx = TenantTx::begin(&w.db.app, t, r).await.unwrap();
    let row = client(&mut tx, c.id.as_str()).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    row.client_uuid
}

fn b64url(b: &[u8]) -> String {
    access_kernel::json::b64url_encode(b)
}

// OP-149 m.9, §9.8, L2-RCP-2: the receipt of each new ALLOW is kept, so an allowed Exercise is
// read back by its id with that receipt; an Exercise the domain never allowed is not found
#[tokio::test]
async fn an_allowed_exercise_is_read_back_with_its_receipt() {
    // OP-141 m.6
    let w = World::new().await;
    let (_, _, d) = w.realm("acme").await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let challenge = challenge_of(ALICE_KEY);
    let id = meta::exercise_id(&d, &challenge).unwrap();
    let found = w
        .plane
        .domains
        .exercise_record(d, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.exercise, id);
    let receipt =
        access_kernel::receipt::Receipt::from_bytes(found.receipt.as_ref().unwrap()).unwrap();
    assert_eq!(
        (receipt.exercise, receipt.record, receipt.intent),
        (id, found.position, found.intent)
    );
    assert!(found.signed_receipt.is_none(), "no signer in this test");
    let other = meta::exercise_id(&d, &[0x77; 32]).unwrap();
    assert!(
        w.plane
            .domains
            .exercise_record(d, other)
            .await
            .unwrap()
            .is_none()
    );
}
