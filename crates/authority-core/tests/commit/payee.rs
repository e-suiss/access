//! The new-payee floor on the real store (§13.7.2, SEC10, L0-EVAL-71, OP-159 m.3 (m), Ek B
//! 5602): a payment to a payee the domain has not paid is CT2, and once an ALLOW to it is
//! committed the next payment keeps its own tier.

use access_kernel::intent::ParamValue;
use access_kernel::record::RecordEnvelope;

use super::*;

async fn tier_of(db: &TestDb, d: Digest, nonce: u8) -> Option<u8> {
    access_store::authority::find_nonce(&db.app, &DomainId::from_bytes(d.0), &[nonce; 16])
        .await
        .unwrap()
        .and_then(|n| n.tier)
}

async fn cited(db: &TestDb, d: Digest, record: u64) -> Option<Value> {
    let log =
        access_store::authority::read_log(&db.app, &DomainId::from_bytes(d.0), record, record)
            .await
            .unwrap();
    let envelope = RecordEnvelope::from_bytes(&log.first().unwrap().envelope).unwrap();
    envelope
        .fields
        .get("state_basis")
        .unwrap()
        .value
        .get("derived")
        .and_then(|v| v.get("payee_seen"))
        .cloned()
}

fn paying(d: Digest, nonce: u8, mode: Mode, payee: Id) -> Request {
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut r = shop_request(d, nonce, mode, shop);
    r.intent.params.insert(
        "amount".to_owned(),
        ParamValue::Amount {
            value: 500,
            unit: access_kernel::tier::THRESHOLD_UNIT.to_owned(),
        },
    );
    r.intent.recipient = Some(payee);
    r
}

// L0-EVAL-71, SEC10, OP-159 m.3 (m), Ek B 5602
#[tokio::test]
async fn a_first_payment_to_a_payee_is_ct2_and_a_seen_payee_keeps_ct1() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let (bob, carol) = (Id([0xb0; 16]), Id([0xc0; 16]));
    let checked = send(&mut core, paying(d, 10, Mode::Check, bob), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(checked.decision.outcome, Outcome::Allow);
    let first = send(&mut core, paying(d, 11, Mode::Commit, bob), ROOT_KEY)
        .await
        .unwrap();
    allowed(&first);
    assert_eq!(tier_of(&db, d, 11).await, Some(2), "a check marks nothing");
    assert_eq!(
        cited(&db, d, first.record.unwrap()).await,
        Some(Value::Unsigned(0))
    );
    let second = send(&mut core, paying(d, 12, Mode::Commit, bob), ROOT_KEY)
        .await
        .unwrap();
    allowed(&second);
    assert_eq!(tier_of(&db, d, 12).await, Some(1));
    assert_eq!(
        cited(&db, d, second.record.unwrap()).await,
        Some(Value::Unsigned(1))
    );
    let other = send(&mut core, paying(d, 13, Mode::Commit, carol), ROOT_KEY)
        .await
        .unwrap();
    allowed(&other);
    assert_eq!(tier_of(&db, d, 13).await, Some(2));
    // SI-8
    let again = core
        .explain_recorded(
            &incoming(paying(d, 12, Mode::Commit, bob), ROOT_KEY),
            second.record.unwrap(),
            Scope::Requester,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(again.decision, second.decision);
    fold_check(&db.sequencer, d).await.unwrap();
}
