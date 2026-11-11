//! E52, E66, OP-74, OP-78: the operator's side of the user-keyed domain on a real PostgreSQL. The
//! erasure plan of `suiss-retention` is applied to the copies the operator records: one record's
//! key goes everywhere it is held, a device that is away keeps the `erasure_log` entry open until
//! it reconnects, and a hold suspends destruction without making anything readable.

#![allow(
    clippy::unwrap_used,
    clippy::unreachable,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::testing::fresh;
use access_store::user_keyed::KeyCopy;
use suiss_retention::user_keyed::{
    ErasureState, Holder, Key, Plan, Target, Wrapped, plan, reconnected,
};
use suiss_retention::{
    Class, DeviceId, Hold, HoldId, HoldKind, HoldScope, JobId, RecordKeyId, SubjectId,
    TenantId as PolicyTenant, Timestamp,
};

const T: TenantId = TenantId::from_bytes([0x71; 16]);
const R: RealmId = RealmId::from_bytes([0x72; 16]);
const NOW: Timestamp = Timestamp::from_unix_millis(1_800_000_000_000);

fn subject() -> [u8; 16] {
    access_crypto::random::bytes::<16>().unwrap()
}

fn wrapped_bytes() -> Vec<u8> {
    access_crypto::random::bytes::<48>().unwrap().to_vec()
}

fn row_of(w: &Wrapped) -> KeyCopy {
    let (class, record_key) = match &w.key {
        Key::ClassDek(c) => (c.name().to_owned(), String::new()),
        Key::Record(c, r) => (c.name().to_owned(), r.as_str().to_owned()),
    };
    let (holder, holder_id, wrapped) = match &w.holder {
        Holder::Server => ("server", String::new(), Some(wrapped_bytes())),
        Holder::Vault => ("vault", String::new(), Some(wrapped_bytes())),
        Holder::Tee(j) => ("tee", j.as_str().to_owned(), None),
        Holder::Device(d) => ("device", d.as_str().to_owned(), None),
    };
    KeyCopy {
        class,
        record_key,
        holder: holder.to_owned(),
        holder_id,
        wrapped,
        destroyed: false,
    }
}

fn copies() -> Vec<Wrapped> {
    let mut out = Vec::new();
    for holder in [
        Holder::Server,
        Holder::Vault,
        Holder::Tee(JobId::new("job-1")),
        Holder::Device(DeviceId::new("phone")),
        Holder::Device(DeviceId::new("laptop")),
    ] {
        for key in [
            Key::ClassDek(Class::OneMemory),
            Key::Record(Class::OneMemory, RecordKeyId::new("r1")),
            Key::Record(Class::OneMemory, RecordKeyId::new("r2")),
        ] {
            out.push(Wrapped {
                key,
                holder: holder.clone(),
            });
        }
    }
    out
}

fn state_text(s: &ErasureState) -> (&'static str, Vec<String>) {
    match s {
        ErasureState::Applied => ("applied", Vec::new()),
        ErasureState::PendingDevices(d) => (
            "pending_devices",
            d.iter().map(|x| x.as_str().to_owned()).collect(),
        ),
        ErasureState::PendingHold => ("pending_hold", Vec::new()),
        _ => unreachable!("every state is listed"),
    }
}

async fn apply(tx: &mut TenantTx, s: [u8; 16], p: &Plan) {
    for w in &p.destroy {
        assert!(tx.destroy_key_copy(s, &row_of(w)).await.unwrap(), "{w:?}");
    }
}

async fn seeded(tx: &mut TenantTx, s: [u8; 16]) {
    for w in copies() {
        tx.add_key_copy(s, &row_of(&w)).await.unwrap();
    }
}

// E66 (2), E52 (3), OP-74
#[tokio::test]
async fn one_record_is_forgotten_everywhere_and_a_device_away_keeps_the_entry_open() {
    let db = fresh().await.unwrap();
    let s = subject();
    let mut tx = TenantTx::begin(&db.app, T, R).await.unwrap();
    seeded(&mut tx, s).await;
    let target = Target::Record(Class::OneMemory, RecordKeyId::new("r1"));
    let who = (&PolicyTenant::new("t"), &SubjectId::new("p_1"));
    let p = plan(
        who,
        &target,
        &copies(),
        (&[DeviceId::new("phone")], &[], NOW),
    )
    .unwrap();
    apply(&mut tx, s, &p).await;
    let (state, waiting) = state_text(&p.state);
    assert_eq!(
        (state, waiting.as_slice()),
        ("pending_devices", &[String::from("laptop")][..])
    );
    let id = tx
        .open_erasure(
            s,
            ("record", Some("one_memory"), Some("r1")),
            (state, &waiting),
        )
        .await
        .unwrap();
    let held = tx.key_copies(s).await.unwrap();
    for c in &held {
        let gone = c.record_key == "r1" && c.holder_id != "laptop";
        assert_eq!(c.destroyed, gone, "{c:?}");
        assert_eq!(
            c.wrapped.is_some(),
            !gone && matches!(c.holder.as_str(), "server" | "vault")
        );
    }
    assert!(
        held.iter().any(|c| c.record_key.is_empty() && !c.destroyed),
        "the class DEK lives"
    );

    let back = reconnected(&p.state, &target, &DeviceId::new("laptop"), &copies());
    apply(&mut tx, s, &back).await;
    let (state, waiting) = state_text(&back.state);
    assert!(tx.advance_erasure(id, state, &waiting).await.unwrap());
    assert_eq!(tx.erasure(id).await.unwrap().unwrap().state, "applied");
    assert!(
        tx.advance_erasure(id, "pending_hold", &[]).await.is_err(),
        "a closed entry stays closed"
    );
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, T, R).await.unwrap();
    let again = row_of(&Wrapped {
        key: Key::Record(Class::OneMemory, RecordKeyId::new("r1")),
        holder: Holder::Server,
    });
    assert!(
        !tx.destroy_key_copy(s, &again).await.unwrap(),
        "destroyed once"
    );
    tx.commit().await.unwrap();
}

// OP-78 m.1–m.3
#[tokio::test]
async fn a_hold_keeps_every_copy_and_the_erasure_waits_for_its_end() {
    let db = fresh().await.unwrap();
    let s = subject();
    let mut tx = TenantTx::begin(&db.app, T, R).await.unwrap();
    seeded(&mut tx, s).await;
    let policy_tenant = PolicyTenant::new("t");
    let person = SubjectId::new("p_2");
    let hold = |until| Hold {
        id: HoldId::new("h"),
        tenant: policy_tenant.clone(),
        scope: HoldScope::Subject(person.clone()),
        placed_at: Timestamp::from_unix_millis(1),
        until,
        kind: HoldKind::Regulator,
        suspicious_activity: false,
    };
    let everyone = [DeviceId::new("phone"), DeviceId::new("laptop")];
    let p = plan(
        (&policy_tenant, &person),
        &Target::Account,
        &copies(),
        (&everyone, &[hold(None)], NOW),
    )
    .unwrap();
    assert_eq!(p.destroy, vec![]);
    let (state, waiting) = state_text(&p.state);
    let id = tx
        .open_erasure(s, ("account", None, None), (state, &waiting))
        .await
        .unwrap();
    assert!(tx.key_copies(s).await.unwrap().iter().all(|c| !c.destroyed));
    let lifted = plan(
        (&policy_tenant, &person),
        &Target::Account,
        &copies(),
        (
            &everyone,
            &[hold(Some(Timestamp::from_unix_millis(2)))],
            NOW,
        ),
    )
    .unwrap();
    apply(&mut tx, s, &lifted).await;
    let (state, waiting) = state_text(&lifted.state);
    assert!(tx.advance_erasure(id, state, &waiting).await.unwrap());
    assert!(
        tx.key_copies(s)
            .await
            .unwrap()
            .iter()
            .all(|c| c.destroyed && c.wrapped.is_none())
    );
    tx.commit().await.unwrap();
}
