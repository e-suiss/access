use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::hold::{HoldKind, HoldScope};
use crate::ids::HoldId;

fn tenant() -> TenantId {
    TenantId::new("t1")
}

fn subject() -> SubjectId {
    SubjectId::new("p_9f2")
}

fn rk(id: &str) -> RecordKeyId {
    RecordKeyId::new(id)
}

fn dev(id: &str) -> DeviceId {
    DeviceId::new(id)
}

fn copies() -> Vec<Wrapped> {
    let mut out = Vec::new();
    for holder in [
        Holder::Server,
        Holder::Vault,
        Holder::Tee(JobId::new("job1")),
        Holder::Device(dev("phone")),
        Holder::Device(dev("laptop")),
    ] {
        out.push(Wrapped {
            key: Key::ClassDek(Class::OneMemory),
            holder: holder.clone(),
        });
        out.push(Wrapped {
            key: Key::Record(Class::OneMemory, rk("r1")),
            holder: holder.clone(),
        });
        out.push(Wrapped {
            key: Key::Record(Class::OneMemory, rk("r2")),
            holder: holder.clone(),
        });
        out.push(Wrapped {
            key: Key::ClassDek(Class::OneModel),
            holder,
        });
    }
    out
}

fn hold(scope: HoldScope, until: Option<u64>) -> Hold {
    Hold {
        id: HoldId::new("h1"),
        tenant: tenant(),
        scope,
        placed_at: Timestamp::from_unix_millis(1_000),
        until: until.map(Timestamp::from_unix_millis),
        kind: HoldKind::Regulator,
        suspicious_activity: false,
    }
}

const NOW: Timestamp = Timestamp::from_unix_millis(5_000);

fn path(kind: RecoveryPath, assurance: Assurance) -> Path {
    Path { kind, assurance }
}

// E52 (2), TN-H2
#[test]
fn setup_needs_two_paths_none_weaker_than_what_they_protect() {
    let vault = path(RecoveryPath::Vault, Assurance::High);
    let key = path(RecoveryPath::RecoveryKey, Assurance::High);
    let contact = path(RecoveryPath::RecoveryContact, Assurance::Substantial);
    assert_eq!(check_setup(&[vault, key], Assurance::High), Ok(()));
    assert_eq!(
        check_setup(&[vault], Assurance::High),
        Err(SetupRefusal::TooFewPaths)
    );
    assert_eq!(
        check_setup(&[vault, vault], Assurance::High),
        Err(SetupRefusal::TooFewPaths)
    );
    assert_eq!(
        check_setup(&[vault, contact], Assurance::High),
        Err(SetupRefusal::WeakerThanProtected(
            RecoveryPath::RecoveryContact
        ))
    );
    assert_eq!(
        check_setup(&[vault, contact], Assurance::Substantial),
        Ok(())
    );
}

// E52 (2)
#[test]
fn without_a_usable_path_the_data_is_lost_and_said_so() {
    let device = path(RecoveryPath::SecondDevice, Assurance::High);
    let contact = path(RecoveryPath::RecoveryContact, Assurance::Substantial);
    assert_eq!(
        kek_recovery(&[contact, device], Assurance::High),
        KekRecovery::Through(RecoveryPath::SecondDevice)
    );
    assert_eq!(
        kek_recovery(&[contact], Assurance::High),
        KekRecovery::DataLost
    );
    assert_eq!(kek_recovery(&[], Assurance::Low), KekRecovery::DataLost);
}

// E66 (2), OP-74
#[test]
fn forgetting_one_record_destroys_only_its_record_key_everywhere() {
    let all = copies();
    let connected = [dev("phone"), dev("laptop")];
    let p = plan(
        (&tenant(), &subject()),
        &Target::Record(Class::OneMemory, rk("r1")),
        &all,
        (&connected, &[], NOW),
    )
    .unwrap();
    assert_eq!(p.state, ErasureState::Applied);
    assert_eq!(p.destroy.len(), 5);
    assert!(
        p.destroy
            .iter()
            .all(|c| c.key == Key::Record(Class::OneMemory, rk("r1")))
    );
    for holder in [
        Holder::Server,
        Holder::Vault,
        Holder::Tee(JobId::new("job1")),
    ] {
        assert!(p.destroy.iter().any(|c| c.holder == holder));
    }
}

// E66 (3)
#[test]
fn a_class_shred_destroys_the_class_dek_and_its_record_keys_and_nothing_else() {
    let p = plan(
        (&tenant(), &subject()),
        &Target::Class(Class::OneMemory),
        &copies(),
        (&[dev("phone"), dev("laptop")], &[], NOW),
    )
    .unwrap();
    assert_eq!(p.destroy.len(), 15);
    assert!(p.destroy.iter().all(|c| c.key.class() == Class::OneMemory));
    let account = plan(
        (&tenant(), &subject()),
        &Target::Account,
        &copies(),
        (&[dev("phone"), dev("laptop")], &[], NOW),
    )
    .unwrap();
    assert_eq!(account.destroy.len(), 20);
    assert_eq!(
        plan(
            (&tenant(), &subject()),
            &Target::Class(Class::Profile),
            &copies(),
            (&[], &[], NOW)
        ),
        Err(Refusal::NotUserKeyed(Class::Profile))
    );
}

// E52 (3)
#[test]
fn an_offline_device_destroys_its_copy_when_it_reconnects_and_the_entry_waits() {
    let all = copies();
    let target = Target::Record(Class::OneMemory, rk("r2"));
    let p = plan(
        (&tenant(), &subject()),
        &target,
        &all,
        (&[dev("phone")], &[], NOW),
    )
    .unwrap();
    assert_eq!(p.state, ErasureState::PendingDevices(vec![dev("laptop")]));
    assert!(
        p.destroy
            .iter()
            .all(|c| c.holder != Holder::Device(dev("laptop")))
    );
    let unrelated = reconnected(&p.state, &target, &dev("tablet"), &all);
    assert_eq!(unrelated.state, p.state);
    assert_eq!(unrelated.destroy, vec![]);
    let back = reconnected(&p.state, &target, &dev("laptop"), &all);
    assert_eq!(back.state, ErasureState::Applied);
    assert_eq!(
        back.destroy,
        vec![Wrapped {
            key: Key::Record(Class::OneMemory, rk("r2")),
            holder: Holder::Device(dev("laptop")),
        }]
    );
}

// OP-78 m.1–m.4
#[test]
fn a_hold_suspends_destruction_gives_no_readability_and_releases_the_pending_erasure() {
    let all = copies();
    let target = Target::Account;
    let connected = [dev("phone"), dev("laptop")];
    for scope in [
        HoldScope::Subject(subject()),
        HoldScope::Classes(vec![Class::OneModel]),
        HoldScope::Tenant,
    ] {
        let active = hold(scope.clone(), None);
        let p = plan(
            (&tenant(), &subject()),
            &target,
            &all,
            (&connected, &[active], NOW),
        )
        .unwrap();
        assert_eq!(p.state, ErasureState::PendingHold);
        assert_eq!(p.destroy, vec![]);
        let lifted = hold(scope, Some(4_000));
        let p = plan(
            (&tenant(), &subject()),
            &target,
            &all,
            (&connected, &[lifted], NOW),
        )
        .unwrap();
        assert_eq!(p.state, ErasureState::Applied);
        assert_eq!(p.destroy.len(), 20);
    }
    let other = hold(HoldScope::Classes(vec![Class::Kyc]), None);
    let p = plan(
        (&tenant(), &subject()),
        &target,
        &all,
        (&connected, &[other], NOW),
    )
    .unwrap();
    assert_eq!(p.state, ErasureState::Applied);
    assert_eq!(delivery(Class::OneMemory), Delivery::UserKeyedNoKey);
    assert_eq!(delivery(Class::OneTrainingLineage), Delivery::Readable);
    assert_eq!(delivery(Class::Audit), Delivery::Readable);
}
