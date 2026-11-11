//! The user-keyed domain (E52, E59, E66, OP-74, OP-78, Ek C C.1.1 (2), C.4): the person's KEK
//! lives on their devices and passkeys; the person × class DEK is wrapped under it; each record
//! has its own random key wrapped under the class DEK. The operator holds wrapped copies only.
//!
//! - **KEK recovery** goes with account recovery: at setup at least two recovery paths, none
//!   weaker than what they protect; when none is left the data is lost, and that is said.
//! - **Erasure** destroys every copy of the keys it covers (server, recovery vault, TEE jobs,
//!   devices). A device that is not connected destroys its copy when it reconnects; until then
//!   the `erasure_log` entry stays open.
//! - **Holds** suspend destruction and give no readability: there is no readable extraction,
//!   no escrow, and the pending erasure is applied when the hold ends.

use alloc::vec::Vec;

use crate::class::Class;
use crate::decision::{Occurrence, Record};
use crate::hold::Hold;
use crate::ids::{DeviceId, JobId, RecordKeyId, SubjectId, TenantId};
use crate::time::Timestamp;

/// A way to recover the KEK, registered as an account recovery method (E52 (2), TN-H2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RecoveryPath {
    /// A PIN with limited attempts, against an HSM or TEE recovery vault.
    Vault,
    /// A recovery key the person keeps.
    RecoveryKey,
    /// A recovery contact.
    RecoveryContact,
    /// A second device of the person.
    SecondDevice,
}

/// The assurance label of a recovery path or of what it protects (TN-H2), weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Assurance {
    /// Knowledge or possession of one weak factor.
    Low,
    /// Two factors, not phishing-resistant.
    Substantial,
    /// Phishing-resistant, hardware-bound.
    High,
}

/// A registered recovery path with its label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Path {
    /// The kind of path.
    pub kind: RecoveryPath,
    /// Its assurance label.
    pub assurance: Assurance,
}

/// Paths required at setup (E52 (2)).
pub const MIN_PATHS: usize = 2;

/// Why a set of recovery paths is refused at setup. A refusal, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetupRefusal {
    /// Fewer than [`MIN_PATHS`] different paths.
    TooFewPaths,
    /// A path is weaker than what it protects: recovery cannot be weaker than the protected
    /// (E52 (2), TN-H2).
    WeakerThanProtected(RecoveryPath),
}

/// Checks the recovery paths a person sets up for a user-keyed domain protected at `protected`.
///
/// # Errors
/// [`SetupRefusal`].
pub fn check_setup(paths: &[Path], protected: Assurance) -> Result<(), SetupRefusal> {
    if let Some(weak) = paths.iter().find(|p| p.assurance < protected) {
        return Err(SetupRefusal::WeakerThanProtected(weak.kind));
    }
    let mut kinds: Vec<RecoveryPath> = paths.iter().map(|p| p.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.len() < MIN_PATHS {
        return Err(SetupRefusal::TooFewPaths);
    }
    Ok(())
}

/// What a recovered account gets back of its user-keyed data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KekRecovery {
    /// The KEK comes back through this path.
    Through(RecoveryPath),
    /// No path at the protected assurance is left: the encrypted data is lost, and the person
    /// is told so plainly (E52 (2)).
    DataLost,
}

/// The path a recovery uses among those still usable, the strongest first.
#[must_use]
pub fn kek_recovery(usable: &[Path], protected: Assurance) -> KekRecovery {
    usable
        .iter()
        .filter(|p| p.assurance >= protected)
        .max_by_key(|p| p.assurance)
        .map_or(KekRecovery::DataLost, |p| KekRecovery::Through(p.kind))
}

/// A key of the hierarchy below the KEK.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// The person × class DEK.
    ClassDek(Class),
    /// A record's own key, wrapped under its class DEK (E66).
    Record(Class, RecordKeyId),
}

impl Key {
    /// The key's class.
    #[must_use]
    pub const fn class(&self) -> Class {
        match self {
            Self::ClassDek(c) | Self::Record(c, _) => *c,
        }
    }
}

/// Who holds a wrapped copy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Holder {
    /// The operator's store.
    Server,
    /// The recovery vault (E52 (2)).
    Vault,
    /// A TEE job under a cloud key permission (E59).
    Tee(JobId),
    /// One of the person's devices.
    Device(DeviceId),
}

/// One wrapped copy of a key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Wrapped {
    /// The key.
    pub key: Key,
    /// Where it is.
    pub holder: Holder,
}

/// What an erasure covers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// Permanent forgetting of one record: its record key only; the class DEK and the other
    /// records live on (E66 (2)).
    Record(Class, RecordKeyId),
    /// A class shred: the class DEK, so every record key of the class becomes unreadable.
    Class(Class),
    /// Account deletion: every class an account deletion shreds (Ek C C.3.7).
    Account,
}

impl Target {
    fn covers(&self, key: &Key) -> bool {
        match (self, key) {
            (Self::Record(c, r), Key::Record(kc, kr)) => c == kc && r == kr,
            (Self::Record(..), Key::ClassDek(_)) => false,
            (Self::Class(c), k) => k.class() == *c,
            (Self::Account, k) => k.class().shredded_with_account(),
        }
    }

    fn classes(&self) -> Vec<Class> {
        match self {
            Self::Record(c, _) | Self::Class(c) => alloc::vec![*c],
            Self::Account => Class::ALL
                .into_iter()
                .filter(|c| c.shredded_with_account())
                .collect(),
        }
    }
}

/// The state of an `erasure_log` entry (Ek C C.1.1 (2) 6, OP-78 m.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErasureState {
    /// Every copy is destroyed; the entry is closed.
    Applied,
    /// Destroyed everywhere but on these devices, which destroy their copy when they reconnect;
    /// the entry stays open until then.
    PendingDevices(Vec<DeviceId>),
    /// A hold covers it: nothing is destroyed until the hold ends, and nothing becomes readable.
    PendingHold,
}

/// What to do now for an erasure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Plan {
    /// The copies to destroy now.
    pub destroy: Vec<Wrapped>,
    /// The entry's state once they are.
    pub state: ErasureState,
}

/// Why an erasure cannot be planned. A refusal, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Refusal {
    /// The class is not user-keyed; its keys follow the operator-keyed rules (OP-74).
    NotUserKeyed(Class),
}

/// Plans the erasure of `target` for `subject` of `tenant` at `now`, given every known copy,
/// the devices connected now, and the tenant's holds.
///
/// # Errors
/// [`Refusal`].
pub fn plan(
    (tenant, subject): (&TenantId, &SubjectId),
    target: &Target,
    copies: &[Wrapped],
    (connected, holds, now): (&[DeviceId], &[Hold], Timestamp),
) -> Result<Plan, Refusal> {
    let classes = target.classes();
    if let Some(c) = classes.iter().find(|c| !c.is_user_keyed()) {
        return Err(Refusal::NotUserKeyed(*c));
    }
    // OP-78 m.1, m.2
    let held = classes.iter().any(|class| {
        let record = Record {
            tenant: tenant.clone(),
            class: *class,
            subject: Some(subject.clone()),
            start: Occurrence::Unknown,
            end: Occurrence::Unknown,
        };
        holds.iter().any(|h| h.is_active(now) && h.covers(&record))
    });
    if held {
        return Ok(Plan {
            destroy: Vec::new(),
            state: ErasureState::PendingHold,
        });
    }
    let mut destroy = Vec::new();
    let mut waiting: Vec<DeviceId> = Vec::new();
    for c in copies.iter().filter(|c| target.covers(&c.key)) {
        match &c.holder {
            Holder::Device(d) if !connected.contains(d) => waiting.push(d.clone()),
            _ => destroy.push(c.clone()),
        }
    }
    waiting.sort_unstable();
    waiting.dedup();
    let state = if waiting.is_empty() {
        ErasureState::Applied
    } else {
        ErasureState::PendingDevices(waiting)
    };
    Ok(Plan { destroy, state })
}

/// A device reconnected: the copies it must destroy now and the entry's next state.
#[must_use]
pub fn reconnected(
    state: &ErasureState,
    target: &Target,
    device: &DeviceId,
    copies: &[Wrapped],
) -> Plan {
    let ErasureState::PendingDevices(waiting) = state else {
        return Plan {
            destroy: Vec::new(),
            state: state.clone(),
        };
    };
    if !waiting.contains(device) {
        return Plan {
            destroy: Vec::new(),
            state: state.clone(),
        };
    }
    let destroy = copies
        .iter()
        .filter(|c| target.covers(&c.key) && c.holder == Holder::Device(device.clone()))
        .cloned()
        .collect();
    let rest: Vec<DeviceId> = waiting.iter().filter(|d| *d != device).cloned().collect();
    Plan {
        destroy,
        state: if rest.is_empty() {
            ErasureState::Applied
        } else {
            ErasureState::PendingDevices(rest)
        },
    }
}

/// How a regulator or court request is answered for a class (Ek C C.4, OP-78 m.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Delivery {
    /// Readable extraction with two-person approval (OP-74 m.5).
    Readable,
    /// The data is user-keyed and the operator has no key: the answer says so, and only the
    /// records the operator can read are delivered. No escrow, no vault opening.
    UserKeyedNoKey,
}

/// The delivery rule of `class`.
#[must_use]
pub const fn delivery(class: Class) -> Delivery {
    if class.is_user_keyed() {
        Delivery::UserKeyedNoKey
    } else {
        Delivery::Readable
    }
}

#[cfg(test)]
mod tests;
