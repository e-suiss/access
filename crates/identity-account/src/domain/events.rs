//! The identity events of the account life cycle (OP-151 m.3 (i), TN-136): what an account,
//! session or credential change queues in its own transaction for webhook delivery. A payload
//! holds pseudonymous ids only, never an identifier, a name or a secret (OP-73). Delivery is a
//! notification, never an authority source: losing or delaying one changes no decision (INV-24).

use serde_json::{Value, json};

use crate::domain::status::AccountStatus;

/// The identity outbox kind prefix of events.
pub const OUTBOX_PREFIX: &str = "event.";

/// An identity event the account and session use cases produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountEvent {
    /// `account.created`.
    Created,
    /// `account.updated`: a status move none of the others names.
    Updated,
    /// `account.suspended`.
    Suspended,
    /// `account.reactivated`: back to `active` from `suspended` or `deactivated`.
    Reactivated,
    /// `account.deleted`: deprovisioned (TN-50).
    Deleted,
    /// `session.revoked`: the subject's `session_epoch` moved, every session ended (OP-21).
    SessionRevoked,
    /// `credential.changed`: a password, passkey or second factor was added, replaced or removed.
    CredentialChanged,
}

impl AccountEvent {
    /// Every one.
    pub const ALL: [Self; 7] = [
        Self::Created,
        Self::Updated,
        Self::Suspended,
        Self::Reactivated,
        Self::Deleted,
        Self::SessionRevoked,
        Self::CredentialChanged,
    ];

    /// The catalog name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Created => "account.created",
            Self::Updated => "account.updated",
            Self::Suspended => "account.suspended",
            Self::Reactivated => "account.reactivated",
            Self::Deleted => "account.deleted",
            Self::SessionRevoked => "session.revoked",
            Self::CredentialChanged => "credential.changed",
        }
    }

    /// The identity outbox kind.
    #[must_use]
    pub const fn outbox_kind(self) -> &'static str {
        match self {
            Self::Created => "event.account.created",
            Self::Updated => "event.account.updated",
            Self::Suspended => "event.account.suspended",
            Self::Reactivated => "event.account.reactivated",
            Self::Deleted => "event.account.deleted",
            Self::SessionRevoked => "event.session.revoked",
            Self::CredentialChanged => "event.credential.changed",
        }
    }

    /// The event of an identity outbox kind.
    #[must_use]
    pub fn from_outbox(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.outbox_kind() == kind)
    }

    /// The event a status move announces (TN-49); `None` when it announces none.
    #[must_use]
    pub const fn of_status(from: AccountStatus, to: AccountStatus) -> Option<Self> {
        match (from, to) {
            (_, AccountStatus::Suspended) => Some(Self::Suspended),
            (AccountStatus::Suspended | AccountStatus::Deactivated, AccountStatus::Active) => {
                Some(Self::Reactivated)
            }
            (_, AccountStatus::Deactivated) => Some(Self::Deleted),
            (_, AccountStatus::Tombstone | AccountStatus::Purging) => None,
            _ => Some(Self::Updated),
        }
    }
}

/// What happened to a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialChange {
    /// A new one.
    Added,
    /// A new one took the place of the old.
    Replaced,
    /// One was removed.
    Removed,
}

impl CredentialChange {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Replaced => "replaced",
            Self::Removed => "removed",
        }
    }
}

/// One event as it sits in the identity outbox: `{"id", "payload"}`.
#[derive(Clone, Debug, PartialEq)]
pub struct EventOrder {
    /// What happened.
    pub kind: AccountEvent,
    /// 32 random bytes, the dedup key and `webhook-id`.
    pub id: [u8; 32],
    /// The payload, as its schema in `sdks/openapi/events` defines it.
    pub payload: Value,
}

fn uuid(b: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl EventOrder {
    /// `account.created` of `account` (its `usr_` id) in `realm`.
    #[must_use]
    pub fn created(id: [u8; 32], realm: &[u8; 16], account: &str, at: u64) -> Self {
        Self {
            kind: AccountEvent::Created,
            id,
            payload: json!({"realm": uuid(realm), "account": account, "at": at}),
        }
    }

    /// The event of a status move, with the new status.
    #[must_use]
    pub fn status(
        kind: AccountEvent,
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        to: AccountStatus,
        at: u64,
    ) -> Self {
        Self {
            kind,
            id,
            payload: json!({
                "realm": uuid(realm),
                "account": account,
                "status": to.name(),
                "at": at,
            }),
        }
    }

    /// `session.revoked`: every session of `account` ended at epoch `rev` (OP-21).
    #[must_use]
    pub fn session_revoked(
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        rev: i64,
        at: u64,
    ) -> Self {
        Self {
            kind: AccountEvent::SessionRevoked,
            id,
            payload: json!({"realm": uuid(realm), "account": account, "rev": rev, "at": at}),
        }
    }

    /// `credential.changed` of a credential of `credential_kind` (`password`, `webauthn`,
    /// `totp`, `recovery_code`).
    #[must_use]
    pub fn credential(
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        credential_kind: &str,
        change: CredentialChange,
        at: u64,
    ) -> Self {
        Self {
            kind: AccountEvent::CredentialChanged,
            id,
            payload: json!({
                "realm": uuid(realm),
                "account": account,
                "credential": credential_kind,
                "change": change.name(),
                "at": at,
            }),
        }
    }

    /// The outbox bytes.
    ///
    /// # Errors
    /// [`serde_json::Error`].
    pub fn to_outbox(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&json!({
            "id": access_kernel::json::b64url_encode(&self.id),
            "payload": self.payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.3 (i), TN-49: every status move names one event or none; a terminal move after
    // deprovisioning names none
    #[test]
    fn status_moves_name_their_event() {
        use AccountStatus as S;
        assert_eq!(
            AccountEvent::of_status(S::Active, S::Suspended),
            Some(AccountEvent::Suspended)
        );
        assert_eq!(
            AccountEvent::of_status(S::Suspended, S::Active),
            Some(AccountEvent::Reactivated)
        );
        assert_eq!(
            AccountEvent::of_status(S::Deactivated, S::Active),
            Some(AccountEvent::Reactivated)
        );
        assert_eq!(
            AccountEvent::of_status(S::Active, S::Deactivated),
            Some(AccountEvent::Deleted)
        );
        assert_eq!(
            AccountEvent::of_status(S::Locked, S::Active),
            Some(AccountEvent::Updated)
        );
        assert_eq!(AccountEvent::of_status(S::Deactivated, S::Tombstone), None);
        for k in AccountEvent::ALL {
            assert_eq!(AccountEvent::from_outbox(k.outbox_kind()), Some(k));
            assert!(k.outbox_kind().starts_with(OUTBOX_PREFIX));
            assert!(k.outbox_kind().ends_with(k.name()));
        }
    }

    // OP-73, TN-136: a payload carries ids only
    #[test]
    fn payloads_hold_ids_only() {
        let e = EventOrder::credential(
            [1; 32],
            &[2; 16],
            "usr_x",
            "password",
            CredentialChange::Replaced,
            5,
        );
        let keys: Vec<&String> = e.payload.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["account", "at", "change", "credential", "realm"]);
        let back: Value = serde_json::from_slice(&e.to_outbox().unwrap()).unwrap();
        assert_eq!(back["payload"], e.payload);
    }
}
