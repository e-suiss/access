//! The account state machine (TN-49, §12.3.1): `staged → pending_user_action → active ↔
//! locked / suspended → deactivated → tombstone → purging`. `locked` is the system's,
//! `suspended` the administrator's; they are never merged.

/// An account status (TN-49 names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccountStatus {
    /// Created, activation not started.
    Staged,
    /// Waiting for the user's verification.
    PendingUserAction,
    /// Usable.
    Active,
    /// Locked by the system (policy, failed attempts); the user recovers it.
    Locked,
    /// Suspended by an administrator, who lifts it.
    Suspended,
    /// Deprovisioned; an administrator may reactivate it.
    Deactivated,
    /// Terminal; the identity and its identifiers stay reserved.
    Tombstone,
    /// Crypto-shredding in progress.
    Purging,
}

/// A move outside the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{from:?} -> {to:?} is not a TN-49 transition")]
pub struct InvalidTransition {
    /// Current status.
    pub from: AccountStatus,
    /// Requested status.
    pub to: AccountStatus,
}

/// What deactivating an account in a status does (§12.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deactivation {
    /// Moves to `deactivated`.
    Move,
    /// Already deprovisioned: no effect (idempotent).
    AlreadyDone,
}

impl AccountStatus {
    /// Every status.
    pub const ALL: [Self; 8] = [
        Self::Staged,
        Self::PendingUserAction,
        Self::Active,
        Self::Locked,
        Self::Suspended,
        Self::Deactivated,
        Self::Tombstone,
        Self::Purging,
    ];

    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::PendingUserAction => "pending_user_action",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
            Self::Tombstone => "tombstone",
            Self::Purging => "purging",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether `self → to` is in the chain. The database trigger carries the same table.
    #[must_use]
    pub const fn can_move(self, to: Self) -> bool {
        use AccountStatus::{
            Active, Deactivated, Locked, PendingUserAction, Purging, Staged, Suspended, Tombstone,
        };
        matches!(
            (self, to),
            (Staged, PendingUserAction)
                | (PendingUserAction | Locked | Suspended | Deactivated, Active)
                | (Active, Locked | Suspended)
                | (Locked, Suspended)
                | (
                    Staged | PendingUserAction | Active | Locked | Suspended,
                    Deactivated
                )
                | (Deactivated, Tombstone)
                | (Tombstone, Purging)
        )
    }

    /// Checks `self → to`.
    ///
    /// # Errors
    /// [`InvalidTransition`].
    pub const fn transition(self, to: Self) -> Result<Self, InvalidTransition> {
        if self.can_move(to) {
            Ok(to)
        } else {
            Err(InvalidTransition { from: self, to })
        }
    }

    /// Only an active account authenticates; `locked` fails actor-binding (§12.3.1).
    #[must_use]
    pub const fn can_authenticate(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Deactivation is idempotent on an account already deprovisioned (§12.3.1).
    #[must_use]
    pub const fn deactivation(self) -> Deactivation {
        match self {
            Self::Deactivated | Self::Tombstone | Self::Purging => Deactivation::AlreadyDone,
            _ => Deactivation::Move,
        }
    }

    /// The statuses whose `account.status` Claim narrows authority (TN-49, E5).
    #[must_use]
    pub const fn narrows_authority(self) -> bool {
        matches!(self, Self::Suspended | Self::Deactivated | Self::Tombstone)
    }
}

#[cfg(test)]
mod tests {
    use super::AccountStatus::{
        Active, Deactivated, Locked, PendingUserAction, Purging, Staged, Suspended, Tombstone,
    };
    use super::*;

    // TN-49
    #[test]
    fn the_chain_and_nothing_else() {
        let allowed = [
            (Staged, PendingUserAction),
            (PendingUserAction, Active),
            (Active, Locked),
            (Locked, Active),
            (Active, Suspended),
            (Suspended, Active),
            (Locked, Suspended),
            (Staged, Deactivated),
            (PendingUserAction, Deactivated),
            (Active, Deactivated),
            (Locked, Deactivated),
            (Suspended, Deactivated),
            (Deactivated, Active),
            (Deactivated, Tombstone),
            (Tombstone, Purging),
        ];
        for from in AccountStatus::ALL {
            for to in AccountStatus::ALL {
                assert_eq!(
                    from.can_move(to),
                    allowed.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
        assert_eq!(
            Tombstone.transition(Active),
            Err(InvalidTransition {
                from: Tombstone,
                to: Active
            })
        );
    }

    // TN-49
    #[test]
    fn names_round_trip() {
        for s in AccountStatus::ALL {
            assert_eq!(AccountStatus::parse(s.name()), Some(s));
        }
        assert_eq!(AccountStatus::parse("disabled"), None);
    }

    // §12.3.1, TN-50
    #[test]
    fn deactivation_is_idempotent() {
        for s in [Deactivated, Tombstone, Purging] {
            assert_eq!(s.deactivation(), Deactivation::AlreadyDone);
        }
        for s in [Staged, PendingUserAction, Active, Locked, Suspended] {
            assert_eq!(s.deactivation(), Deactivation::Move);
            assert!(s.can_move(Deactivated));
        }
    }

    // TN-49, E5
    #[test]
    fn locked_is_not_suspended() {
        assert!(!Locked.narrows_authority());
        assert!(Suspended.narrows_authority());
        assert!(Deactivated.narrows_authority());
        assert!(!Locked.can_authenticate());
        assert!(Active.can_authenticate());
    }
}
