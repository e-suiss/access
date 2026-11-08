//! The text keys the experience emits (§8.8, OP-153 m.3 (s)): the surface renders them from the
//! `hub` Fluent catalogue. A key names what is known; none asks for an action (IA-2), none
//! claims more than its owner reported (XI-2), and the contract's own names (`ValidityContract`,
//! token) never reach a key (§8.8, §8.9).

/// "Not shown: domains you haven't connected" (§8.17.7.2).
pub const NOT_SHOWN: &str = "hub.not_shown_unconnected";
/// "Some domains could not be reached; their rows are not shown as current."
pub const SOME_UNKNOWN: &str = "hub.some_unknown";
/// "As of 14:05".
pub const DOMAIN_CURRENT: &str = "domain.current";
/// "Current status unknown (*Acme Access* unreachable)" (XI-16).
pub const DOMAIN_UNREACHABLE: &str = "domain.unreachable";
/// The row is current.
pub const STATUS_CURRENT: &str = "status.current";
/// "Needs refresh — not removed" (XI-15).
pub const STATUS_NEEDS_REFRESH: &str = "status.needs_refresh";
/// "for their own use".
pub const CAPACITY_OWN_USE: &str = "capacity.own_use";
/// "on behalf of *Acme*".
pub const CAPACITY_ON_BEHALF: &str = "capacity.on_behalf_of";
/// "as yourself".
pub const CAPACITY_AS_YOURSELF: &str = "capacity.as_yourself";
/// "Valid until …".
pub const VALID_UNTIL: &str = "validity.valid_until";
/// "Who can: the person who gave it".
pub const WHO_CAN_GRANTOR: &str = "who_can.grantor";
/// "Confirm with your hardware key; takes effect after 24 h — you can cancel until then" (§13.8).
pub const ROOT_SOLE_CONFIRM: &str = "root.sole_confirm";
/// A joint root: the other roots confirm too.
pub const ROOT_JOINT_CONFIRM: &str = "root.joint_confirm";
/// "You used this".
pub const ACTIVITY_BY_YOU: &str = "activity.by_you";
/// "Used on your behalf".
pub const ACTIVITY_FOR_YOU: &str = "activity.for_you";

/// The change text of a change kind (IA-2): information only.
#[must_use]
pub fn change(kind: &str, ended: bool) -> String {
    if ended {
        format!("change.{kind}_ended")
    } else {
        format!("change.{kind}")
    }
}

/// "Submitted" (XI-3): sent, not yet recorded.
pub const OUTCOME_SUBMITTED: &str = "outcome.submitted";
/// "Revoked 14:03:12" and the like: recorded, with its position.
pub const OUTCOME_CONFIRMED: &str = "outcome.confirmed";
/// "Not allowed": recorded as refused.
pub const OUTCOME_NOT_ALLOWED: &str = "outcome.not_allowed";
/// "Not confirmed — checking" (§13.8, G39).
pub const OUTCOME_CHECKING: &str = "outcome.not_confirmed_checking";
/// "Witness pending".
pub const OUTCOME_WITNESS_PENDING: &str = "outcome.witness_pending";
/// "Not recorded — try again": only when the nonce is not in the lineage.
pub const OUTCOME_NOT_RECORDED: &str = "outcome.not_recorded";
/// "Couldn't revoke — *Acme Access* is unreachable. Your request was not recorded.": only when
/// no attempt was sent, on a direct path.
pub const OUTCOME_COULDNT_REACH: &str = "outcome.couldnt_reach";
/// "Busy — retry".
pub const OUTCOME_BUSY: &str = "outcome.busy_retry";
/// "Unavailable — time check".
pub const OUTCOME_TIME: &str = "outcome.unavailable_time_check";

/// Every key, for the catalogue check.
pub const ALL: [&str; 27] = [
    NOT_SHOWN,
    SOME_UNKNOWN,
    DOMAIN_CURRENT,
    DOMAIN_UNREACHABLE,
    STATUS_CURRENT,
    STATUS_NEEDS_REFRESH,
    CAPACITY_OWN_USE,
    CAPACITY_ON_BEHALF,
    CAPACITY_AS_YOURSELF,
    VALID_UNTIL,
    WHO_CAN_GRANTOR,
    ROOT_SOLE_CONFIRM,
    ROOT_JOINT_CONFIRM,
    ACTIVITY_BY_YOU,
    ACTIVITY_FOR_YOU,
    OUTCOME_SUBMITTED,
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_ALLOWED,
    OUTCOME_CHECKING,
    OUTCOME_WITNESS_PENDING,
    OUTCOME_NOT_RECORDED,
    OUTCOME_COULDNT_REACH,
    OUTCOME_BUSY,
    OUTCOME_TIME,
    "change.grant",
    "change.instance",
    "change.key_event",
];
