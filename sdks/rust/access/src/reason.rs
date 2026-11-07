//! Why Access refused (§9.6, P15): the closed set of ten blocker classes and the namespaced
//! subcodes this SDK knows. A subcode the SDK does not know is read as its parent class, so a
//! newer Access never makes an older SDK misread a refusal; a class outside the closed set is
//! not a refusal this SDK can read, and the whole answer is malformed.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::combinator::BlockerClass;
use access_kernel::json::{self, Json};

use crate::authorize::MAX_BODY;

/// The closed class set and its wire names (§9.6).
const CLASSES: [(&str, BlockerClass); 10] = [
    ("no-covering-authority", BlockerClass::NoCoveringAuthority),
    (
        "outside-instance-limits",
        BlockerClass::OutsideInstanceLimits,
    ),
    ("restricted", BlockerClass::Restricted),
    ("budget-exhausted", BlockerClass::BudgetExhausted),
    ("ended", BlockerClass::Ended),
    ("capacity-mismatch", BlockerClass::CapacityMismatch),
    ("source-not-accepted", BlockerClass::SourceNotAccepted),
    ("schema-not-accepted", BlockerClass::SchemaNotAccepted),
    ("nonce-closed", BlockerClass::NonceClosed),
    (
        "foreign-status-unavailable",
        BlockerClass::ForeignStatusUnavailable,
    ),
];

/// A class by its wire name; `None` outside the closed set.
#[must_use]
pub fn class(name: &str) -> Option<BlockerClass> {
    CLASSES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// A class's wire name.
#[must_use]
pub fn class_name(class: BlockerClass) -> &'static str {
    CLASSES
        .iter()
        .find(|(_, c)| *c == class)
        .map_or("no-covering-authority", |(n, _)| n)
}

/// A subcode this SDK knows (§9.6 table).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Subcode {
    /// `ended/expired`.
    Expired,
    /// `ended/revoked`.
    Revoked,
    /// `ended/lapsed`.
    Lapsed,
    /// `restricted/policy:<PolicyRef>`.
    Policy(String),
    /// `nonce-closed/pre-recovery`.
    PreRecovery,
    /// `budget-exhausted/release-exceeds-draw`.
    ReleaseExceedsDraw,
}

impl Subcode {
    fn parse(class: BlockerClass, text: &str) -> Option<Self> {
        let (parent, rest) = text.split_once('/')?;
        if parent != class_name(class) {
            return None;
        }
        match (class, rest) {
            (BlockerClass::Ended, "expired") => Some(Self::Expired),
            (BlockerClass::Ended, "revoked") => Some(Self::Revoked),
            (BlockerClass::Ended, "lapsed") => Some(Self::Lapsed),
            (BlockerClass::NonceClosed, "pre-recovery") => Some(Self::PreRecovery),
            (BlockerClass::BudgetExhausted, "release-exceeds-draw") => {
                Some(Self::ReleaseExceedsDraw)
            }
            (BlockerClass::Restricted, r) => r
                .strip_prefix("policy:")
                .filter(|p| !p.is_empty())
                .map(|p| Self::Policy(String::from(p))),
            _ => None,
        }
    }
}

/// One reason of a refusal: its class, and its subcode when the SDK knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    /// The class; always known.
    pub class: BlockerClass,
    /// The subcode; `None` when none was sent or the SDK does not know it (P15).
    pub subcode: Option<Subcode>,
}

/// Reads one reason (P15): an unknown subcode, or one under another class, is dropped and the
/// parent class stands; an unknown class is `None`.
#[must_use]
pub fn reason(class_text: &str, subcode: Option<&str>) -> Option<Reason> {
    let class = class(class_text)?;
    Some(Reason {
        class,
        subcode: subcode.and_then(|s| Subcode::parse(class, s)),
    })
}

/// Why the reasons of a decision body could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReasonError {
    /// Not a decision body.
    #[error("malformed")]
    Malformed,
    /// A blocker class outside the closed set (P15: there is no unknown class).
    #[error("unknown-class")]
    UnknownClass,
}

/// The reasons of a decision body (`context.blockers`, L1-ADP-10). An ALLOW has none.
///
/// # Errors
/// [`ReasonError`].
pub fn reasons(body: &[u8]) -> Result<Vec<Reason>, ReasonError> {
    let root = json::parse(body, MAX_BODY).map_err(|_| ReasonError::Malformed)?;
    let blockers = match root.get("context").and_then(|c| c.get("blockers")) {
        None => return Ok(Vec::new()),
        Some(Json::Array(items)) => items,
        Some(_) => return Err(ReasonError::Malformed),
    };
    blockers
        .iter()
        .map(|b| {
            let class_text = b
                .get("class")
                .and_then(Json::as_str)
                .ok_or(ReasonError::Malformed)?;
            let subcode = match b.get("subcode") {
                None => None,
                Some(s) => Some(s.as_str().ok_or(ReasonError::Malformed)?),
            };
            reason(class_text, subcode).ok_or(ReasonError::UnknownClass)
        })
        .collect()
}
