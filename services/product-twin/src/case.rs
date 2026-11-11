//! A case system twin (OP-157 m.3 (e), TN-73): a support desk registered as its own issuer that
//! issues `support_case` Claims (`product-seam.cddl`). A support Grant names its case only as
//! the `PurposeRef::Case` digest of `(system, case id)`; the case system's Claim says whether
//! that case is open, and Access holds the Grant only while it is. Reading a vendor's ticket
//! event is sans-I/O; the vendor tenant, its credentials and its webhook stay in the adapter.

use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id};
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

use crate::twin::{Issue, Signed};

/// The Claim class.
pub const CLASS: &str = "support_case";

/// The body format a case system states (OP-157 m.3 (e)).
pub const FORMAT: &str = "product-seam/v1";

/// A case system vendor whose ticket events the twin reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Vendor {
    /// Zendesk ticket webhook.
    Zendesk,
    /// Freshdesk automation webhook.
    Freshdesk,
    /// `ServiceNow` Customer Service case business rule.
    ServiceNow,
    /// Jira Service Management issue webhook.
    JiraServiceManagement,
}

/// Every vendor, in the order the registration names them.
pub const VENDORS: [Vendor; 4] = [
    Vendor::Zendesk,
    Vendor::Freshdesk,
    Vendor::ServiceNow,
    Vendor::JiraServiceManagement,
];

/// What a ticket event says about one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseEvent {
    /// The case id in the vendor.
    pub case: String,
    /// Whether it is open.
    pub open: bool,
}

fn text(v: Option<&Value>) -> Option<String> {
    let s = match v? {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    (!s.is_empty() && s.len() <= 128).then_some(s)
}

/// Whether a status reads open, closed, or neither; neither issues no Claim.
fn state(status: &str, open: &[&str], closed: &[&str]) -> Option<bool> {
    let s = status.to_ascii_lowercase();
    if open.contains(&s.as_str()) {
        Some(true)
    } else if closed.contains(&s.as_str()) {
        Some(false)
    } else {
        None
    }
}

impl Vendor {
    /// The provider name the registration names (`idp.support.case_system_register`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zendesk => "zendesk",
            Self::Freshdesk => "freshdesk",
            Self::ServiceNow => "servicenow",
            Self::JiraServiceManagement => "jira-service-management",
        }
    }

    /// The case one ticket event of this vendor is about and whether it is open; `None` for an
    /// event the twin cannot read or a status that is neither open nor closed.
    #[must_use]
    pub fn read(self, event: &[u8]) -> Option<CaseEvent> {
        let v: Value = serde_json::from_slice(event).ok()?;
        let (case, open) = match self {
            Self::Zendesk => {
                let t = v.get("ticket")?;
                (
                    text(t.get("id"))?,
                    state(
                        t.get("status")?.as_str()?,
                        &["new", "open", "pending", "hold"],
                        &["solved", "closed"],
                    )?,
                )
            }
            Self::Freshdesk => {
                let t = v.get("freshdesk_webhook")?;
                (
                    text(t.get("ticket_id"))?,
                    state(
                        t.get("ticket_status")?.as_str()?,
                        &["open", "pending"],
                        &["resolved", "closed"],
                    )?,
                )
            }
            Self::ServiceNow => (
                text(v.get("number"))?,
                state(
                    v.get("state")?.as_str()?,
                    &["new", "open", "awaiting info", "in progress"],
                    &["resolved", "closed", "cancelled"],
                )?,
            ),
            Self::JiraServiceManagement => {
                let i = v.get("issue")?;
                let category = i
                    .get("fields")?
                    .get("status")?
                    .get("statusCategory")?
                    .get("key")?
                    .as_str()?;
                (
                    text(i.get("key"))?,
                    state(category, &["new", "indeterminate"], &["done"])?,
                )
            }
        };
        Some(CaseEvent { case, open })
    }
}

/// A registered case system: its name, which is the `system` of every case ref it states, and
/// its vendor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseSystem {
    /// The registered name.
    pub name: String,
    /// The vendor.
    pub vendor: Vendor,
}

impl CaseSystem {
    /// The `PurposeRef::Case` digest of `case` in this system (TN-73); `None` when the texts
    /// are outside the structural limits.
    #[must_use]
    pub fn case_ref(&self, case: &str) -> Option<Digest> {
        access_kernel::digest::case_ref(&self.name, case).ok()
    }

    /// The `support-case` body: the case ref, whether it is open and whose case it is.
    #[must_use]
    pub fn body(case: &Digest, subject: &Id, open: bool) -> Cbor {
        Cbor::Map(vec![
            (Cbor::text("case"), Cbor::Bytes(case.0.to_vec())),
            (Cbor::text("open"), Cbor::Bool(open)),
            (Cbor::text("subject"), Cbor::Bytes(subject.0.to_vec())),
        ])
    }

    /// The Claim of `event` about `subject`, holding for `for_ms`, with its body beside it
    /// (L2-CLB-1); `None` when the case id is outside the limits.
    #[must_use]
    pub fn claim(&self, subject: Id, event: &CaseEvent, for_ms: u64) -> Option<Signed> {
        let case = self.case_ref(&event.case)?;
        let body = Self::body(&case, &subject, event.open);
        let bytes = dcbor::encode(&body, Limits::CEILING).ok()?;
        let tagged =
            dcbor::encode(&Cbor::Array(vec![Cbor::text(CLASS), body]), Limits::CEILING).ok()?;
        let value = context_digest(BODY_CONTEXT, &tagged).0;
        Some(Signed::with_body(
            Issue {
                subject,
                class: String::from(CLASS),
                value: Some(EqValue::Bytes(value.to_vec())),
                for_ms,
                resource: None,
            },
            bytes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDED: [(Vendor, &str, &str, &str); 4] = [
        (
            Vendor::Zendesk,
            include_str!("../fixtures/case/zendesk-open.json"),
            include_str!("../fixtures/case/zendesk-solved.json"),
            "\"open\"",
        ),
        (
            Vendor::Freshdesk,
            include_str!("../fixtures/case/freshdesk-open.json"),
            include_str!("../fixtures/case/freshdesk-closed.json"),
            "\"Open\"",
        ),
        (
            Vendor::ServiceNow,
            include_str!("../fixtures/case/servicenow-open.json"),
            include_str!("../fixtures/case/servicenow-resolved.json"),
            "\"Open\"",
        ),
        (
            Vendor::JiraServiceManagement,
            include_str!("../fixtures/case/jira-service-management-open.json"),
            include_str!("../fixtures/case/jira-service-management-done.json"),
            "\"indeterminate\"",
        ),
    ];

    // OP-157 m.3 (e), TN-73, Ek B 5410
    #[test]
    fn each_vendor_event_reads_as_one_case_open_or_closed() {
        for (vendor, open, closed, word) in RECORDED {
            let o = vendor.read(open.as_bytes()).unwrap();
            let c = vendor.read(closed.as_bytes()).unwrap();
            assert!(o.open, "{}", vendor.name());
            assert!(!c.open, "{}", vendor.name());
            assert_eq!(o.case, c.case, "{}", vendor.name());
            assert!(vendor.read(b"{}").is_none());
            assert!(
                vendor
                    .read(open.replace(word, "\"unheard\"").as_bytes())
                    .is_none(),
                "{}: an unknown status issues no Claim",
                vendor.name()
            );
        }
        assert_eq!(
            VENDORS.map(Vendor::name),
            [
                "zendesk",
                "freshdesk",
                "servicenow",
                "jira-service-management"
            ]
        );
    }

    // OP-157 m.3 (b), (e), L2-CLB-1
    #[test]
    fn the_claim_carries_the_case_ref_and_no_case_number() {
        let desk = CaseSystem {
            name: String::from("acme-desk"),
            vendor: Vendor::Zendesk,
        };
        let subject = Id([1; 16]);
        let event = CaseEvent {
            case: String::from("4411"),
            open: true,
        };
        let s = desk.claim(subject, &event, 60_000).unwrap();
        let body = s.body.unwrap();
        assert!(!body.windows(4).any(|w| w == b"4411"));
        let case = desk.case_ref("4411").unwrap();
        assert_eq!(
            dcbor::decode(&body, Limits::CEILING).unwrap(),
            CaseSystem::body(&case, &subject, true)
        );
        let closed = desk
            .claim(
                subject,
                &CaseEvent {
                    open: false,
                    ..event
                },
                60_000,
            )
            .unwrap();
        assert_ne!(closed.issue.value, s.issue.value);
    }
}
