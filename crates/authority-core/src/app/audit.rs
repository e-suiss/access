//! What an explanation of a recorded decision adds beyond the requester's view (§9.6, §9.6.1,
//! §13.7.5, §17.1.1): the lineage for a viewer, with identities two or more hops below the viewer
//! shown only as the viewer's stable pseudonyms (SEC29, TI-RT10); and at audit scope the
//! expanded `basis_ref`, the `StateBasis`, `reason_admin` by the P41 table, the cited proofs and
//! the consumption. Nothing here is recorded (C30); the answer is built from the decision record
//! and the state just before it.

use access_crypto::pseudonym::PseudonymKey;
use access_kernel::combinator::{BlockerClass, Decision};
use access_kernel::digest::Digest;
use access_kernel::fold::State;
use access_kernel::meta::{AnchorState, ExerciseBasis, GrantBasis, GrantState, Root, View, kind};
use access_kernel::model::{Id, ProofKind, SubjectSelector};
use access_kernel::record::RecordEnvelope;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::domain::export::VERSIONS_CONTEXT;
use crate::domain::read;
use crate::domain::reasons::{self, AdminDetail};

/// `basis_ref` expanded (§17.1.1): the domain, the position the decision was evaluated at
/// (`q − 1`) and the digest of the version vector it cites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasisRef {
    /// `DomainID`.
    pub domain: Digest,
    /// The decision's position minus one.
    pub position_q_minus_1: u64,
    /// Digest of the decision's version vector.
    pub version_vector_digest: Digest,
}

/// An identity as one viewer may see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Named {
    /// In clear.
    Clear(Id),
    /// As the viewer's stable pseudonym (§13.7.5).
    Pseudonym([u8; 16]),
}

/// One lineage hop: hop 0 is the basis Grant, the last the Grant on the Anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageHop {
    /// `k` of `hop(k)`.
    pub hop: u64,
    /// The Grant.
    pub grant: Named,
    /// Its holder, when that is a Party.
    pub holder: Option<Named>,
}

/// One `reason_admin` entry (§9.6.1): the P41 row and what the audit scope shows of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminReason {
    /// The explanation category.
    pub category: &'static str,
    /// The `reason_user` code of the same row.
    pub user: &'static str,
    /// What the row adds at audit scope.
    pub admin: &'static [AdminDetail],
    /// The subcode, when the row discloses it.
    pub subcode: Option<String>,
}

/// The audit-scope part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditDetail {
    /// `basis_ref` expanded.
    pub basis: BasisRef,
    /// Trusted evaluation time of the decision.
    pub evaluated_at: u64,
    /// The `StateBasis`: each key read and its version.
    pub reads: Vec<(Vec<u8>, u64)>,
    /// `reason_admin`, one entry per blocker or unmet requirement.
    pub reason_admin: Vec<AdminReason>,
    /// The proofs the decision relied on.
    pub cited: Vec<Id>,
    /// The recorded consumption, if any.
    pub consumption: Option<Value>,
}

/// What a viewer or auditor sees beyond the requester's view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explained {
    /// The lineage of the recorded basis.
    pub lineage: Vec<LineageHop>,
    /// The audit-scope part; `None` below audit scope, where `reason_admin` does not exist.
    pub audit: Option<AuditDetail>,
}

struct Past<'a>(&'a State);

impl View for Past<'_> {
    fn get(&self, key: &[u8]) -> Option<Value> {
        self.0.get(key).and_then(|e| e.value.clone())
    }
}

/// The Grants of the lineage of `basis`, from the basis Grant up, with their holders; and the
/// root of the Anchor at the top.
fn lineage(state: &State, basis: &ExerciseBasis) -> (Vec<(Id, SubjectSelector)>, Option<Root>) {
    let view = Past(state);
    let mut at = match basis {
        ExerciseBasis::Anchor(a) => {
            return (
                Vec::new(),
                read::<AnchorState>(&view, kind::ANCHOR, a).map(|s| s.root),
            );
        }
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    let mut out = Vec::new();
    while out.len() < access_kernel::meta::MAX_LINEAGE {
        let Some(g) = read::<GrantState>(&view, kind::GRANT, &at) else {
            break;
        };
        out.push((at, g.content.holder.clone()));
        match g.content.basis {
            GrantBasis::Holding(h) => at = h.grant,
            GrantBasis::Anchor(a) => {
                return (
                    out,
                    read::<AnchorState>(&view, kind::ANCHOR, &a).map(|s| s.root),
                );
            }
        }
    }
    (out, None)
}

fn root_holds(root: Option<&Root>, party: &Id) -> bool {
    match root {
        Some(Root::Sole(p)) => p == party,
        Some(Root::Joint { parties, .. }) => parties.contains(party),
        None => false,
    }
}

/// The lineage as `viewer` sees it (§13.7.5): in clear at audit scope; otherwise identities
/// two or more hops below the viewer as the viewer's pseudonyms.
///
/// # Errors
/// [`CoreError::Unavailable`] when the pseudonym key refuses.
pub fn viewed_lineage(
    state: &State,
    basis: &ExerciseBasis,
    viewer: &Id,
    audit: bool,
    key: Option<&PseudonymKey>,
) -> Result<Vec<LineageHop>, CoreError> {
    let (hops, root) = lineage(state, basis);
    let n = hops.len();
    let at = hops
        .iter()
        .position(|(_, h)| *h == SubjectSelector::Party(*viewer))
        .or_else(|| root_holds(root.as_ref(), viewer).then_some(n));
    let named = |k: usize, id: &Id| -> Result<Named, CoreError> {
        let below = at.map_or(usize::MAX, |j| j.saturating_sub(k));
        if audit || below < 2 {
            return Ok(Named::Clear(*id));
        }
        let key = key.ok_or(CoreError::Unavailable("pseudonym-key"))?;
        key.viewer_ref(&viewer.0, &id.0)
            .map(Named::Pseudonym)
            .map_err(|_| CoreError::Unavailable("pseudonym-key"))
    };
    let mut out = Vec::with_capacity(n);
    for (k, (grant, holder)) in hops.iter().enumerate() {
        out.push(LineageHop {
            hop: u64::try_from(k).map_err(|_| CoreError::Protocol("lineage"))?,
            grant: named(k, grant)?,
            holder: match holder {
                SubjectSelector::Party(p) => Some(named(k, p)?),
                _ => None,
            },
        });
    }
    Ok(out)
}

const fn proof_word(kind: ProofKind) -> Option<&'static str> {
    match kind {
        ProofKind::Contribution => Some("contribution"),
        ProofKind::Authentication => Some("authentication"),
        ProofKind::Claim => Some("claim"),
        ProofKind::ForeignAuthority => None,
    }
}

/// `reason_admin` of `decision` by the P41 table: one entry per blocker and per unmet
/// requirement, with the subcode only where the row discloses it.
#[must_use]
pub fn reason_admin(decision: &Decision) -> Vec<AdminReason> {
    let mut out = Vec::new();
    for b in &decision.blockers {
        if let Some(r) = reasons::of_blocker(b.class) {
            out.push(AdminReason {
                category: r.category,
                user: r.user,
                admin: r.admin,
                subcode: if r.admin.contains(&AdminDetail::Subcode) {
                    b.subcode.clone()
                } else {
                    None
                },
            });
        }
    }
    for u in &decision.unmet {
        let row = match proof_word(u.term.proof_kind) {
            Some(w) => reasons::of_requirement(w),
            None => reasons::of_blocker(BlockerClass::ForeignStatusUnavailable),
        };
        if let Some(r) = row {
            out.push(AdminReason {
                category: r.category,
                user: r.user,
                admin: r.admin,
                subcode: None,
            });
        }
    }
    out
}

/// `reason_user` of `decision` (P41, §9.6.1): the closed requester-scope codes of its blockers
/// and unmet requirements, never free text (A-7).
#[must_use]
pub fn reason_user(decision: &Decision) -> Vec<&'static str> {
    let blockers = decision
        .blockers
        .iter()
        .filter_map(|b| reasons::of_blocker(b.class));
    let unmet = decision
        .unmet
        .iter()
        .filter_map(|u| match proof_word(u.term.proof_kind) {
            Some(w) => reasons::of_requirement(w),
            None => reasons::of_blocker(BlockerClass::ForeignStatusUnavailable),
        });
    let mut out: Vec<&'static str> = Vec::new();
    for code in blockers.chain(unmet).map(|r| r.user) {
        if !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

fn reads_of(v: Option<&Value>) -> Vec<(Vec<u8>, u64)> {
    let Some(Value::Array(reads)) = v.and_then(|s| s.get("reads")) else {
        return Vec::new();
    };
    reads
        .iter()
        .filter_map(|r| match r {
            Value::Array(pair) => match pair.as_slice() {
                [Value::Bytes(k), Value::Unsigned(ver)] => Some((k.clone(), *ver)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The audit-scope detail of the decision record `record` of `domain`, rebuilt as `decision`.
///
/// # Errors
/// [`CoreError::Protocol`] `explain-record` when the record lacks a field the answer needs.
pub fn audit_detail(
    domain: Digest,
    record: &RecordEnvelope,
    decision: &Decision,
) -> Result<AuditDetail, CoreError> {
    let bad = || CoreError::Protocol("explain-record");
    let field = |name: &str| record.fields.get(name).map(|f| &f.value);
    let versions = field("versions").ok_or_else(bad)?;
    let bytes = dcbor::encode(versions, Limits::CEILING).map_err(|_| bad())?;
    Ok(AuditDetail {
        basis: BasisRef {
            domain,
            position_q_minus_1: record.header.pos.checked_sub(1).ok_or_else(bad)?,
            version_vector_digest: suiss_crypto::digest::context_digest(VERSIONS_CONTEXT, &bytes),
        },
        evaluated_at: record.header.recorded_at,
        reads: reads_of(field("state_basis")),
        reason_admin: reason_admin(decision),
        cited: decision.relied_on.clone(),
        consumption: field("consumption").cloned(),
    })
}

#[cfg(test)]
mod tests;
