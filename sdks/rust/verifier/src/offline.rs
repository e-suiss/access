//! The offline verifier (§9.10, §9.12, §11.19, EP-7, CMP-17): the seven steps of L2-PAP-3 in
//! the Kernel, with the inputs a conformant verifier must not take from the artefact. Time comes
//! from the guarded trusted clock, the horizon ceiling from the Verifier Profile, Domain
//! Metadata and the class table, Domain Metadata freshness from a witness, status from a
//! verified list, and the slice from tamper-evident counters. Every use of a verified
//! projection is chained into its Offline Exercise Report. There is no online fallback inside
//! the verifier and no degraded window: a use it cannot prove is a DENY (EP-7, SEC27).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::algebra::Catalog;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::model::{Id, RequirementTerm, TrustedTime};
use access_kernel::pap::{self, Expected, Pap, PapError};
use access_kernel::report::{Entry, LocalOutcome, ReportError, SliceAmount, Summary};
use access_kernel::schema::ActionSchema;
use access_kernel::status::StatusError;
use access_kernel::tier::{self, Tier};
use access_kernel::validity::{ValidityContract, ValidityError};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::parse_sign1;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::counter::{CounterError, CounterReading, Draw, SliceGuard, TamperEvidentCounter};
use crate::metadata::MetadataView;
use crate::profile::{LocalProfile, ProfileError};
use crate::report::{CutReport, ReportBuilder};
use crate::status::StatusList;
use crate::time::{ClockError, ClockGuard, TrustedClock};

/// Digest context of a holder's presentation as received, the entry's `holder_proof`.
pub const PRESENTATION_CONTEXT: &str = "access/pap-presentation/v1";

/// Digest context of a validity contract, the report's `contract`.
pub const CONTRACT_CONTEXT: &str = "access/validity/v1";

/// Why a use is refused. Every variant is a local DENY.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Denial {
    /// No trusted time (T25, TI-RT2).
    #[error("clock: {0}")]
    Clock(ClockError),
    /// A step of L2-PAP-3.
    #[error("{0}")]
    Pap(PapError),
    /// The Verifier Profile or the class ceilings do not admit the contract.
    #[error("{0}")]
    Profile(ProfileError),
    /// The projection's status list entry is set (L2-STL-3).
    #[error("status-revoked")]
    Revoked,
    /// The status list cannot be read for the projection's entry.
    #[error("{0}")]
    Status(StatusError),
    /// Protected content was written after the projection's basis (§9.10.1 step 8).
    #[error("content-position")]
    ContentPosition,
    /// The tamper-evident counter cannot be trusted.
    #[error("counter: {0}")]
    Counter(CounterError),
    /// No counter is provisioned for a slice of the projection.
    #[error("counter-missing")]
    CounterMissing,
    /// The slice was used up by the group meanwhile.
    #[error("pap-slice")]
    Exhausted,
    /// The use cannot be chained into the report.
    #[error("report: {0}")]
    Report(ReportError),
}

impl Denial {
    /// Stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Clock(_) => "clock",
            Self::Pap(e) => e.code(),
            Self::Profile(e) => e.code(),
            Self::Revoked => "status-revoked",
            Self::Status(e) => e.code(),
            Self::ContentPosition => "content-position",
            Self::Counter(_) => "counter",
            Self::CounterMissing => "counter-missing",
            Self::Exhausted => "pap-slice",
            Self::Report(e) => e.code(),
        }
    }

    /// Whether an online decision may still allow the use (§9.10 step 6, step 8, EP-7): the
    /// verifier is stale or the profile asks for one. The verifier itself never makes it.
    #[must_use]
    pub const fn online_may_allow(&self) -> bool {
        matches!(
            self,
            Self::Pap(
                PapError::Stale
                    | PapError::Validity(ValidityError::OnlineRequired | ValidityError::Stale)
            ) | Self::ContentPosition
        )
    }
}

/// An allowed use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The verified PAP.
    pub pap: Pap,
    /// Trusted time of the use.
    pub now: TrustedTime,
    /// Its consequence tier.
    pub tier: Tier,
    /// What it drew from the slice.
    pub drawn: BTreeSet<SliceAmount>,
    /// Its sequence number in the projection's report chain.
    pub seq: u64,
}

/// One use of a PAP the holder presents.
#[derive(Clone, Copy, Debug)]
pub struct Use<'a> {
    /// The PAP `COSE_Sign1`.
    pub pap: &'a [u8],
    /// Its binding-signed key excerpt (the Domain Metadata excerpt).
    pub excerpt: &'a [u8],
    /// The holder's presentation `COSE_Sign1`.
    pub presentation: &'a [u8],
    /// The intent to apply.
    pub intent: &'a IntentEnvelope,
    /// The nonce the verifier gave the holder.
    pub nonce: &'a [u8],
    /// Local requirement terms satisfied now, for example a local user verification or a
    /// contribution obtained in advance.
    pub satisfied: &'a BTreeSet<RequirementTerm>,
    /// The intent's Action Schema, for its consequence tier.
    pub schema: Option<&'a ActionSchema>,
    /// The position the protected content was written at, when the verifier knows it and its
    /// profile declares the content position check (§9.10.1 step 8).
    pub content_position: Option<u64>,
}

/// The outcome of a use: a decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The use is within the projection; apply it.
    Allow(Box<Allowed>),
    /// Refused locally.
    Deny(Denial),
}

#[derive(Debug)]
struct Slot<C> {
    counter: C,
    guard: SliceGuard,
}

/// What the verifier is: its audience identifier, domain, profile and catalog.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The verifier's audience identifier.
    pub audience: String,
    /// Its Instance, if it has one.
    pub instance: Option<Id>,
    /// Its domain.
    pub domain: Digest,
    /// Its Verifier Profile.
    pub profile: LocalProfile,
    /// Catalog for coverage.
    pub catalog: Catalog,
    /// Extensions it understands.
    pub understood: BTreeSet<String>,
}

/// An offline verifier over a trusted clock `K` and tamper-evident counters `C`.
#[derive(Debug)]
pub struct OfflineVerifier<K, C> {
    me: Identity,
    metadata: MetadataView,
    clock: K,
    guard: ClockGuard,
    slots: BTreeMap<(Digest, Digest), Slot<C>>,
    lists: BTreeMap<String, StatusList>,
    reports: BTreeMap<Digest, ReportBuilder>,
}

/// Reads a PAP without verifying it: what the holder claims it is. Use it to provision slices;
/// never to decide.
///
/// # Errors
/// [`PapError::Malformed`].
pub fn peek(sign1: &[u8]) -> Result<Pap, PapError> {
    let payload = parse_sign1(sign1)
        .ok()
        .and_then(|s| s.payload)
        .ok_or(PapError::Malformed)?;
    Pap::from_bytes(&payload).map_err(|_| PapError::Malformed)
}

/// The position a contract's `basis_ref` names, when it is the plain `[DomainID, position]`
/// form (OP-150 m.3 (l)).
#[must_use]
pub fn basis_position(contract: &ValidityContract) -> Option<u64> {
    let v = dcbor::decode(&contract.basis_ref, Limits::CEILING).ok()?;
    let Value::Array(items) = v else {
        return None;
    };
    match items.as_slice() {
        [domain, Value::Unsigned(pos)] if Digest::from_value(domain).is_some() => Some(*pos),
        _ => None,
    }
}

const fn signature_passed(e: PapError) -> bool {
    !matches!(
        e,
        PapError::Malformed | PapError::Key(_) | PapError::Signature(_) | PapError::Domain
    )
}

impl<K: TrustedClock, C: TamperEvidentCounter> OfflineVerifier<K, C> {
    /// A verifier with its identity, verified Domain Metadata, clock and clock guard.
    #[must_use]
    pub const fn new(me: Identity, metadata: MetadataView, clock: K, guard: ClockGuard) -> Self {
        Self {
            me,
            metadata,
            clock,
            guard,
            slots: BTreeMap::new(),
            lists: BTreeMap::new(),
            reports: BTreeMap::new(),
        }
    }

    /// The verifier's identity.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.me
    }

    /// The Domain Metadata view, to refresh it or record a witness.
    pub const fn metadata_mut(&mut self) -> &mut MetadataView {
        &mut self.metadata
    }

    /// The device clock.
    #[must_use]
    pub const fn clock(&self) -> &K {
        &self.clock
    }

    /// The clock guard's last accepted reading, to persist across restarts.
    #[must_use]
    pub const fn clock_guard(&self) -> &ClockGuard {
        &self.guard
    }

    /// Provisions the counter for the slice of projection `exercise` drawn from
    /// `budget_term`, starting at the counter's current reading.
    ///
    /// # Errors
    /// [`CounterError`] when the counter cannot be read.
    pub fn provision(
        &mut self,
        exercise: Digest,
        budget_term: Digest,
        amount: u64,
        counter: C,
    ) -> Result<CounterReading, CounterError> {
        let base = counter.read()?;
        self.slots.insert(
            (exercise, budget_term),
            Slot {
                counter,
                guard: SliceGuard::new(base, amount),
            },
        );
        Ok(base)
    }

    /// Installs a verified status list, replacing an older one for the same URI. A list
    /// older than the one held is ignored.
    pub fn install_list(&mut self, list: StatusList) {
        let uri = list.token().uri.clone();
        let newer = self
            .lists
            .get(&uri)
            .is_none_or(|old| old.token().iat <= list.token().iat);
        if newer {
            self.lists.insert(uri, list);
        }
    }

    /// Continues a projection's report chain after a report Access acknowledged.
    pub fn resume_report(
        &mut self,
        exercise: Digest,
        contract: Digest,
        profile_version: u64,
        previous: &Summary,
    ) {
        self.reports.insert(
            exercise,
            ReportBuilder::resume(
                *self.me.profile.digest(),
                self.me.instance,
                exercise,
                contract,
                profile_version,
                previous,
            ),
        );
    }

    fn remaining(&self, exercise: &Digest, contract: &ValidityContract) -> BTreeMap<Digest, u64> {
        contract
            .offline_slice
            .iter()
            .filter_map(|s| {
                let slot = self.slots.get(&(*exercise, s.budget_term))?;
                Some((s.budget_term, s.amount.saturating_sub(slot.guard.used())))
            })
            .collect()
    }

    fn status(&self, contract: &ValidityContract) -> Result<Option<TrustedTime>, Denial> {
        let Some(reference) = &contract.status else {
            return Ok(None);
        };
        let Some(list) = self.lists.get(&reference.uri) else {
            return Ok(None);
        };
        if list.is_invalid(reference).map_err(Denial::Status)? {
            return Err(Denial::Revoked);
        }
        Ok(list.recorded_at())
    }

    fn draw(
        &mut self,
        pap: &Pap,
        intent: &IntentEnvelope,
    ) -> Result<BTreeSet<SliceAmount>, Denial> {
        let mut drawn = BTreeSet::new();
        for s in &pap.validity.offline_slice {
            let units = pap::demand(&s.unit, intent).ok_or(Denial::Exhausted)?;
            let slot = self
                .slots
                .get_mut(&(pap.projection_exercise, s.budget_term))
                .ok_or(Denial::CounterMissing)?;
            if units == 0 {
                continue;
            }
            match slot
                .guard
                .draw(&mut slot.counter, units)
                .map_err(Denial::Counter)?
            {
                Draw::Granted(_) => {
                    drawn.insert(SliceAmount {
                        budget_term: s.budget_term,
                        amount: units,
                    });
                }
                Draw::Exhausted => return Err(Denial::Exhausted),
            }
        }
        Ok(drawn)
    }

    fn chain(&mut self, pap: &Pap, entry: Entry) -> Result<u64, Denial> {
        let contract =
            contract_digest(&pap.validity).map_err(|_| Denial::Report(ReportError::Malformed))?;
        let builder = match self.reports.entry(pap.projection_exercise) {
            alloc::collections::btree_map::Entry::Occupied(o) => o.into_mut(),
            alloc::collections::btree_map::Entry::Vacant(v) => v.insert(
                ReportBuilder::start(
                    *self.me.profile.digest(),
                    self.me.instance,
                    pap.projection_exercise,
                    contract,
                    pap.validity.profile_version,
                )
                .map_err(Denial::Report)?,
            ),
        };
        builder.record(entry).map_err(Denial::Report)
    }

    /// Decides one use (§9.10, L2-PAP-3), with the optional step 8 when the profile declares
    /// it, draws the slice, and chains the use into the projection's report.
    pub fn verify(&mut self, u: &Use<'_>) -> Verdict {
        match self.decide(u) {
            Ok(a) => Verdict::Allow(Box::new(a)),
            Err(d) => Verdict::Deny(d),
        }
    }

    fn decide(&mut self, u: &Use<'_>) -> Result<Allowed, Denial> {
        let now = self.guard.now(&self.clock).map_err(Denial::Clock)?;
        let claimed = peek(u.pap).map_err(Denial::Pap)?;
        let contract = &claimed.validity;
        let tier = tier::of(u.intent, None, false, u.schema);
        let caps = self.metadata.metadata().caps.as_ref();
        let admitted = self.me.profile.admits(contract, tier, caps);
        let uncapped = contract.horizon.saturating_sub(claimed.iat);
        let horizon_cap_ms = admitted.as_ref().map_or(uncapped, |c| {
            self.me.profile.horizon_cap(c, contract.variant, tier, caps)
        });
        let status = self.status(contract);
        let last_refresh = status.as_ref().ok().copied().flatten();
        let remaining = self.remaining(&claimed.projection_exercise, contract);
        let expected = Expected {
            domain: &self.me.domain,
            intent: u.intent,
            audience: &self.me.audience,
            nonce: u.nonce,
            now,
            catalog: &self.me.catalog,
            satisfied: u.satisfied,
            remaining: &remaining,
            metadata_fresh: self.metadata.fresh(now, contract.max_staleness_ms),
            understood: &self.me.understood,
            last_refresh,
            online: false,
            skew_ms: self.me.profile.skew_ms(tier),
            horizon_cap_ms,
        };
        let checked = pap::verify(
            &PureBackend,
            self.metadata.metadata(),
            u.pap,
            u.excerpt,
            u.presentation,
            &expected,
        );
        let verdict = checked.map_err(Denial::Pap).and_then(|p| {
            admitted.map_err(Denial::Profile)?;
            status?;
            self.step8(&p, u.content_position)?;
            Ok(p)
        });
        let intent = intent_digest(u.intent).map_err(|_| Denial::Pap(PapError::Malformed))?;
        let holder_proof = Some(Digest(
            suiss_crypto::digest::context_digest(PRESENTATION_CONTEXT, u.presentation).0,
        ));
        let mut entry = Entry {
            intent,
            params: None,
            time: now,
            clock_evidence: None,
            outcome: LocalOutcome::Deny,
            drawn: BTreeSet::new(),
            holder_proof,
        };
        let pap = match verdict {
            Ok(p) => p,
            Err(d) => {
                if !matches!(d, Denial::Pap(e) if !signature_passed(e)) {
                    self.chain(&claimed, entry)?;
                }
                return Err(d);
            }
        };
        match self.draw(&pap, u.intent) {
            Ok(drawn) => {
                entry.outcome = LocalOutcome::Allow;
                entry.drawn.clone_from(&drawn);
                let seq = self.chain(&pap, entry)?;
                Ok(Allowed {
                    pap,
                    now,
                    tier,
                    drawn,
                    seq,
                })
            }
            Err(d) => {
                self.chain(&pap, entry)?;
                Err(d)
            }
        }
    }

    fn step8(&self, pap: &Pap, content_position: Option<u64>) -> Result<(), Denial> {
        // §9.10.1 step 8, U60
        if !self.me.profile.body().content_position_check {
            return Ok(());
        }
        let Some(written) = content_position else {
            return Ok(());
        };
        match basis_position(&pap.validity) {
            Some(basis) if basis >= written => Ok(()),
            _ => Err(Denial::ContentPosition),
        }
    }

    /// What remains of each slice of projection `exercise`, by budget term.
    #[must_use]
    pub fn slice_unused(&self, exercise: &Digest) -> BTreeSet<SliceAmount> {
        self.slots
            .iter()
            .filter(|((e, _), _)| e == exercise)
            .map(|((_, term), slot)| SliceAmount {
                budget_term: *term,
                amount: slot.guard.slice().saturating_sub(slot.guard.used()),
            })
            .filter(|s| s.amount > 0)
            .collect()
    }

    /// Projections with uses not yet reported.
    #[must_use]
    pub fn unreported(&self) -> Vec<Digest> {
        self.reports
            .iter()
            .filter(|(_, b)| !b.pending().is_empty())
            .map(|(e, _)| *e)
            .collect()
    }

    /// Cuts the Offline Exercise Report of projection `exercise` on reconnect (§9.12.2): the
    /// chained uses since the last report and what remains of its slice. `None` when the
    /// verifier has never seen a use of it.
    ///
    /// # Errors
    /// [`Denial::Clock`] or [`Denial::Report`].
    pub fn report(&mut self, exercise: &Digest) -> Result<Option<CutReport>, Denial> {
        let now = self.guard.now(&self.clock).map_err(Denial::Clock)?;
        let unused = self.slice_unused(exercise);
        let Some(builder) = self.reports.get_mut(exercise) else {
            return Ok(None);
        };
        builder.cut(now, unused).map(Some).map_err(Denial::Report)
    }
}

/// The contract digest a report names (L2-RPT-1): the contract's canonical bytes under
/// [`CONTRACT_CONTEXT`].
///
/// # Errors
/// The contract cannot be encoded.
pub fn contract_digest(contract: &ValidityContract) -> Result<Digest, dcbor::EncodeError> {
    Ok(Digest(
        suiss_crypto::digest::context_digest(CONTRACT_CONTEXT, &contract.to_bytes()?).0,
    ))
}

impl<K, C> OfflineVerifier<K, C> {
    /// The status lists held, by URI.
    #[must_use]
    pub fn lists(&self) -> Vec<&str> {
        self.lists.keys().map(String::as_str).collect()
    }
}
