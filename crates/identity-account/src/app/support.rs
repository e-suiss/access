//! Support access in the identity plane (MD-9, TN-137, SI-21, XI-7, OP-157 m.3 (f)): an operator's
//! request is an invitation only; the person's own `grant.issue` of the support template is what
//! gives access, and the identity plane records, audits and announces what became of it. The
//! Grant a request asks for is drafted here from the request alone, so the person signs exactly
//! what the operator asked and nothing wider (§8.16).
//!
//! - [`Scope::Read`] asks to view the account, for at most 60 minutes, or up to 24 hours as the
//!   read-only standing permission (TN-137 (2), (4)).
//! - [`Scope::Profile`] also asks to change the profile fields, for at most 60 minutes.
//! - [`Scope::Artifacts`] asks to read the person's support artifacts alone, for at most 60
//!   minutes: a Grant apart from any other (§8.16 #12, TN-74).

use std::collections::{BTreeMap, BTreeSet};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_internal_api::idp::IdpAction;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::{GrantBasis, GrantContent};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id, PurposeRef,
    ResourceSelector, Structural, SubjectSelector, WhileCondition, Window,
};
use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::support_access::{Answer, End, SupportRequestRow};
use suiss_crypto::envelope::Kek;

use crate::app::SUBJECT_PREFIX;
use crate::app::vault::{PiiClass, open};
use crate::notify::NotifyError;
use crate::notify::message::{Body, SupportEvent};
use crate::notify::notices::queue_body;
use crate::ports::{Clock, Entropy};

/// The opaque id prefix of a support request.
pub const REQUEST_PREFIX: &str = "spr";

/// The Claim class of a case system's case state (OP-157 m.3 (e)).
pub const CASE_CLASS: &str = "support_case";

/// The resource namespace of a Party's own resources under its self-anchor (L0-META-7).
pub const RESOURCES: &str = "access.party";

/// How long an operator's invitation can be answered, ms (PD).
pub const INVITATION_MS: u64 = 60 * 60 * 1000;

/// Longest support access that may change anything, minutes (§8.16 #5, PD).
pub const SESSION_MAX_MIN: u32 = 60;

/// Longest read-only standing support access, minutes (TN-137 (2), OP-157 m.3 (c), PD).
pub const STANDING_MAX_MIN: u32 = 24 * 60;

/// The account page a request invitation opens, under the realm issuer; the operator cannot
/// open it (XI-7).
pub const ACCOUNT_PATH: &str = "/account/support";

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// View the account.
    Read,
    /// View the account and change its profile fields.
    Profile,
    /// Read the person's support artifacts.
    Artifacts,
}

impl Scope {
    /// Every scope.
    pub const ALL: [Self; 3] = [Self::Read, Self::Profile, Self::Artifacts];

    /// Its wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Profile => "profile",
            Self::Artifacts => "artifacts",
        }
    }

    /// The scope named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    /// What it allows, as the person reads it (OP-157 m.3 (f)).
    #[must_use]
    pub const fn what(self) -> &'static str {
        match self {
            Self::Read => "view your account settings",
            Self::Profile => "view your account settings and change your profile",
            Self::Artifacts => "read the files you shared with support",
        }
    }

    /// Longest access it may ask for, minutes.
    #[must_use]
    pub const fn max_minutes(self) -> u32 {
        match self {
            Self::Read => STANDING_MAX_MIN,
            Self::Profile | Self::Artifacts => SESSION_MAX_MIN,
        }
    }

    /// The template a Grant of `minutes` takes, and the actions it names.
    #[must_use]
    pub fn template(self, minutes: u32) -> (&'static str, Vec<IdpAction>) {
        match self {
            Self::Read if minutes > SESSION_MAX_MIN => {
                ("support.standing", vec![IdpAction::AccountRead])
            }
            Self::Read => ("support.session", vec![IdpAction::AccountRead]),
            Self::Profile => (
                "support.session",
                vec![IdpAction::AccountRead, IdpAction::AccountProfileUpdate],
            ),
            Self::Artifacts => ("support.artifacts", vec![IdpAction::AccountArtifactRead]),
        }
    }

    /// Whether it may be asked for `minutes`.
    #[must_use]
    pub const fn fits(self, minutes: u32) -> bool {
        minutes >= 1 && minutes <= self.max_minutes()
    }
}

/// Lower-case hex of `b`.
#[must_use]
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

/// What the person gives for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Draft {
    /// The person's Party.
    pub person: Id,
    /// The person's self-anchor.
    pub anchor: Id,
    /// The operator's Party.
    pub operator: Id,
    /// The case digest.
    pub case: Digest,
    /// The case system's `support_case` Acceptance.
    pub acceptance: Digest,
    /// What is asked.
    pub scope: Scope,
    /// For how long.
    pub validity: Window,
}

impl Draft {
    /// The `grant.issue` content of this support access: the template shape on the person's
    /// own resources, `For` the person alone, passing on to no one, bound to the one case and
    /// held while its case is open (§8.16, OP-157 m.3 (c), (e)).
    #[must_use]
    pub fn grant(&self) -> GrantContent {
        let minutes = u32::try_from(
            self.validity
                .until
                .saturating_sub(self.validity.from)
                .div_ceil(60_000),
        )
        .unwrap_or(u32::MAX);
        let (_, actions) = self.scope.template(minutes);
        GrantContent {
            basis: GrantBasis::Anchor(self.anchor),
            holder: SubjectSelector::Party(self.operator),
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: actions.iter().map(|a| a.action_ref()).collect(),
                        prefix: BTreeSet::new(),
                    },
                    resource: ResourceSelector::Structural(Structural {
                        namespace: String::from(RESOURCES),
                        prefix: vec![hex(&self.person.0)],
                        kind: None,
                        attrs: BTreeMap::new(),
                    }),
                    params: BTreeMap::new(),
                    recipient: None,
                    purpose: Some(BTreeSet::from([PurposeRef::Case(self.case)])),
                },
                constraints: ConstraintSet {
                    validity: self.validity,
                    conditions: BTreeSet::from([WhileCondition::ClaimHeld {
                        class: String::from(CASE_CLASS),
                        subject: SubjectSelector::Party(self.person),
                        acceptance: self.acceptance,
                    }]),
                    budget: BTreeSet::new(),
                },
                delegation: DelegationTerms::default(),
                requirements: BTreeSet::new(),
            },
            agency: BTreeSet::from([Capacity::For(self.person)]),
            named: None,
        }
    }

    /// Whether `content`, as the person's device signed it, is this draft at a window that
    /// starts within a few minutes of `now` and lasts no longer than the request asked:
    /// anything else is not what the operator asked for (§8.16).
    #[must_use]
    pub fn signed_as(&self, content: &GrantContent, minutes: u32, now: u64) -> bool {
        let v = content.authority.constraints.validity;
        let span = v.until.checked_sub(v.from);
        let fresh =
            v.from.saturating_add(5 * 60_000) >= now && v.from <= now.saturating_add(60_000);
        let short = span.is_some_and(|s| s > 0 && s <= u64::from(minutes).saturating_mul(60_000));
        let same = Self {
            validity: v,
            ..*self
        }
        .grant();
        fresh && short && same == *content
    }
}

/// The names a notice shows for a request: the operator's and their organization's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names {
    /// The operator's display name.
    pub operator: String,
    /// The support organization's name.
    pub organization: String,
}

/// The operator's display name: the profile `name`, else the given name, else a plain word;
/// attacker-controlled text, cut to 200 characters (XI-17).
///
/// # Errors
/// [`NotifyError`].
pub async fn display_name(
    tx: &mut TenantTx,
    kek: &(dyn Kek + Send + Sync),
    subject: [u8; 16],
) -> Result<String, NotifyError> {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    if let Some(row) = tx.subject_key(subject, PiiClass::Profile.name()).await?
        && let Some(wrapped) = row.wrapped_dek
        && row.kek_id == kek.id()
        && let Ok(dek) = kek.unwrap(&wrapped)
    {
        for (field, nonce, ciphertext) in tx.profile_fields(subject).await? {
            if (field == "name" || field == "given_name")
                && let Ok(v) = open(
                    tx,
                    &dek,
                    subject,
                    PiiClass::Profile,
                    &field,
                    &suiss_crypto::envelope::Sealed { nonce, ciphertext },
                )
            {
                found.insert(field, v);
            }
        }
    }
    let name = found
        .remove("name")
        .or_else(|| found.remove("given_name"))
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| String::from("A support agent"));
    Ok(name.chars().take(200).collect())
}

/// The organization an operator acts for: their Party's own organization, or the first one
/// their account belongs to, or `fallback`.
///
/// # Errors
/// [`NotifyError`].
pub async fn organization(
    tx: &mut TenantTx,
    operator: [u8; 16],
    operator_party: [u8; 16],
    fallback: &str,
) -> Result<String, NotifyError> {
    if let Some(o) = tx.org_by_party(operator_party).await? {
        return Ok(o.display_name.chars().take(200).collect());
    }
    Ok(tx
        .orgs_of(operator)
        .await?
        .into_iter()
        .map(|(o, _)| o)
        .find(|o| !o.ended)
        .map_or_else(|| String::from(fallback), |o| o.display_name)
        .chars()
        .take(200)
        .collect())
}

/// The names of `row`'s operator.
///
/// # Errors
/// [`NotifyError`].
pub async fn names(
    tx: &mut TenantTx,
    kek: &(dyn Kek + Send + Sync),
    row: &SupportRequestRow,
    fallback: &str,
) -> Result<Names, NotifyError> {
    Ok(Names {
        operator: display_name(tx, kek, row.operator).await?,
        organization: organization(tx, row.operator, row.operator_party, fallback).await?,
    })
}

fn account(ids: &IdKey, subject: [u8; 16]) -> Result<String, NotifyError> {
    ids.encode(SUBJECT_PREFIX, subject)
        .map_err(|_| NotifyError::NoSubject)
}

fn request_id(ids: &IdKey, id: [u8; 16]) -> Result<String, NotifyError> {
    ids.encode(REQUEST_PREFIX, id)
        .map_err(|_| NotifyError::NoSubject)
}

/// Audits the new request `row` and sends the person its invitation, whose link opens their
/// own account page (OP-157 m.3 (f), m.6 (k)); whether the invitation was queued.
///
/// # Errors
/// [`NotifyError`]; the caller rolls back.
pub async fn requested(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    (entropy, clock): (&(dyn Entropy + Sync), &(dyn Clock + Sync)),
    row: &SupportRequestRow,
    (names, issuer): (&Names, &str),
) -> Result<bool, NotifyError> {
    let id = request_id(ids, row.id)?;
    tx.audit(&AuditEvent {
        event_type: "support.access_requested",
        actor: &account(ids, row.operator)?,
        target: &id,
        correlation: "-",
    })
    .await?;
    let link = format!(
        "{}{ACCOUNT_PATH}?request={id}",
        issuer.trim_end_matches('/')
    );
    let body = Body::SupportAccessRequest {
        organization: names.organization.clone(),
        case: row.case_label.clone(),
        scope: String::from(
            Scope::parse(&row.scope)
                .ok_or(NotifyError::NoSubject)?
                .what(),
        ),
        minutes: row.minutes,
        link: Secret::new(link),
        expires_at_ms: row.expires_ms,
    };
    Ok(
        queue_body(tx, (kek, ids), entropy, clock, row.subject, body)
            .await?
            .is_some(),
    )
}

/// Records that the person's `grant.issue` of `row` committed, audits it and tells the person
/// (SI-21, §8.16 #6, #7); whether it was new.
///
/// # Errors
/// [`NotifyError`]; the caller rolls back.
pub async fn granted(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    (entropy, clock): (&(dyn Entropy + Sync), &(dyn Clock + Sync)),
    row: &SupportRequestRow,
    (answer, at_ms): (&Answer, u64),
    names: &Names,
) -> Result<bool, NotifyError> {
    let Answer::Granted { until_ms, .. } = answer else {
        return Ok(false);
    };
    if !tx.answer_support_request(row.id, answer, at_ms).await? {
        return Ok(false);
    }
    tx.audit(&AuditEvent {
        event_type: "support.access_granted",
        actor: &account(ids, row.subject)?,
        target: &request_id(ids, row.id)?,
        correlation: "-",
    })
    .await?;
    let body = Body::SupportAccessNotice {
        event: SupportEvent::Granted,
        operator: names.operator.clone(),
        organization: names.organization.clone(),
        case: row.case_label.clone(),
        at_ms,
        until_ms: Some(*until_ms),
    };
    queue_body(tx, (kek, ids), entropy, clock, row.subject, body).await?;
    Ok(true)
}

/// Records that `row`'s Grant ended, audits it and tells the person (SI-21, §8.16 #6, #7):
/// "Support access ended" at its end, "You revoked support access" on a revoke; whether it
/// was new.
///
/// # Errors
/// [`NotifyError`]; the caller rolls back.
pub async fn ended(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    (entropy, clock): (&(dyn Entropy + Sync), &(dyn Clock + Sync)),
    row: &SupportRequestRow,
    (end, at_ms): (End, u64),
    fallback: &str,
) -> Result<bool, NotifyError> {
    if !tx.end_support_request(row.id, end, at_ms).await? {
        return Ok(false);
    }
    tx.audit(&AuditEvent {
        event_type: "support.access_ended",
        actor: if end == End::Revoked {
            "subject"
        } else {
            "authority"
        },
        target: &request_id(ids, row.id)?,
        correlation: "-",
    })
    .await?;
    let n = names(tx, kek, row, fallback).await?;
    let body = Body::SupportAccessNotice {
        event: match end {
            End::Ended => SupportEvent::Ended,
            End::Revoked => SupportEvent::Revoked,
        },
        operator: n.operator,
        organization: n.organization,
        case: row.case_label.clone(),
        at_ms,
        until_ms: None,
    };
    queue_body(tx, (kek, ids), entropy, clock, row.subject, body).await?;
    Ok(true)
}

/// Most ends one sweep writes.
const SWEEP: i64 = 200;

/// Ends the realm's support access whose Grant reached its end by `now_ms` and shreds the
/// support artifacts past their retention (§8.16 #5, OP-73); the requests that ended now.
///
/// # Errors
/// [`NotifyError`].
pub async fn sweep(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    (entropy, clock): (&(dyn Entropy + Sync), &(dyn Clock + Sync)),
    now_ms: u64,
    fallback: &str,
) -> Result<Vec<SupportRequestRow>, NotifyError> {
    let mut out = Vec::new();
    for id in tx.support_grants_past(now_ms, SWEEP).await? {
        let Some(row) = tx.support_request(id).await? else {
            continue;
        };
        let until = match &row.answer {
            Some((Answer::Granted { until_ms, .. }, _)) => *until_ms,
            _ => continue,
        };
        if ended(
            tx,
            (kek, ids),
            (entropy, clock),
            &row,
            (End::Ended, until),
            fallback,
        )
        .await?
        {
            out.push(row);
        }
    }
    tx.shred_support_artifacts(now_ms).await?;
    Ok(out)
}

/// When the Grant `grant` was revoked by any Exercise, the support access it gave ends
/// (SI-21); the request, when it was a support Grant that had not ended yet.
///
/// # Errors
/// [`NotifyError`].
pub async fn revoked(
    tx: &mut TenantTx,
    (kek, ids): (&(dyn Kek + Send + Sync), &IdKey),
    (entropy, clock): (&(dyn Entropy + Sync), &(dyn Clock + Sync)),
    (grant, at_ms): ([u8; 16], u64),
    fallback: &str,
) -> Result<Option<SupportRequestRow>, NotifyError> {
    let Some(row) = tx.support_request_by_grant(grant).await? else {
        return Ok(None);
    };
    let now = ended(
        tx,
        (kek, ids),
        (entropy, clock),
        &row,
        (End::Revoked, at_ms),
        fallback,
    )
    .await?;
    Ok(now.then_some(row))
}

#[cfg(test)]
mod tests;
