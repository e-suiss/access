//! The local deployment's Stage 12 fixtures (OP-157 m.4 (a), m.6 (i), OP-69): a support
//! operator in its support organization with a registered case system and an open case of the
//! test user, a marked break-glass account with its two pre-issued break-glass Grants, and a
//! scheduled access review whose manager is the test user. The `@live` specs read them.
//!
//! - Every authority and realm fact comes from an Exercise: the realm root's `idp.*` changes
//!   (MD-14, EI-25), the founder's organization, the root's `grant_issue`s and the case system's
//!   own signed `support_case` Claim through Claim Ingest (CMP-8). Nothing is a SQL seed.
//! - Accounts are made through the account service, as the test user is.
//! - Every step looks for its result first, so a second run changes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use access_authority_core::app::breakglass::Setup;
use access_authority_core::genesis::IDP_ANCHOR;
use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::Realm;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::ports::{AccountDb, AccountTx};
use access_identity_admin::app::Admin;
use access_identity_admin::domain::breakglass::BreakglassMark;
use access_identity_admin::domain::hr::name_ok;
use access_identity_admin::domain::review::{ReviewChange, ReviewSchedule};
use access_identity_admin::domain::support::{CaseSystem, CaseSystemChange};
use access_identity_admin::domain::{Change, OrgCreate};
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_events::adapters::RealmKek as _;
use access_internal_api::claims::{Carrier, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::{IdpAction, RESOURCE_NAMESPACE};
use access_internal_api::instances::{
    SelfSigned, bootstrap_basis, register_nonce, self_signed_intent,
};
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::claim::{
    CONTENT_TYPE as CLAIM_CONTENT_TYPE, PREDICATE_INPUT, Statement as ClaimStatement,
};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{
    self, ActorKind, ExerciseBasis, GrantBasis, GrantContent, Payload, Root,
};
use access_kernel::model::{EqValue, Id, ResourceSelector, Structural, SubjectSelector, Window};
use access_kernel::verify::key_scope::thumbprint;
use access_store::authority::server_time;
use access_store::identity::{RealmId, TenantId, TenantTx};
use serde::{Deserialize, Serialize};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::{Signer as _, sign_sign1};

use super::local::create_account;
use super::{
    Bootstrap, BootstrapError, MetaExercises, Moment, authority, holding_json, root_challenge,
    root_party, sample_tenant, sign, token_key,
};
use crate::login::RealmKeks;

/// The token label of the support operator's device key.
pub(crate) const SUPPORT_DEVICE_LABEL: &str = "access/bootstrap/support-operator-device";

/// The token label of the key that registers the support organization's Party.
const SUPPORT_ORG_LABEL: &str = "access/bootstrap/support-organization";

/// The token label of the case system's issuer key: it signs the `support_case` Claims.
pub(crate) const CASE_SYSTEM_LABEL: &str = "access/bootstrap/support-case-system";

/// The token label of the break-glass account's device key.
const BREAKGLASS_DEVICE_LABEL: &str = "access/bootstrap/breakglass-device";

/// The token label of the key that registers the break-glass account's organization's Party.
const BREAKGLASS_ORG_LABEL: &str = "access/bootstrap/breakglass-organization";

/// What the root signs to derive the nonce of one break-glass Grant.
const BREAKGLASS_GRANT_LABEL: &[u8] = b"access-bootstrap/breakglass-grant:1";

/// What the root signs to derive the nonce of the test user's Grant of one console screen's
/// action.
const SCREEN_GRANT_LABEL: &[u8] = b"access-bootstrap/screen-grant:1";

/// The attestation class the fixtures' own bootstrap Exercises are counted under, apart from the
/// realm's (§13.7.4, OP-152 m.5 (b)): the per-hour limit still holds for them.
const FIXTURE_CONTEXT: &str = "local-bootstrap.fixtures";

/// The `support_case` Claim class (OP-157 m.3 (e)).
pub(crate) const CASE_CLASS: &str = "support_case";

/// The vendor the local case system names (OP-157 m.3 (e)).
const CASE_PROVIDER: &str = "zendesk";

/// The body format the local case system states (OP-157 m.3 (e)).
const CASE_FORMAT: &str = "product-seam/v1";

/// The local case system's name unless the plan names one.
const DEFAULT_CASE_SYSTEM: &str = "local-desk";

/// The open case unless the plan names one.
const DEFAULT_CASE: &str = "4411";

/// The break-glass account's organization unless the plan names one.
const DEFAULT_BREAKGLASS_ORG: &str = "Acme Security";

/// The review campaign's name unless the plan names one.
const DEFAULT_REVIEW: &str = "local-review";

/// How long one case Claim holds (PD): a run on a later day states a new one.
const CASE_CLAIM_MS: u64 = 7 * DAY_MS;

const DAY_MS: u64 = 86_400_000;

/// Longest display name or identifier (it is rendered as text).
const MAX_TEXT: usize = 200;

/// Longest review period, in days.
const MAX_PERIOD_DAYS: u16 = 366;

/// How many approvals from distinct Parties a use of the local break-glass Grants needs.
const BREAKGLASS_APPROVALS: u64 = 2;

/// `[support_operator]` as written: a support operator in its team's organization. The password
/// is read from the environment variable `password_env` names, never from the plan.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SupportOperatorFile {
    realm: String,
    display_name: String,
    organisation: String,
    identifier: String,
    password_env: String,
    case_system: Option<String>,
    case: Option<String>,
}

/// `[breakglass_account]` as written: an organization member marked `is_breakglass`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BreakglassAccountFile {
    realm: String,
    identifier: String,
    organisation: Option<String>,
}

/// `[review_schedule]` as written: an `idp.review.schedule` over the manager's team.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewScheduleFile {
    realm: String,
    period_days: u16,
    name: Option<String>,
}

/// The support operator of a realm that also has the test user, whose case is open.
#[derive(Clone)]
pub(crate) struct SupportOperatorPlan {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The operator's name people see.
    pub(crate) display_name: String,
    /// The support organization's name.
    pub(crate) organisation: String,
    /// The operator's login identifier.
    pub(crate) identifier: String,
    /// The operator's password, from the environment variable the plan named.
    pub(crate) password: Secret<String>,
    /// The case system's registered name.
    pub(crate) case_system: String,
    /// The test user's open case, as the case system shows it.
    pub(crate) case: String,
}

impl core::fmt::Debug for SupportOperatorPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SupportOperatorPlan")
            .field("realm", &self.realm)
            .field("identifier", &self.identifier)
            .field("case_system", &self.case_system)
            .field("case", &self.case)
            .finish_non_exhaustive()
    }
}

/// The break-glass account of a realm that also has the test user.
#[derive(Clone, Debug)]
pub(crate) struct BreakglassPlan {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The account's login identifier.
    pub(crate) identifier: String,
    /// Its organization's name.
    pub(crate) organisation: String,
}

/// The access review of a realm whose test user manages the sample agent's Grant.
#[derive(Clone, Debug)]
pub(crate) struct ReviewPlan {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The campaign's name.
    pub(crate) name: String,
    /// Its period, in days.
    pub(crate) period_days: u32,
}

/// The plan's Stage 12 fixture sections as written.
pub(super) struct Fixtures {
    pub(super) support_operator: Option<SupportOperatorFile>,
    pub(super) breakglass_account: Option<BreakglassAccountFile>,
    pub(super) review_schedule: Option<ReviewScheduleFile>,
}

/// The plan's Stage 12 fixtures, checked.
pub(super) type Plans = (
    Option<SupportOperatorPlan>,
    Option<BreakglassPlan>,
    Option<ReviewPlan>,
);

fn text(section: &str, field: &str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() || value.chars().count() > MAX_TEXT {
        return Err(BootstrapError::Plan(format!(
            "{section}: {field} is 1 to {MAX_TEXT} characters"
        )));
    }
    Ok(())
}

/// Whether `case` is a label a case system could show: no free text (TN-73).
fn case_label(case: &str) -> bool {
    let mut chars = case.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && case.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '#' | '-'))
}

fn needs(
    section: &str,
    what: &str,
    realm: &str,
    there: Option<&str>,
) -> Result<(), BootstrapError> {
    if there == Some(realm) {
        Ok(())
    } else {
        Err(BootstrapError::Plan(format!(
            "{section}: the realm needs the {what}"
        )))
    }
}

impl Fixtures {
    /// Checks each section that is present: its realm is one of `tenants` with the test user,
    /// and a review's realm also has the sample agent, whose Grant from the test user is the
    /// manager's team.
    pub(super) fn plans(
        self,
        tenants: &[String],
        test_user: Option<&str>,
        sample_agent: Option<&str>,
    ) -> Result<Plans, BootstrapError> {
        let support = match self.support_operator {
            None => None,
            Some(s) => {
                sample_tenant(tenants, "support_operator", &s.realm)?;
                needs("support_operator", "[test_user]", &s.realm, test_user)?;
                text("support_operator", "display_name", &s.display_name)?;
                text("support_operator", "organisation", &s.organisation)?;
                text("support_operator", "identifier", &s.identifier)?;
                let case_system = s
                    .case_system
                    .unwrap_or_else(|| String::from(DEFAULT_CASE_SYSTEM));
                let case = s.case.unwrap_or_else(|| String::from(DEFAULT_CASE));
                if !name_ok(&case_system)
                    || !case_label(&case)
                    || access_kernel::digest::case_ref(&case_system, &case).is_err()
                {
                    return Err(BootstrapError::Plan(String::from(
                        "support_operator: case_system is a lower-case name and case a case label",
                    )));
                }
                let password = std::env::var(&s.password_env)
                    .ok()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        BootstrapError::Plan(format!(
                            "support_operator: password_env {} is not set",
                            s.password_env
                        ))
                    })?;
                Some(SupportOperatorPlan {
                    realm: s.realm,
                    display_name: s.display_name,
                    organisation: s.organisation,
                    identifier: s.identifier,
                    password: Secret::new(password),
                    case_system,
                    case,
                })
            }
        };
        let breakglass = match self.breakglass_account {
            None => None,
            Some(b) => {
                sample_tenant(tenants, "breakglass_account", &b.realm)?;
                needs("breakglass_account", "[test_user]", &b.realm, test_user)?;
                text("breakglass_account", "identifier", &b.identifier)?;
                let organisation = b
                    .organisation
                    .unwrap_or_else(|| String::from(DEFAULT_BREAKGLASS_ORG));
                text("breakglass_account", "organisation", &organisation)?;
                Some(BreakglassPlan {
                    realm: b.realm,
                    identifier: b.identifier,
                    organisation,
                })
            }
        };
        let review = match self.review_schedule {
            None => None,
            Some(r) => {
                sample_tenant(tenants, "review_schedule", &r.realm)?;
                needs("review_schedule", "[test_user]", &r.realm, test_user)?;
                needs("review_schedule", "[sample_agent]", &r.realm, sample_agent)?;
                if r.period_days < 7 || r.period_days > MAX_PERIOD_DAYS {
                    return Err(BootstrapError::Plan(format!(
                        "review_schedule: period_days is 7 to {MAX_PERIOD_DAYS}"
                    )));
                }
                let name = r.name.unwrap_or_else(|| String::from(DEFAULT_REVIEW));
                if !name_ok(&name) {
                    return Err(BootstrapError::Plan(String::from(
                        "review_schedule: name is a lower-case name",
                    )));
                }
                Some(ReviewPlan {
                    realm: r.realm,
                    name,
                    period_days: u32::from(r.period_days),
                })
            }
        };
        Ok((support, breakglass, review))
    }
}

/// The `acceptance-content` under which the local case system's `support_case` Claims are
/// predicate input about any subject, for good (L2-CLM-3, OP-157 m.3 (e)).
pub(super) fn case_acceptance(issuer: Id) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(PREDICATE_INPUT)),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(CASE_CLASS)]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// The support operator in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SupportOperatorOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The operator's login identifier.
    pub(crate) identifier: String,
    /// The operator's account (`usr_…`).
    pub(crate) subject: String,
    /// The operator's Party, base64url.
    pub(crate) party: String,
    /// The support organization's name.
    pub(crate) organisation: String,
    /// The support organization's Party, base64url.
    pub(crate) organisation_party: String,
    /// The case system's registered name.
    pub(crate) case_system: String,
    /// Its issuer Party, base64url.
    pub(crate) case_issuer: String,
    /// The test user's open case.
    pub(crate) case: String,
    /// `accepted` once the domain takes the case system's Claims, `pending` while the
    /// time-lock of a realm made before runs.
    pub(crate) acceptance: &'static str,
    /// When the case Claim stops holding, Unix ms; absent while the Acceptance is pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) case_until: Option<u64>,
    /// Whether this run made the operator's account.
    pub(crate) created: bool,
}

/// The break-glass account in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct BreakglassOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The account's login identifier.
    pub(crate) identifier: String,
    /// The account (`usr_…`).
    pub(crate) subject: String,
    /// Its Party, base64url.
    pub(crate) party: String,
    /// Its organization's name.
    pub(crate) organisation: String,
    /// Its organization's Party, base64url.
    pub(crate) organisation_party: String,
    /// The pre-issued break-glass Grants: each holder's `basis`.
    pub(crate) grants: Vec<serde_json::Value>,
    /// Whether this run made the account.
    pub(crate) created: bool,
}

/// The access review in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ReviewOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The campaign's name.
    pub(crate) name: String,
    /// Its period, in days.
    pub(crate) period_days: u32,
    /// The manager: the test user's Party, base64url.
    pub(crate) manager: String,
    /// How many Grants the manager's team shows.
    pub(crate) items: usize,
    /// Whether this run scheduled it.
    pub(crate) created: bool,
}

/// The realm's `idp` resources: what every `idp.*` change names.
fn realm_resources(slug: &str) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: String::from(RESOURCE_NAMESPACE),
        prefix: vec![String::from(slug)],
        kind: None,
        attrs: BTreeMap::new(),
    })
}

/// The fixtures' rate context.
fn context() -> Option<access_internal_api::context::RateContext> {
    access_internal_api::context::RateContext::attestation(FIXTURE_CONTEXT)
}

/// The Unix ms day `now` falls in.
const fn day_of(now: u64) -> u64 {
    now - now % DAY_MS
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// The case system's issuer key, made in the token once, and its Party.
    pub(super) fn case_system(&self) -> Result<(HsmSigner, Id), BootstrapError> {
        let key = token_key(self.hsm, CASE_SYSTEM_LABEL)?;
        let party = root_party(&key.public_key());
        Ok((key, party))
    }

    /// The account of `identifier` in the realm, made with `password` when there is none.
    async fn account(
        &self,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        identifier: &str,
        password: Option<&Secret<String>>,
    ) -> Result<([u8; 16], String, bool), BootstrapError> {
        let kind = if identifier.contains('@') {
            IdentifierKind::Email
        } else {
            IdentifierKind::Username
        };
        let identifier = Identifier::new(kind, identifier)
            .map_err(|e| BootstrapError::Plan(format!("identifier: {e}")))?;
        let keks = RealmKeks::new(Arc::clone(self.hsm));
        let kek = keks
            .kek(tenant, realm)
            .ok_or_else(|| BootstrapError::Unavailable(String::from("realm KEK")))?;
        let scope = Realm {
            tenant,
            realm,
            kek: &*kek,
            ids,
        };
        let vault = keks
            .vault(realm)
            .ok_or_else(|| BootstrapError::Unavailable(String::from("PII vault keys")))?;
        let accounts = PgAccounts::sealed(self.app.clone(), vault);
        let mut tx = accounts.begin(tenant, realm).await?;
        let existing = tx.subject_by_identifier(identifier.value()).await?;
        tx.commit().await?;
        let (subject, created) = match existing {
            Some(s) => (s, false),
            None => (
                create_account(&accounts, &scope, &identifier, password.map(|p| (p, None))).await?,
                true,
            ),
        };
        Ok((subject, scope.external(subject)?, created))
    }

    /// The organization `name` whose Party the token key `label` registers, rooted solely in
    /// `founder`'s Party and created by `idp.org.create` with `founder` as its first owner
    /// (TN-5, OP-153 m.3 (b)). The realm root grants the founder's Party `idp.org.create`, and
    /// the founder's device key `device` signs the creation on that holding; found, not made
    /// again.
    async fn organization(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug): (Digest, &HsmSigner, &str),
        (founder, founder_party, device): ([u8; 16], Id, &str),
        (label, name): (&str, &str),
    ) -> Result<Id, BootstrapError> {
        let key = token_key(self.hsm, label)?;
        let party = root_party(&key.public_key());
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let found = t.org_by_party(party.0).await?;
        t.commit().await?;
        if found.is_some() {
            return Ok(party);
        }
        let w = Moment::at(server_time(self.app).await?);
        let register = Payload::PartyRegister {
            party,
            root: Root::Sole(founder_party),
            actor_kind: ActorKind::Organization,
        };
        let nonce = register_nonce(&root_challenge(&key, domain)?);
        let intent =
            self_signed_intent(&register, party, w.validity).ok_or(BootstrapError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
        let ais = sign(
            &key,
            &w.statement(domain, &nonce, digest, bootstrap_basis(&domain)),
        )?;
        self.lead(domain).await?;
        admin
            .register_organization(
                (tenant, realm),
                founder,
                party,
                key.public_key(),
                (
                    SelfSigned {
                        nonce,
                        validity: w.validity,
                        ais,
                    },
                    context(),
                ),
            )
            .await?;
        // TN-5, OP-153 m.3 (b), §13.4 G54
        let held = self
            .screen_grant((domain, root, slug), founder_party, IdpAction::OrgCreate)
            .await?;
        let device = token_key(self.hsm, device)?;
        self.change_as(
            admin,
            (tenant, realm),
            (&device, ExerciseBasis::Holding(held)),
            (
                Change::OrgCreate(OrgCreate {
                    party: party.0,
                    display_name: String::from(name),
                }),
                Some(founder),
            ),
        )
        .await?;
        Ok(party)
    }

    /// The root's Grant to `holder` of `action` over the realm's `idp` resources, on the realm's
    /// `idp` Anchor: what makes a console screen's eligibility check answer for the test user
    /// (IA-5, OP-157 m.3 (h), (w)), or lets a founder create its organization; its holding.
    async fn screen_grant(
        &self,
        (domain, root, slug): (Digest, &HsmSigner, &str),
        holder: Id,
        action: IdpAction,
    ) -> Result<access_kernel::meta::HoldingRef, BootstrapError> {
        let idp = meta::object_id(&domain, meta::kind::ANCHOR, IDP_ANCHOR);
        let mut content = super::grant_of(
            &domain,
            holder,
            authority(
                BTreeSet::from([action.action_ref()]),
                RESOURCE_NAMESPACE,
                BTreeSet::new(),
            ),
        );
        content.basis = GrantBasis::Anchor(idp);
        content.authority.authority.resource = realm_resources(slug);
        let mut label = SCREEN_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&holder.0);
        label.extend_from_slice(action.action_ref().name.as_bytes());
        self.granted_on(
            domain,
            root,
            &label,
            (content, ExerciseBasis::Anchor(idp)),
            holder,
        )
        .await
    }

    /// The support operator of `s` (OP-157 m.3 (c)–(f), m.6 (i)): an active account with a
    /// password, a device Party, its name, and its support organization with it as owner; the
    /// case system registered by `idp.support.case_system_register` with its own issuer Party;
    /// and the case system's signed Claim that `person`'s case is open, admitted through Claim
    /// Ingest under the Acceptance the realm's Genesis or the root's time-locked
    /// `acceptance_establish` set up. The operator can then ask `person` for support access.
    #[expect(
        clippy::too_many_lines,
        reason = "one operator, its organization, its case system and the open case, in order"
    )]
    pub(super) async fn support_operator(
        &self,
        admin: &Admin<'_, P, P, K>,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug): (Digest, &HsmSigner, &str),
        s: &SupportOperatorPlan,
        person: Id,
    ) -> Result<SupportOperatorOut, BootstrapError> {
        let (subject, external, created) = self
            .account(ids, (tenant, realm), &s.identifier, Some(&s.password))
            .await?;
        if created {
            let vault = RealmKeks::new(Arc::clone(self.hsm))
                .vault(realm)
                .ok_or_else(|| BootstrapError::Unavailable(String::from("PII vault keys")))?;
            let mut t = TenantTx::begin(self.app, tenant, realm).await?;
            access_identity_account::app::vault::set_profile(
                &mut t,
                &vault,
                subject,
                "name",
                &s.display_name,
            )
            .await?;
            t.commit().await?;
        }
        let (party, _) = self
            .device_party(
                (tenant, realm),
                domain,
                subject,
                (SUPPORT_DEVICE_LABEL, context()),
            )
            .await?;
        // OP-157 m.6 (f)
        let org = self
            .organization(
                admin,
                (tenant, realm),
                (domain, root, slug),
                (subject, party, SUPPORT_DEVICE_LABEL),
                (SUPPORT_ORG_LABEL, &s.organisation),
            )
            .await?;
        let (key, issuer) = self.case_system()?;
        self.register_in(tenant, realm, domain, (&key, issuer), ([0; 16], context()))
            .await?;
        // L2-CLM-3, OP-157 m.3 (e)
        let accepted = if self
            .issuer_accepts(domain, issuer, PREDICATE_INPUT, &[String::from(CASE_CLASS)])
            .await?
        {
            true
        } else {
            let mut label = b"access-bootstrap/case-acceptance:1".to_vec();
            label.extend_from_slice(&domain.0);
            self.time_locked(
                domain,
                root,
                root_party(&root.public_key()),
                &label,
                Payload::AcceptanceEstablish(case_acceptance(issuer)),
                String::from("access.support_case"),
            )
            .await?
            .state
                == "accepted"
        };
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let registered = t
            .case_systems()
            .await?
            .iter()
            .any(|c| c.name == s.case_system && c.live);
        t.commit().await?;
        if !registered {
            // OP-157 m.3 (e)
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::CaseSystem(CaseSystemChange::Register(CaseSystem {
                    name: s.case_system.clone(),
                    issuer: issuer.0,
                    provider: String::from(CASE_PROVIDER),
                    format: String::from(CASE_FORMAT),
                })),
            )
            .await?;
        }
        let case_until = if accepted {
            Some(self.open_case((domain, &key, issuer), s, person).await?)
        } else {
            None
        };
        Ok(SupportOperatorOut {
            realm: s.realm.clone(),
            identifier: s.identifier.clone(),
            subject: external,
            party: b64url_encode(&party.0),
            organisation: s.organisation.clone(),
            organisation_party: b64url_encode(&org.0),
            case_system: s.case_system.clone(),
            case_issuer: b64url_encode(&issuer.0),
            case: s.case.clone(),
            acceptance: if accepted { "accepted" } else { "pending" },
            case_until,
            created,
        })
    }

    /// The case system's Claim that `person`'s case is open (`product-seam.cddl` `support-case`,
    /// TN-73), signed by its issuer Instance and handed to Claim Ingest (CMP-8). It is issued at
    /// the start of the day and holds for [`CASE_CLAIM_MS`], so the same day's runs hand in the
    /// same Claim and a later day's run a fresh one; returns when it stops holding.
    async fn open_case(
        &self,
        (domain, key, issuer): (Digest, &HsmSigner, Id),
        s: &SupportOperatorPlan,
        person: Id,
    ) -> Result<u64, BootstrapError> {
        let case = access_kernel::digest::case_ref(&s.case_system, &s.case)
            .map_err(|_| BootstrapError::Encode)?;
        let body = Value::Map(vec![
            (Value::text("case"), Value::Bytes(case.0.to_vec())),
            (Value::text("open"), Value::Bool(true)),
            (Value::text("subject"), Value::Bytes(person.0.to_vec())),
        ]);
        let bytes = dcbor::encode(&body, Limits::CEILING).map_err(|_| BootstrapError::Encode)?;
        let tagged = dcbor::encode(
            &Value::Array(vec![Value::text(CASE_CLASS), body]),
            Limits::CEILING,
        )
        .map_err(|_| BootstrapError::Encode)?;
        let value = suiss_crypto::digest::context_digest(BODY_CONTEXT, &tagged);
        let issued_at = day_of(server_time(self.app).await?);
        let until = issued_at.saturating_add(CASE_CLAIM_MS);
        let statement = ClaimStatement {
            domain,
            issuer,
            subject: person,
            class: String::from(CASE_CLASS),
            value: Some(EqValue::Bytes(value.0.to_vec())),
            issued_at,
            validity: Window {
                from: issued_at,
                until,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        };
        let payload = statement.to_bytes().map_err(|_| BootstrapError::Encode)?;
        let claim = sign_sign1(
            key,
            thumbprint(&key.public_key()),
            CLAIM_CONTENT_TYPE,
            &payload,
        )
        .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))?;
        self.lead(domain).await?;
        match MetaExercises::claim(
            self.plane,
            ClaimSubmission {
                domain,
                carrier: Carrier::Cose,
                claim,
                body: Some(bytes),
                evidence: None,
            },
        )
        .await
        .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            ClaimVerdict::Admitted { .. } => Ok(until),
            ClaimVerdict::Quarantined { reason, .. } => Err(BootstrapError::Refused(format!(
                "support_case claim quarantined: {}",
                reason.word()
            ))),
            ClaimVerdict::Rejected { code } => Err(BootstrapError::Refused(code)),
        }
    }

    /// The break-glass account of `b` (OP-157 m.3 (h), m.10, §12.3.8): an active account with
    /// no password (it signs in only with the realm's own phishing-resistant method), a device
    /// Party, its organization with it as owner, marked by `idp.org.member_breakglass`; and two
    /// pre-issued break-glass Grants from the realm's `idp` Anchor, one to its Party and one to
    /// `person`'s, each naming a reserved action and asking for two fresh approvals from
    /// distinct Parties. `person` may also review break-glass uses, so the console offers the
    /// screen.
    pub(super) async fn breakglass_account(
        &self,
        admin: &Admin<'_, P, P, K>,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug): (Digest, &HsmSigner, &str),
        b: &BreakglassPlan,
        person: Id,
    ) -> Result<BreakglassOut, BootstrapError> {
        let (subject, external, created) = self
            .account(ids, (tenant, realm), &b.identifier, None)
            .await?;
        let (party, _) = self
            .device_party(
                (tenant, realm),
                domain,
                subject,
                (BREAKGLASS_DEVICE_LABEL, context()),
            )
            .await?;
        let org = self
            .organization(
                admin,
                (tenant, realm),
                (domain, root, slug),
                (subject, party, BREAKGLASS_DEVICE_LABEL),
                (BREAKGLASS_ORG_LABEL, &b.organisation),
            )
            .await?;
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let marked = t
            .breakglass_accounts()
            .await?
            .iter()
            .any(|a| a.subject == subject && a.org == org.0);
        t.commit().await?;
        if !marked {
            // OP-157 m.3 (h)
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::Breakglass(BreakglassMark {
                    org: org.0,
                    member: subject,
                    on: true,
                }),
            )
            .await?;
        }
        // OP-157 m.3 (h), m.10, §12.3.8 (1), TN-93
        let idp = meta::object_id(&domain, meta::kind::ANCHOR, IDP_ANCHOR);
        let contents: Vec<GrantContent> = Setup {
            basis: GrantBasis::Anchor(idp),
            holders: BTreeSet::from([party, person]),
            actions: BTreeSet::from([IdpAction::AccountMfaChange.action_ref()]),
            resource: realm_resources(slug),
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            approvals: BREAKGLASS_APPROVALS,
            approvers: None,
        }
        .grants()
        .map_err(|e| BootstrapError::Refused(String::from(e.code())))?;
        let mut grants = Vec::with_capacity(contents.len());
        for content in contents {
            let SubjectSelector::Party(holder) = content.holder else {
                return Err(BootstrapError::Encode);
            };
            let mut label = BREAKGLASS_GRANT_LABEL.to_vec();
            label.extend_from_slice(&domain.0);
            label.extend_from_slice(&holder.0);
            let held = self
                .granted_on(
                    domain,
                    root,
                    &label,
                    (content, ExerciseBasis::Anchor(idp)),
                    holder,
                )
                .await?;
            grants.push(holding_json(&held));
        }
        // IA-5, OP-157 m.3 (h)
        self.screen_grant((domain, root, slug), person, IdpAction::OrgBreakglassReview)
            .await?;
        Ok(BreakglassOut {
            realm: b.realm.clone(),
            identifier: b.identifier.clone(),
            subject: external,
            party: b64url_encode(&party.0),
            organisation: b.organisation.clone(),
            organisation_party: b64url_encode(&org.0),
            grants,
            created,
        })
    }

    /// The access review of `r` (OP-157 m.3 (w), IDP-39 (3)): `idp.review.schedule` over the
    /// manager's team, which the root signs; the test user's Grant to the sample agent is its
    /// item for the test user as manager, who may also close it, so the console offers the
    /// screen.
    pub(super) async fn review_schedule(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        (domain, root, slug): (Digest, &HsmSigner, &str),
        r: &ReviewPlan,
        manager: Id,
    ) -> Result<ReviewOut, BootstrapError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let scheduled = t.review_schedules().await?.iter().any(|x| x.name == r.name);
        t.commit().await?;
        if !scheduled {
            // OP-157 m.3 (w)
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::Review(ReviewChange::Schedule(ReviewSchedule {
                    name: r.name.clone(),
                    period_days: r.period_days,
                    scope: String::from("manager_team"),
                })),
            )
            .await?;
        }
        // IA-5, OP-157 m.3 (w)
        self.screen_grant(
            (domain, root, slug),
            manager,
            IdpAction::ReviewScheduleClose,
        )
        .await?;
        self.lead(domain).await?;
        let items = Instances::review_items(self.plane, domain, manager)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
            .len();
        Ok(ReviewOut {
            realm: r.realm.clone(),
            name: r.name.clone(),
            period_days: r.period_days,
            manager: b64url_encode(&manager.0),
            items,
            created: !scheduled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plan;

    // OP-157 m.4 (a), m.6 (i), TI-9
    #[test]
    fn a_fixture_needs_its_realm_and_what_it_stands_on() {
        let dir = std::env::temp_dir().join(format!("abs-fixtures-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let head = "platform = \"platform\"\ntenants = [\"acme\"]\n";
        for (name, section, want) in [
            (
                "support",
                "[support_operator]\nrealm = \"acme\"\ndisplay_name = \"Mehmet Y.\"\norganisation = \"Acme Support\"\nidentifier = \"support@acme.example\"\npassword_env = \"ABS_FIXTURES_UNSET\"\n",
                "the realm needs the [test_user]",
            ),
            (
                "breakglass",
                "[breakglass_account]\nrealm = \"acme\"\nidentifier = \"oncall@acme.example\"\n",
                "the realm needs the [test_user]",
            ),
            (
                "review",
                "[review_schedule]\nrealm = \"acme\"\nperiod_days = 90\n",
                "the realm needs the [test_user]",
            ),
            (
                "elsewhere",
                "[review_schedule]\nrealm = \"beta\"\nperiod_days = 90\n",
                "not one of the plan's tenants",
            ),
            (
                "short",
                "[review_schedule]\nrealm = \"acme\"\nperiod_days = 1\n",
                "the realm needs the [test_user]",
            ),
        ] {
            let path = dir.join(format!("{name}.toml"));
            std::fs::write(&path, format!("{head}{section}")).unwrap();
            let err = Plan::load(&path).unwrap_err().to_string();
            assert!(err.contains(want), "{name}: {err}");
        }
    }

    // TN-73, OP-157 m.3 (e)
    #[test]
    fn a_case_is_a_label_and_never_free_text() {
        assert!(super::case_label("4411"));
        assert!(super::case_label("INC-2026.11#7"));
        assert!(!super::case_label("Ayşe's locked account"));
        assert!(!super::case_label("-4411"));
        assert!(!super::case_label(&"9".repeat(65)));
    }
}
