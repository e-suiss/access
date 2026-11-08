//! The bootstrap of a local deployment (OP-69, OP-149 m.21): the platform tenant with its realm,
//! sample customer tenants, and platform product clients, each through the paths the identity
//! plane uses in production. Realms are created by `Admin::create_realm` (Genesis through the
//! authority plane), their root Party registers its Instance by the self-signed Exercises
//! (L0-META-7), and a platform client is an `idp.client.register` Exercise that root signs
//! (MD-14, EI-25). A sample realm can publish a product's catalog in its Genesis, and its root
//! then grants a sample subject one action by a `grant_issue` Exercise, so a product can run a
//! real eligibility check (OP-149 m.10). A sample realm can also get a test user with a
//! password and a public client to sign in with, and a Party whose unsigned `party_compromise`
//! Claims the realm accepts, for a product's end-to-end tests (OP-149 m.26 (b), (c)). Every
//! step looks for its result first, so a second run changes nothing.

pub(crate) mod local;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use access_authority_core::domain::Request;
use access_authority_core::genesis::IDP_ANCHOR;
use access_crypto::Secret;
use access_crypto::oauth::ClientKey;
use access_crypto::opaque_id::IdKey;
use access_identity_admin::AdminError;
use access_identity_admin::app::{Admin, Applied, NewRealm, Proposal};
use access_identity_admin::domain::{AuthMethod, Change, Client, ClientId, Platform, RedirectUri};
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_identity_oauth::domain::jwt::parse_jwks;
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_internal_api::approvals::CONTRIBUTION_NAMESPACE;
use access_internal_api::idp::{Unavailable, Verdict};
use access_internal_api::instances::{
    PlatformProduct, Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis,
    core_action, register_nonce, self_signed_intent,
};
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::assurance;
use access_kernel::claim::body::Class;
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::{
    self, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, CanonicalAuthority, ConstraintSet, Consumption,
    DelegationTerms, Id, Independence, ProofKind, RequirementTerm, ResourceRef, ResourceSelector,
    Structural, SubjectSelector, Window,
};
use access_kernel::schema::{ActionSchema, EffectClass, Spp};
use access_kernel::tier::Tier;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::authority::{find_nonce, server_time};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_tenant, route_by_slug};
use access_store::{Pool, StoreError, idp};
use figment::Figment;
use figment::providers::{Format, Toml};
use serde::{Deserialize, Serialize};
use suiss_crypto::pkcs11::{HsmError, HsmSigner, KeyStore};
use suiss_crypto::signer::{Signer as _, sign_sign1};

use crate::login::id_key_bytes;

/// The token label of the bootstrap root key: the founding root of every realm it creates.
pub(crate) const ROOT_LABEL: &str = "access/bootstrap/root";

/// The token label of the sample subject's key (OP-149 m.10).
pub(crate) const SUBJECT_LABEL: &str = "access/bootstrap/sample-subject";

/// What a key signs to derive its `instance_create` challenge in a domain.
const ROOT_CHALLENGE_LABEL: &[u8] = b"access-bootstrap/root-instance:1";

/// What the root signs to derive the nonce of the sample Grant's `grant_issue`.
const SAMPLE_GRANT_LABEL: &[u8] = b"access-bootstrap/sample-grant:1";

/// What the root signs to derive the nonce of the test user's Grant of the allowed action
/// (OP-149 m.29 (b), m.30 (a)); the Grant's bounds are part of it, so a Grant of another shape
/// is another Grant.
const ALLOWED_GRANT_LABEL: &[u8] = b"access-bootstrap/allowed-grant:2";

/// What the root signs to derive the nonce of the test user's Grant to contribute approvals.
const CONTRIBUTE_GRANT_LABEL: &[u8] = b"access-bootstrap/contribute-grant:1";

/// The contribution class an approval of the allowed action is (§9.14.1, L0-META-30).
const APPROVE_CLASS: &str = "approve";

/// The typed parameters of the allowed action: a ledger name and a declaration digest.
const ALLOWED_PARAMS: [(&str, &str); 2] = [("declaration", "bytes"), ("ledger", "text")];

/// The resource namespace the allowed Grant covers unless the plan names one (OP-149 m.30 (a)).
const DEFAULT_RESOURCE_NAMESPACE: &str = "work.ledger";

/// What the first path element of an allowed resource starts with unless the plan names it
/// (OP-149 m.30 (a); Work E-45 item 5).
const DEFAULT_RESOURCE_PATH_PREFIX: &str = "led_";

/// The resource path a sample eligibility check names.
const SAMPLE_PATH: &str = "sample";

/// The placement new tenants and realms are created in (OP-40).
const PLACEMENT: &str = "pool-default";

/// How long the bootstrap's intents stay valid, ms.
const VALIDITY_MS: u64 = 10 * 60 * 1000;

/// How far back an intent's validity starts, ms: the clocks of this process and the database
/// may differ a little.
const SKEW_MS: u64 = 60 * 1000;

/// Why the bootstrap stopped. What was done before stays and the next run continues.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BootstrapError {
    #[error("bootstrap plan: {0}")]
    Plan(String),
    #[error(transparent)]
    Admin(#[from] AdminError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("account: {0}")]
    Account(#[from] access_identity_account::AccountError),
    #[error("hsm: {0}")]
    Hsm(#[from] HsmError),
    #[error("the authority plane refused: {0}")]
    Refused(String),
    #[error("the authority plane is unavailable: {0}")]
    Unavailable(String),
    #[error("encoding")]
    Encode,
}

/// How realm issuers are formed.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Style {
    /// `https://<slug>.<realm_base>`, the default (TN-10).
    #[default]
    Subdomain,
    /// `https://<realm_base>/realms/<slug>`: one host for every realm.
    Path,
}

/// The bootstrap plan as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFile {
    platform: String,
    #[serde(default)]
    tenants: Vec<String>,
    #[serde(default)]
    issuer_style: Style,
    #[serde(default)]
    products: Vec<ProductFile>,
    sample: Option<SampleFile>,
    test_user: Option<TestUserFile>,
    compromise: Option<CompromiseFile>,
}

/// `[test_user]` as written: the password is never in the plan file itself unless the operator
/// wrote it there; `password_env` names the variable it is read from (OP-149 m.26 (b)).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestUserFile {
    realm: String,
    identifier: String,
    password: Option<String>,
    password_env: Option<String>,
    client_display_name: Option<String>,
    redirect_uri: String,
    breach_ranges_dir: Option<PathBuf>,
}

impl core::fmt::Debug for TestUserFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestUserFile")
            .field("realm", &self.realm)
            .field("identifier", &self.identifier)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_env", &self.password_env)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompromiseFile {
    realm: String,
}

/// A test user with a password in a sample realm, and the public client (PKCE and DPoP, no
/// secret) a headless login signs in with (OP-149 m.26 (b)).
#[derive(Clone)]
pub(crate) struct TestUserPlan {
    /// The slug of one of the plan's sample tenants.
    pub(crate) realm: String,
    /// The login identifier: an e-mail address or a user name.
    pub(crate) identifier: String,
    /// The password, from the plan or the environment variable it named.
    pub(crate) password: Secret<String>,
    /// The display name of the public client.
    pub(crate) client_display_name: String,
    /// The public client's one redirect URI.
    pub(crate) redirect_uri: RedirectUri,
    /// A local mirror of the breach ranges, when the deployment has one (IDP-3).
    pub(crate) breach_ranges_dir: Option<PathBuf>,
}

impl core::fmt::Debug for TestUserPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestUserPlan")
            .field("realm", &self.realm)
            .field("identifier", &self.identifier)
            .field("client_display_name", &self.client_display_name)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// A sample realm that accepts unsigned `party_compromise` Claims from a local declarant
/// Party, so a product's PEP can produce `party.compromised` (OP-149 m.26 (c)).
#[derive(Clone, Debug)]
pub(crate) struct CompromisePlan {
    /// The slug of one of the plan's sample tenants.
    pub(crate) realm: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleFile {
    realm: String,
    namespace: String,
    action: String,
    allowed: Option<String>,
    resource_namespace: Option<String>,
    resource_path_prefix: Option<String>,
    step_up: Option<String>,
}

/// The step-up the allowed Grant asks for beside the approval (OP-149 m.33 (c), §13.7.3,
/// §8.17.5.4): an `authentication` Claim of this level, fresh within the CT1 ceiling and bound
/// to the actor's Instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepUp {
    /// AAL2 by a phishing-resistant authenticator: the test user's passkey.
    Aal2,
}

impl StepUp {
    /// The plan's word for it.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Aal2 => "aal2",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "aal2" => Some(Self::Aal2),
            _ => None,
        }
    }

    /// The `authentication` requirement of this step-up: the Kernel's CT1 term (phishing-resistant,
    /// fresh within 15 minutes, bound to the actor Instance) at this AAL.
    fn term(self) -> RequirementTerm {
        let mut term = assurance::authentication_term(Tier::Ct1, false);
        match self {
            Self::Aal2 => {
                term.assurance.insert(String::from("aal"), 2);
            }
        }
        term
    }
}

/// A sample catalog and Grant for a product's eligibility checks (OP-149 m.10): the realm's
/// Genesis publishes `action` in `namespace`, and its root grants it over the whole namespace
/// to the sample subject. With `allowed`, the Genesis also publishes that exact-intent action
/// (CT1, a ledger and a declaration digest), and the root grants it to the test user's Party
/// under an approval requirement, with the Grant to contribute that approval (OP-149 m.29 (b)).
/// That Grant covers the resources of `resource_namespace` whose first path element starts
/// with `resource_path_prefix` (OP-149 m.30 (a)). With `step_up`, the Grant also asks for the
/// actor's fresh authentication at that level (OP-149 m.33 (c)).
#[derive(Clone, Debug)]
pub(crate) struct SamplePlan {
    /// The slug of one of the plan's sample tenants.
    pub(crate) realm: String,
    /// The catalog's namespace, such as `work`.
    pub(crate) namespace: String,
    /// The action's name.
    pub(crate) action: String,
    /// The allowed action's name, when the test user gets one.
    pub(crate) allowed: Option<String>,
    /// The resource namespace of the allowed Grant, such as `work.ledger`.
    pub(crate) resource_namespace: String,
    /// What the first path element of an allowed resource starts with, such as `led_`.
    pub(crate) resource_path_prefix: String,
    /// The step-up the allowed Grant asks for beside the approval.
    pub(crate) step_up: Option<StepUp>,
}

/// An authority over `actions` on the whole `namespace`, for good, with `requirements`.
fn authority(
    actions: BTreeSet<ActionRef>,
    namespace: &str,
    requirements: BTreeSet<RequirementTerm>,
) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: actions,
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from(namespace),
                prefix: Vec::new(),
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth: 0,
            downstream_holder_class: None,
        },
        requirements,
    }
}

/// A Grant of `authority` to `holder` on the meta-anchor, in its own capacity.
fn grant_of(domain: &Digest, holder: Id, authority: CanonicalAuthority) -> GrantContent {
    GrantContent {
        basis: GrantBasis::Anchor(meta::meta_anchor(domain)),
        holder: SubjectSelector::Party(holder),
        authority,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    }
}

/// The requirement an Exercise of the allowed action meets with one `approve` contribution
/// bound to its intent (§9.14.1, OP-141 m.19).
fn approval_term() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(APPROVE_CLASS),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

impl SamplePlan {
    /// The plan's `[sample]` section, checked: the realm is one of `tenants`, the catalog entry
    /// is valid and outside the planes' namespaces (OP-141 m.35 (a)), the allowed action has a
    /// test user in the same realm (OP-149 m.29 (b)), and a resource of the allowed shape is a
    /// valid Kernel resource outside the planes' namespaces (OP-149 m.30 (a)).
    fn from_file(
        s: SampleFile,
        tenants: &[String],
        test_user: Option<&TestUserFile>,
    ) -> Result<Self, BootstrapError> {
        if !tenants.contains(&s.realm) {
            return Err(BootstrapError::Plan(format!(
                "sample realm {} is not one of the plan's tenants",
                s.realm
            )));
        }
        let step_up = match s.step_up.as_deref() {
            None => None,
            Some(word) => Some(StepUp::parse(word).ok_or_else(|| {
                BootstrapError::Plan(format!("sample.step_up {word} is not a known level"))
            })?),
        };
        if step_up.is_some() && s.allowed.is_none() {
            return Err(BootstrapError::Plan(String::from(
                "sample.step_up needs sample.allowed",
            )));
        }
        let sample = Self {
            realm: s.realm,
            namespace: s.namespace,
            action: s.action,
            allowed: s.allowed,
            resource_namespace: s
                .resource_namespace
                .unwrap_or_else(|| String::from(DEFAULT_RESOURCE_NAMESPACE)),
            resource_path_prefix: s
                .resource_path_prefix
                .unwrap_or_else(|| String::from(DEFAULT_RESOURCE_PATH_PREFIX)),
            step_up,
        };
        let catalog = sample.catalog(Id([0; 16]));
        if Spp::from_value(&catalog.to_value()).as_ref() != Ok(&catalog)
            || sample.namespace == meta::NAMESPACE
            || sample.namespace.starts_with("idp.")
            || sample.allowed.as_deref() == Some(sample.action.as_str())
        {
            return Err(BootstrapError::Plan(String::from(
                "the sample namespace or action is not a valid catalog entry",
            )));
        }
        if sample.allowed.is_some() && test_user.is_none_or(|u| u.realm != sample.realm) {
            return Err(BootstrapError::Plan(String::from(
                "sample.allowed needs a test_user in the sample realm",
            )));
        }
        let resource = sample.allowed_resource("x");
        if ResourceRef::from_value(&resource.to_value()).as_ref() != Ok(&resource)
            || sample.resource_path_prefix.is_empty()
            || sample.resource_namespace == meta::NAMESPACE
            || sample.resource_namespace == "idp"
            || sample.resource_namespace.starts_with("idp.")
        {
            return Err(BootstrapError::Plan(String::from(
                "the sample resource namespace or path prefix is not a valid resource",
            )));
        }
        Ok(sample)
    }

    /// The Action Schema of `name`: version 1, reversible (CT1), with `params`.
    fn schema_of(name: &str, params: &[(&str, &str)]) -> ActionSchema {
        ActionSchema {
            name: String::from(name),
            major: 1,
            effect: EffectClass::Reversible,
            reserved: false,
            consumption_bearing: false,
            params: params
                .iter()
                .map(|(k, v)| (String::from(*k), String::from(*v)))
                .collect(),
            resource_types: BTreeSet::new(),
            render: None,
        }
    }

    /// The Action Schema of the sample action: version 1, reversible, no parameters.
    fn schema(&self) -> ActionSchema {
        Self::schema_of(&self.action, &[])
    }

    /// The Action Schema of the allowed action.
    fn allowed_schema(&self) -> Option<ActionSchema> {
        self.allowed
            .as_deref()
            .map(|name| Self::schema_of(name, &ALLOWED_PARAMS))
    }

    /// The catalog `publisher` publishes in the realm's Genesis.
    fn catalog(&self, publisher: Id) -> Spp {
        Spp {
            publisher,
            namespace: self.namespace.clone(),
            catalog_version: 1,
            actions: std::iter::once(self.schema())
                .chain(self.allowed_schema())
                .collect(),
            retirements: BTreeSet::new(),
            core_spec_min: None,
        }
    }

    fn reference(&self, schema: &ActionSchema) -> ActionRef {
        ActionRef {
            namespace: self.namespace.clone(),
            name: schema.name.clone(),
            major: 1,
            schema: access_kernel::schema::action_digest(schema),
        }
    }

    /// The sample action's reference.
    fn action_ref(&self) -> ActionRef {
        self.reference(&self.schema())
    }

    /// The allowed action's reference.
    fn allowed_ref(&self) -> Option<ActionRef> {
        self.allowed_schema().map(|s| self.reference(&s))
    }

    /// The Grant of the action over the whole namespace to `holder`, on the meta-anchor.
    fn grant(&self, domain: &Digest, holder: Id) -> GrantContent {
        grant_of(
            domain,
            holder,
            authority(
                BTreeSet::from([self.action_ref()]),
                &self.namespace,
                BTreeSet::new(),
            ),
        )
    }

    /// The Grant of the allowed action to `holder` over the allowed resources, met only with an
    /// approval and, when the plan asks for a step-up, the actor's fresh authentication at that
    /// level (OP-149 m.33 (c)). A structural selector matches path prefixes at segment
    /// boundaries (OP-109 m.2), so the Grant covers the whole resource namespace; the path
    /// prefix is what the summary tells products to write (OP-149 m.30 (a)).
    fn allowed_grant(&self, domain: &Digest, holder: Id) -> Option<GrantContent> {
        let requirements = std::iter::once(approval_term())
            .chain(self.step_up.map(StepUp::term))
            .collect();
        Some(grant_of(
            domain,
            holder,
            authority(
                BTreeSet::from([self.allowed_ref()?]),
                &self.resource_namespace,
                requirements,
            ),
        ))
    }

    /// A resource an Exercise of the allowed action may name: `rest` after the allowed prefix.
    fn allowed_resource(&self, rest: &str) -> ResourceRef {
        ResourceRef {
            namespace: self.resource_namespace.clone(),
            path: vec![format!("{}{rest}", self.resource_path_prefix)],
            incarnation: 0,
        }
    }

    /// What the summary says the allowed Grant covers (OP-149 m.30 (a)).
    fn allowed_resource_json(&self) -> serde_json::Value {
        serde_json::json!({
            "namespace": self.resource_namespace,
            "path_prefix": self.resource_path_prefix,
        })
    }

    /// The Grant to contribute `approve` approvals to `holder` (L0-META-30).
    fn contribute_grant(domain: &Digest, holder: Id) -> GrantContent {
        grant_of(
            domain,
            holder,
            authority(
                BTreeSet::from([core_action("contribute")]),
                CONTRIBUTION_NAMESPACE,
                BTreeSet::new(),
            ),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductFile {
    product: String,
    display_name: Option<String>,
    client_key: PathBuf,
    service_key: PathBuf,
    event_receiver: Option<String>,
    redirect_uri: Option<String>,
    redirect_uris: Option<Vec<String>>,
}

impl ProductFile {
    /// The product's return addresses (OP-149 m.35): `redirect_uris`, or the one `redirect_uri`
    /// of an older plan; exactly one of the two keys, at least one address, no repeats, each
    /// `https` or a loopback `http` (RFC 8252).
    fn redirect_uris(&self) -> Result<Vec<RedirectUri>, BootstrapError> {
        let listed = match (&self.redirect_uri, &self.redirect_uris) {
            (Some(one), None) => std::slice::from_ref(one),
            (None, Some(list)) => list.as_slice(),
            _ => {
                return Err(BootstrapError::Plan(format!(
                    "product {} names exactly one of redirect_uri and redirect_uris",
                    self.product
                )));
            }
        };
        if listed.is_empty() {
            return Err(BootstrapError::Plan(format!(
                "product {} needs at least one redirect URI",
                self.product
            )));
        }
        let mut uris = Vec::with_capacity(listed.len());
        for uri in listed {
            let parsed =
                RedirectUri::parse(uri).map_err(|e| BootstrapError::Plan(e.to_string()))?;
            if uris.contains(&parsed) {
                return Err(BootstrapError::Plan(format!(
                    "product {} repeats the redirect URI {uri}",
                    self.product
                )));
            }
            uris.push(parsed);
        }
        Ok(uris)
    }
}

/// A platform product client to register.
#[derive(Clone, Debug)]
pub(crate) struct ProductPlan {
    pub(crate) product: PlatformProduct,
    pub(crate) display_name: String,
    /// The P-256 key its `private_key_jwt` assertions are verified with (OP-149 m.20).
    pub(crate) client_key: PublicKey,
    /// Its service Instance key in each paired tenant (OP-149 m.4).
    pub(crate) service_key: PublicKey,
    pub(crate) event_receiver: Option<String>,
    /// Its return addresses, exactly as the Approval Surface and the authorization server
    /// match them (RFC 6749 §3.1.2; OP-149 m.33 (d), m.35).
    pub(crate) redirect_uris: Vec<RedirectUri>,
}

/// What the bootstrap creates.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    /// The platform tenant's realm slug.
    pub(crate) platform: String,
    /// One sample customer tenant per slug.
    pub(crate) tenants: Vec<String>,
    pub(crate) style: Style,
    pub(crate) products: Vec<ProductPlan>,
    pub(crate) sample: Option<SamplePlan>,
    pub(crate) test_user: Option<TestUserPlan>,
    pub(crate) compromise: Option<CompromisePlan>,
}

/// One of the plan's sample tenants, or a plan error naming the section.
fn sample_tenant(tenants: &[String], section: &str, realm: &str) -> Result<(), BootstrapError> {
    if tenants.iter().any(|t| t == realm) {
        Ok(())
    } else {
        Err(BootstrapError::Plan(format!(
            "{section} realm {realm} is not one of the plan's tenants"
        )))
    }
}

/// The test user's password: the plan's literal, or the environment variable the plan names
/// (OP-149 m.26 (b)); never a default.
fn test_password(file: &TestUserFile) -> Result<Secret<String>, BootstrapError> {
    let plan = |what: &str| BootstrapError::Plan(format!("test_user: {what}"));
    let raw = match (&file.password, &file.password_env) {
        (Some(p), None) => p.clone(),
        (None, Some(var)) => {
            std::env::var(var).map_err(|_| plan(&format!("password_env {var} is not set")))?
        }
        _ => return Err(plan("exactly one of password and password_env is required")),
    };
    if raw.is_empty() {
        return Err(plan("the password is empty"));
    }
    Ok(Secret::new(raw))
}

/// One public key from a file holding a JWK or a one-key JWKS.
fn jwk(path: &Path) -> Result<PublicKey, BootstrapError> {
    let bad = |what: &str| BootstrapError::Plan(format!("{}: {what}", path.display()));
    let text = std::fs::read_to_string(path).map_err(|e| bad(&e.to_string()))?;
    let keys = parse_jwks(text.as_bytes())
        .or_else(|_| parse_jwks(format!(r#"{{"keys":[{text}]}}"#).as_bytes()))
        .map_err(|_| bad("not a public JWK"))?;
    match keys.as_slice() {
        [one] => match &one.key {
            ClientKey::P256(sec1) => Ok(PublicKey::P256(sec1.clone())),
            ClientKey::Ed25519(x) => Ok(PublicKey::Ed25519(*x)),
            ClientKey::Rsa { .. } => Err(bad("an EC P-256 or OKP Ed25519 key is required")),
        },
        _ => Err(bad("exactly one key is required")),
    }
}

impl Plan {
    /// Reads the plan at `path` and the key files it names; before the lockdown.
    pub(crate) fn load(path: &Path) -> Result<Self, BootstrapError> {
        let file: PlanFile = Figment::from(Toml::file_exact(path))
            .extract()
            .map_err(|e| BootstrapError::Plan(e.to_string()))?;
        let mut products = Vec::new();
        for p in file.products {
            let product = PlatformProduct::parse(&p.product).ok_or_else(|| {
                BootstrapError::Plan(format!(
                    "product name {} does not match {}",
                    p.product,
                    PlatformProduct::GRAMMAR
                ))
            })?;
            let redirect_uris = p.redirect_uris()?;
            products.push(ProductPlan {
                display_name: p.display_name.unwrap_or_else(|| product.name().to_owned()),
                product,
                client_key: jwk(&p.client_key)?,
                service_key: jwk(&p.service_key)?,
                event_receiver: p.event_receiver,
                redirect_uris,
            });
        }
        let sample = match file.sample {
            None => None,
            Some(s) => Some(SamplePlan::from_file(
                s,
                &file.tenants,
                file.test_user.as_ref(),
            )?),
        };
        let test_user = match file.test_user {
            None => None,
            Some(u) => {
                sample_tenant(&file.tenants, "test_user", &u.realm)?;
                let password = test_password(&u)?;
                Some(TestUserPlan {
                    realm: u.realm,
                    identifier: u.identifier,
                    password,
                    client_display_name: u
                        .client_display_name
                        .unwrap_or_else(|| String::from("Local test client")),
                    redirect_uri: RedirectUri::parse(&u.redirect_uri)
                        .map_err(|e| BootstrapError::Plan(e.to_string()))?,
                    breach_ranges_dir: u.breach_ranges_dir,
                })
            }
        };
        let compromise = match file.compromise {
            None => None,
            Some(c) => {
                sample_tenant(&file.tenants, "compromise", &c.realm)?;
                Some(CompromisePlan { realm: c.realm })
            }
        };
        Ok(Self {
            platform: file.platform,
            tenants: file.tenants,
            style: file.issuer_style,
            products,
            sample,
            test_user,
            compromise,
        })
    }
}

impl ProductPlan {
    /// The platform client registration of this product (OP-149 m.4), as the
    /// `idp.client.register` Exercise checks it.
    pub(crate) fn client(&self, id: ClientId) -> Client {
        Client {
            id,
            display_name: self.display_name.clone(),
            auth: AuthMethod::PrivateKeyJwtKey {
                key: self.client_key.clone(),
            },
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            platform: Some(Platform {
                product: self.product.clone(),
                service_key: self.service_key.clone(),
                event_receiver: self.event_receiver.clone(),
            }),
            require_par: false,
            subject: access_identity_admin::domain::Subject::default(),
        }
    }
}

/// A realm the bootstrap made sure of.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RealmOut {
    /// The tenant's opaque `tnt_` id (OP-149 m.15 (i)).
    pub(crate) tenant: String,
    /// The realm, a UUID (OP-149 m.19 (b)).
    pub(crate) realm: String,
    pub(crate) slug: String,
    pub(crate) issuer: String,
    /// The Suiss discovery document (OP-149 m.3).
    pub(crate) discovery: String,
    /// The governing domain, base64url (OP-149 m.16 (f)).
    pub(crate) domain: String,
    /// Whether this is the platform tenant.
    pub(crate) platform: bool,
    /// Whether this run created it.
    pub(crate) created: bool,
}

/// A platform client the bootstrap made sure of.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ClientOut {
    pub(crate) product: String,
    pub(crate) client_id: String,
    /// The `aud` of its client assertions: the platform realm's issuer (OP-149 m.19 (e)).
    pub(crate) audience: String,
    /// Its registered return addresses, as the plan names them (OP-149 m.35); the Approval
    /// Surface of every realm matches a pushed request's `redirect_uri` against them exactly.
    pub(crate) redirect_uris: Vec<String>,
    /// The first of them, for readers of older summaries.
    pub(crate) redirect_uri: String,
    /// Whether this run registered it.
    pub(crate) created: bool,
}

/// The founding root of the bootstrapped realms.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct RootOut {
    /// The Party, base64url.
    pub(crate) party: String,
    /// Its Instance key's RFC 7638 thumbprint, base64url (CR-24).
    pub(crate) kid: String,
}

/// What a product's eligibility check names to be answered `eligible` (OP-149 m.10), in the
/// ADP JSON encoding (base64url ids and digests).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SampleOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// Its governing domain: `set.domain`.
    pub(crate) domain: String,
    /// The sample subject's Party: the check's `subject`.
    pub(crate) subject: String,
    /// The granted action: `set.intent.action`.
    pub(crate) action: serde_json::Value,
    /// A resource the Grant covers: an entry of `set.intent.resources`.
    pub(crate) resource: serde_json::Value,
    /// The subject's holding of the Grant: `set.basis`.
    pub(crate) basis: serde_json::Value,
}

/// The test user and the public client a headless login uses (OP-149 m.26 (b)).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TestUserOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The realm's issuer: `/authorize` and `/token` hang under it.
    pub(crate) issuer: String,
    /// The login identifier.
    pub(crate) identifier: String,
    /// The subject's external id (`usr_…`).
    pub(crate) subject: String,
    /// The public client's `client_id`.
    pub(crate) client_id: String,
    /// Its registered redirect URI.
    pub(crate) redirect_uri: String,
    /// The Party the user's device Instances belong to, base64url (OP-149 m.28 (b)); what
    /// `subjects:resolve` answers for the user's pairwise `sub`.
    pub(crate) party: String,
    /// The user's device Instance in the realm's governing domain, base64url.
    pub(crate) instance: String,
    /// The credential id of the user's software passkey, base64url (OP-149 m.26 (e)).
    pub(crate) passkey: String,
    /// The allowed Exercise the user's Party holds, when the sample names one (OP-149 m.29
    /// (b)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allowed: Option<AllowedOut>,
    /// Whether this run created the account.
    pub(crate) created: bool,
}

/// What a product's Exercise of the allowed action names (OP-149 m.29 (b)), in the ADP JSON
/// encoding: the action, the shape of the resources the Grant covers, the typed parameters, the
/// test user's holding as `basis`, and the holding its approval is contributed under.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct AllowedOut {
    /// The governing domain, base64url.
    pub(crate) domain: String,
    /// The allowed action: `intent.action`.
    pub(crate) action: serde_json::Value,
    /// The resources the Grant covers: their `namespace` and the `path_prefix` their first path
    /// element starts with; an entry of `intent.resources` is
    /// `{namespace, path: ["<path_prefix>…", …]}` (OP-149 m.30 (a)).
    pub(crate) resource: serde_json::Value,
    /// The action's typed parameters, name to type.
    pub(crate) params: serde_json::Value,
    /// The Party's holding of the Grant: `basis`.
    pub(crate) basis: serde_json::Value,
    /// The approval the Exercise needs: its class and the Party's basis for contributing it.
    pub(crate) contribution: ContributionOut,
    /// The step-up the Exercise needs beside the approval, when the plan asks for one: the
    /// first commit's `REQUIRE_ACTION` then also leaves an `authentication` term unmet, and the
    /// approval's Claim meets it (OP-149 m.33 (c)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) step_up: Option<&'static str>,
}

/// The approval a product's Exercise of the allowed action waits for.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ContributionOut {
    /// The contribute class.
    pub(crate) class: &'static str,
    /// The Party's holding of the Grant over `access/contribute`: the contribution's `basis`.
    pub(crate) basis: serde_json::Value,
}

/// What an unsigned `party_compromise` Claim names to be admitted in the sample realm
/// (OP-149 m.26 (c)): the issuer Party the realm accepts, over the PEP channel.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct CompromiseOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// Its governing domain, base64url.
    pub(crate) domain: String,
    /// The accepted issuer Party, base64url.
    pub(crate) issuer: String,
    /// The accepted class.
    pub(crate) class: &'static str,
    /// Whether this run established the Acceptance.
    pub(crate) created: bool,
}

/// What a product needs from the bootstrap.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Summary {
    /// The version of this summary's shape.
    pub(crate) v: u8,
    pub(crate) root: RootOut,
    pub(crate) realms: Vec<RealmOut>,
    pub(crate) clients: Vec<ClientOut>,
    /// Present when the plan names a sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sample: Option<SampleOut>,
    /// Present when the plan names a test user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) test_user: Option<TestUserOut>,
    /// Present when the plan names a compromise declarant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) compromise: Option<CompromiseOut>,
}

/// Meta-actions the bootstrap's keys sign, committed by the authority plane with the identity
/// plane as PEP (EI-25), on a domain this process leads.
pub(crate) trait MetaExercises: Send + Sync {
    /// Commits `request` with the actor's `ais` as `pep`.
    fn meta(
        &self,
        request: Request,
        ais: Vec<u8>,
        pep: String,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;

    /// Leads `domain` in this process before a commit (OP-149 m.28 (a)): a `serve` process
    /// holding its lease is asked to hand it over, and this waits for the release.
    fn lead(&self, domain: Digest) -> impl Future<Output = Result<(), Unavailable>> + Send;
}

/// The ports and stores the bootstrap runs over.
pub(crate) struct Bootstrap<'a, P, K> {
    /// `access_app`.
    pub(crate) app: &'a Pool,
    /// `access_router`.
    pub(crate) router: &'a Pool,
    /// The authority plane: Genesis, decisions and self-signed registrations.
    pub(crate) plane: &'a P,
    /// Realms' keys outside the database.
    pub(crate) realm_keys: &'a K,
    /// The server's token: the root key, the cell's opaque-id root and the realms' KEKs.
    pub(crate) hsm: &'a Arc<KeyStore>,
    /// Where realm issuers are formed.
    pub(crate) base: &'a RealmBase,
    /// The operator's declared delivery targets (OP-149 m.23).
    pub(crate) declared: &'a DeclaredTargets,
    /// The management origin, `suiss.management_api`: every realm gets the console's client
    /// with its callback there (OP-151 m.12 (b)); `None` registers none.
    pub(crate) console: Option<&'a str>,
}

/// The cell's opaque-id key; its root is made by the path the server starts with (OP-137,
/// OP-149 m.22 (g)).
async fn cell_ids(app: &Pool, hsm: &KeyStore) -> Result<IdKey, BootstrapError> {
    crate::ids::open_root(app, hsm)
        .await
        .map_err(BootstrapError::Unavailable)?;
    let bytes = id_key_bytes(hsm).map_err(BootstrapError::Unavailable)?;
    Ok(IdKey::new(Secret::new(bytes)))
}

/// The bootstrap key `label`, made in the token once.
fn token_key(hsm: &KeyStore, label: &str) -> Result<HsmSigner, BootstrapError> {
    Ok(match hsm.signer(label) {
        Ok(s) => s,
        Err(_) => hsm.generate_ed25519(label)?,
    })
}

/// The bootstrap root key, made in the token once.
fn root_key(hsm: &KeyStore) -> Result<HsmSigner, BootstrapError> {
    token_key(hsm, ROOT_LABEL)
}

/// A bootstrap key's Party: the first half of its thumbprint, so every run names the same one.
fn root_party(key: &PublicKey) -> Id {
    let t = thumbprint(key);
    let mut id = [0; 16];
    id.copy_from_slice(t.get(..16).unwrap_or(&[0; 16]));
    Id(id)
}

/// The issuer style of the plan as the admin forms it.
const fn issuer_style(style: Style) -> IssuerStyle {
    match style {
        Style::Subdomain => IssuerStyle::Subdomain,
        Style::Path => IssuerStyle::Path,
    }
}

/// What a sample realm's Genesis accepts beyond the catalogs: the local declarant's
/// `party_compromise` Claims (OP-149 m.26 (c)) and, with an allowed action, the realm issuer's
/// `authentication` Claims as predicate input, which a hosted approval proves with (OP-149 m.29
/// (b), SI-5).
fn genesis_acceptances(
    catalog: Option<&SamplePlan>,
    declarant: Option<Id>,
) -> (Vec<suiss_crypto::dcbor::Value>, Vec<String>) {
    (
        declarant
            .map(|issuer| vec![local::acceptance(issuer)])
            .unwrap_or_default(),
        catalog
            .filter(|s| s.allowed.is_some())
            .map(|_| vec![Class::Authentication.name()])
            .unwrap_or_default(),
    )
}

/// An action reference in the ADP JSON encoding.
fn action_json(action: &ActionRef) -> serde_json::Value {
    serde_json::json!({
        "namespace": action.namespace,
        "name": action.name,
        "major": action.major,
        "schema": b64url_encode(&action.schema.0),
    })
}

/// The sample resource of `namespace` in the ADP JSON encoding.
fn resource_json(namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "namespace": namespace,
        "path": [SAMPLE_PATH],
    })
}

/// A holding basis in the ADP JSON encoding.
fn holding_json(h: &HoldingRef) -> serde_json::Value {
    serde_json::json!({
        "holding": {
            "grant": b64url_encode(&h.grant.0),
            "holder": b64url_encode(&h.holder.0),
            "since": h.since,
        }
    })
}

/// The summary's line for a realm.
fn realm_out(
    ids: &IdKey,
    (tenant, realm, domain): (TenantId, RealmId, Digest),
    slug: &str,
    issuer: String,
    (platform, created): (bool, bool),
) -> Result<RealmOut, BootstrapError> {
    Ok(RealmOut {
        tenant: ids
            .encode(TENANT_PREFIX, *tenant.as_bytes())
            .map_err(AdminError::from)?,
        realm: uuid(realm.as_bytes()),
        slug: String::from(slug),
        discovery: format!("{issuer}/.well-known/suiss-configuration"),
        issuer,
        domain: b64url_encode(&domain.0),
        platform,
        created,
    })
}

/// A UUID's hyphenated text.
pub(crate) fn uuid(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// The AIS `root` signs over `s` (`COSE_Sign1`, L2-SIG-1).
/// The root's `instance_create` challenge in `domain`: the SHA-256 of the root's Ed25519
/// signature over a label and the domain. Ed25519 signing is deterministic (RFC 8032), so a
/// second run finds the same nonce, and nobody without the root key can predict it.
fn root_challenge(root: &HsmSigner, domain: Digest) -> Result<Vec<u8>, BootstrapError> {
    let mut message = ROOT_CHALLENGE_LABEL.to_vec();
    message.extend_from_slice(&domain.0);
    let signature = root
        .sign(&message)
        .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))?;
    Ok(suiss_crypto::digest::sha256(&signature).to_vec())
}

fn sign(root: &HsmSigner, s: &Statement) -> Result<Vec<u8>, BootstrapError> {
    let payload = s.to_bytes().map_err(|_| BootstrapError::Encode)?;
    sign_sign1(root, thumbprint(&root.public_key()), CONTENT_TYPE, &payload)
        .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))
}

/// A key's Instance in a domain, registered by its own Exercises or found registered.
pub(crate) struct Onboarded {
    /// The Instance.
    pub(crate) instance: Id,
    /// The key's self-signed `party_register` AIS: the evidence an identity binding names by
    /// digest (OP-150 m.12 (d)).
    pub(crate) register_ais: Vec<u8>,
}

/// The server time of a step and the validity of what it signs.
struct Moment {
    now: u64,
    validity: Window,
}

impl Moment {
    fn at(now: u64) -> Self {
        Self {
            now,
            validity: Window {
                from: now.saturating_sub(SKEW_MS),
                until: now.saturating_add(VALIDITY_MS),
            },
        }
    }

    fn statement(
        &self,
        domain: Digest,
        nonce: &[u8],
        intent: Digest,
        basis: ExerciseBasis,
    ) -> Statement {
        Statement {
            domain,
            nonce: nonce.to_vec(),
            intent,
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: self.now,
            exercise: None,
        }
    }
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// Makes sure of everything `plan` names and reports it.
    ///
    /// # Errors
    /// [`BootstrapError`]; what was done stays.
    pub(crate) async fn run(&self, plan: &Plan) -> Result<Summary, BootstrapError> {
        let ids = cell_ids(self.app, self.hsm).await?;
        let root = root_key(self.hsm)?;
        let key = root.public_key();
        let party = root_party(&key);
        let style = issuer_style(plan.style);
        let mut realms = Vec::new();
        let slugs =
            std::iter::once((&plan.platform, true)).chain(plan.tenants.iter().map(|s| (s, false)));
        let mut platform = None;
        let mut sample = None;
        let mut test_user = None;
        let mut compromise = None;
        // OP-149 m.26 (c): the declarant is accepted at the realm's Genesis
        let declarant = match &plan.compromise {
            Some(_) => Some(self.declarant()?),
            None => None,
        };
        for (slug, is_platform) in slugs {
            let admin = self.admin(&ids, None);
            let catalog = plan
                .sample
                .as_ref()
                .filter(|s| !is_platform && s.realm == *slug);
            let accepted = plan
                .compromise
                .as_ref()
                .filter(|c| !is_platform && c.realm == *slug)
                .zip(declarant.as_ref());
            let (tenant, realm, domain, created) = self
                .realm(
                    &admin,
                    slug,
                    style,
                    party,
                    // OP-151 m.2 M2: only the platform realm's domain decides provisioning
                    if is_platform {
                        vec![access_identity_admin::domain::provision::catalog(party)]
                    } else {
                        catalog.map(|s| vec![s.catalog(party)]).unwrap_or_default()
                    },
                    genesis_acceptances(catalog, accepted.map(|(_, (_, issuer))| *issuer)),
                )
                .await?;
            self.onboard(tenant, realm, domain, &root, party).await?;
            // OP-151 m.12 (b)
            if let Some(origin) = self.console {
                self.console_client(&admin, (tenant, realm), domain, &root, origin)
                    .await?;
            }
            if let Some(s) = catalog {
                sample = Some(self.sample(s, (tenant, realm), domain, &root).await?);
            }
            let route = route_by_slug(self.router, slug)
                .await?
                .ok_or(AdminError::NoRealm)?;
            if is_platform {
                platform = Some((tenant, realm, domain, route.issuer.clone()));
            }
            // OP-149 m.26 (b), (c), m.29 (b)
            if let Some(u) = plan.test_user.as_ref().filter(|u| u.realm == *slug) {
                let (mut out, party) = self
                    .test_user(&admin, &ids, (tenant, realm), domain, &root, u)
                    .await?;
                out.issuer = route.issuer.clone();
                out.allowed = match catalog.filter(|s| s.allowed.is_some()) {
                    Some(s) => Some(self.allowed_exercise(s, domain, party, &root).await?),
                    None => None,
                };
                test_user = Some(out);
            }
            if let Some((c, (key, issuer))) = accepted {
                compromise = Some(
                    self.compromise(c, (tenant, realm), domain, key, *issuer, created)
                        .await?,
                );
            }
            realms.push(realm_out(
                &ids,
                (tenant, realm, domain),
                slug,
                route.issuer,
                (is_platform, created),
            )?);
        }
        let clients = self.clients(plan, &ids, &root, platform).await?;
        Ok(Summary {
            v: 1,
            root: RootOut {
                party: b64url_encode(&party.0),
                kid: b64url_encode(&thumbprint(&key)),
            },
            realms,
            clients,
            sample,
            test_user,
            compromise,
        })
    }

    /// The platform clients of the plan's products in the platform realm (OP-149 m.4).
    async fn clients(
        &self,
        plan: &Plan,
        ids: &IdKey,
        root: &HsmSigner,
        platform: Option<(TenantId, RealmId, Digest, String)>,
    ) -> Result<Vec<ClientOut>, BootstrapError> {
        let mut clients = Vec::new();
        if let Some((tenant, realm, domain, issuer)) = platform {
            let admin = self.admin(ids, Some(tenant));
            for p in &plan.products {
                let (client_id, created) = self
                    .client(&admin, (tenant, realm), domain, root, p)
                    .await?;
                let redirect_uris: Vec<String> = p
                    .redirect_uris
                    .iter()
                    .map(|u| String::from(u.as_str()))
                    .collect();
                clients.push(ClientOut {
                    product: p.product.name().to_owned(),
                    client_id,
                    audience: issuer.clone(),
                    redirect_uri: redirect_uris.first().cloned().unwrap_or_default(),
                    redirect_uris,
                    created,
                });
            }
        }
        Ok(clients)
    }

    /// The sample subject in the sample realm and its Grant of the sample action, issued by a
    /// `grant_issue` Exercise the root signs when its nonce has no ALLOW yet (OP-149 m.10).
    async fn sample(
        &self,
        s: &SamplePlan,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
    ) -> Result<SampleOut, BootstrapError> {
        let subject_key = token_key(self.hsm, SUBJECT_LABEL)?;
        let subject = root_party(&subject_key.public_key());
        self.onboard(tenant, realm, domain, &subject_key, subject)
            .await?;
        let action = s.action_ref();
        let mut label = SAMPLE_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&subject.0);
        label.extend_from_slice(&action.schema.0);
        let holding = self
            .granted(domain, root, &label, s.grant(&domain, subject), subject)
            .await?;
        Ok(SampleOut {
            realm: s.realm.clone(),
            domain: b64url_encode(&domain.0),
            subject: b64url_encode(&subject.0),
            action: action_json(&action),
            resource: resource_json(&s.namespace),
            basis: holding_json(&holding),
        })
    }

    /// The test user's Grant of the allowed action and its Grant to contribute the approval the
    /// action needs, each issued by a `grant_issue` Exercise the root signs when its nonce has no
    /// ALLOW yet (OP-149 m.29 (b)); the summary names both holdings.
    async fn allowed_exercise(
        &self,
        s: &SamplePlan,
        domain: Digest,
        party: Id,
        root: &HsmSigner,
    ) -> Result<AllowedOut, BootstrapError> {
        let action = s.allowed_ref().ok_or(BootstrapError::Encode)?;
        let grant = s
            .allowed_grant(&domain, party)
            .ok_or(BootstrapError::Encode)?;
        let mut label = ALLOWED_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&party.0);
        label.extend_from_slice(&action.schema.0);
        label.extend_from_slice(&meta::bounds_digest(&grant.authority).0);
        let holding = self.granted(domain, root, &label, grant, party).await?;
        let mut label = CONTRIBUTE_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&party.0);
        let contribute = self
            .granted(
                domain,
                root,
                &label,
                SamplePlan::contribute_grant(&domain, party),
                party,
            )
            .await?;
        Ok(AllowedOut {
            domain: b64url_encode(&domain.0),
            action: action_json(&action),
            resource: s.allowed_resource_json(),
            params: serde_json::Value::Object(
                ALLOWED_PARAMS
                    .iter()
                    .map(|(k, v)| (String::from(*k), serde_json::Value::from(*v)))
                    .collect(),
            ),
            basis: holding_json(&holding),
            contribution: ContributionOut {
                class: APPROVE_CLASS,
                basis: holding_json(&contribute),
            },
            step_up: s.step_up.map(StepUp::word),
        })
    }

    /// The holding of the Grant `content` issued to `party` by a `grant_issue` on the
    /// meta-anchor, signed by the root under the nonce derived from `label`; committed when
    /// that nonce has no ALLOW yet. Ed25519 signing is deterministic (RFC 8032), so every run
    /// derives the same nonce, and nobody without the root key can predict it.
    async fn granted(
        &self,
        domain: Digest,
        root: &HsmSigner,
        label: &[u8],
        content: GrantContent,
        party: Id,
    ) -> Result<HoldingRef, BootstrapError> {
        let signature = root
            .sign(label)
            .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))?;
        let nonce = suiss_crypto::digest::sha256(&signature).to_vec();
        let found = find_nonce(self.app, &DomainId::from_bytes(domain.0), &nonce)
            .await?
            .filter(|n| n.outcome == "allow");
        let since = match found {
            Some(row) => row.decision_pos,
            None => {
                self.commit_meta(domain, root, &nonce, Payload::GrantIssue(content), party)
                    .await?
            }
        };
        let exercise = meta::exercise_id(&domain, &nonce).map_err(|_| BootstrapError::Encode)?;
        Ok(HoldingRef {
            grant: meta::object_id(&exercise, kind::GRANT, 0),
            holder: party,
            since,
        })
    }

    /// Commits the meta-action `payload` about `party` on the meta-anchor, signed by the root;
    /// returns its record's position.
    async fn commit_meta(
        &self,
        domain: Digest,
        root: &HsmSigner,
        nonce: &[u8],
        payload: Payload,
        party: Id,
    ) -> Result<u64, BootstrapError> {
        self.lead(domain).await?;
        let w = Moment::at(server_time(self.app).await?);
        let intent =
            self_signed_intent(&payload, party, w.validity).ok_or(BootstrapError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
        let ais = sign(root, &w.statement(domain, nonce, digest, basis))?;
        let request = Request {
            domain,
            mode: Mode::Commit,
            nonce: nonce.to_vec(),
            intent,
            payload: Some(payload),
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        match MetaExercises::meta(self.plane, request, ais, String::from(IDENTITY_PEP))
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            Verdict::Committed(c) => Ok(c.position),
            Verdict::Refused { code, .. } => Err(BootstrapError::Refused(code)),
            Verdict::NotAllowed { decision, .. } => {
                Err(BootstrapError::Refused(format!("{:?}", decision.outcome)))
            }
        }
    }

    /// Leads `domain` in this process before a commit (OP-149 m.28 (a)); a `serve` process
    /// holding its lease hands it over.
    async fn lead(&self, domain: Digest) -> Result<(), BootstrapError> {
        MetaExercises::lead(self.plane, domain)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))
    }

    fn admin<'b>(&'b self, ids: &'b IdKey, platform: Option<TenantId>) -> Admin<'b, P, P, K> {
        Admin {
            app: self.app,
            ids,
            decider: self.plane,
            governance: self.plane,
            pep: IDENTITY_PEP,
            base: self.base,
            keys: self.realm_keys,
            platform_tenant: platform,
            declared: self.declared.clone(),
            vault: None,
        }
    }

    /// The live realm `slug`, created in a new tenant with `root` as its founding root when
    /// there is none (TN-111). Its keys outside the database are opened every time: a step
    /// that failed after the realm was written is repeated (OP-146 m.16 (m)).
    async fn realm(
        &self,
        admin: &Admin<'_, P, P, K>,
        slug: &str,
        style: IssuerStyle,
        root: Id,
        schemas: Vec<Spp>,
        (acceptances, issuer_predicate_input): (Vec<suiss_crypto::dcbor::Value>, Vec<String>),
    ) -> Result<(TenantId, RealmId, Digest, bool), BootstrapError> {
        if let Some(route) = route_by_slug(self.router, slug).await? {
            let mut t = TenantTx::begin(self.app, route.tenant, route.realm).await?;
            let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
            t.commit().await?;
            admin.open_keys(route.tenant, route.realm).await?;
            return Ok((
                route.tenant,
                route.realm,
                Digest(*g.domain.as_bytes()),
                false,
            ));
        }
        let tenant = create_tenant(self.app, PLACEMENT).await?;
        let created = admin
            .create_realm(&NewRealm {
                tenant,
                slug,
                style,
                placement: PLACEMENT,
                root: Root::Sole(root),
                ct3_delay_s: None,
                schemas,
                acceptances,
                issuer_predicate_input,
                provisioned_by: None,
            })
            .await?;
        Ok((tenant, created.realm, created.domain, true))
    }

    /// Whether `nonce` is a recorded ALLOW in `domain`.
    async fn allowed(&self, domain: Digest, nonce: &[u8]) -> Result<bool, BootstrapError> {
        let row = find_nonce(self.app, &DomainId::from_bytes(domain.0), nonce).await?;
        Ok(row.is_some_and(|n| n.outcome == "allow"))
    }

    /// The Instance of the bootstrap key `root` in `domain`: `party_register` when the Party is
    /// new, then `instance_create`, both signed by that key under the bootstrap Grant
    /// (L0-META-7, OP-149 m.16 (a)). A recorded ALLOW of a step is not repeated.
    async fn onboard(
        &self,
        tenant: TenantId,
        realm: RealmId,
        domain: Digest,
        root: &HsmSigner,
        party: Id,
    ) -> Result<(), BootstrapError> {
        self.register(tenant, realm, domain, root, party, [0; 16])
            .await
            .map(|_| ())
    }

    /// The Instance of `key` in `domain` as the device of `subject` (zero for a key that is
    /// nobody's device): `party_register` when the Party is new, then `instance_create`, both
    /// signed by that key under the bootstrap Grant (L0-META-7, OP-149 m.16 (a)). A recorded
    /// ALLOW of a step is not repeated; the Instance is the same on every run, as its
    /// challenge is.
    async fn register(
        &self,
        tenant: TenantId,
        realm: RealmId,
        domain: Digest,
        key: &HsmSigner,
        party: Id,
        subject: [u8; 16],
    ) -> Result<Onboarded, BootstrapError> {
        let challenge = root_challenge(key, domain)?;
        let w = Moment::at(server_time(self.app).await?);
        let mut r = Registration {
            tenant: *tenant.as_bytes(),
            domain,
            registrant: Registrant::Device {
                realm: *realm.as_bytes(),
                subject,
            },
            party,
            key: key.public_key(),
            register: None,
            create: SelfSigned {
                nonce: challenge.clone(),
                validity: w.validity,
                ais: Vec::new(),
            },
            pep: String::from(IDENTITY_PEP),
            context: None,
        };
        let instance = r.instance().ok_or(BootstrapError::Encode)?;
        let signed = |nonce: &[u8], payload: &meta::Payload| -> Result<Vec<u8>, BootstrapError> {
            let intent =
                self_signed_intent(payload, party, w.validity).ok_or(BootstrapError::Encode)?;
            let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
            sign(
                key,
                &w.statement(domain, nonce, digest, bootstrap_basis(&domain)),
            )
        };
        let register = register_nonce(&challenge);
        let register_ais = signed(&register, &r.register_payload())?;
        if self.allowed(domain, &challenge).await? {
            return Ok(Onboarded {
                instance,
                register_ais,
            });
        }
        self.lead(domain).await?;
        r.create.ais = signed(&challenge, &r.create_payload())?;
        if !self.allowed(domain, &register).await? {
            r.register = Some(SelfSigned {
                nonce: register,
                validity: w.validity,
                ais: register_ais.clone(),
            });
        }
        match Instances::register(self.plane, r)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            RegistrationVerdict::Registered(_) => Ok(Onboarded {
                instance,
                register_ais,
            }),
            RegistrationVerdict::Refused { code } => Err(BootstrapError::Refused(code)),
        }
    }

    /// The active platform client of `p` in the platform realm with its redirect URI and
    /// client key, registered by an `idp.client.register` Exercise the root signs when there is
    /// none (OP-149 m.4, MD-14, EI-25).
    async fn client(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        p: &ProductPlan,
    ) -> Result<(String, bool), BootstrapError> {
        if let Some(id) = self.find_product_client((tenant, realm), p).await? {
            return Ok((id, false));
        }
        let client = p.client(admin.new_client_id().await?);
        let id = String::from(client.id.as_str());
        self.change(
            admin,
            (tenant, realm),
            domain,
            root,
            Change::ClientRegister(client),
        )
        .await?;
        Ok((id, true))
    }

    /// The active platform client of `p` in the realm: the one with any of its redirect URIs,
    /// its product and its client key.
    async fn find_product_client(
        &self,
        (tenant, realm): (TenantId, RealmId),
        p: &ProductPlan,
    ) -> Result<Option<String>, BootstrapError> {
        let kid = b64url_encode(&thumbprint(&p.client_key));
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let mut found = None;
        'uris: for uri in &p.redirect_uris {
            for id in idp::clients_with_redirect(&mut t, uri.as_str()).await? {
                if let Some(row) = idp::client(&mut t, &id).await?
                    && row.active
                    && row.platform_product.as_deref() == Some(p.product.name())
                    && row.jwks.as_deref().is_some_and(|j| j.contains(&kid))
                {
                    found = Some(row.client_id);
                    break 'uris;
                }
            }
        }
        t.commit().await?;
        Ok(found)
    }

    /// Commits the `idp.*` change `change` in the realm as an Exercise the root signs on the
    /// realm's `idp` Anchor (MD-14, EI-25); a fresh nonce every time.
    /// The realm's console client (OP-151 m.12 (b), RFC 10017 BFF pattern): a first-party
    /// confidential client whose one redirect URI is the management origin's sign-in callback
    /// and whose `private_key_jwt` key is the server's console key in the HSM; registered by
    /// the realm's founding root through `idp.client.register` once, when the realm has no
    /// active client with that callback and key.
    async fn console_client(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        origin: &str,
    ) -> Result<(), BootstrapError> {
        use crate::console::sign_in::{CLIENT_NAME, client_key, registered};
        let callback = format!("{origin}{}", access_http::console::app::CALLBACK_PATH);
        let key = client_key(self.hsm)
            .map_err(BootstrapError::Unavailable)?
            .public_key();
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let found = registered(&mut t, &callback, &key).await?;
        t.commit().await?;
        if found.is_some() {
            return Ok(());
        }
        // OP-151 m.12 (b): an origin no client may name (a single-label host) gets no console
        // client; the console then signs no one in there
        let Ok(redirect) = RedirectUri::parse(&callback) else {
            tracing::warn!(
                event = "console.client.skipped",
                outcome = "refused",
                "management origin is not a registrable redirect URI"
            );
            return Ok(());
        };
        let client = Client {
            id: admin.new_client_id().await?,
            display_name: String::from(CLIENT_NAME),
            auth: AuthMethod::PrivateKeyJwtKey { key },
            redirect_uris: vec![redirect],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            platform: None,
            subject: access_identity_admin::domain::Subject::default(),
        };
        self.change(
            admin,
            (tenant, realm),
            domain,
            root,
            Change::ClientRegister(client),
        )
        .await
        .map(drop)
    }

    async fn change(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        change: Change,
    ) -> Result<Applied, BootstrapError> {
        let w = Moment::at(server_time(self.app).await?);
        let nonce = access_crypto::random::bytes::<16>()
            .map_err(|_| BootstrapError::Unavailable(String::from("rng")))?
            .to_vec();
        let proposal = Proposal {
            tenant,
            realm,
            change,
            nonce,
            validity: w.validity,
            basis: ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR)),
            capacity: Capacity::Own,
            subject: None,
        };
        let prepared = admin.prepare(&proposal).await?;
        self.lead(prepared.domain).await?;
        let ais = sign(
            root,
            &w.statement(
                prepared.domain,
                &proposal.nonce,
                prepared.digest,
                proposal.basis,
            ),
        )?;
        match Box::pin(admin.apply(&proposal, ais)).await? {
            Applied::NotAllowed { decision, .. } => {
                Err(BootstrapError::Refused(format!("{:?}", decision.outcome)))
            }
            applied => Ok(applied),
        }
    }
}

#[cfg(test)]
mod tests;
