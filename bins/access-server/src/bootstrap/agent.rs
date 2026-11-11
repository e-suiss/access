//! The local deployment's opt-in sample agent (OP-154 m.15 (i), OP-69): an agent Party the
//! realm root operates, registered by its own `party_register` and an `idp.agent.register` the
//! root signs with the test user as its sponsor; one Instance its runtime key opens under the
//! test user's account; a Grant the test user's device issues to it for the test user; and one
//! allowed Exercise of the sample action by that Instance. Nothing here is an executor and no
//! executor report is made: a report only comes from a running executor (E64, INV-18).

use std::collections::BTreeSet;

use access_identity_admin::app::Admin;
use access_identity_admin::domain::Change;
use access_identity_admin::domain::agent::{AgentChange, AgentKind, AgentRegister};
use access_identity_admin::ports::{
    AgentRegistration, Decider, Governance, Instances, OrgRegistered, RealmKeys,
};
use access_identity_ui::domain::frontend::IDENTITY_PEP;
use access_internal_api::idp::Verdict;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, register_nonce,
    self_signed_intent,
};
use access_kernel::ais::Statement;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{
    self, ActorKind, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
};
use access_kernel::model::{DelegationTerms, Id, ResourceRef, SubjectSelector};
use access_store::authority::{find_nonce, server_time};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp;
use access_store::scope::DomainId;
use serde::{Deserialize, Serialize};
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::Signer as _;

use super::local::TEST_DEVICE_LABEL;
use super::{
    Bootstrap, BootstrapError, MetaExercises, Moment, SAMPLE_PATH, SamplePlan, holding_json,
    root_challenge, root_party, sign, token_key,
};

/// The token label of the sample agent's key: its `party_register` signer.
pub(crate) const SAMPLE_AGENT_LABEL: &str = "access/bootstrap/sample-agent";

/// The token label of the sample agent's runtime key: its Instance's key.
pub(crate) const SAMPLE_AGENT_RUNTIME_LABEL: &str = "access/bootstrap/sample-agent-runtime";

/// The PEP name the sample agent's Exercise names: the agent asking for itself.
const SAMPLE_AGENT_PEP: &str = "access-bootstrap-sample-agent";

/// What the root signs to derive the nonce of the test user's delegable Grant for the agent.
const DELEGABLE_GRANT_LABEL: &[u8] = b"access-bootstrap/sample-agent-delegable:1";

/// What the test user's device signs to derive the nonce of its Grant to the agent.
const AGENT_GRANT_LABEL: &[u8] = b"access-bootstrap/sample-agent-grant:1";

/// What the agent's runtime key signs to derive the nonce of its sample Exercise.
const AGENT_EXERCISE_LABEL: &[u8] = b"access-bootstrap/sample-agent-exercise:1";

/// Longest display name (it is rendered as text).
const MAX_NAME: usize = 200;

/// `[sample_agent]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SampleAgentFile {
    pub(super) realm: String,
    display_name: Option<String>,
}

/// The sample agent of a realm that also has the sample catalog and the test user.
#[derive(Clone, Debug)]
pub(crate) struct SampleAgentPlan {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The name people see.
    pub(crate) display_name: String,
}

impl SampleAgentPlan {
    /// The plan's `[sample_agent]`, checked: the sample and the test user are in its realm.
    pub(super) fn from_file(
        f: SampleAgentFile,
        sample: Option<&str>,
        test_user: Option<&str>,
    ) -> Result<Self, BootstrapError> {
        let plan = |what: &str| BootstrapError::Plan(format!("sample_agent: {what}"));
        if sample != Some(f.realm.as_str()) {
            return Err(plan("the realm needs the [sample] catalog"));
        }
        if test_user != Some(f.realm.as_str()) {
            return Err(plan("the realm needs the [test_user] as its sponsor"));
        }
        let display_name = f
            .display_name
            .unwrap_or_else(|| String::from("Local sample agent"));
        if display_name.trim().is_empty() || display_name.chars().count() > MAX_NAME {
            return Err(plan("display_name is 1 to 200 characters"));
        }
        Ok(Self {
            realm: f.realm,
            display_name,
        })
    }
}

/// The sample agent in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SampleAgentOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The agent's Party, base64url.
    pub(crate) party: String,
    /// Its operator, the realm root's Party, base64url.
    pub(crate) operator: String,
    /// Its Instance, base64url.
    pub(crate) instance: String,
    /// Its holding of the test user's Grant for the test user: an Exercise's `basis`.
    pub(crate) basis: serde_json::Value,
    /// The allowed Exercise of the sample action, base64url.
    pub(crate) exercise: String,
    /// Whether this run registered it.
    pub(crate) created: bool,
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// The sample agent of `a` (OP-154 m.15 (i)); every step looks for its result first.
    pub(super) async fn sample_agent(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        (s, a): (&SamplePlan, &SampleAgentPlan),
        person: Id,
    ) -> Result<SampleAgentOut, BootstrapError> {
        let key = token_key(self.hsm, SAMPLE_AGENT_LABEL)?;
        let party = root_party(&key.public_key());
        let operator = root_party(&root.public_key());
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let sponsor = idp::party_subject(&mut t, &person.0)
            .await?
            .ok_or_else(|| BootstrapError::Plan(String::from("sample_agent: no test user")))?;
        let registered = t.agent(party.0).await?.is_some();
        t.commit().await?;
        if !registered {
            self.register_sample_agent((tenant, domain), &key, party, operator)
                .await?;
            // OP-154 m.3 (c), AG-41
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::Agent(AgentChange::Register(AgentRegister {
                    party: party.0,
                    operator: operator.0,
                    kind: AgentKind::Cloud,
                    display_name: a.display_name.clone(),
                    description: None,
                    sponsors: vec![sponsor],
                })),
            )
            .await?;
        }
        let instance = self
            .agent_instance((tenant, realm), domain, party, sponsor)
            .await?;
        let held = self.agent_grant(domain, root, s, (person, party)).await?;
        let exercise = self.agent_exercise(domain, s, held, person).await?;
        Ok(SampleAgentOut {
            realm: a.realm.clone(),
            party: b64url_encode(&party.0),
            operator: b64url_encode(&operator.0),
            instance: b64url_encode(&instance.0),
            basis: holding_json(&held),
            exercise: b64url_encode(&exercise.0),
            created: !registered,
        })
    }

    /// The agent Party's own `party_register`, its key signing for it (L0-META-7).
    async fn register_sample_agent(
        &self,
        (tenant, domain): (TenantId, Digest),
        key: &HsmSigner,
        party: Id,
        operator: Id,
    ) -> Result<(), BootstrapError> {
        let w = Moment::at(server_time(self.app).await?);
        let register = Payload::PartyRegister {
            party,
            root: Root::Sole(operator),
            actor_kind: ActorKind::Agent,
        };
        let nonce = register_nonce(&root_challenge(key, domain)?);
        let intent =
            self_signed_intent(&register, party, w.validity).ok_or(BootstrapError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
        let ais = sign(
            key,
            &w.statement(domain, &nonce, digest, bootstrap_basis(&domain)),
        )?;
        self.lead(domain).await?;
        match self
            .plane
            .register_agent(AgentRegistration {
                tenant: *tenant.as_bytes(),
                domain,
                party,
                operator,
                key: key.public_key(),
                register: SelfSigned {
                    ais,
                    nonce,
                    validity: w.validity,
                },
                pep: String::from(IDENTITY_PEP),
            })
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            OrgRegistered::Registered { .. } => Ok(()),
            OrgRegistered::Refused { code } => Err(BootstrapError::Refused(code)),
        }
    }

    /// The agent's live Instance, opened by its runtime key under the sponsor's account when it
    /// has none (OP-154 m.3 (c)).
    async fn agent_instance(
        &self,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        party: Id,
        sponsor: [u8; 16],
    ) -> Result<Id, BootstrapError> {
        let live = Instances::instances(self.plane, domain, party)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?;
        if let Some(i) = live.first() {
            return Ok(*i);
        }
        let runtime = token_key(self.hsm, SAMPLE_AGENT_RUNTIME_LABEL)?;
        let w = Moment::at(server_time(self.app).await?);
        let challenge = root_challenge(&runtime, domain)?;
        let mut r = Registration {
            tenant: *tenant.as_bytes(),
            domain,
            registrant: Registrant::Device {
                realm: *realm.as_bytes(),
                subject: sponsor,
            },
            party,
            key: runtime.public_key(),
            register: None,
            create: SelfSigned {
                nonce: challenge.clone(),
                validity: w.validity,
                ais: Vec::new(),
            },
            pep: String::from(IDENTITY_PEP),
            context: None,
        };
        let intent = self_signed_intent(&r.create_payload(), party, w.validity)
            .ok_or(BootstrapError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
        r.create.ais = sign(
            &runtime,
            &w.statement(domain, &challenge, digest, bootstrap_basis(&domain)),
        )?;
        self.lead(domain).await?;
        match Instances::register(self.plane, r)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            RegistrationVerdict::Registered(done) => Ok(done.instance),
            RegistrationVerdict::Refused { code, .. } => Err(BootstrapError::Refused(code)),
        }
    }

    /// The test user's Grant of the sample action to the agent for the test user (INV-4): the
    /// root's delegable Grant to the test user, then the test user's device issuing on it.
    async fn agent_grant(
        &self,
        domain: Digest,
        root: &HsmSigner,
        s: &SamplePlan,
        (person, agent): (Id, Id),
    ) -> Result<HoldingRef, BootstrapError> {
        let mut delegable = s.grant(&domain, person);
        delegable.authority.delegation = DelegationTerms {
            depth: 1,
            downstream_holder_class: Some(SubjectSelector::Party(agent)),
        };
        let mut onward = delegable.authority.clone();
        onward.delegation.depth = 0;
        let mut label = DELEGABLE_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&person.0);
        label.extend_from_slice(&agent.0);
        let parent = self
            .granted(domain, root, &label, delegable, person)
            .await?;
        let device = token_key(self.hsm, TEST_DEVICE_LABEL)?;
        let mut label = AGENT_GRANT_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        label.extend_from_slice(&agent.0);
        let content = GrantContent {
            basis: GrantBasis::Holding(parent),
            holder: SubjectSelector::Party(agent),
            authority: onward,
            agency: BTreeSet::from([Capacity::For(person)]),
            named: None,
        };
        let (exercise, since) = self
            .committed(
                domain,
                (&device, ExerciseBasis::Holding(parent), &label),
                (Some(Payload::GrantIssue(content)), None),
                (IDENTITY_PEP, Capacity::Own, agent),
            )
            .await?;
        Ok(HoldingRef {
            grant: meta::object_id(&exercise, kind::GRANT, 0),
            holder: agent,
            since,
        })
    }

    /// The agent Instance's allowed Exercise of the sample action for the test user.
    async fn agent_exercise(
        &self,
        domain: Digest,
        s: &SamplePlan,
        held: HoldingRef,
        person: Id,
    ) -> Result<Digest, BootstrapError> {
        let runtime = token_key(self.hsm, SAMPLE_AGENT_RUNTIME_LABEL)?;
        let w = Moment::at(server_time(self.app).await?);
        let intent = IntentEnvelope {
            provenance: std::collections::BTreeMap::new(),
            action: s.action_ref(),
            resources: vec![ResourceRef {
                namespace: s.namespace.clone(),
                path: vec![String::from(SAMPLE_PATH)],
                incarnation: 0,
            }],
            params: std::collections::BTreeMap::new(),
            opaque: std::collections::BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: w.validity,
        };
        let mut label = AGENT_EXERCISE_LABEL.to_vec();
        label.extend_from_slice(&domain.0);
        let (exercise, _) = self
            .committed(
                domain,
                (&runtime, ExerciseBasis::Holding(held), &label),
                (None, Some(intent)),
                (SAMPLE_AGENT_PEP, Capacity::For(person), held.holder),
            )
            .await?;
        Ok(exercise)
    }

    /// The Exercise `key` signs on `basis` under the nonce derived from `label`, committed when
    /// that nonce has no ALLOW yet: a meta-action `payload` about `about` (its self-signed
    /// intent), or `intent` itself; its id and its record's position.
    async fn committed(
        &self,
        domain: Digest,
        (key, basis, label): (&HsmSigner, ExerciseBasis, &[u8]),
        (payload, intent): (Option<Payload>, Option<IntentEnvelope>),
        (pep, capacity, about): (&str, Capacity, Id),
    ) -> Result<(Digest, u64), BootstrapError> {
        let signature = key
            .sign(label)
            .map_err(|e| BootstrapError::Unavailable(String::from(e.code())))?;
        let nonce = suiss_crypto::digest::sha256(&signature).to_vec();
        let exercise = meta::exercise_id(&domain, &nonce).map_err(|_| BootstrapError::Encode)?;
        if let Some(row) = find_nonce(self.app, &DomainId::from_bytes(domain.0), &nonce)
            .await?
            .filter(|n| n.outcome == "allow")
        {
            return Ok((exercise, row.decision_pos));
        }
        let w = Moment::at(server_time(self.app).await?);
        let intent = match (&payload, intent) {
            (Some(p), _) => {
                self_signed_intent(p, about, w.validity).ok_or(BootstrapError::Encode)?
            }
            (None, Some(i)) => i,
            (None, None) => return Err(BootstrapError::Encode),
        };
        let digest = intent_digest(&intent).map_err(|_| BootstrapError::Encode)?;
        let ais = sign(
            key,
            &Statement {
                domain,
                nonce: nonce.clone(),
                intent: digest,
                mode: Mode::Commit,
                pep: String::from(pep),
                capacity,
                basis,
                iat: w.now,
                exercise: None,
            },
        )?;
        self.lead(domain).await?;
        let request = access_authority_core::domain::Request {
            domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload,
            basis,
            capacity,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        };
        match MetaExercises::meta(self.plane, request, ais, String::from(pep))
            .await
            .map_err(|e| BootstrapError::Unavailable(e.0))?
        {
            Verdict::Committed(c) => Ok((c.exercise, c.position)),
            Verdict::Refused { code, .. } => Err(BootstrapError::Refused(code)),
            Verdict::NotAllowed { decision, .. } => {
                Err(BootstrapError::Refused(format!("{:?}", decision.outcome)))
            }
        }
    }
}
