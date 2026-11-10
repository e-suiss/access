//! The product twin (§7.9.10.3, E16, E24, PI-14): a domain product as a third party builds it.
//! It registers its own Party and Instance by pairing (OP-149 m.4, m.16 (a)), publishes its
//! action namespace (L1-ADP-18), issues predicate, lifecycle and effect Claims as its own issuer
//! (CMP-8), asks Access before each of its effects and applies only a verified ALLOW (§9.5,
//! X21). It never writes an Anchor, a Grant or an Acceptance: [`Twin::attempt`] exists so a
//! test can show that such a write by a product is refused like anyone else's.

use std::collections::BTreeMap;
use std::sync::Mutex;

use access_kernel::ais::{CONTENT_TYPE as AIS_CONTENT_TYPE, Statement};
use access_kernel::claim::{
    CONTENT_TYPE as CLAIM_CONTENT_TYPE, Statement as ClaimStatement, claim_id,
};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, PAYLOAD_PARAM, Payload, core_action};
use access_kernel::model::{EqValue, Id, ResourceRef, Window};
use access_kernel::verify::cose::parse_sign1;
use access_kernel::verify::key_scope::{DomainMetadata, thumbprint};
use access_sdk::authorize::{
    Actor, Ask, AskDecision, Authorized, Denied, ExerciseRequest, Intent, Nonce, Pep, adp_body,
};
use access_sdk::transport::{Answer, Clock, FixedClock};
use serde_json::{Value as Json, json};
use suiss_crypto::signer::{Signer as _, SoftSigner, sign_sign1};

use crate::schema::Schema;
use crate::wire::{self, Call, Method, Wire};

/// How long the twin's own intents stay valid, ms.
const VALIDITY_MS: u64 = 10 * 60 * 1000;

/// How far back an intent's validity starts, ms: this process's clock and Access's may differ.
const SKEW_MS: u64 = 60 * 1000;

/// How long a client assertion lives, s (RFC 7523).
const ASSERTION_S: u64 = 60;

/// The resource namespace of a Party's own meta-actions (L0-META-7).
const PARTY_NAMESPACE: &str = "access.party";

/// Why a twin call did not complete. A refusal by Access is a value, not this error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TwinError {
    /// No answer, no time, no randomness or no key: nothing happened.
    #[error("unavailable: {0}")]
    Unavailable(&'static str),
    /// Access refused the call with a problem.
    #[error("refused {status}: {code}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The problem's `code`.
        code: String,
    },
    /// An answer the twin cannot read.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The twin is not paired in that domain.
    #[error("not paired")]
    NotPaired,
}

/// Randomness.
pub trait Random: Send + Sync {
    /// `n` fresh bytes; `None` when there are none.
    fn bytes(&self, n: usize) -> Option<Vec<u8>>;
}

/// What the twin is: its platform client and its PEP name.
#[derive(Clone, Debug)]
pub struct Config {
    /// Its platform client id (OP-149 m.4).
    pub client_id: String,
    /// The `aud` of its client assertions: the platform realm's issuer (OP-149 m.19 (e)).
    pub audience: String,
    /// Its PEP name: what its client certificate authenticates as (L1-ADP-2).
    pub pep: String,
}

/// The twin's keys; neither ever leaves it.
pub struct Keys {
    /// Its Ed25519 service key: its Instance key in every paired domain, which signs its
    /// pairing Exercises, its Claims and its own statements.
    pub service: SoftSigner,
    /// Its ES256 client key, which signs its client assertions.
    pub client: SoftSigner,
}

/// The twin in one domain after pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paired {
    /// The domain.
    pub domain: Digest,
    /// The product's own Party in it.
    pub party: Id,
    /// Its Instance.
    pub instance: Id,
    /// The registration basis the domain named: the Public bootstrap Grant (L0-META-7).
    pub basis: ExerciseBasis,
}

/// What a publish answered (L1-ADP-18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The package fingerprint a domain names when it accepts it.
    pub fingerprint: Digest,
    /// Whether this call kept it.
    pub new: bool,
}

/// One Claim to issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// About whom.
    pub subject: Id,
    /// Its class: one of the product schema's Claim classes.
    pub class: String,
    /// Its value.
    pub value: Option<EqValue>,
    /// How long it holds, ms from now.
    pub for_ms: u64,
    /// The resource it is about, when it is about one.
    pub resource: Option<ResourceRef>,
}

/// What Claim Ingest did with a Claim (CMP-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The Claim's id.
    pub claim: Id,
    /// `admit` or `quarantine`.
    pub disposition: String,
    /// Why it was quarantined.
    pub reason: Option<String>,
    /// The position it was recorded at.
    pub position: Option<u64>,
    /// The signed Claim, for a request to carry (L1-ADP-12).
    pub sign1: Vec<u8>,
}

/// One effect the twin asks about, on behalf of the actor whose statement it forwards.
#[derive(Clone, Debug)]
pub struct Request {
    /// The actor's Actor Intent Statement, exactly as signed.
    pub ais: Vec<u8>,
    /// The intent.
    pub envelope: IntentEnvelope,
    /// The nonce the statement names.
    pub nonce: Vec<u8>,
    /// The basis the statement names.
    pub basis: ExerciseBasis,
    /// The capacity the statement names.
    pub capacity: Capacity,
    /// Claims the twin presents as proofs (L1-ADP-12).
    pub proofs: Vec<Proof>,
}

/// A Claim the twin presents with a request (L1-ADP-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    /// A Claim the domain recorded, by id.
    Recorded(Id),
    /// A signed Claim, carried whole: the domain admits it, or not, by its own Acceptances.
    Carried(Vec<u8>),
}

/// How Access answered a write a product must not make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// HTTP status.
    pub status: u16,
    /// `decision`, when the body was a decision.
    pub decision: Option<bool>,
    /// `context.outcome`, when present.
    pub outcome: Option<String>,
    /// The problem's `code`, when it was one.
    pub code: Option<String>,
}

impl Attempt {
    /// Whether the write took effect.
    #[must_use]
    pub fn took_effect(&self) -> bool {
        self.status == 200 && self.decision == Some(true)
    }
}

struct Prefetched(Answer);

impl AskDecision for Prefetched {
    fn ask(&self, _: &ExerciseRequest<'_>) -> Answer {
        self.0.clone()
    }
}

/// A product twin over wire `W`, clock `C` and randomness `R`.
pub struct Twin<W, C, R> {
    config: Config,
    keys: Keys,
    wire: W,
    clock: C,
    random: R,
    paired: Mutex<BTreeMap<[u8; 32], Paired>>,
    metadata: Mutex<BTreeMap<[u8; 32], DomainMetadata>>,
}

fn json_of(answer: &Answer) -> Option<(u16, Json)> {
    match answer {
        Answer::Response(r) => {
            let v = if r.body.is_empty() {
                Json::Null
            } else {
                serde_json::from_slice(&r.body).ok()?
            };
            Some((r.status, v))
        }
        Answer::Unanswered(_) => None,
    }
}

fn refused(status: u16, v: &Json) -> TwinError {
    TwinError::Refused {
        status,
        code: v
            .get("code")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
    }
}

fn b64_member(v: &Json, k: &str) -> Option<Vec<u8>> {
    v.get(k)
        .and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
}

fn id_member(v: &Json, k: &str) -> Option<Id> {
    <[u8; 16]>::try_from(b64_member(v, k)?.as_slice())
        .ok()
        .map(Id)
}

fn digest_member(v: &Json, k: &str) -> Option<Digest> {
    <[u8; 32]>::try_from(b64_member(v, k)?.as_slice())
        .ok()
        .map(Digest)
}

/// Sets `key` of an ADP body's `context`.
fn in_context(body: &mut Json, key: &str, value: Json) -> Option<()> {
    body.get_mut("context")?
        .as_object_mut()?
        .insert(String::from(key), value);
    Some(())
}

/// `v` with every object's members in name order, whatever order the map keeps.
fn sorted(v: &Json) -> Json {
    match v {
        Json::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            Json::Object(
                keys.into_iter()
                    .filter_map(|k| m.get(k).map(|x| (k.clone(), sorted(x))))
                    .collect(),
            )
        }
        Json::Array(items) => Json::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// `SHA-256("access/schema-package/v1" ‖ 0x00 ‖ JSON(package))`, members sorted by name: what
/// a publish intent's `opaque.package` names (L1-ADP-18).
#[must_use]
pub fn package_digest(package: &Json) -> Digest {
    let bytes = serde_json::to_vec(&sorted(package)).unwrap_or_default();
    Digest(suiss_crypto::digest::context_digest("access/schema-package/v1", &bytes).0)
}

fn hex(id: &Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The intent of a meta-action `payload` about `party` (L0-META-7): `access/<action>` on
/// `access.party:[party]` with the payload's digest as `opaque.payload`.
#[must_use]
pub fn meta_intent(payload: &Payload, party: Id, validity: Window) -> Option<IntentEnvelope> {
    Some(IntentEnvelope {
        provenance: BTreeMap::new(),
        action: core_action(payload.action()),
        resources: vec![ResourceRef {
            namespace: String::from(PARTY_NAMESPACE),
            path: vec![hex(&party)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from(PAYLOAD_PARAM), payload.digest().ok()?)]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}

impl<W: Wire, C: Clock + Send + Sync, R: Random> Twin<W, C, R> {
    /// A twin with `config` and `keys` over `wire`, `clock` and `random`; paired nowhere yet.
    pub fn new(config: Config, keys: Keys, (wire, clock, random): (W, C, R)) -> Self {
        Self {
            config,
            keys,
            wire,
            clock,
            random,
            paired: Mutex::new(BTreeMap::new()),
            metadata: Mutex::new(BTreeMap::new()),
        }
    }

    /// Its PEP name.
    #[must_use]
    pub fn pep(&self) -> &str {
        &self.config.pep
    }

    /// Where it is paired in `domain`.
    ///
    /// # Errors
    /// [`TwinError::NotPaired`].
    pub fn paired(&self, domain: &Digest) -> Result<Paired, TwinError> {
        self.paired
            .lock()
            .map_err(|_| TwinError::Unavailable("lock"))?
            .get(&domain.0)
            .copied()
            .ok_or(TwinError::NotPaired)
    }

    fn now(&self) -> Result<u64, TwinError> {
        self.clock.now().ok_or(TwinError::Unavailable("clock"))
    }

    fn random(&self, n: usize) -> Result<Vec<u8>, TwinError> {
        self.random
            .bytes(n)
            .filter(|b| b.len() == n)
            .ok_or(TwinError::Unavailable("random"))
    }

    fn window(&self) -> Result<Window, TwinError> {
        let now = self.now()?;
        Ok(Window {
            from: now.saturating_sub(SKEW_MS),
            until: now.saturating_add(VALIDITY_MS),
        })
    }

    /// A fresh `private_key_jwt` client assertion (RFC 7523) for its platform client.
    fn assertion(&self) -> Result<String, TwinError> {
        let now_s = self.now()? / 1000;
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = json!({
            "iss": self.config.client_id,
            "sub": self.config.client_id,
            "aud": self.config.audience,
            "iat": now_s,
            "exp": now_s.saturating_add(ASSERTION_S),
            "jti": b64url_encode(&self.random(16)?),
        })
        .to_string();
        let input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(payload.as_bytes())
        );
        let sig = self
            .keys
            .client
            .sign(input.as_bytes())
            .map_err(|_| TwinError::Unavailable("sign"))?;
        Ok(format!("{input}.{}", b64url_encode(&sig)))
    }

    /// The service key's signature over statement `s` (CR-24).
    fn sign_statement(&self, s: &Statement) -> Result<Vec<u8>, TwinError> {
        let bytes = s
            .to_bytes()
            .map_err(|_| TwinError::Malformed("statement"))?;
        sign_sign1(
            &self.keys.service,
            thumbprint(&self.keys.service.public_key()),
            AIS_CONTENT_TYPE,
            &bytes,
        )
        .map_err(|_| TwinError::Unavailable("sign"))
    }

    async fn send(&self, call: Option<Call>) -> Result<(u16, Json), TwinError> {
        let call = call.ok_or(TwinError::Malformed("call"))?;
        let answer = self.wire.send(call).await;
        json_of(&answer).ok_or(TwinError::Unavailable("access"))
    }

    /// One pairing target's signed Exercises (OP-149 m.16 (a), m.17b (e)).
    fn sign_target(&self, t: &Json, now: u64) -> Result<(Json, Paired), TwinError> {
        let bad = || TwinError::Malformed("target");
        let domain = digest_member(t, "domain").ok_or_else(bad)?;
        let basis = ExerciseBasis::Public(id_member(t, "basis").ok_or_else(bad)?);
        let party = id_member(t, "party").ok_or_else(bad)?;
        let pep = t.get("pep").and_then(Json::as_str).ok_or_else(bad)?;
        let ais = |part: &Json| -> Result<String, TwinError> {
            let s = Statement {
                domain,
                nonce: b64_member(part, "nonce").ok_or_else(bad)?,
                intent: digest_member(part, "intent").ok_or_else(bad)?,
                mode: Mode::Commit,
                pep: String::from(pep),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            };
            Ok(b64url_encode(&self.sign_statement(&s)?))
        };
        let mut out = json!({
            "realm": t.get("realm").cloned().ok_or_else(bad)?,
            "challenge": t.get("challenge").cloned().ok_or_else(bad)?,
            "ais": ais(t.get("instance_create").ok_or_else(bad)?)?,
        });
        if let Some(register) = t.get("party_register") {
            let signed = ais(register)?;
            if let Some(o) = out.as_object_mut() {
                o.insert(String::from("register_ais"), Json::String(signed));
            }
        }
        Ok((
            out,
            Paired {
                domain,
                party,
                instance: Id([0; 16]),
                basis,
            },
        ))
    }

    /// Pairs with every live realm of `tenant` (OP-149 m.4): the platform API hands out one
    /// challenge per realm and the twin signs its own `party_register` and `instance_create`
    /// with its service key. Answers the domains it is now paired in.
    ///
    /// # Errors
    /// [`TwinError`].
    pub async fn register(&self, tenant: &str) -> Result<Vec<Paired>, TwinError> {
        let mut c = wire::call(
            Method::Post,
            wire::PAIRING_CHALLENGES,
            &[("tenant", tenant)],
            Vec::new(),
        );
        if let Some(c) = c.as_mut() {
            c.bearer = Some(self.assertion()?);
        }
        let (status, v) = self.send(c).await?;
        if status != 201 {
            return Err(refused(status, &v));
        }
        let now = self.now()?;
        let mut targets = Vec::new();
        let mut pending = Vec::new();
        for t in v
            .get("targets")
            .and_then(Json::as_array)
            .ok_or(TwinError::Malformed("targets"))?
        {
            if t.get("status").and_then(Json::as_str) != Some("unpaired") {
                continue;
            }
            let (signed, paired) = self.sign_target(t, now)?;
            targets.push(signed);
            pending.push(paired);
        }
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        let mut c = wire::call(
            Method::Post,
            wire::PAIRING,
            &[("tenant", tenant)],
            json!({ "targets": targets }).to_string().into_bytes(),
        );
        if let Some(c) = c.as_mut() {
            c.bearer = Some(self.assertion()?);
        }
        let (status, v) = self.send(c).await?;
        if status != 200 {
            return Err(refused(status, &v));
        }
        let mut out = Vec::new();
        let answered = v
            .get("targets")
            .and_then(Json::as_array)
            .ok_or(TwinError::Malformed("targets"))?;
        for (t, mut p) in answered.iter().zip(pending) {
            if t.get("status").and_then(Json::as_str) != Some("paired")
                || id_member(t, "party") != Some(p.party)
            {
                return Err(TwinError::Malformed("pairing"));
            }
            p.instance = id_member(t, "instance").ok_or(TwinError::Malformed("instance"))?;
            self.paired
                .lock()
                .map_err(|_| TwinError::Unavailable("lock"))?
                .insert(p.domain.0, p);
            out.push(p);
        }
        Ok(out)
    }

    /// The twin's own statement over `envelope` in `domain` as its own PEP.
    fn own_statement(
        &self,
        p: &Paired,
        envelope: &IntentEnvelope,
        mode: Mode,
        basis: ExerciseBasis,
    ) -> Result<(Vec<u8>, Vec<u8>), TwinError> {
        let nonce = self.random(16)?;
        let s = Statement {
            domain: p.domain,
            nonce: nonce.clone(),
            intent: intent_digest(envelope).map_err(|_| TwinError::Malformed("intent"))?,
            mode,
            pep: self.config.pep.clone(),
            capacity: Capacity::Own,
            basis,
            iat: self.now()?,
            exercise: None,
        };
        Ok((self.sign_statement(&s)?, nonce))
    }

    /// The `context` member of an ADP body (L1-ADP-5).
    fn context(request: &ExerciseRequest<'_>) -> Result<Json, TwinError> {
        let body = adp_body(request).ok_or(TwinError::Malformed("body"))?;
        let v: Json = serde_json::from_str(&body).map_err(|_| TwinError::Malformed("body"))?;
        v.get("context")
            .cloned()
            .ok_or(TwinError::Malformed("context"))
    }

    /// Publishes `schema` as its own publisher, offered to `domain` (L1-ADP-18): a `check`
    /// statement over `access/publish` on `access.publication:[namespace]` names the package
    /// digest. The domain accepts it, or not, with its own Exercise; nothing here can.
    ///
    /// # Errors
    /// [`TwinError`].
    pub async fn publish_schema(
        &self,
        domain: &Digest,
        schema: &Schema,
    ) -> Result<Published, TwinError> {
        let p = self.paired(domain)?;
        let package = schema.package();
        let envelope = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: core_action("publish"),
            resources: vec![ResourceRef {
                namespace: String::from("access.publication"),
                path: vec![schema.namespace.clone()],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from("package"), package_digest(&package))]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: self.window()?,
        };
        let (ais, nonce) = self.own_statement(&p, &envelope, Mode::Check, p.basis)?;
        let digest = intent_digest(&envelope).map_err(|_| TwinError::Malformed("intent"))?;
        let actor = Actor::Statement(ais);
        let context = Self::context(&ExerciseRequest {
            domain: &p.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &actor,
            basis: &p.basis,
            capacity: Capacity::Own,
            pep: &self.config.pep,
            exercise: None,
        })?;
        let body = json!({
            "context": context,
            "package": package,
            "domains": [b64url_encode(&p.domain.0)],
        });
        let (status, v) = self
            .send(wire::call(
                Method::Post,
                wire::PUBLICATIONS,
                &[],
                body.to_string().into_bytes(),
            ))
            .await?;
        if status != 201 {
            return Err(refused(status, &v));
        }
        Ok(Published {
            fingerprint: digest_member(&v, "fingerprint")
                .ok_or(TwinError::Malformed("fingerprint"))?,
            new: v.get("new").and_then(Json::as_bool).unwrap_or(false),
        })
    }

    /// Issues one Claim in `domain` as its own issuer, signed with its Instance key (CMP-8,
    /// §7.9.10.5): the domain's Acceptance decides whether it is an input at all.
    ///
    /// # Errors
    /// [`TwinError`].
    pub async fn issue_claim(&self, domain: &Digest, issue: Issue) -> Result<Issued, TwinError> {
        let p = self.paired(domain)?;
        let claim = self.sign_claim(domain, issue)?;
        let id = claim_id(&claim);
        let body = json!({
            "domain": format!("sha-256:{}", b64url_encode(&p.domain.0)),
            "carrier": "cose",
            "claim": b64url_encode(&claim),
        });
        let mut c = wire::call(
            Method::Post,
            wire::CLAIMS_INGEST,
            &[],
            body.to_string().into_bytes(),
        );
        if let Some(c) = c.as_mut() {
            c.idempotency_key = Some(b64url_encode(&id.0));
        }
        let (status, v) = self.send(c).await?;
        if status != 200 {
            return Err(refused(status, &v));
        }
        Ok(Issued {
            claim: id,
            disposition: v
                .get("disposition")
                .and_then(Json::as_str)
                .ok_or(TwinError::Malformed("disposition"))?
                .to_owned(),
            reason: v.get("reason").and_then(Json::as_str).map(String::from),
            position: v
                .get("position")
                .and_then(Json::as_str)
                .and_then(|p| p.parse().ok()),
            sign1: claim,
        })
    }

    /// One Claim signed as its own issuer in `domain` with its Instance key, not sent
    /// (§7.9.10.5): a request may carry it whole.
    ///
    /// # Errors
    /// [`TwinError`].
    pub fn sign_claim(&self, domain: &Digest, issue: Issue) -> Result<Vec<u8>, TwinError> {
        let p = self.paired(domain)?;
        let now = self.now()?;
        let statement = ClaimStatement {
            domain: p.domain,
            issuer: p.party,
            subject: issue.subject,
            class: issue.class,
            value: issue.value,
            issued_at: now,
            validity: Window {
                from: now.saturating_sub(SKEW_MS),
                until: now.saturating_add(issue.for_ms),
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: issue.resource,
            supersedes: None,
        };
        let payload = statement
            .to_bytes()
            .map_err(|_| TwinError::Malformed("claim"))?;
        sign_sign1(
            &self.keys.service,
            thumbprint(&self.keys.service.public_key()),
            CLAIM_CONTENT_TYPE,
            &payload,
        )
        .map_err(|_| TwinError::Unavailable("sign"))
    }

    /// The domain's Domain Metadata, read once (L1-ADP-11).
    async fn metadata(&self, domain: &Digest) -> Result<DomainMetadata, TwinError> {
        if let Some(m) = self
            .metadata
            .lock()
            .map_err(|_| TwinError::Unavailable("lock"))?
            .get(&domain.0)
            .cloned()
        {
            return Ok(m);
        }
        let named = format!("sha-256:{}", b64url_encode(&domain.0));
        let c = wire::call(
            Method::Get,
            wire::DOMAIN_METADATA,
            &[("domain", &named)],
            Vec::new(),
        )
        .ok_or(TwinError::Malformed("call"))?;
        let m = match self.wire.send(c).await {
            Answer::Response(r) if r.status == 200 => parse_sign1(&r.body)
                .ok()
                .and_then(|s| s.payload)
                .and_then(|p| DomainMetadata::from_bytes(&p).ok())
                .ok_or(TwinError::Malformed("metadata"))?,
            Answer::Response(_) => return Err(TwinError::Malformed("metadata")),
            Answer::Unanswered(_) => return Err(TwinError::Unavailable("metadata")),
        };
        self.metadata
            .lock()
            .map_err(|_| TwinError::Unavailable("lock"))?
            .insert(domain.0, m.clone());
        Ok(m)
    }

    /// Asks Access about `request` in `domain` as its own PEP and verifies the answer (§9.5,
    /// L2-RCP-3): only a verified ALLOW for this intent, this PEP and this Exercise comes back
    /// as [`Authorized`]; anything else, an unavailable Access included, is [`Denied`].
    ///
    /// # Errors
    /// [`Denied`]: no effect.
    pub async fn ask(
        &self,
        domain: &Digest,
        request: &Request,
    ) -> Result<Authorized<(), ()>, Denied> {
        let Some(now) = self.clock.now() else {
            return Err(Denied::Clock);
        };
        let digest = intent_digest(&request.envelope).map_err(|_| Denied::Malformed)?;
        let actor = Actor::Statement(request.ais.clone());
        let exercise = ExerciseRequest {
            domain,
            mode: Mode::Commit,
            nonce: &request.nonce,
            intent: &digest,
            envelope: Some(&request.envelope),
            actor: &actor,
            basis: &request.basis,
            capacity: request.capacity,
            pep: &self.config.pep,
            exercise: None,
        };
        let mut body: Json = adp_body(&exercise)
            .and_then(|b| serde_json::from_str(&b).ok())
            .ok_or(Denied::Malformed)?;
        if !request.proofs.is_empty() {
            let proofs: Vec<Json> = request
                .proofs
                .iter()
                .map(|p| match p {
                    Proof::Recorded(id) => json!({ "claim_ref": b64url_encode(&id.0) }),
                    Proof::Carried(c) => json!({ "claim": b64url_encode(c) }),
                })
                .collect();
            in_context(&mut body, "proofs", Json::Array(proofs)).ok_or(Denied::Malformed)?;
        }
        let metadata = self.metadata(domain).await.map_err(|_| Denied::Malformed)?;
        let Some(call) = wire::call(
            Method::Post,
            wire::EVALUATION,
            &[],
            body.to_string().into_bytes(),
        ) else {
            return Err(Denied::Malformed);
        };
        let answer = self.wire.send(call).await;
        let pep = Pep {
            audience: self.config.pep.clone(),
            domain: *domain,
            metadata,
        };
        let intent =
            Intent::<(), ()>::named(request.envelope.clone()).map_err(|_| Denied::Malformed)?;
        let nonce = Nonce::new(request.nonce.clone()).map_err(|_| Denied::Malformed)?;
        pep.authorize(
            &Ask {
                intent: &intent,
                nonce: &nonce,
                actor: &actor,
                basis: &request.basis,
                capacity: request.capacity,
                continued: None,
                content_position: None,
            },
            &FixedClock(now),
            &Prefetched(answer),
        )
    }

    /// Applies its effect `effect` for `envelope` only under `authorized` (§9.5.2 k.6, INV-19):
    /// the effect runs once, and only for the intent Access allowed.
    ///
    /// # Errors
    /// [`Denied::Body`]: the effect does not run.
    pub fn enforce<T>(
        authorized: Authorized<(), ()>,
        envelope: &IntentEnvelope,
        effect: impl FnOnce() -> T,
    ) -> Result<T, Denied> {
        let digest = intent_digest(envelope).map_err(|_| Denied::Body)?;
        authorized.apply(&digest, |_| effect())
    }

    /// Tries to commit the meta-action `payload` in `domain` as itself on `basis`. A product
    /// never writes authority (§7.9.10.3); this exists so a test can show the refusal.
    ///
    /// # Errors
    /// [`TwinError`] when nothing came back.
    pub async fn attempt(
        &self,
        domain: &Digest,
        payload: &Payload,
        basis: ExerciseBasis,
    ) -> Result<Attempt, TwinError> {
        let p = self.paired(domain)?;
        let envelope =
            meta_intent(payload, p.party, self.window()?).ok_or(TwinError::Malformed("payload"))?;
        let (ais, nonce) = self.own_statement(&p, &envelope, Mode::Commit, basis)?;
        let digest = intent_digest(&envelope).map_err(|_| TwinError::Malformed("intent"))?;
        let actor = Actor::Statement(ais);
        let mut body: Json = adp_body(&ExerciseRequest {
            domain: &p.domain,
            mode: Mode::Commit,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &actor,
            basis: &basis,
            capacity: Capacity::Own,
            pep: &self.config.pep,
            exercise: None,
        })
        .and_then(|b| serde_json::from_str(&b).ok())
        .ok_or(TwinError::Malformed("body"))?;
        let bytes = payload
            .to_bytes()
            .map_err(|_| TwinError::Malformed("payload"))?;
        in_context(&mut body, "payload", Json::String(b64url_encode(&bytes)))
            .ok_or(TwinError::Malformed("body"))?;
        let (status, v) = self
            .send(wire::call(
                Method::Post,
                wire::EVALUATION,
                &[],
                body.to_string().into_bytes(),
            ))
            .await?;
        Ok(Attempt {
            status,
            decision: v.get("decision").and_then(Json::as_bool),
            outcome: v
                .pointer("/context/outcome")
                .and_then(Json::as_str)
                .map(String::from),
            code: v.get("code").and_then(Json::as_str).map(String::from),
        })
    }

    /// Where its publication `fingerprint` of `namespace` stands in `domain` (L1-ADP-18):
    /// answers whether the domain accepted it.
    ///
    /// # Errors
    /// [`TwinError`].
    pub async fn accepted(
        &self,
        domain: &Digest,
        namespace: &str,
        fingerprint: &Digest,
    ) -> Result<bool, TwinError> {
        let p = self.paired(domain)?;
        let envelope = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.publication"),
                path: vec![String::from(namespace)],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: self.window()?,
        };
        let (ais, nonce) = self.own_statement(&p, &envelope, Mode::Check, p.basis)?;
        let digest = intent_digest(&envelope).map_err(|_| TwinError::Malformed("intent"))?;
        let actor = Actor::Statement(ais);
        let context = Self::context(&ExerciseRequest {
            domain: &p.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &actor,
            basis: &p.basis,
            capacity: Capacity::Own,
            pep: &self.config.pep,
            exercise: None,
        })?;
        let named = b64url_encode(&p.domain.0);
        let body = json!({
            "context": context,
            "fingerprint": b64url_encode(&fingerprint.0),
            "domains": [named],
        });
        let (status, v) = self
            .send(wire::call(
                Method::Post,
                wire::PUBLICATION_STATUS,
                &[],
                body.to_string().into_bytes(),
            ))
            .await?;
        if status != 200 {
            return Err(refused(status, &v));
        }
        Ok(v.get("accepted_in")
            .and_then(Json::as_array)
            .is_some_and(|a| a.iter().any(|d| d.as_str() == Some(named.as_str()))))
    }
}
