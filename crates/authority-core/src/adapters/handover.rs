//! The decision point's side of a cooperative handover and a binding re-anchor (§16.6
//! HO-1…HO-9, §16.6.1 RB-0…RB-6, U11, U27, PI-15, OP-158 m.3 (l)): the freeze, the gate every
//! commit passes while a domain is frozen, the binding requests to the signer, the re-anchor's
//! thaw and the incoming provider's adoption.

use access_authority_sequencer::ports::Clock;
use access_authority_sequencer::witness::Target;
use access_authority_signer::adapters::call;
use access_authority_signer::handover::{CONTINUATION, Continuation, NO_WRITE, NoWrite, verify};
use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Mode;
use access_kernel::digest::Digest;
use access_kernel::meta::Payload;
use access_kernel::verify::key_scope::{BindingKey, Declarations, DomainMetadata};
use access_store::handover::{Role, Step};
use access_store::scope::DomainId;
use access_store::witness::{Cosign, checkpoint_of_size, record_cosign, witnessed_through};
use suiss_crypto::sig::PureBackend;
use suiss_ledger::checkpoint::witness::Cosignature;

use crate::CoreError;
use crate::adapters::Domains;
use crate::app::Incoming;
use crate::app::handover::{FROZEN, NOT_CONFORMANT, Statement, TakeOver, conformance_digest};
use crate::domain::ProofRef;
use crate::ports::{Binding, Keys, Salts};

/// The domain was frozen for a handover or a re-anchor (HO-1, RB-1).
pub(crate) const AUDIT_EVENT_FROZEN: &str = "domain.frozen";

/// The domain was taken over at `h + 1`, or its re-anchor's new binding signs from there
/// (HO-8, RB-6).
pub(crate) const AUDIT_EVENT_HANDOVER: &str = "domain.handover";

/// A frozen domain (HO-1, HO-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frozen {
    /// The run.
    pub run: [u8; 16],
    /// The batch's first position.
    pub k: u64,
    /// When, Unix ms.
    pub at: u64,
}

fn store(e: access_store::StoreError) -> CoreError {
    CoreError::Store(e)
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    async fn audit_handover(
        &self,
        domain: Digest,
        event_type: &'static str,
        (target, reason, run): (&str, &str, &[u8; 16]),
    ) -> Result<(), CoreError> {
        let correlation = access_kernel::json::b64url_encode(run);
        let id = DomainId::from_bytes(domain.0);
        let tenant = access_store::authority::domain_tenant(&self.setup.app, &id)
            .await
            .map_err(store)?;
        let now = access_store::authority::server_time(&self.setup.app)
            .await
            .map_err(store)?;
        access_store::operational::record_operational(
            &self.setup.app,
            &access_store::operational::OperationalEvent {
                occurred_at_ms: now,
                tenant,
                domain: tenant.map(|_| domain.0),
                event_type,
                actor: "provider",
                target,
                reason,
                correlation: &correlation,
            },
        )
        .await
        .map_err(|_| CoreError::Unavailable("audit"))
    }

    async fn sign(&self, request: &SignRequest) -> Result<SignResponse, CoreError> {
        let path = self
            .setup
            .signer
            .as_deref()
            .ok_or(CoreError::Unavailable("signer"))?;
        match tokio::time::timeout(super::SIGNER_DEADLINE, call(path, request)).await {
            Ok(Ok(SignResponse::Error(code))) => {
                Err(CoreError::Unavailable(super::signer_reason(&code)))
            }
            Ok(Ok(r)) => Ok(r),
            _ => Err(CoreError::Unavailable("signer-unreachable")),
        }
    }

    /// The domain's binding key, or with `next` its next generation's, created in the HSM when
    /// missing (RB-2); the keyring is opened first.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the signer cannot answer.
    pub async fn binding_key(&self, domain: Digest, next: bool) -> Result<BindingKey, CoreError> {
        let path = self
            .setup
            .signer
            .as_deref()
            .ok_or(CoreError::Unavailable("signer"))?;
        if !super::open_keyring(path, domain).await {
            return Err(CoreError::Unavailable("signer-binding"));
        }
        match self.sign(&SignRequest::Binding { domain, next }).await? {
            SignResponse::Binding(b) => Ok(b),
            _ => Err(CoreError::Unavailable("signer-error")),
        }
    }

    /// A handover statement signed by the domain's binding, or with `next` by its next
    /// generation's (HO-6, RB-4).
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the signer cannot sign it.
    pub async fn sign_statement(
        &self,
        domain: Digest,
        next: bool,
        content_type: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let request = SignRequest::Statement {
            domain,
            next,
            content_type: String::from(content_type),
            payload,
        };
        match self.sign(&request).await? {
            SignResponse::Statement(s) => Ok(s),
            _ => Err(CoreError::Unavailable("signer-error")),
        }
    }

    async fn declared_of(&self, domain: Digest) -> Result<DomainMetadata, CoreError> {
        let signed = self
            .metadata(domain)
            .await
            .ok_or(CoreError::Unavailable("signer-binding"))?;
        let msg = access_kernel::verify::cose::parse_sign1(&signed)
            .map_err(|_| CoreError::Unavailable("signer-binding"))?;
        DomainMetadata::from_bytes(msg.payload.as_deref().unwrap_or_default())
            .map_err(|_| CoreError::Unavailable("signer-binding"))
    }

    /// HO-1, HO-2, RB-1: freezes `domain` for a handover to another provider, or with
    /// [`Role::Reanchor`] for a binding re-anchor; the leader stays and commits only the batch.
    /// RB-0: a re-anchor needs a declared independent witness that cosigns under the incoming
    /// binding's algorithm, or it is not started.
    ///
    /// # Errors
    /// [`CoreError::Refused`] `handover-frozen` for a domain already frozen or sealed,
    /// `provider-not-conformant` for RB-0; [`CoreError::Store`].
    pub async fn freeze(&self, domain: Digest, role: Role) -> Result<Frozen, CoreError> {
        if role == Role::Reanchor {
            let next = self.binding_key(domain, true).await?;
            let m = self.declared_of(domain).await?;
            // RB-0, CR-45 RA-1c
            if !m
                .declared
                .witnesses
                .iter()
                .any(|w| w.independent && w.algorithm == next.alg)
            {
                return Err(CoreError::Refused(NOT_CONFORMANT));
            }
        }
        let id = DomainId::from_bytes(domain.0);
        let at = access_store::authority::server_time(&self.setup.app)
            .await
            .map_err(store)?;
        let run =
            access_crypto::random::bytes::<16>().map_err(|_| CoreError::Unavailable("random"))?;
        let k =
            match access_store::handover::freeze(&self.setup.sequencer, &id, run, role, at).await {
                Ok(k) => k,
                Err(access_store::StoreError::HeadMoved) => return Err(CoreError::Refused(FROZEN)),
                Err(e) => return Err(store(e)),
            };
        let role_word = match role {
            Role::Reanchor => "reanchor",
            _ => "outgoing",
        };
        self.audit_handover(
            domain,
            AUDIT_EVENT_FROZEN,
            (&format!("k:{k}"), role_word, &run),
        )
        .await?;
        Ok(Frozen { run, k, at })
    }

    /// The recorded handover steps of `domain`.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn handover_steps(&self, domain: Digest) -> Result<Vec<Step>, CoreError> {
        access_store::handover::steps(&self.setup.app, &DomainId::from_bytes(domain.0))
            .await
            .map_err(store)
    }

    /// OP-158 m.3 (l), U11: what a request may do while its domain is frozen. A commit other
    /// than the handover is refused; the handover's `domain_handover` Exercise must cite the
    /// witnessed `C_k` at the frozen `k` and carry exactly the outgoing binding's no-write
    /// statement and the incoming binding's continuation statement, which must name a passing
    /// provider profile. The verified statements, for the batch.
    pub(super) async fn handover_gate(
        &self,
        inc: &Incoming,
        head: u64,
    ) -> Result<Vec<Statement>, CoreError> {
        let req = &inc.request;
        let handover = match &req.payload {
            Some(Payload::DomainHandover(h)) => Some(h),
            _ => None,
        };
        if req.mode != Mode::Commit {
            return Ok(Vec::new());
        }
        let id = DomainId::from_bytes(req.domain.0);
        let frozen = access_store::handover::frozen_at(&self.setup.app, &id)
            .await
            .map_err(store)?;
        let (Some(h), Some(frozen_at)) = (handover, frozen) else {
            return match (handover, frozen) {
                (None, None) => Ok(Vec::new()),
                (None, Some(_)) => Err(CoreError::Refused(FROZEN)),
                _ => Err(CoreError::Protocol("payload")),
            };
        };
        let steps = self.handover_steps(req.domain).await?;
        let open = steps.iter().rev().find(|s| {
            s.step == "frozen"
                && !steps
                    .iter()
                    .any(|c| c.run == s.run && (c.step == "committed" || c.step == "thawed"))
        });
        let Some(run) = open else {
            return Err(CoreError::Refused(FROZEN));
        };
        let k = run.k;
        // SEC26
        let first = head.checked_add(1) == Some(k);
        if head.checked_add(1) < Some(k)
            || h.cited.size != k
            || h.reanchor != (run.role == Role::Reanchor)
        {
            return Err(CoreError::Protocol("payload"));
        }
        // HO-4
        let ck = checkpoint_of_size(&self.setup.app, &id, k)
            .await
            .map_err(store)?;
        let witnessed = witnessed_through(&self.setup.app, &id)
            .await
            .map_err(store)?;
        if ck.is_none_or(|c| c.root != h.cited.root.0) || witnessed < k {
            return Err(CoreError::Protocol("payload"));
        }
        let cited = (k, h.cited.root.0);
        let (no_write, continuation) = self.statements(req, h, cited, frozen_at).await?;
        if !first {
            return Ok(Vec::new());
        }
        Ok(vec![
            Statement::of(NO_WRITE, no_write).ok_or(CoreError::Protocol("proof"))?,
            Statement::of(CONTINUATION, continuation).ok_or(CoreError::Protocol("proof"))?,
        ])
    }

    /// HO-6, RB-4: the request's no-write statement under the current binding and its
    /// continuation under the incoming one, both citing `cited`; the continuation names a
    /// passing provider profile.
    async fn statements(
        &self,
        req: &crate::domain::Request,
        h: &access_kernel::recovery::HandoverInput,
        cited: (u64, [u8; 32]),
        frozen_at: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
        let (mut no_write, mut continuation) = (None, None);
        for p in &req.proofs {
            match p {
                ProofRef::Claim(b)
                    if access_authority_signer::handover::kind_of(b) == Some(NO_WRITE)
                        && no_write.is_none() =>
                {
                    no_write = Some(b.clone());
                }
                ProofRef::Claim(b)
                    if access_authority_signer::handover::kind_of(b) == Some(CONTINUATION)
                        && continuation.is_none() =>
                {
                    continuation = Some(b.clone());
                }
                _ => return Err(CoreError::Protocol("proof")),
            }
        }
        let (Some(no_write), Some(continuation)) = (no_write, continuation) else {
            return Err(CoreError::Protocol("proof"));
        };
        let outgoing = self.binding_key(req.domain, false).await?;
        let (payload, _) = verify(
            &PureBackend,
            &no_write,
            std::slice::from_ref(&outgoing),
            NO_WRITE,
        )
        .map_err(|_| CoreError::Protocol("proof"))?;
        let nw = NoWrite::from_bytes(&payload).map_err(|_| CoreError::Protocol("proof"))?;
        if nw.domain != req.domain || nw.last != cited || nw.frozen_at != frozen_at {
            return Err(CoreError::Protocol("proof"));
        }
        let incoming: Vec<BindingKey> = h.binding.values().cloned().collect();
        // RB-2
        if h.reanchor {
            let next = self.binding_key(req.domain, true).await?;
            if incoming.len() != 1 || incoming.first().map(|b| b.kid) != Some(next.kid) {
                return Err(CoreError::Protocol("payload"));
            }
        } else if incoming.iter().any(|b| b.kid == outgoing.kid) {
            return Err(CoreError::Protocol("payload"));
        }
        let (payload, _) = verify(&PureBackend, &continuation, &incoming, CONTINUATION)
            .map_err(|_| CoreError::Protocol("proof"))?;
        let c = Continuation::from_bytes(&payload).map_err(|_| CoreError::Protocol("proof"))?;
        if c.domain != req.domain || c.from != cited {
            return Err(CoreError::Protocol("proof"));
        }
        // OP-158 m.3 (l)
        if c.conformance != conformance_digest() {
            return Err(CoreError::Refused(NOT_CONFORMANT));
        }
        Ok((no_write, continuation))
    }

    /// RB-5, RB-6: once an independent witness cosigned `C_{h+1}` of the committed re-anchor
    /// `run`, the signer moves to the next binding generation (the old one superseded at
    /// `C_{h+1}` citing `C_k`) and the domain commits again from `h + 1`.
    ///
    /// # Errors
    /// [`CoreError::Refused`] `handover-frozen` while `C_{h+1}` is not witnessed;
    /// [`CoreError::Store`]; [`CoreError::Unavailable`] when the signer cannot rebind.
    pub async fn thaw_reanchor(&self, domain: Digest, run: [u8; 16]) -> Result<u64, CoreError> {
        let id = DomainId::from_bytes(domain.0);
        let steps = self.handover_steps(domain).await?;
        let committed = steps
            .iter()
            .find(|s| s.run == run && s.step == "committed" && s.role == Role::Reanchor)
            .ok_or(CoreError::Refused(FROZEN))?;
        let h = committed.h.ok_or(CoreError::Refused(FROZEN))?;
        let after = h.checked_add(1).ok_or(CoreError::Protocol("position"))?;
        let witnessed = witnessed_through(&self.setup.app, &id)
            .await
            .map_err(store)?;
        let (Some(at), Some(ck)) = (
            checkpoint_of_size(&self.setup.app, &id, after)
                .await
                .map_err(store)?,
            checkpoint_of_size(&self.setup.app, &id, committed.k)
                .await
                .map_err(store)?,
        ) else {
            return Err(CoreError::Refused(FROZEN));
        };
        if witnessed < after {
            return Err(CoreError::Refused(FROZEN));
        }
        let transcript = transcript(&domain, (ck.size, ck.root), (at.size, at.root));
        match self
            .sign(&SignRequest::Rebind {
                domain,
                at: Digest(at.root),
                cited: Digest(ck.root),
                transcript,
            })
            .await?
        {
            SignResponse::Opened => {}
            _ => return Err(CoreError::Unavailable("signer-binding")),
        }
        access_store::handover::thaw(&self.setup.sequencer, &id, run)
            .await
            .map_err(store)?;
        self.release().await;
        self.audit_handover(
            domain,
            AUDIT_EVENT_HANDOVER,
            (&format!("h:{h}"), "reanchor", &run),
        )
        .await?;
        Ok(after)
    }

    /// HO-8: takes the domain over as `tenant`'s at `h + 1`: the log and state from the
    /// export and the batch, the outgoing bindings published as superseded at `C_{h+1}`, the
    /// domain's declarations carried over, `C_{h+1}` and its cosignatures of the declared
    /// `witnesses` kept; from here this install leads it.
    ///
    /// # Errors
    /// [`CoreError::Store`]; [`CoreError::Unavailable`] when the signer or the key store
    /// fails.
    pub async fn adopt(
        &self,
        tenant: [u8; 16],
        t: &TakeOver,
        (note, excerpt): (&str, &[u8]),
        declared: Declarations,
        witnesses: &[Target],
    ) -> Result<(), CoreError> {
        let domain = t.domain;
        let id = DomainId::from_bytes(domain.0);
        self.setup.keys.open_domain(&domain)?;
        access_store::handover::adopt(&self.setup.sequencer, &id, tenant, &t.adoption)
            .await
            .map_err(store)?;
        let size = t.h.checked_add(1).ok_or(CoreError::Protocol("position"))?;
        let issued_at = access_store::authority::server_time(&self.setup.app)
            .await
            .map_err(store)?;
        access_store::authority_checkpoint::append(
            &self.setup.sequencer,
            &id,
            &access_store::authority_checkpoint::AuthorityCheckpoint {
                issued_at,
                size,
                root: t.at,
                note: String::from(note),
                excerpt: excerpt.to_vec(),
            },
        )
        .await
        .map_err(store)?;
        for w in witnesses {
            let Ok(time) = w.verify(note, "") else {
                continue;
            };
            let Some((parsed, _)) = note
                .lines()
                .filter_map(|l| Cosignature::from_line(&format!("{l}\n")).ok())
                .find(|(c, _)| w.vkey.starts_with(&format!("{}+", c.name)))
            else {
                continue;
            };
            record_cosign(
                &self.setup.sequencer,
                &id,
                &Cosign {
                    size,
                    root: t.at,
                    witness: parsed.name,
                    vkey: w.vkey.clone(),
                    independent: w.independent,
                    cosigned_at: time,
                    signature: parsed.signature,
                },
            )
            .await
            .map_err(store)?;
        }
        let path = self
            .setup
            .signer
            .as_deref()
            .ok_or(CoreError::Unavailable("signer"))?;
        if !super::open_keyring(path, domain).await {
            return Err(CoreError::Unavailable("signer-binding"));
        }
        match self
            .sign(&SignRequest::Declare {
                domain,
                declared: Box::new(declared),
            })
            .await?
        {
            SignResponse::Opened => {}
            _ => return Err(CoreError::Unavailable("signer-binding")),
        }
        match self
            .sign(&SignRequest::Supersede {
                domain,
                keys: t.superseded.clone(),
            })
            .await?
        {
            SignResponse::Opened => {}
            _ => return Err(CoreError::Unavailable("signer-binding")),
        }
        self.audit_handover(
            domain,
            AUDIT_EVENT_HANDOVER,
            (&format!("h:{}", t.h), "incoming", &t.adoption.run),
        )
        .await
    }
}

/// The re-anchor's ceremony transcript digest (OP-157 m.7 (i)): the domain, `C_k` and
/// `C_{h+1}` the double-signed change is bound to.
#[must_use]
pub fn transcript(domain: &Digest, ck: (u64, [u8; 32]), at: (u64, [u8; 32])) -> Digest {
    let mut input = domain.0.to_vec();
    input.extend_from_slice(&ck.0.to_be_bytes());
    input.extend_from_slice(&ck.1);
    input.extend_from_slice(&at.0.to_be_bytes());
    input.extend_from_slice(&at.1);
    Digest(suiss_crypto::digest::context_digest("access/binding-reanchor/v1", &input).0)
}
