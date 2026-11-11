//! The binding key's quorum and ceremony (CR-29, FA-6, OP-157 m.3 (x)): k-of-n ceremony keys
//! approve a permit `{op, digest, not_after, nonce}`; a quorate permit is sealed into a
//! hash-chained transcript of dCBOR entries; the signer uses binding keys only while the
//! transcript holds an activation for the rotation policy it runs.
//!
//! The quorum guards the activation and the policy, not each signature (CR-29 m.2): inside an
//! activation the rotation automation signs excerpts and Domain Metadata, and creates the
//! binding key of a newly opened domain.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use access_kernel::digest::Digest;
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::dcbor::{self, Limits, TagAllowlist, Value};
use suiss_crypto::rotation::Policy;
use suiss_crypto::signer::{SignError, Signer};

use crate::ports::Bindings;

/// The audit event of a sealed ceremony entry or an activation the signer adopts (OP-157 m.3 (x)).
pub const AUDIT_EVENT: &str = "signer.ceremony";

/// Approvals a permit needs by default: 2 of 3 ceremony keys (OP-157 m.3 (x)).
pub const DEFAULT_THRESHOLD: u8 = 2;

/// The longest a permit is valid after it is drafted (OP-157 m.3 (x)).
pub const PERMIT_MAX_MS: u64 = 15 * 60_000;

/// The longest one activation of the binding keys lasts (PD).
pub const ACTIVATION_MAX_MS: u64 = 30 * 24 * 3_600_000;

/// The most ceremony keys a roster holds.
pub const MAX_MEMBERS: usize = 16;

/// Bytes of a permit nonce.
pub const NONCE_LEN: usize = 16;

const PERMIT_CONTEXT: &str = "access/signer/ceremony-permit/v1";
const POLICY_CONTEXT: &str = "access/signer/rotation-policy/v1";
const ENTRY_CONTEXT: &str = "access/signer/ceremony-entry/v1";

/// WebAuthn authenticator data flags: user present and user verified.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// Why a permit, an approval or a transcript was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CeremonyError {
    /// Fewer distinct ceremony keys approved than the roster requires.
    #[error("quorum missing")]
    QuorumMissing,
    /// An approval does not verify, or names no member.
    #[error("approval invalid")]
    Approval,
    /// The permit is past its `not_after`, or `not_after` is more than 15 minutes out.
    #[error("permit expired")]
    Expired,
    /// The permit's nonce was already sealed.
    #[error("nonce reused")]
    NonceReused,
    /// The roster is malformed: threshold outside 2 to n, a repeated or invalid key.
    #[error("roster invalid")]
    Roster,
    /// An entry does not chain onto the one before it, or the first is not the pinned genesis.
    #[error("transcript chain broken")]
    Chain,
    /// The binding keys are not activated for this policy now.
    #[error("not activated")]
    Inactive,
    /// The activation is longer than allowed, or ends before it starts.
    #[error("activation window")]
    Window,
    /// A permit or entry is not well-formed dCBOR of the expected shape.
    #[error("malformed")]
    Malformed,
}

impl CeremonyError {
    /// Stable reason code for logs and problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::QuorumMissing => "ceremony-quorum-missing",
            Self::Approval => "ceremony-approval-invalid",
            Self::Expired => "ceremony-permit-expired",
            Self::NonceReused => "ceremony-nonce-reused",
            Self::Roster => "ceremony-roster-invalid",
            Self::Chain => "ceremony-chain-broken",
            Self::Inactive => "ceremony-inactive",
            Self::Window => "ceremony-activation-window",
            Self::Malformed => "ceremony-malformed",
        }
    }
}

/// A ceremony key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Member {
    /// An Ed25519 public key.
    Ed25519([u8; 32]),
    /// A FIDO2 authenticator's P-256 credential key (uncompressed SEC1) under `rp_id`.
    Fido2 {
        /// The uncompressed SEC1 point.
        sec1: Vec<u8>,
        /// The relying party id the assertions name.
        rp_id: String,
    },
}

/// The ceremony keys and how many of them a permit needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    /// Approvals needed.
    pub threshold: u8,
    /// The keys, by index.
    pub members: Vec<Member>,
}

impl Roster {
    /// Checks the threshold is 2 to n, n is at most 16, and every key is distinct and valid.
    ///
    /// # Errors
    /// [`CeremonyError::Roster`].
    pub fn check(&self) -> Result<(), CeremonyError> {
        let n = self.members.len();
        let k = usize::from(self.threshold);
        if k < 2 || k > n || n > MAX_MEMBERS {
            return Err(CeremonyError::Roster);
        }
        let mut seen = BTreeSet::new();
        for m in &self.members {
            let key = match m {
                Member::Ed25519(k) => k.to_vec(),
                Member::Fido2 { sec1, rp_id } => {
                    if rp_id.is_empty() || !access_crypto::webauthn::p256_point_valid(sec1) {
                        return Err(CeremonyError::Roster);
                    }
                    sec1.clone()
                }
            };
            if !seen.insert(key) {
                return Err(CeremonyError::Roster);
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let members = self
            .members
            .iter()
            .map(|m| match m {
                Member::Ed25519(k) => {
                    Value::Map(vec![(Value::text("ed25519"), Value::Bytes(k.to_vec()))])
                }
                Member::Fido2 { sec1, rp_id } => Value::Map(vec![
                    (Value::text("fido2"), Value::Bytes(sec1.clone())),
                    (Value::text("rp_id"), Value::text(rp_id)),
                ]),
            })
            .collect();
        Value::Map(vec![
            (
                Value::text("threshold"),
                Value::Unsigned(u64::from(self.threshold)),
            ),
            (Value::text("members"), Value::Array(members)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, CeremonyError> {
        let threshold =
            u8::try_from(uint(v.get("threshold"))?).map_err(|_| CeremonyError::Roster)?;
        let Some(Value::Array(items)) = v.get("members") else {
            return Err(CeremonyError::Malformed);
        };
        let mut members = Vec::with_capacity(items.len().min(MAX_MEMBERS));
        for m in items {
            if let Some(Value::Bytes(k)) = m.get("ed25519") {
                let k: [u8; 32] = k.as_slice().try_into().map_err(|_| CeremonyError::Roster)?;
                members.push(Member::Ed25519(k));
            } else if let (Some(Value::Bytes(sec1)), Some(Value::Text(rp_id))) =
                (m.get("fido2"), m.get("rp_id"))
            {
                members.push(Member::Fido2 {
                    sec1: sec1.clone(),
                    rp_id: rp_id.clone(),
                });
            } else {
                return Err(CeremonyError::Malformed);
            }
        }
        let roster = Self { threshold, members };
        roster.check()?;
        Ok(roster)
    }
}

/// What a permit allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Starts a transcript with this roster; every member approves it.
    Init(Roster),
    /// Activates the binding keys for the rotation policy with this digest until `until`.
    Activate {
        /// [`policy_digest`] of the rotation policy the automation runs.
        policy: [u8; 32],
        /// When the activation ends, in Unix milliseconds.
        until: u64,
    },
    /// Ends the current activation.
    Deactivate,
}

impl Op {
    /// The operation's stable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::Activate { .. } => "activate",
            Self::Deactivate => "deactivate",
        }
    }

    fn body(&self) -> Value {
        match self {
            Self::Init(r) => r.to_value(),
            Self::Activate { policy, until } => Value::Map(vec![
                (Value::text("policy"), Value::Bytes(policy.to_vec())),
                (Value::text("until"), Value::Unsigned(*until)),
            ]),
            Self::Deactivate => Value::Map(Vec::new()),
        }
    }

    fn of(name: &str, body: &Value) -> Result<Self, CeremonyError> {
        match name {
            "init" => Ok(Self::Init(Roster::from_value(body)?)),
            "activate" => Ok(Self::Activate {
                policy: bytes(body.get("policy"))?
                    .as_slice()
                    .try_into()
                    .map_err(|_| CeremonyError::Malformed)?,
                until: uint(body.get("until"))?,
            }),
            "deactivate" => Ok(Self::Deactivate),
            _ => Err(CeremonyError::Malformed),
        }
    }
}

/// One ceremony key's approval of a permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    /// An Ed25519 signature over [`Permit::signed_bytes`].
    Ed25519 {
        /// The member's index in the roster.
        member: u8,
        /// The signature.
        sig: Vec<u8>,
    },
    /// A FIDO2 assertion whose client data hash is SHA-256 of [`Permit::signed_bytes`]; the
    /// authenticator data must name the member's `rp_id` and carry user presence and
    /// verification.
    Fido2 {
        /// The member's index in the roster.
        member: u8,
        /// Authenticator data.
        auth_data: Vec<u8>,
        /// DER ECDSA signature over `auth_data ‖ SHA-256(signed bytes)`.
        sig: Vec<u8>,
    },
}

impl Approval {
    /// The member's index.
    #[must_use]
    pub const fn member(&self) -> u8 {
        match self {
            Self::Ed25519 { member, .. } | Self::Fido2 { member, .. } => *member,
        }
    }

    fn verify(&self, roster: &Roster, signed: &[u8]) -> Result<(), CeremonyError> {
        let member = roster
            .members
            .get(usize::from(self.member()))
            .ok_or(CeremonyError::Approval)?;
        match (self, member) {
            (Self::Ed25519 { sig, .. }, Member::Ed25519(key)) => {
                access_crypto::webauthn::verify_ed25519(key, signed, sig)
                    .map_err(|_| CeremonyError::Approval)
            }
            (Self::Fido2 { auth_data, sig, .. }, Member::Fido2 { sec1, rp_id }) => {
                let rp = auth_data.get(..32).ok_or(CeremonyError::Approval)?;
                let flags = *auth_data.get(32).ok_or(CeremonyError::Approval)?;
                if auth_data.len() < 37
                    || rp != access_crypto::webauthn::sha256(rp_id.as_bytes())
                    || flags & FLAG_UP == 0
                    || flags & FLAG_UV == 0
                {
                    return Err(CeremonyError::Approval);
                }
                let mut message = auth_data.clone();
                message.extend_from_slice(&access_crypto::webauthn::sha256(signed));
                access_crypto::webauthn::verify_es256(sec1, &message, sig)
                    .map_err(|_| CeremonyError::Approval)
            }
            _ => Err(CeremonyError::Approval),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Ed25519 { member, sig } => Value::Map(vec![
                (Value::text("member"), Value::Unsigned(u64::from(*member))),
                (Value::text("sig"), Value::Bytes(sig.clone())),
            ]),
            Self::Fido2 {
                member,
                auth_data,
                sig,
            } => Value::Map(vec![
                (Value::text("member"), Value::Unsigned(u64::from(*member))),
                (Value::text("auth_data"), Value::Bytes(auth_data.clone())),
                (Value::text("sig"), Value::Bytes(sig.clone())),
            ]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, CeremonyError> {
        let member = u8::try_from(uint(v.get("member"))?).map_err(|_| CeremonyError::Malformed)?;
        let sig = bytes(v.get("sig"))?;
        Ok(match v.get("auth_data") {
            Some(Value::Bytes(a)) => Self::Fido2 {
                member,
                auth_data: a.clone(),
                sig,
            },
            None => Self::Ed25519 { member, sig },
            Some(_) => return Err(CeremonyError::Malformed),
        })
    }
}

/// A permit for one binding key operation: `{op, digest, not_after, nonce}` and its approvals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    /// What it allows.
    pub op: Op,
    /// Last instant it may be sealed, Unix milliseconds.
    pub not_after: u64,
    /// Single-use nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Approvals, at most one per member.
    pub approvals: Vec<Approval>,
}

impl Permit {
    /// A permit for `op` drafted at `now`, valid for 15 minutes.
    ///
    /// # Errors
    /// [`CeremonyError::Roster`] for an invalid roster, [`CeremonyError::Window`] for an
    /// activation that ends before `now` or lasts too long.
    pub fn draft(op: Op, now: u64, nonce: [u8; NONCE_LEN]) -> Result<Self, CeremonyError> {
        let not_after = now
            .checked_add(PERMIT_MAX_MS)
            .ok_or(CeremonyError::Window)?;
        match &op {
            Op::Init(r) => r.check()?,
            Op::Activate { until, .. } => window(now, *until)?,
            Op::Deactivate => {}
        }
        Ok(Self {
            op,
            not_after,
            nonce,
            approvals: Vec::new(),
        })
    }

    /// The digest of the operation's body.
    ///
    /// # Errors
    /// [`CeremonyError::Malformed`].
    pub fn digest(&self) -> Result<[u8; 32], CeremonyError> {
        Ok(suiss_crypto::digest::sha256(&encode(&self.op.body())?))
    }

    /// What each ceremony key signs: the dCBOR of `{op, digest, not_after, nonce}` under the
    /// permit context.
    ///
    /// # Errors
    /// [`CeremonyError::Malformed`].
    pub fn signed_bytes(&self) -> Result<Vec<u8>, CeremonyError> {
        encode(&Value::Map(vec![
            (Value::text("ctx"), Value::text(PERMIT_CONTEXT)),
            (Value::text("op"), Value::text(self.op.name())),
            (Value::text("digest"), Value::Bytes(self.digest()?.to_vec())),
            (Value::text("not_after"), Value::Unsigned(self.not_after)),
            (Value::text("nonce"), Value::Bytes(self.nonce.to_vec())),
        ]))
    }

    /// Adds `approval` after checking it against `roster`; a second approval by the same
    /// member replaces the first.
    ///
    /// # Errors
    /// [`CeremonyError::Approval`].
    pub fn approve(&mut self, roster: &Roster, approval: Approval) -> Result<(), CeremonyError> {
        approval.verify(roster, &self.signed_bytes()?)?;
        self.approvals.retain(|a| a.member() != approval.member());
        self.approvals.push(approval);
        self.approvals.sort_by_key(Approval::member);
        Ok(())
    }

    /// Signs `self` with an Ed25519 ceremony key and adds the approval.
    ///
    /// # Errors
    /// [`CeremonyError::Approval`] when the key is not member `member`'s.
    pub fn approve_with(
        &mut self,
        roster: &Roster,
        member: u8,
        key: &dyn Signer,
    ) -> Result<(), CeremonyError> {
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(CeremonyError::Approval);
        }
        let sig = key
            .sign(&self.signed_bytes()?)
            .map_err(|_| CeremonyError::Approval)?;
        self.approve(roster, Approval::Ed25519 { member, sig })
    }

    /// Checks the approvals: each verifies, members are distinct, and they reach the
    /// threshold, or every member for [`Op::Init`].
    ///
    /// # Errors
    /// [`CeremonyError::Approval`] or [`CeremonyError::QuorumMissing`].
    pub fn quorate(&self, roster: &Roster) -> Result<(), CeremonyError> {
        let signed = self.signed_bytes()?;
        let mut members = BTreeSet::new();
        for a in &self.approvals {
            a.verify(roster, &signed)?;
            if !members.insert(a.member()) {
                return Err(CeremonyError::Approval);
            }
        }
        let needed = match self.op {
            Op::Init(_) => roster.members.len(),
            _ => usize::from(roster.threshold),
        };
        if members.len() < needed {
            return Err(CeremonyError::QuorumMissing);
        }
        Ok(())
    }

    fn fields(&self) -> Result<Vec<(Value, Value)>, CeremonyError> {
        Ok(vec![
            (Value::text("op"), Value::text(self.op.name())),
            (Value::text("body"), Value::Bytes(encode(&self.op.body())?)),
            (Value::text("not_after"), Value::Unsigned(self.not_after)),
            (Value::text("nonce"), Value::Bytes(self.nonce.to_vec())),
            (
                Value::text("approvals"),
                Value::Array(self.approvals.iter().map(Approval::to_value).collect()),
            ),
        ])
    }

    fn from_fields(v: &Value) -> Result<Self, CeremonyError> {
        let Some(Value::Text(name)) = v.get("op") else {
            return Err(CeremonyError::Malformed);
        };
        let body = decode(&bytes(v.get("body"))?)?;
        let Some(Value::Array(approvals)) = v.get("approvals") else {
            return Err(CeremonyError::Malformed);
        };
        Ok(Self {
            op: Op::of(name, &body)?,
            not_after: uint(v.get("not_after"))?,
            nonce: bytes(v.get("nonce"))?
                .as_slice()
                .try_into()
                .map_err(|_| CeremonyError::Malformed)?,
            approvals: approvals
                .iter()
                .map(Approval::from_value)
                .collect::<Result<_, _>>()?,
        })
    }

    /// The permit file's bytes.
    ///
    /// # Errors
    /// [`CeremonyError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, CeremonyError> {
        encode(&Value::Map(self.fields()?))
    }

    /// A permit file.
    ///
    /// # Errors
    /// [`CeremonyError::Malformed`] or [`CeremonyError::Roster`].
    pub fn decode(b: &[u8]) -> Result<Self, CeremonyError> {
        Self::from_fields(&decode(b)?)
    }
}

fn window(now: u64, until: u64) -> Result<(), CeremonyError> {
    let longest = now
        .checked_add(ACTIVATION_MAX_MS)
        .ok_or(CeremonyError::Window)?;
    if until <= now || until > longest {
        return Err(CeremonyError::Window);
    }
    Ok(())
}

/// The digest an activation names for a rotation policy.
#[must_use]
pub fn policy_digest(p: &Policy) -> [u8; 32] {
    let v = Value::Map(vec![
        (Value::text("lifetime_ms"), Value::Unsigned(p.lifetime_ms)),
        (Value::text("window_ms"), Value::Unsigned(p.window_ms)),
        (
            Value::text("publish_lead_ms"),
            Value::Unsigned(p.publish_lead_ms),
        ),
        (Value::text("retain_ms"), Value::Unsigned(p.retain_ms)),
        (
            Value::text("max_signatures"),
            Value::Unsigned(p.max_signatures),
        ),
        (
            Value::text("jitter_permille"),
            Value::Unsigned(u64::from(p.jitter_permille)),
        ),
    ]);
    let canonical = dcbor::encode(&v, Limits::CEILING).unwrap_or_default();
    suiss_crypto::digest::context_digest(POLICY_CONTEXT, &canonical).0
}

/// An activation the transcript holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    /// The rotation policy it covers.
    pub policy: [u8; 32],
    /// When it ends.
    pub until: u64,
    /// The entry that made it.
    pub seq: u64,
}

/// What a verified transcript says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The ceremony keys.
    pub roster: Roster,
    /// Hash of the first entry; operators pin it in the signer's configuration.
    pub genesis: [u8; 32],
    /// Hash of the last entry: the transcript digest.
    pub head: [u8; 32],
    /// Number of entries.
    pub len: u64,
    /// The current activation, if any.
    pub activation: Option<Activation>,
    /// The time of the last entry.
    pub last_at: u64,
    nonces: BTreeSet<[u8; NONCE_LEN]>,
}

impl State {
    /// Checks the binding keys are activated for `policy` at `now`.
    ///
    /// # Errors
    /// [`CeremonyError::Inactive`].
    pub fn active(&self, policy: &[u8; 32], now: u64) -> Result<Activation, CeremonyError> {
        self.activation
            .filter(|a| a.policy == *policy && now < a.until)
            .ok_or(CeremonyError::Inactive)
    }
}

/// The hash-chained ceremony transcript: a CBOR sequence (RFC 8742) of signed entries.
#[derive(Clone, Debug)]
pub struct Transcript {
    bytes: Vec<u8>,
    state: State,
}

fn entry_value(
    seq: u64,
    prev: Option<&[u8; 32]>,
    at: u64,
    p: &Permit,
) -> Result<Value, CeremonyError> {
    let mut fields = p.fields()?;
    fields.push((Value::text("ctx"), Value::text(ENTRY_CONTEXT)));
    fields.push((Value::text("seq"), Value::Unsigned(seq)));
    fields.push((Value::text("at"), Value::Unsigned(at)));
    if let Some(prev) = prev {
        fields.push((Value::text("prev"), Value::Bytes(prev.to_vec())));
    }
    Ok(Value::Map(fields))
}

impl Transcript {
    /// A new transcript whose first entry is the quorate [`Op::Init`] permit, sealed at `now`.
    ///
    /// # Errors
    /// [`CeremonyError`] when the permit is not an init, not quorate or expired.
    pub fn genesis(permit: &Permit, now: u64) -> Result<Self, CeremonyError> {
        let Op::Init(roster) = &permit.op else {
            return Err(CeremonyError::Chain);
        };
        within(permit, now)?;
        permit.quorate(roster)?;
        let bytes = encode(&entry_value(0, None, now, permit)?)?;
        let head = suiss_crypto::digest::sha256(&bytes);
        Ok(Self {
            state: State {
                roster: roster.clone(),
                genesis: head,
                head,
                len: 1,
                activation: None,
                last_at: now,
                nonces: BTreeSet::from([permit.nonce]),
            },
            bytes,
        })
    }

    /// Reads and verifies a whole transcript whose first entry hashes to `genesis`.
    ///
    /// # Errors
    /// [`CeremonyError::Chain`] for a broken chain or another genesis, or the error of the first
    /// entry that does not verify.
    pub fn open(bytes: &[u8], genesis: &[u8; 32]) -> Result<Self, CeremonyError> {
        let mut rest = bytes;
        let mut state: Option<State> = None;
        while !rest.is_empty() {
            let (v, used) = dcbor::decode_prefix(rest, Limits::CEILING, &TagAllowlist::none())
                .map_err(|_| CeremonyError::Chain)?;
            let raw = rest.get(..used).ok_or(CeremonyError::Chain)?;
            rest = rest.get(used..).ok_or(CeremonyError::Chain)?;
            let hash = suiss_crypto::digest::sha256(raw);
            let permit = Permit::from_fields(&v)?;
            let seq = uint(v.get("seq"))?;
            let at = uint(v.get("at"))?;
            let prev = match v.get("prev") {
                Some(Value::Bytes(p)) => Some(p.as_slice()),
                None => None,
                Some(_) => return Err(CeremonyError::Malformed),
            };
            if !matches!(v.get("ctx"), Some(Value::Text(c)) if c == ENTRY_CONTEXT) {
                return Err(CeremonyError::Malformed);
            }
            within(&permit, at)?;
            match state.as_mut() {
                None => {
                    let Op::Init(roster) = &permit.op else {
                        return Err(CeremonyError::Chain);
                    };
                    if seq != 0 || prev.is_some() || hash != *genesis {
                        return Err(CeremonyError::Chain);
                    }
                    permit.quorate(roster)?;
                    state = Some(State {
                        roster: roster.clone(),
                        genesis: hash,
                        head: hash,
                        len: 1,
                        activation: None,
                        last_at: at,
                        nonces: BTreeSet::from([permit.nonce]),
                    });
                }
                Some(s) => {
                    if seq != s.len || prev != Some(s.head.as_slice()) || at < s.last_at {
                        return Err(CeremonyError::Chain);
                    }
                    apply(s, &permit, at)?;
                    s.head = hash;
                    s.len = s.len.checked_add(1).ok_or(CeremonyError::Chain)?;
                    s.last_at = at;
                }
            }
        }
        let state = state.ok_or(CeremonyError::Chain)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            state,
        })
    }

    /// The hash of the first entry of `bytes`, unverified: what a pin would name.
    ///
    /// # Errors
    /// [`CeremonyError::Chain`] when there is no first entry.
    pub fn genesis_of(bytes: &[u8]) -> Result<[u8; 32], CeremonyError> {
        let (_, used) = dcbor::decode_prefix(bytes, Limits::CEILING, &TagAllowlist::none())
            .map_err(|_| CeremonyError::Chain)?;
        Ok(suiss_crypto::digest::sha256(
            bytes.get(..used).ok_or(CeremonyError::Chain)?,
        ))
    }

    /// Seals the quorate `permit` as the next entry at `now`.
    ///
    /// # Errors
    /// [`CeremonyError`] when it is expired, not quorate, reuses a nonce or is an init.
    pub fn seal(&mut self, permit: &Permit, now: u64) -> Result<&State, CeremonyError> {
        within(permit, now)?;
        let at = now.max(self.state.last_at);
        let mut next = self.state.clone();
        apply(&mut next, permit, at)?;
        let entry = encode(&entry_value(
            self.state.len,
            Some(&self.state.head),
            at,
            permit,
        )?)?;
        next.head = suiss_crypto::digest::sha256(&entry);
        next.len = next.len.checked_add(1).ok_or(CeremonyError::Chain)?;
        next.last_at = at;
        self.bytes.extend_from_slice(&entry);
        self.state = next;
        Ok(&self.state)
    }

    /// The transcript file's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What it says.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }
}

/// A permit sealed at `at` is in its validity, at most 15 minutes long.
fn within(p: &Permit, at: u64) -> Result<(), CeremonyError> {
    let longest = at
        .checked_add(PERMIT_MAX_MS)
        .ok_or(CeremonyError::Expired)?;
    if at > p.not_after || p.not_after > longest {
        return Err(CeremonyError::Expired);
    }
    Ok(())
}

fn apply(s: &mut State, p: &Permit, at: u64) -> Result<(), CeremonyError> {
    if matches!(p.op, Op::Init(_)) {
        return Err(CeremonyError::Chain);
    }
    p.quorate(&s.roster)?;
    if !s.nonces.insert(p.nonce) {
        return Err(CeremonyError::NonceReused);
    }
    s.activation = match p.op {
        Op::Activate { policy, until } => {
            window(at, until)?;
            Some(Activation {
                policy,
                until,
                seq: s.len,
            })
        }
        _ => None,
    };
    Ok(())
}

fn encode(v: &Value) -> Result<Vec<u8>, CeremonyError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| CeremonyError::Malformed)
}

fn decode(b: &[u8]) -> Result<Value, CeremonyError> {
    dcbor::decode(b, Limits::CEILING).map_err(|_| CeremonyError::Malformed)
}

fn uint(v: Option<&Value>) -> Result<u64, CeremonyError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(CeremonyError::Malformed),
    }
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, CeremonyError> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(CeremonyError::Malformed),
    }
}

/// The activation the signer runs under, shared by its binding keys (CR-29 m.2).
#[derive(Clone)]
pub struct Gate {
    policy: [u8; 32],
    until: Arc<Mutex<Option<u64>>>,
    clock: fn() -> u64,
}

impl Gate {
    /// A closed gate for the rotation policy `policy`, read against `clock`.
    #[must_use]
    pub fn new(policy: &Policy, clock: fn() -> u64) -> Self {
        Self {
            policy: policy_digest(policy),
            until: Arc::new(Mutex::new(None)),
            clock,
        }
    }

    /// Adopts what `state` says at the gate's clock; closes the gate when it holds no
    /// activation for this policy.
    ///
    /// # Errors
    /// [`CeremonyError::Inactive`].
    pub fn adopt(&self, state: &State) -> Result<Activation, CeremonyError> {
        let found = state.active(&self.policy, (self.clock)());
        if let Ok(mut until) = self.until.lock() {
            *until = found.as_ref().ok().map(|a| a.until);
        }
        found
    }

    /// Closes the gate, e.g. when the transcript no longer verifies.
    pub fn close(&self) {
        if let Ok(mut until) = self.until.lock() {
            *until = None;
        }
    }

    /// Whether binding keys may be used now.
    #[must_use]
    pub fn open(&self) -> bool {
        let now = (self.clock)();
        self.until
            .lock()
            .is_ok_and(|u| u.is_some_and(|until| now < until))
    }
}

/// A binding key that signs only while the gate is open.
struct Gated {
    inner: Box<dyn Signer + Send>,
    gate: Gate,
}

impl Signer for Gated {
    fn algorithm(&self) -> Algorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        if !self.gate.open() {
            return Err(SignError::Key);
        }
        self.inner.sign(message)
    }
}

/// Binding keys behind the quorum: none is created, opened or used while the gate is closed
/// (CR-29, OP-157 m.3 (x)).
pub struct Quorate<B> {
    inner: B,
    gate: Gate,
}

impl<B> Quorate<B> {
    /// `inner`'s binding keys behind `gate`.
    pub const fn new(inner: B, gate: Gate) -> Self {
        Self { inner, gate }
    }
}

impl<B: Bindings> Bindings for Quorate<B> {
    fn binding(&mut self, domain: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        if !self.gate.open() {
            return Err(SignError::Key);
        }
        let inner = self.inner.binding(domain)?;
        Ok(Box::new(Gated {
            inner,
            gate: self.gate.clone(),
        }))
    }

    fn generation(
        &mut self,
        domain: &Digest,
        generation: u64,
    ) -> Result<Box<dyn Signer + Send>, SignError> {
        if !self.gate.open() {
            return Err(SignError::Key);
        }
        let inner = self.inner.generation(domain, generation)?;
        Ok(Box::new(Gated {
            inner,
            gate: self.gate.clone(),
        }))
    }
}

#[cfg(test)]
mod tests;
