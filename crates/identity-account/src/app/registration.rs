//! Self-service registration and e-mail change by proof of the mailbox (§12.3.6, TN-64, TN-66,
//! TN-80, TN-81, TN-82, TN-83, OP-153 m.3 (g), (h), (i)).
//!
//! The order is the spec's: address syntax, the realm's domain lists, the cheap gate per address
//! prefix before any hash or lookup, the per-address code limits, the bot signal and the abuse
//! score (step-up only, never a refusal), then always an out-of-band message. Whether the address
//! already has an account is decided only inside that message: a new address gets a code, a
//! known one a notice to its owner, and the answer to the browser is the same (TN-80 invariants
//! 1–3, CR-40). The account row is created only when the code returns.

use std::net::IpAddr;

use access_crypto::Secret;
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::challenges::{ChallengeRow, NewChallenge};
use access_store::identity::TenantTx;
use suiss_crypto::digest::sha256;
use suiss_crypto::envelope::{Dek, Sealed, open_body, seal_body};

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::vault::{self, Vault};
use crate::app::{Actor, Realm, events};
use crate::domain::bot::BotSignal;
use crate::domain::gcra::{Gcra, GcraDecision};
use crate::domain::identifier::{Identifier, IdentifierKind};
use crate::domain::registration::{
    ACCOUNT_MAIL_RATE, Assessment, CODE_ATTEMPTS, CODE_DIGITS, CODE_TTL_MS, DisposableDomains,
    EMAIL_DAILY, EMAIL_HOURLY, Email, IP_RATE, gate_key, tag,
};
use crate::domain::status::AccountStatus;
use crate::domain::throttle::DAY_MS;
use crate::notify::message::{Address, Body, Message, Notice, OtpPurpose};
use crate::notify::ports::Notifier;
use crate::ports::{AccountTx, BotSignals, Deliverability, MailDomains};

/// The cheap gate's network: the /24 or /48 prefix (OP-153 m.3 (g)).
#[must_use]
pub fn prefix(ip: IpAddr) -> Vec<u8> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => v4.octets().get(..3).unwrap_or_default().to_vec(),
        IpAddr::V6(v6) => v6.octets().get(..6).unwrap_or_default().to_vec(),
    }
}

const SEAL_CONTEXT: &[u8] = b"access/address-challenge/v1\0";
const CODE_CONTEXT: &[u8] = b"access/address-challenge-code/v1\0";

/// Days a quiet gate key is kept.
const GATE_HORIZON_DAYS: i32 = 2;

/// What a challenge proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A new account (OP-153 m.3 (g)).
    Registration,
    /// A new address for an account (OP-153 m.3 (i)).
    EmailChange,
}

impl Purpose {
    const fn name(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::EmailChange => "email_change",
        }
    }
}

/// The realm's registration rules as the flow reads them (TN-132).
#[derive(Clone, Debug, Default)]
pub struct Rules {
    /// Whether the address's domain may register (the realm's allow and deny lists).
    pub domain_allowed: bool,
    /// Whether the display name is required; the hosted page asks for it with the code.
    pub name_required: bool,
}

/// One registration request.
pub struct Start<'a> {
    /// The address as typed.
    pub email: &'a str,
    /// The hosted page's bot token, if any.
    pub bot_token: Option<&'a str>,
    /// The client's /24 or /48 prefix.
    pub prefix: &'a [u8],
    /// Digest of the new flow handle.
    pub flow_hash: [u8; 32],
    /// Digest of the browser's flow cookie.
    pub device_hash: [u8; 32],
    /// Trusted time, Unix ms.
    pub now_ms: u64,
}

/// Why a request was refused before anything was sent. None of these depends on whether the
/// address has an account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The address cannot receive mail (TN-80 step 1).
    Address,
    /// The realm does not take this domain (TN-132).
    Domain,
    /// A required field is missing.
    Required,
    /// The cheap gate or the per-address limit: retry after this long.
    Throttled {
        /// Milliseconds.
        retry_after_ms: u64,
    },
}

/// What a registration request did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Started {
    /// The message is queued; the browser goes to the code step.
    Sent {
        /// Whether the abuse score asked for step-up (OP-153 m.3 (h)).
        step_up: bool,
    },
    /// Refused before anything was sent.
    Refused(Refused),
}

/// What a code did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proven {
    /// The address is proven: the account it now belongs to, and since when it owns it.
    Done {
        /// The account.
        subject: [u8; 16],
        /// Unix ms.
        owner_since_ms: u64,
    },
    /// The code did not match; the step stays.
    Wrong,
    /// No open challenge for this flow and browser, or it ran out.
    Gone,
}

/// The registration services of one realm for one request.
pub struct Registrar<'a, B, N> {
    /// The `access_app` pool.
    pub pool: &'a Pool,
    /// The realm.
    pub realm: &'a Realm<'a>,
    /// The realm's vault keys.
    pub vault: &'a Vault,
    /// The bot signal.
    pub bots: &'a B,
    /// The disposable-domain list.
    pub disposable: &'a DisposableDomains,
    /// The MX/A lookup (OP-153 m.11 (f)).
    pub mail: &'a dyn MailDomains,
    /// The Relay seam.
    pub notifier: &'a N,
}

fn i64_of(v: u64) -> Result<i64, AccountError> {
    i64::try_from(v).map_err(|_| AccountError::Corrupt)
}

fn day_of(now_ms: u64) -> Result<i32, AccountError> {
    i32::try_from(now_ms / DAY_MS).map_err(|_| AccountError::Corrupt)
}

/// One GCRA step on a stored gate key; `Some(retry)` when over the rate.
async fn gate<T: AccountTx>(
    tx: &mut T,
    key: &[u8; 32],
    rate: Gcra,
    now_ms: u64,
) -> Result<Option<u64>, AccountError> {
    let day = day_of(now_ms)?;
    let mut row = tx.throttle(key, day, GATE_HORIZON_DAYS).await?;
    let tat = u64::try_from(row.tat_ms).unwrap_or(0);
    match rate.check(tat, now_ms) {
        GcraDecision::Allow { tat_ms } => {
            row.tat_ms = i64_of(tat_ms)?;
            tx.put_throttle(key, day, &row).await?;
            Ok(None)
        }
        GcraDecision::Deny { retry_after_ms } => Ok(Some(retry_after_ms)),
    }
}

/// The 8-digit code (OP-153 m.3 (g)).
///
/// # Errors
/// [`AccountError::Random`].
pub fn new_code() -> Result<Secret<String>, AccountError> {
    let r = access_crypto::random::bytes::<16>().map_err(|_| AccountError::Random)?;
    let n = u128::from_be_bytes(r) % 100_000_000;
    let width = CODE_DIGITS;
    Ok(Secret::new(format!("{n:0width$}")))
}

/// The digest a code is kept as, bound to its flow.
#[must_use]
pub fn code_digest(flow_hash: &[u8; 32], code: &str) -> [u8; 32] {
    let mut m = CODE_CONTEXT.to_vec();
    m.extend_from_slice(flow_hash);
    m.extend_from_slice(code.trim().as_bytes());
    sha256(&m)
}

fn seal_context(t: &TenantTx, flow_hash: &[u8; 32]) -> Vec<u8> {
    let mut c = SEAL_CONTEXT.to_vec();
    c.extend_from_slice(t.tenant().as_bytes());
    if let Some(r) = t.realm() {
        c.extend_from_slice(r.as_bytes());
    }
    c.extend_from_slice(flow_hash);
    c
}

async fn notify<N: Notifier + Sync>(
    notifier: &N,
    tx: &mut PgTx,
    message: &Message,
) -> Result<(), AccountError> {
    use crate::notify::NotifyError;
    match notifier.notify(&mut tx.0, message).await {
        Ok(_) => Ok(()),
        Err(NotifyError::Store(e)) => Err(AccountError::Store(e)),
        Err(NotifyError::Random) => Err(AccountError::Random),
        Err(_) => Err(AccountError::Corrupt),
    }
}

async fn audit<T: AccountTx>(
    tx: &mut T,
    event_type: &str,
    actor: &str,
    target: &str,
    correlation: &str,
) -> Result<(), AccountError> {
    tx.audit(&AuditEvent {
        event_type,
        actor,
        target,
        correlation,
    })
    .await
}

/// The per-account cap on messages sent to an address the requester does not prove (TN-83 (6),
/// IDP-3): a mail-bomb amplifier is capped; past it nothing is sent and the answer is unchanged.
///
/// # Errors
/// [`AccountError`].
pub async fn account_mail_allowed<T: AccountTx>(
    tx: &mut T,
    tenant: &[u8; 16],
    realm: &[u8; 16],
    subject: [u8; 16],
    now_ms: u64,
) -> Result<bool, AccountError> {
    let key = gate_key(tag::ACCOUNT_MAIL, tenant, realm, &subject);
    Ok(gate(tx, &key, ACCOUNT_MAIL_RATE, now_ms).await?.is_none())
}

impl<B: BotSignals, N: Notifier + Sync> Registrar<'_, B, N> {
    async fn begin(&self) -> Result<PgTx, AccountError> {
        Ok(PgTx(
            TenantTx::begin(self.pool, self.realm.tenant, self.realm.realm).await?,
            Some(self.vault.clone()),
        ))
    }

    fn ids(&self) -> ([u8; 16], [u8; 16]) {
        (*self.realm.tenant.as_bytes(), *self.realm.realm.as_bytes())
    }

    /// The registration request (TN-80 steps 1–7). The answer depends on the realm's rules and
    /// the limits only, never on whether the address has an account.
    ///
    /// # Errors
    /// [`AccountError`]: storage, keys or randomness (`503`).
    #[expect(clippy::too_many_lines, reason = "the steps of TN-80 in their order")]
    pub async fn start(
        &self,
        req: &Start<'_>,
        rules: &Rules,
        who: &Actor<'_>,
    ) -> Result<Started, AccountError> {
        let Ok(email) = Email::parse(req.email) else {
            return Ok(Started::Refused(Refused::Address));
        };
        if !rules.domain_allowed {
            return Ok(Started::Refused(Refused::Domain));
        }
        let (tenant, realm) = self.ids();
        let mut tx = self.begin().await?;
        // TN-80, TN-83
        let ip_key = gate_key(tag::IP, &tenant, &realm, req.prefix);
        if let Some(retry_after_ms) = gate(&mut tx, &ip_key, IP_RATE, req.now_ms).await? {
            tx.commit().await?;
            return Ok(Started::Refused(Refused::Throttled { retry_after_ms }));
        }
        let canonical = self.vault.index_of(&tenant, &realm, &email.canonical())?;
        for (t, rate) in [
            (tag::EMAIL_HOUR, EMAIL_HOURLY),
            (tag::EMAIL_DAY, EMAIL_DAILY),
        ] {
            let key = gate_key(t, &tenant, &realm, &canonical);
            if let Some(retry_after_ms) = gate(&mut tx, &key, rate, req.now_ms).await? {
                tx.commit().await?;
                return Ok(Started::Refused(Refused::Throttled { retry_after_ms }));
            }
        }
        tx.commit().await?;
        // TN-80, OP-153 m.11 (f)
        if self.mail.deliverable(email.domain()).await == Deliverability::Undeliverable {
            return Ok(Started::Refused(Refused::Address));
        }
        // TN-81, OP-153 m.3 (h)
        let bot = self.bots.assess(req.bot_token, req.prefix).await;
        let assessment = Assessment {
            bot,
            disposable: self.disposable.contains(email.domain()),
        };
        access_telemetry::signals::REGISTRATION_SCORES.incr([assessment.band()]);
        let mut tx = self.begin().await?;
        let index = self.vault.index_of(&tenant, &realm, email.raw())?;
        let holder = tx.subject_by_identifier(email.raw()).await?;
        let retired = tx.0.identifier_retired(&index, i64_of(req.now_ms)?).await?;
        let staged = match holder {
            Some(s) => tx
                .subject(s, false)
                .await?
                .is_some_and(|r| r.status == AccountStatus::Staged.name()),
            None => false,
        };
        let takes_code = (holder.is_none() && !retired) || staged;
        let code = new_code()?;
        let digest = takes_code.then(|| code_digest(&req.flow_hash, code.expose()));
        let id = self
            .insert(
                &mut tx,
                Purpose::Registration,
                req,
                &email,
                &canonical,
                digest.as_ref(),
                &assessment,
                None,
            )
            .await?;
        let expires_at_ms = req.now_ms.saturating_add(CODE_TTL_MS);
        if takes_code {
            notify(
                self.notifier,
                &mut tx,
                &Message {
                    subject: id,
                    to: Address::Email(email.raw().to_owned()),
                    locale: None,
                    valid_since_ms: Some(req.now_ms),
                    body: Body::Otp {
                        code,
                        purpose: OtpPurpose::SignUp,
                        expires_at_ms,
                    },
                },
            )
            .await?;
        } else if let Some(owner) = holder
            && account_mail_allowed(&mut tx, &tenant, &realm, owner, req.now_ms).await?
        {
            let since = tx.0.mailbox_since(owner).await?.unwrap_or(1);
            notify(
                self.notifier,
                &mut tx,
                &Message {
                    subject: owner,
                    to: Address::Email(email.raw().to_owned()),
                    locale: None,
                    valid_since_ms: Some(u64::try_from(since).unwrap_or(1)),
                    body: Body::Notice {
                        notice: Notice::SignUpExisting,
                        at_ms: req.now_ms,
                        until_ms: None,
                    },
                },
            )
            .await?;
        }
        audit(
            &mut tx,
            "auth.registration.started",
            who.actor,
            "unknown",
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Started::Sent {
            step_up: assessment.step_up(),
        })
    }

    #[expect(clippy::too_many_arguments, reason = "one challenge's columns")]
    async fn insert(
        &self,
        tx: &mut PgTx,
        purpose: Purpose,
        req: &Start<'_>,
        email: &Email,
        canonical: &[u8; 32],
        digest: Option<&[u8; 32]>,
        assessment: &Assessment,
        subject: Option<[u8; 16]>,
    ) -> Result<[u8; 16], AccountError> {
        let (tenant, realm) = self.ids();
        let dek = Dek::generate()?;
        let wrapped = self.realm.kek.wrap(&dek)?;
        let sealed = seal_body(
            dek,
            &seal_context(&tx.0, &req.flow_hash),
            email.raw().as_bytes(),
        )?;
        let index = self.vault.index_of(&tenant, &realm, email.raw())?;
        let score = i16::from(assessment.score());
        Ok(tx
            .0
            .insert_challenge(&NewChallenge {
                purpose: purpose.name(),
                flow_hash: &req.flow_hash,
                device_hash: &req.device_hash,
                kek_id: self.realm.kek.id(),
                wrapped_dek: &wrapped,
                nonce: &sealed.nonce,
                ciphertext: &sealed.ciphertext,
                address_index: &index,
                canonical_index: canonical,
                code_digest: digest,
                attempts: i16::from(CODE_ATTEMPTS),
                step_up: assessment.step_up(),
                score,
                subject,
                created_ms: i64_of(req.now_ms)?,
                expires_ms: i64_of(req.now_ms.saturating_add(CODE_TTL_MS))?,
            })
            .await?)
    }

    /// The address a challenge names, opened with its own DEK.
    fn address(
        &self,
        tx: &PgTx,
        flow_hash: &[u8; 32],
        row: &ChallengeRow,
    ) -> Result<String, AccountError> {
        let wrapped = row.wrapped_dek.as_ref().ok_or(AccountError::Shredded)?;
        if row.kek_id != self.realm.kek.id() {
            return Err(AccountError::Corrupt);
        }
        let dek = self.realm.kek.unwrap(wrapped)?;
        let plain = open_body(
            &dek,
            &seal_context(&tx.0, flow_hash),
            &Sealed {
                nonce: row.nonce,
                ciphertext: row.ciphertext.clone(),
            },
        )?;
        String::from_utf8(plain.to_vec()).map_err(|_| AccountError::Corrupt)
    }

    /// The open challenge of this flow and browser, checking the code; a wrong code costs one of
    /// its five attempts (OP-153 m.3 (g)).
    async fn take(
        &self,
        tx: &mut PgTx,
        purpose: Purpose,
        flow_hash: &[u8; 32],
        device_hash: &[u8; 32],
        code: &str,
        now_ms: u64,
    ) -> Result<Result<(ChallengeRow, String), Proven>, AccountError> {
        let Some(row) = tx.0.challenge_by_flow(flow_hash).await? else {
            return Ok(Err(Proven::Gone));
        };
        let device_ok = Secret::new(row.device_hash).ct_eq_bytes(device_hash);
        if row.status != "open" || row.purpose != purpose.name() || !device_ok {
            return Ok(Err(Proven::Gone));
        }
        if i64_of(now_ms)? >= row.expires_ms {
            tx.0.end_challenge(row.id, "expired", None, i64_of(now_ms)?)
                .await?;
            return Ok(Err(Proven::Gone));
        }
        let presented = code_digest(flow_hash, code);
        let matches = row
            .code_digest
            .is_some_and(|d| Secret::new(d).ct_eq_bytes(&presented));
        if !matches {
            let left = row.attempts_left.saturating_sub(1);
            if left <= 0 {
                tx.0.end_challenge(row.id, "failed", None, i64_of(now_ms)?)
                    .await?;
            } else {
                tx.0.challenge_attempt(row.id, left).await?;
            }
            return Ok(Err(Proven::Wrong));
        }
        let address = self.address(tx, flow_hash, &row)?;
        Ok(Ok((row, address)))
    }

    /// The code of a registration (TN-80 step 8): creates the `active` account with its proven
    /// address, or claims a `staged` one whose every earlier credential and session dies with the
    /// proof (TN-64, TNI-5).
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn complete(
        &self,
        flow_hash: &[u8; 32],
        device_hash: &[u8; 32],
        code: &str,
        name: Option<&str>,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Proven, AccountError> {
        let mut tx = self.begin().await?;
        let (row, address) = match self
            .take(
                &mut tx,
                Purpose::Registration,
                flow_hash,
                device_hash,
                code,
                now_ms,
            )
            .await?
        {
            Ok(found) => found,
            Err(p) => {
                tx.commit().await?;
                return Ok(p);
            }
        };
        let identifier =
            Identifier::new(IdentifierKind::Email, &address).map_err(|_| AccountError::Corrupt)?;
        let (subject, staged) = match tx.subject_by_identifier(&address).await? {
            Some(s) => {
                let status = tx
                    .subject(s, true)
                    .await?
                    .ok_or(AccountError::Corrupt)?
                    .status;
                if status != AccountStatus::Staged.name() {
                    tx.0.end_challenge(row.id, "failed", None, i64_of(now_ms)?)
                        .await?;
                    tx.commit().await?;
                    return Ok(Proven::Wrong);
                }
                (s, true)
            }
            None => (self.create(&mut tx, &identifier, who).await?, false),
        };
        let index = self
            .vault
            .index_of(&self.ids().0, &self.ids().1, &address)?;
        let identifier_id =
            tx.0.identifier_id(subject, &index)
                .await?
                .ok_or(AccountError::Corrupt)?;
        // TN-66, OP-153 m.3 (i)
        tx.0.insert_mailbox(identifier_id, subject, i64_of(now_ms)?)
            .await?;
        if staged {
            self.claim_staged(&mut tx, subject, who).await?;
        }
        if let Some(n) = name.map(str::trim).filter(|n| !n.is_empty()) {
            vault::set_profile(&mut tx.0, self.vault, subject, "name", n).await?;
        }
        if !tx
            .0
            .end_challenge(row.id, "completed", Some(subject), i64_of(now_ms)?)
            .await?
        {
            return Err(AccountError::Corrupt);
        }
        audit(
            &mut tx,
            "account.registered",
            who.actor,
            &self.realm.external(subject)?,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Proven::Done {
            subject,
            owner_since_ms: now_ms,
        })
    }

    async fn create(
        &self,
        tx: &mut PgTx,
        identifier: &Identifier,
        who: &Actor<'_>,
    ) -> Result<[u8; 16], AccountError> {
        let wrapped = crate::app::sealing::new_subject_key(self.realm)?;
        let subject = tx
            .insert_subject(AccountStatus::Active, self.realm.kek.id(), &wrapped)
            .await?;
        if !tx.add_identifier(subject, identifier).await? {
            return Err(AccountError::IdentifierTaken);
        }
        audit(
            tx,
            "account.created",
            who.actor,
            &self.realm.external(subject)?,
            who.correlation,
        )
        .await?;
        // OP-151 m.3 (i)
        events::created(tx, self.realm, subject).await?;
        crate::app::accounts::status_claim(tx, subject, AccountStatus::Active).await?;
        Ok(subject)
    }

    /// TN-64, TNI-5: the mailbox proof outranks everything set before it on a never-activated
    /// account: its credentials are revoked and its sessions end before it becomes `active`.
    async fn claim_staged(
        &self,
        tx: &mut PgTx,
        subject: [u8; 16],
        who: &Actor<'_>,
    ) -> Result<(), AccountError> {
        tx.0.revoke_all_credentials(subject).await?;
        tx.end_sessions(subject).await?;
        for (from, to) in [
            (AccountStatus::Staged, AccountStatus::PendingUserAction),
            (AccountStatus::PendingUserAction, AccountStatus::Active),
        ] {
            if !tx.set_status(subject, from, to).await? {
                return Err(AccountError::Corrupt);
            }
            crate::app::accounts::status_moved(tx, self.realm, subject, (from, to), who).await?;
        }
        Ok(())
    }

    /// Starts an e-mail change for `subject` (OP-153 m.3 (i)): the step-up is the caller's; a
    /// code goes to the new address. An address another account holds or retired gets no code
    /// and the same answer.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn start_change(
        &self,
        subject: [u8; 16],
        req: &Start<'_>,
        rules: &Rules,
        who: &Actor<'_>,
    ) -> Result<Started, AccountError> {
        let Ok(email) = Email::parse(req.email) else {
            return Ok(Started::Refused(Refused::Address));
        };
        if !rules.domain_allowed {
            return Ok(Started::Refused(Refused::Domain));
        }
        let (tenant, realm) = self.ids();
        let mut tx = self.begin().await?;
        let canonical = self.vault.index_of(&tenant, &realm, &email.canonical())?;
        let key = gate_key(tag::ACCOUNT_MAIL, &tenant, &realm, &subject);
        if let Some(retry_after_ms) = gate(&mut tx, &key, ACCOUNT_MAIL_RATE, req.now_ms).await? {
            tx.commit().await?;
            return Ok(Started::Refused(Refused::Throttled { retry_after_ms }));
        }
        // TN-80, OP-153 m.11 (f)
        if self.mail.deliverable(email.domain()).await == Deliverability::Undeliverable {
            tx.commit().await?;
            return Ok(Started::Refused(Refused::Address));
        }
        let index = self.vault.index_of(&tenant, &realm, email.raw())?;
        let free = tx.subject_by_identifier(email.raw()).await?.is_none()
            && !tx.0.identifier_retired(&index, i64_of(req.now_ms)?).await?;
        let code = new_code()?;
        let digest = free.then(|| code_digest(&req.flow_hash, code.expose()));
        let assessment = Assessment {
            bot: BotSignal::Positive,
            disposable: self.disposable.contains(email.domain()),
        };
        let id = self
            .insert(
                &mut tx,
                Purpose::EmailChange,
                req,
                &email,
                &canonical,
                digest.as_ref(),
                &assessment,
                Some(subject),
            )
            .await?;
        if free {
            notify(
                self.notifier,
                &mut tx,
                &Message {
                    subject: id,
                    to: Address::Email(email.raw().to_owned()),
                    locale: None,
                    valid_since_ms: Some(req.now_ms),
                    body: Body::Otp {
                        code,
                        purpose: OtpPurpose::VerifyAddress,
                        expires_at_ms: req.now_ms.saturating_add(CODE_TTL_MS),
                    },
                },
            )
            .await?;
        }
        audit(
            &mut tx,
            "account.email_change.started",
            who.actor,
            &self.realm.external(subject)?,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Started::Sent {
            step_up: assessment.step_up(),
        })
    }

    /// The code of an e-mail change (OP-153 m.3 (i), TN-64, TN-66): the new address becomes the
    /// account's with `mailbox_owner_since` now, the old one is retired under the realm's reuse
    /// policy, the old address is told "If this wasn't you: Secure your account", and every other
    /// session ends. `keep_days` is the realm's "keep N days" (N ≥ 365); `None` never frees it.
    ///
    /// # Errors
    /// [`AccountError`].
    #[expect(clippy::too_many_arguments, reason = "one change's facts")]
    pub async fn complete_change(
        &self,
        subject: [u8; 16],
        flow_hash: &[u8; 32],
        device_hash: &[u8; 32],
        code: &str,
        keep_days: Option<u32>,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Proven, AccountError> {
        let mut tx = self.begin().await?;
        let (row, address) = match self
            .take(
                &mut tx,
                Purpose::EmailChange,
                flow_hash,
                device_hash,
                code,
                now_ms,
            )
            .await?
        {
            Ok(found) if found.0.subject == Some(subject) => found,
            Ok(_) => {
                tx.commit().await?;
                return Ok(Proven::Gone);
            }
            Err(p) => {
                tx.commit().await?;
                return Ok(p);
            }
        };
        let (tenant, realm) = self.ids();
        let old = self.old_email(&mut tx, subject).await?;
        let identifier =
            Identifier::new(IdentifierKind::Email, &address).map_err(|_| AccountError::Corrupt)?;
        if !tx.add_identifier(subject, &identifier).await? {
            tx.0.end_challenge(row.id, "failed", None, i64_of(now_ms)?)
                .await?;
            tx.commit().await?;
            return Ok(Proven::Wrong);
        }
        let index = self.vault.index_of(&tenant, &realm, &address)?;
        let identifier_id =
            tx.0.identifier_id(subject, &index)
                .await?
                .ok_or(AccountError::Corrupt)?;
        tx.0.insert_mailbox(identifier_id, subject, i64_of(now_ms)?)
            .await?;
        if let Some((old_address, old_since)) = &old {
            let old_index = self.vault.index_of(&tenant, &realm, old_address)?;
            tx.0.release_identifier(subject, &old_index, &vault::folded(old_address))
                .await?;
            let reusable = keep_days
                .map(|d| now_ms.saturating_add(u64::from(d).saturating_mul(DAY_MS)))
                .map(i64_of)
                .transpose()?;
            tx.0.insert_tombstone(&old_index, subject, i64_of(now_ms)?, reusable)
                .await?;
            notify(
                self.notifier,
                &mut tx,
                &Message {
                    subject,
                    to: Address::Email(old_address.clone()),
                    locale: None,
                    valid_since_ms: Some(*old_since),
                    body: Body::Notice {
                        notice: Notice::EmailChanged,
                        at_ms: now_ms,
                        until_ms: None,
                    },
                },
            )
            .await?;
        }
        // TN-64
        if let Some(epoch) = tx.end_sessions(subject).await? {
            events::sessions_ended(&mut tx, self.realm, subject, epoch).await?;
        }
        if !tx
            .0
            .end_challenge(row.id, "completed", Some(subject), i64_of(now_ms)?)
            .await?
        {
            return Err(AccountError::Corrupt);
        }
        audit(
            &mut tx,
            "account.email_changed",
            who.actor,
            &self.realm.external(subject)?,
            who.correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Proven::Done {
            subject,
            owner_since_ms: now_ms,
        })
    }

    /// The account's current e-mail address and since when it owns it.
    async fn old_email(
        &self,
        tx: &mut PgTx,
        subject: [u8; 16],
    ) -> Result<Option<(String, u64)>, AccountError> {
        for row in tx.0.identifiers(subject).await? {
            if row.live && row.kind == IdentifierKind::Email.name() {
                let Some(value) = tx.reveal(subject, &row.stored).await? else {
                    continue;
                };
                let since = tx.0.mailbox_since(subject).await?.unwrap_or(row.created_ms);
                return Ok(Some((value, u64::try_from(since).unwrap_or(1))));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-153 m.3 (g)
    #[test]
    fn the_prefix_is_a_24_or_a_48() {
        assert_eq!(prefix("203.0.113.9".parse().unwrap()), vec![203, 0, 113]);
        assert_eq!(
            prefix("::ffff:203.0.113.9".parse().unwrap()),
            vec![203, 0, 113]
        );
        assert_eq!(prefix("2001:db8:aa:bb::1".parse().unwrap()).len(), 6);
        assert_eq!(new_code().unwrap().expose().len(), CODE_DIGITS);
    }
}
