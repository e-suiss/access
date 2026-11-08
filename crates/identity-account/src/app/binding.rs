//! Cross-realm `IdentityBinding` in two halves (§12.1.1, §12.1.3, TN-2, TN-65, MD-5, OP-153 m.3
//! (m)).
//!
//! - The person, freshly signed in to realm A, makes an offer and carries its token to realm B.
//! - Signed in to B, the person accepts it: B's half is committed in B with the digest of A's
//!   token as evidence, and B's issuer states its `identity_binding_person` Claim. B answers
//!   with its own token.
//! - Back in A, the person completes: A's half is committed in A with the digest of B's token,
//!   and A's issuer states its Claim.
//!
//! No row names the other realm's account and nothing is read across realms (rule 6); the
//! halves share only a random binding id and digests of the secrets the person carried. One
//! half alone binds nothing and no half produces an actor binding. The proof of both halves is
//! `invite_token`; `admin_exercise` and `verified_idp_subject` are not offered yet.

use access_kernel::claim::body::BindingKind;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::federation::{BindingHalf, NewHalf};

use crate::AccountError;
use crate::app::external::Externals;
use crate::app::{Actor, claims};
use crate::ports::AccountTx as _;

/// How long an offer waits for the other realm (PD, as a social attempt).
pub const OFFER_TTL_MS: u64 = 10 * 60_000;

/// The proof a person gives by carrying a token between the realms.
pub const INVITE_TOKEN: &str = "invite_token";

const TOKEN_CONTEXT: &[u8] = b"access/binding-token/v1\0";

/// The digest a half keeps of a token.
#[must_use]
pub fn token_digest(token: &str) -> [u8; 32] {
    let mut m = TOKEN_CONTEXT.to_vec();
    m.extend_from_slice(token.as_bytes());
    suiss_crypto::digest::sha256(&m)
}

/// A token: base64url of the binding id and a 256-bit secret.
fn token(binding: [u8; 16], secret: &[u8; 32]) -> String {
    let mut b = binding.to_vec();
    b.extend_from_slice(secret);
    b64url_encode(&b)
}

/// The binding id a token names, when it has the form.
#[must_use]
pub fn binding_of(token: &str) -> Option<[u8; 16]> {
    let raw = b64url_decode(token).ok().filter(|r| r.len() == 48)?;
    <[u8; 16]>::try_from(raw.get(..16)?).ok()
}

/// The Claim's evidence: the binding id, the proof and the digest of what the other realm
/// handed over, so each realm's Claim names the same binding and neither names the other
/// account.
fn evidence(binding: [u8; 16], peer: &[u8; 32]) -> Vec<u8> {
    let mut e = binding.to_vec();
    e.extend_from_slice(INVITE_TOKEN.as_bytes());
    e.extend_from_slice(peer);
    e
}

/// What an acceptance or a completion did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bound {
    /// This realm's half is committed; for an acceptance, the token to carry back.
    Committed(Option<String>),
    /// No such offer, a lapsed one, or this realm already keeps a half of the binding.
    Refused,
}

impl Externals<'_> {
    /// Makes an offer of `subject` and returns the token the person carries to the other realm.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn offer_binding(
        &self,
        subject: [u8; 16],
        now_ms: u64,
    ) -> Result<String, AccountError> {
        let binding = access_crypto::random::bytes::<16>().map_err(|_| AccountError::Corrupt)?;
        let secret = access_crypto::random::bytes::<32>().map_err(|_| AccountError::Corrupt)?;
        let t = token(binding, &secret);
        let mut tx = self.begin().await?;
        let fresh =
            tx.0.insert_binding_half(&NewHalf {
                binding,
                subject,
                role: "offer",
                proof: INVITE_TOKEN,
                secret_hash: &token_digest(&t),
                peer_evidence: None,
                now_ms,
                expires_ms: now_ms.saturating_add(OFFER_TTL_MS),
            })
            .await?;
        if !fresh {
            return Err(AccountError::Corrupt);
        }
        tx.commit().await?;
        Ok(t)
    }

    /// Accepts the other realm's offer `offer` for `subject`: this realm's half is committed
    /// and its Claim stated; returns the token to carry back.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn accept_binding(
        &self,
        subject: [u8; 16],
        offer: &str,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Bound, AccountError> {
        let Some(binding) = binding_of(offer) else {
            return Ok(Bound::Refused);
        };
        let secret = access_crypto::random::bytes::<32>().map_err(|_| AccountError::Corrupt)?;
        let back = token(binding, &secret);
        let (own, peer) = (token_digest(&back), token_digest(offer));
        let mut tx = self.begin().await?;
        let fresh =
            tx.0.insert_binding_half(&NewHalf {
                binding,
                subject,
                role: "accept",
                proof: INVITE_TOKEN,
                secret_hash: &own,
                peer_evidence: Some(&peer),
                now_ms,
                expires_ms: now_ms.saturating_add(OFFER_TTL_MS),
            })
            .await?;
        if !fresh {
            tx.commit().await?;
            return Ok(Bound::Refused);
        }
        self.state_half(&mut tx, subject, binding, &peer, who)
            .await?;
        tx.commit().await?;
        Ok(Bound::Committed(Some(back)))
    }

    /// Completes `subject`'s offer with the other realm's token `back`: this realm's half is
    /// committed and its Claim stated.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn complete_binding(
        &self,
        subject: [u8; 16],
        back: &str,
        now_ms: u64,
        who: &Actor<'_>,
    ) -> Result<Bound, AccountError> {
        let Some(binding) = binding_of(back) else {
            return Ok(Bound::Refused);
        };
        let peer = token_digest(back);
        let mut tx = self.begin().await?;
        let own =
            tx.0.binding_halves_of(subject)
                .await?
                .into_iter()
                .any(|h| h.binding == binding && h.role == "offer" && h.state == "offered");
        if !own
            || !tx
                .0
                .commit_binding_half(binding, subject, &peer, now_ms)
                .await?
        {
            tx.commit().await?;
            return Ok(Bound::Refused);
        }
        self.state_half(&mut tx, subject, binding, &peer, who)
            .await?;
        tx.commit().await?;
        Ok(Bound::Committed(None))
    }

    async fn state_half(
        &self,
        tx: &mut crate::adapters::pg::PgTx,
        subject: [u8; 16],
        binding: [u8; 16],
        peer: &[u8; 32],
        who: &Actor<'_>,
    ) -> Result<(), AccountError> {
        let target = self.realm.external(subject)?;
        tx.audit(&access_store::audit::AuditEvent {
            event_type: "account.linked",
            actor: who.actor,
            target: &target,
            correlation: who.correlation,
        })
        .await?;
        let at = tx.server_time().await?;
        claims::emit(
            tx,
            &crate::domain::claims::identity_binding(
                subject,
                BindingKind::Person,
                &evidence(binding, peer),
                at,
            ),
        )
        .await
    }

    /// The binding halves of `subject`.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn binding_halves(
        &self,
        subject: [u8; 16],
    ) -> Result<Vec<BindingHalf>, AccountError> {
        let mut tx = self.begin().await?;
        let rows = tx.0.binding_halves_of(subject).await?;
        tx.commit().await?;
        Ok(rows)
    }
}
