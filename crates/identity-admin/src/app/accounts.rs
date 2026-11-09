//! The account changes of catalog 3 whose identity-plane work follows the bound decision
//! (OP-153 m.25 (b)): an administrator's account import over a file the change names by its
//! SHA-256 (TN-85, OP-153 m.19 (d)), and the reserved migration export to the key the receiving
//! deployment bound to it (TN-86). The decision is bound and recorded first; the file's lines
//! are then imported one account at a time, as `access-server import-accounts` does, with the
//! Exercise as their audit correlation, and an export's bundle is sealed and answered once. An
//! administrator's cross-realm binding (OP-153 m.18 (e)) commits its half here too, and the
//! offering half answers with the realm-signed binding offer the peer realm verifies.

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::import::{Report, file_of, import_all};
use access_kernel::json::b64url_encode;
use access_store::identity::TenantTx;
use suiss_crypto::dcbor::{self, Limits};

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::domain::binding_offer::{
    ADMIN_EXERCISE, BindingOffer, OFFER_TTL_S, OfferProof, TYP, pair_digest,
};
use access_identity_account::ports::AccountTx as _;
use access_kernel::digest::Digest;
use access_store::federation::NewHalf;
use access_store::identity::RealmId;

use super::{Admin, Applied, ClientSecret, DECIDED_BY, Proposal};
use crate::AdminError;
use crate::domain::accounts::{AccountBind, Bundle};
use crate::domain::{Change, Invalid};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Applies `idp.account.import` `p` with the actor's `ais`, then imports `content`, whose
    /// SHA-256 and line count the change names (TN-85, OP-153 m.19 (d)); a retry of a decision
    /// already written imports nothing again.
    ///
    /// # Errors
    /// [`AdminError`]: content the change does not name is [`Invalid::Body`].
    pub async fn import_accounts(
        &self,
        p: &Proposal,
        ais: Vec<u8>,
        content: &str,
    ) -> Result<(Applied, Option<Report>), AdminError> {
        let Change::AccountImport(named) = &p.change else {
            return Err(Invalid::Body.into());
        };
        let (file, lines) = file_of(content);
        if file != named.file || lines != u64::from(named.accounts) {
            return Err(Invalid::Body.into());
        }
        let vault = self
            .keys
            .vault(p.realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let applied = Box::pin(self.apply(p, ais)).await?;
        let Applied::Written { exercise, .. } = &applied else {
            return Ok((applied, None));
        };
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let correlation = b64url_encode(&exercise.0);
        let who = access_identity_account::app::Actor {
            actor: DECIDED_BY,
            correlation: &correlation,
        };
        let db = PgAccounts::sealed(self.app.clone(), vault.clone());
        let report = import_all(&db, &realm, content, &who)
            .await
            .map_err(|(n, e)| AdminError::Unavailable(format!("import line {n}: {e}")))?;
        tracing::info!(
            event = "accounts.imported",
            created = report.created,
            legacy = report.legacy,
            skipped = report.skipped.len(),
            "account import finished (TN-85)"
        );
        Ok((applied, Some(report)))
    }

    /// Applies the reserved `idp.account.migration_export` `p` with the actor's `ais`, then
    /// seals every active account's import line to the change's recipient key (TN-86, OP-153
    /// m.19 (d), m.25 (i)); the bundle's dCBOR is answered once and never kept. A retry of a
    /// decision already written seals nothing.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn export_accounts(
        &self,
        p: &Proposal,
        ais: Vec<u8>,
    ) -> Result<(Applied, Option<Vec<u8>>), AdminError> {
        let Change::MigrationExport(e) = &p.change else {
            return Err(Invalid::Body.into());
        };
        let vault = self
            .keys
            .vault(p.realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let applied = Box::pin(self.apply(p, ais)).await?;
        if !matches!(applied, Applied::Written { .. }) {
            return Ok((applied, None));
        }
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let issuer = access_store::idp::governance(&mut t)
            .await?
            .and_then(|g| g.issuer)
            .ok_or(AdminError::NoRealm)?;
        let mut subjects = Vec::new();
        let mut after = [0; 16];
        loop {
            let page = access_store::idp::realm::accounts(&mut t, after, 500).await?;
            let Some(last) = page.last().map(|a| a.subject) else {
                break;
            };
            subjects.extend(page.iter().map(|a| a.subject));
            if page.len() < 500 {
                break;
            }
            after = last;
        }
        let exported_at = t.server_time().await?;
        t.commit().await?;
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*vault.kek,
            ids: self.ids,
        };
        let db = PgAccounts::sealed(self.app.clone(), vault.clone());
        let (lines, accounts) =
            access_identity_account::app::export::export_lines(&db, &realm, &subjects)
                .await
                .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        let recipient = access_kernel::verify::key_scope::thumbprint(
            &access_kernel::verify::cose::PublicKey::P256(e.recipient.clone()),
        );
        let sealer = access_crypto::migration_bundle::Sealer::new(&e.recipient, &recipient)
            .map_err(|_| AdminError::Invalid(Invalid::Body))?;
        let mut bundle = Bundle {
            realm: issuer,
            exported_at,
            accounts,
            recipient,
            epk: sealer.epk().to_vec(),
            nonce: sealer.nonce(),
            ciphertext: Vec::new(),
        };
        let aad = dcbor::encode(&bundle.aad(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
        bundle.ciphertext = sealer
            .seal(&aad, lines.as_bytes())
            .map_err(|_| AdminError::Encode)?;
        let bytes =
            dcbor::encode(&bundle.to_value(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
        tracing::info!(
            event = "accounts.exported",
            accounts,
            "migration export sealed (TN-86)"
        );
        Ok((applied, Some(bytes)))
    }
}

/// Why an administrator's binding offer is refused (OP-153 m.18 (e)).
pub const BINDING_OFFER_REFUSED: &str = "binding-offer-refused";

/// Context of the digest an offering half keeps of the Exercise that bound it.
const EXERCISE_CONTEXT: &[u8] = b"access/admin-binding-exercise/v1\0";

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// The issuer of the tenant's realm `realm`, when it is one (OP-153 m.18 (e)).
    async fn peer_issuer(&self, p: &Proposal, realm: [u8; 16]) -> Result<String, AdminError> {
        if realm == *p.realm.as_bytes() {
            return Err(Invalid::NoAccount.into());
        }
        let mut t = TenantTx::begin(self.app, p.tenant, RealmId::from_bytes(realm)).await?;
        let issuer = access_store::idp::governance(&mut t)
            .await?
            .and_then(|g| g.issuer);
        t.commit().await?;
        issuer.ok_or_else(|| Invalid::NoAccount.into())
    }

    /// Applies `idp.account.bind` `p` with the actor's `ais` (OP-153 m.18 (e), m.25 (b)): a half
    /// that accepts first verifies `offer`, the peer realm's realm-signed binding offer the change
    /// names by its SHA-256, against the peer realm's keys; it must name this pair and be for this
    /// realm. The offering half's answer carries its own offer.
    ///
    /// # Errors
    /// [`AdminError`]: an offer that does not verify is refused with
    /// [`BINDING_OFFER_REFUSED`].
    pub async fn bind_account(
        &self,
        p: &Proposal,
        ais: Vec<u8>,
        offer: Option<&str>,
    ) -> Result<Applied, AdminError> {
        let Change::AccountBind(b) = &p.change else {
            return Err(Invalid::Body.into());
        };
        let peer = self.peer_issuer(p, b.peer_realm).await?;
        match (b.offer, offer) {
            (None, None) => {}
            (Some(named), Some(token)) => {
                if suiss_crypto::digest::sha256(token.as_bytes()) != named {
                    return Err(Invalid::Body.into());
                }
                let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
                let own = access_store::idp::governance(&mut t)
                    .await?
                    .and_then(|g| g.issuer)
                    .ok_or(AdminError::NoRealm)?;
                let now = t.server_time().await?;
                t.commit().await?;
                let jwks = self
                    .keys
                    .jwks(RealmId::from_bytes(b.peer_realm))
                    .await
                    .map_err(|e| AdminError::Unavailable(e.0))?;
                let refused = || AdminError::Refused(String::from(BINDING_OFFER_REFUSED));
                let keys = access_identity_oauth::domain::jwt::realm_key_set(jwks.as_bytes())
                    .map_err(|_| refused())?;
                let verified = access_kernel::verify::jws::verify_compact(
                    &access_crypto::AwsLcBackend,
                    token,
                    &keys,
                    TYP,
                    access_kernel::verify::jws::Origin::Native,
                )
                .map_err(|_| refused())?;
                let claims: serde_json::Value =
                    serde_json::from_slice(&verified.payload).map_err(|_| refused())?;
                let o =
                    BindingOffer::from_claims(&claims, &own, now / 1000).map_err(|_| refused())?;
                let (offering, accepting) = b.sides(*p.realm.as_bytes());
                let pair = pair_digest(offering, accepting);
                if o.issuer != peer
                    || o.proof != OfferProof::AdminExercise
                    || o.subject != pair
                    || o.binding.as_slice() != pair.get(..16).unwrap_or_default()
                {
                    return Err(refused());
                }
            }
            _ => return Err(Invalid::Body.into()),
        }
        Box::pin(self.apply(p, ais)).await
    }

    /// Commits this realm's half of an administrator's binding against the bound decision
    /// (§12.1.1, TN-2, TN-65, OP-153 m.18 (e)): both halves share the binding id and the
    /// [`pair_digest`], and each realm's issuer states its `identity_binding_person` Claim; no
    /// row names the other realm's account in the clear. The offering half returns its
    /// realm-signed offer for the peer realm.
    pub(super) async fn bind_half(
        &self,
        t: &mut PgTx,
        p: &Proposal,
        governing: &access_store::idp::Governing,
        b: AccountBind,
        exercise: &Digest,
    ) -> Result<Option<ClientSecret>, AdminError> {
        let (offering, accepting) = b.sides(*p.realm.as_bytes());
        let pair = pair_digest(offering, accepting);
        let mut binding = [0; 16];
        binding.copy_from_slice(pair.get(..16).ok_or(AdminError::Encode)?);
        let secret_hash = b.offer.unwrap_or_else(|| {
            let mut m = EXERCISE_CONTEXT.to_vec();
            m.extend_from_slice(&exercise.0);
            suiss_crypto::digest::sha256(&m)
        });
        let now = t.0.server_time().await?;
        let fresh =
            t.0.insert_binding_half(&NewHalf {
                binding,
                subject: b.subject,
                role: if b.offer.is_some() { "accept" } else { "offer" },
                proof: ADMIN_EXERCISE,
                secret_hash: &secret_hash,
                peer_evidence: Some(&pair),
                now_ms: now,
                expires_ms: now.saturating_add(OFFER_TTL_S.saturating_mul(1000)),
            })
            .await?;
        if !fresh {
            return Err(AdminError::Conflict);
        }
        let target = self
            .ids
            .encode(access_identity_account::app::SUBJECT_PREFIX, b.subject)?;
        let correlation = b64url_encode(&exercise.0);
        t.audit(&access_store::audit::AuditEvent {
            event_type: "account.linked",
            actor: DECIDED_BY,
            target: &target,
            correlation: &correlation,
        })
        .await
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        let mut evidence = binding.to_vec();
        evidence.extend_from_slice(ADMIN_EXERCISE.as_bytes());
        evidence.extend_from_slice(&pair);
        access_identity_account::app::claims::emit(
            t,
            &access_identity_account::domain::claims::identity_binding(
                b.subject,
                access_kernel::claim::body::BindingKind::Person,
                &evidence,
                now,
            ),
        )
        .await
        .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        if b.offer.is_some() {
            return Ok(None);
        }
        let issuer = governing.issuer.clone().ok_or(AdminError::NoRealm)?;
        let audience = self.peer_issuer(p, b.peer_realm).await?;
        let iat = now / 1000;
        let offer = BindingOffer {
            issuer,
            audience,
            binding,
            proof: OfferProof::AdminExercise,
            subject: pair,
            issued_at: iat,
            expires_at: iat.saturating_add(OFFER_TTL_S),
        };
        let claims = serde_json::to_vec(&offer.claims()).map_err(|_| AdminError::Encode)?;
        let token = self
            .keys
            .sign_jws(p.realm, TYP, &claims, now)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        Ok(Some(ClientSecret(token)))
    }
}

/// Opens a migration bundle sealed to `key` (TN-86): its import lines, which the receiving
/// realm imports with its own `idp.account.import` (TN-85).
///
/// # Errors
/// [`AdminError`]: a bundle that does not open is [`Invalid::Body`].
pub fn open_bundle(
    bundle: &[u8],
    key: &access_crypto::migration_bundle::RecipientKey,
) -> Result<String, AdminError> {
    let value = dcbor::decode(bundle, Limits::CEILING).map_err(|_| Invalid::Body)?;
    let b = Bundle::from_value(&value).ok_or(Invalid::Body)?;
    let public = key.public().map_err(|_| Invalid::Body)?;
    let salt = access_kernel::verify::key_scope::thumbprint(
        &access_kernel::verify::cose::PublicKey::P256(public),
    );
    if salt != b.recipient {
        return Err(Invalid::Body.into());
    }
    let aad = dcbor::encode(&b.aad(), Limits::CEILING).map_err(|_| AdminError::Encode)?;
    let plain = key
        .open((&b.epk, &salt), b.nonce, &aad, &b.ciphertext)
        .map_err(|_| Invalid::Body)?;
    String::from_utf8(plain).map_err(|_| Invalid::Body.into())
}
