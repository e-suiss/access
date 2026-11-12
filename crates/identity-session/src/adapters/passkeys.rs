//! The PostgreSQL passkey registry (CMP-15.7, OP-146 m.9): realm-scoped, soft delete only
//! (OP-73). Registering stores the public material and a sibling `identity_credentials` row of
//! kind `webauthn` in one transaction, sealed under the subject's DEK like every credential
//! (OP-145), so the last-method rule (TN-68) and crypto-shredding cover passkeys.

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::Realm;
use access_identity_account::app::sealing::{seal, subject_key};
use access_identity_account::domain::events::{CredentialChange, EventOrder};
use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::domain::cose::CoseAlgorithm;
use access_identity_webauthn::domain::credential::{AttestationKind, CredentialRecord};
use access_identity_webauthn::domain::ids::{Aaguid, CredentialId, RealmId, UserHandle};
use access_identity_webauthn::domain::prf::{PrfConfig, PrfSalt};
use access_identity_webauthn::ports::{CredentialRegistry, Inserted};
use access_store::Pool;
use access_store::accounts::{NewCredential, Revoke, SealedSecret};
use access_store::identity::{RealmId as StoreRealm, TenantId, TenantTx};
use access_store::passkeys::PasskeyRow;
use suiss_crypto::envelope::Kek;

/// The credential kind of a passkey's sibling row.
pub const WEBAUTHN: &str = "webauthn";

/// The registry of one tenant.
pub struct PgPasskeys<'a> {
    /// `access_app` pool.
    pub pool: &'a Pool,
    /// Tenant.
    pub tenant: TenantId,
    /// The realm KEK that wraps subject DEKs.
    pub kek: &'a (dyn Kek + Sync),
    /// The cell's id key.
    pub ids: &'a IdKey,
}

fn failed(e: impl core::fmt::Display) -> WebAuthnError {
    WebAuthnError::Registry(e.to_string())
}

fn attestation_text(a: &AttestationKind) -> String {
    match a {
        AttestationKind::None => "none".to_owned(),
        AttestationKind::Verified(fmt) => format!("verified:{fmt}"),
        AttestationKind::Unverified(fmt) => format!("unverified:{fmt}"),
    }
}

fn attestation_kind(text: &str) -> Result<AttestationKind, WebAuthnError> {
    match text {
        "none" => Ok(AttestationKind::None),
        "verified" => Ok(AttestationKind::Verified(String::from("packed"))),
        other => match (
            other.strip_prefix("verified:"),
            other.strip_prefix("unverified:"),
        ) {
            (Some(f), _) => Ok(AttestationKind::Verified(f.to_owned())),
            (_, Some(f)) => Ok(AttestationKind::Unverified(f.to_owned())),
            _ => Err(failed("attestation")),
        },
    }
}

fn algorithm_name(alg: CoseAlgorithm) -> &'static str {
    match alg {
        CoseAlgorithm::Esp256 => "esp256",
        CoseAlgorithm::Es256 => "es256",
        CoseAlgorithm::Ed25519 => "ed25519",
        CoseAlgorithm::EdDsa => "eddsa",
        CoseAlgorithm::Rs256 => "rs256",
    }
}

fn to_row(r: &CredentialRecord, credential: [u8; 16]) -> Result<PasskeyRow, WebAuthnError> {
    let secs = |v: u64| i64::try_from(v).map_err(failed);
    Ok(PasskeyRow {
        raw_id: r.id.as_bytes().to_vec(),
        credential,
        user_handle: r.user.as_bytes().to_vec(),
        public_key: r.public_key.clone(),
        alg: i32::try_from(r.alg.id()).map_err(failed)?,
        sign_count: i64::from(r.sign_count),
        backup_eligible: r.backup_eligible,
        backup_state: r.backup_state,
        user_verified: r.user_verified,
        aaguid: r.aaguid.0.to_vec(),
        transports: r.transports.clone(),
        attestation: attestation_text(&r.attestation),
        cred_protect: r.cred_protect.map(i16::from),
        discoverable: r.discoverable,
        prf_enabled: r.prf.as_ref().map(|p| p.enabled),
        prf_first: r.prf.as_ref().map(|p| p.first.0.to_vec()),
        prf_second: r.prf.as_ref().and_then(|p| p.second.map(|s| s.0.to_vec())),
        created_s: secs(r.created_at)?,
        last_used_s: r.last_used_at.map(secs).transpose()?,
        deleted_s: r.deleted_at.map(secs).transpose()?,
    })
}

fn salt(v: &[u8]) -> Result<PrfSalt, WebAuthnError> {
    <[u8; 32]>::try_from(v)
        .map(PrfSalt)
        .map_err(|_| failed("prf salt"))
}

fn from_row(realm: RealmId, p: PasskeyRow) -> Result<CredentialRecord, WebAuthnError> {
    let secs = |v: i64| u64::try_from(v).map_err(failed);
    let prf = match (p.prf_enabled, p.prf_first.as_deref()) {
        (Some(enabled), Some(first)) => Some(PrfConfig {
            enabled,
            first: salt(first)?,
            second: p.prf_second.as_deref().map(salt).transpose()?,
        }),
        _ => None,
    };
    Ok(CredentialRecord {
        realm,
        id: CredentialId::new(&p.raw_id).ok_or_else(|| failed("credential id"))?,
        user: UserHandle::from_slice(&p.user_handle).ok_or_else(|| failed("user handle"))?,
        public_key: p.public_key,
        alg: CoseAlgorithm::from_id(i64::from(p.alg)).ok_or_else(|| failed("algorithm"))?,
        sign_count: u32::try_from(p.sign_count).map_err(failed)?,
        backup_eligible: p.backup_eligible,
        backup_state: p.backup_state,
        user_verified: p.user_verified,
        aaguid: Aaguid(<[u8; 16]>::try_from(p.aaguid.as_slice()).map_err(failed)?),
        transports: p.transports,
        attestation: attestation_kind(&p.attestation)?,
        cred_protect: p
            .cred_protect
            .map(u8::try_from)
            .transpose()
            .map_err(failed)?,
        discoverable: p.discoverable,
        prf,
        created_at: secs(p.created_s)?,
        last_used_at: p.last_used_s.map(secs).transpose()?,
        deleted_at: p.deleted_s.map(secs).transpose()?,
    })
}

impl PgPasskeys<'_> {
    async fn begin(&self, realm: RealmId) -> Result<TenantTx, WebAuthnError> {
        TenantTx::begin(
            self.pool,
            self.tenant,
            StoreRealm::from_bytes(*realm.as_bytes()),
        )
        .await
        .map_err(failed)
    }

    fn sealed(
        &self,
        realm: RealmId,
        subject: &access_store::accounts::SubjectRow,
        public_key: &[u8],
    ) -> Result<SealedSecret, WebAuthnError> {
        let r = Realm {
            tenant: self.tenant,
            realm: StoreRealm::from_bytes(*realm.as_bytes()),
            kek: self.kek,
            ids: self.ids,
        };
        let dek = subject_key(&r, subject).map_err(failed)?;
        seal(&r, &dek, &subject.id, WEBAUTHN, public_key).map_err(failed)
    }

    async fn insert_record(&self, record: &CredentialRecord) -> Result<Inserted, WebAuthnError> {
        let mut tx = self.begin(record.realm).await?;
        if tx
            .passkey_exists(record.id.as_bytes())
            .await
            .map_err(failed)?
        {
            tx.rollback().await.map_err(failed)?;
            return Ok(Inserted::Duplicate);
        }
        let subject = tx
            .subject_by_user_handle(record.user.as_bytes())
            .await
            .map_err(failed)?
            .ok_or_else(|| failed("unknown user handle"))?;
        let row = tx
            .subject(subject, true)
            .await
            .map_err(failed)?
            .ok_or_else(|| failed("unknown subject"))?;
        let sealed = self.sealed(record.realm, &row, &record.public_key)?;
        let credential = tx
            .insert_credential(&NewCredential {
                subject,
                kind: WEBAUTHN,
                algorithm: algorithm_name(record.alg),
                sealed: &sealed,
            })
            .await
            .map_err(failed)?;
        if !tx
            .insert_passkey(&to_row(record, credential)?)
            .await
            .map_err(failed)?
        {
            tx.rollback().await.map_err(failed)?;
            return Ok(Inserted::Duplicate);
        }
        // OP-151 m.3 (i)
        let at = access_store::authority::server_time(self.pool)
            .await
            .map_err(failed)?;
        let event = EventOrder::credential(
            access_identity_account::app::events::new_id().map_err(failed)?,
            record.realm.as_bytes(),
            &self
                .ids
                .encode(access_identity_account::app::SUBJECT_PREFIX, subject)
                .map_err(failed)?,
            WEBAUTHN,
            CredentialChange::Added,
            at,
        );
        // OP-67 m.1
        let trace = access_telemetry::trace::current_header();
        tx.outbox_traced(
            event.kind.outbox_kind(),
            &event.to_outbox().map_err(failed)?,
            trace.as_deref(),
        )
        .await
        .map_err(failed)?;
        tx.commit().await.map_err(failed)?;
        Ok(Inserted::Stored)
    }

    async fn find_record(
        &self,
        realm: RealmId,
        id: &CredentialId,
    ) -> Result<Option<CredentialRecord>, WebAuthnError> {
        let mut tx = self.begin(realm).await?;
        let row = tx.passkey(id.as_bytes()).await.map_err(failed)?;
        tx.commit().await.map_err(failed)?;
        row.map(|p| from_row(realm, p)).transpose()
    }

    async fn list_records(
        &self,
        realm: RealmId,
        user: &UserHandle,
    ) -> Result<Vec<CredentialRecord>, WebAuthnError> {
        let mut tx = self.begin(realm).await?;
        let rows = tx.passkeys(user.as_bytes()).await.map_err(failed)?;
        tx.commit().await.map_err(failed)?;
        rows.into_iter().map(|p| from_row(realm, p)).collect()
    }

    async fn record_use_of(
        &self,
        realm: RealmId,
        id: &CredentialId,
        sign_count: u32,
        backup_state: bool,
        at: u64,
    ) -> Result<(), WebAuthnError> {
        let mut tx = self.begin(realm).await?;
        let at = i64::try_from(at).map_err(failed)?;
        tx.passkey_used(id.as_bytes(), i64::from(sign_count), backup_state, at)
            .await
            .map_err(failed)?;
        if let Some(p) = tx.passkey(id.as_bytes()).await.map_err(failed)? {
            tx.credential_used(p.credential).await.map_err(failed)?;
        }
        tx.commit().await.map_err(failed)
    }

    async fn delete_record(
        &self,
        realm: RealmId,
        id: &CredentialId,
        at: u64,
    ) -> Result<(), WebAuthnError> {
        let mut tx = self.begin(realm).await?;
        let Some(p) = tx.passkey(id.as_bytes()).await.map_err(failed)? else {
            return tx.commit().await.map_err(failed);
        };
        let Some(subject) = tx
            .subject_by_user_handle(&p.user_handle)
            .await
            .map_err(failed)?
        else {
            return Err(failed("unknown user handle"));
        };
        match tx
            .revoke_credential(subject, p.credential)
            .await
            .map_err(failed)?
        {
            Revoke::Done | Revoke::Missing => {}
            Revoke::LastMethod => {
                tx.rollback().await.map_err(failed)?;
                return Err(failed("last authentication method (TN-68)"));
            }
        }
        let at = i64::try_from(at).map_err(failed)?;
        tx.passkey_deleted(id.as_bytes(), at)
            .await
            .map_err(failed)?;
        tx.commit().await.map_err(failed)
    }
}

impl CredentialRegistry for PgPasskeys<'_> {
    fn insert(
        &self,
        record: &CredentialRecord,
    ) -> impl Future<Output = Result<Inserted, WebAuthnError>> + Send {
        self.insert_record(record)
    }

    fn find(
        &self,
        realm: RealmId,
        id: &CredentialId,
    ) -> impl Future<Output = Result<Option<CredentialRecord>, WebAuthnError>> + Send {
        self.find_record(realm, id)
    }

    fn list(
        &self,
        realm: RealmId,
        user: &UserHandle,
    ) -> impl Future<Output = Result<Vec<CredentialRecord>, WebAuthnError>> + Send {
        self.list_records(realm, user)
    }

    fn record_use(
        &self,
        realm: RealmId,
        id: &CredentialId,
        sign_count: u32,
        backup_state: bool,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        self.record_use_of(realm, id, sign_count, backup_state, at)
    }

    fn soft_delete(
        &self,
        realm: RealmId,
        id: &CredentialId,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        self.delete_record(realm, id, at)
    }
}
