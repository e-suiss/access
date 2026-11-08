//! The account owner's own credential export (§12.3.7, §18.1, TN-86, B19, MKT-D9): the stored
//! password hash and the authenticator app seeds, free and without a commercial cap, after a
//! fresh step-up. The password hash leaves without the realm's pepper, in the form another
//! provider imports; a seed leaves as base32 with its RFC 6238 parameters. Passkeys stay bound
//! to their relying party ID and are not part of it.

use access_crypto::Secret;
use access_identity_account::app::sealing::{open, open_password, subject_key};
use access_identity_account::domain::legacy;
use access_identity_account::ports::AccountTx as _;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};

use super::{Auth, Notifier, TOTP, audit, hex_decode};
use crate::SessionError;
use crate::domain::codes::base32;
use crate::ports::{Clock, Random, SessionDb};

/// The password part of an export. Never printed.
pub struct PasswordExport {
    /// The scheme: `argon2id`, or the imported `legacy-<scheme>` not yet migrated.
    pub algorithm: String,
    /// The hash as stored, without the realm's pepper.
    pub hash: Secret<String>,
    /// An imported hash's pepper and pre-hash, as it was imported.
    pub transform: Option<Secret<String>>,
}

/// What the export holds. Never printed.
#[derive(Default)]
pub struct CredentialExport {
    /// The password, if the account has a hash here.
    pub password: Option<PasswordExport>,
    /// The authenticator app seeds, base32 (RFC 4648), SHA-1, 6 digits, 30 seconds.
    pub totp: Vec<Secret<String>>,
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    /// The owner's credential export; the caller has checked the fresh step-up (TN-86).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn export_credentials(
        &self,
        subject: [u8; 16],
        correlation: &str,
    ) -> Result<CredentialExport, SessionError> {
        let mut tx = self.begin().await?;
        let row = tx
            .subject(subject, false)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let mut out = CredentialExport::default();
        for c in tx.credentials(subject, "password").await? {
            if c.algorithm == legacy::IDP {
                continue;
            }
            let (stored, _) = open_password(&self.realm, &dek, &subject, &c.sealed)?;
            out.password = Some(
                if legacy::is_legacy(&c.algorithm) && c.algorithm != legacy::ARGON2 {
                    let (spec, hash) = stored
                        .expose()
                        .split_once('\n')
                        .ok_or(SessionError::Corrupt)?;
                    PasswordExport {
                        algorithm: c.algorithm.clone(),
                        hash: Secret::new(hash.to_owned()),
                        transform: (!spec.is_empty()).then(|| Secret::new(spec.to_owned())),
                    }
                } else {
                    PasswordExport {
                        algorithm: c.algorithm.clone(),
                        hash: stored,
                        transform: None,
                    }
                },
            );
        }
        for c in tx.credentials(subject, TOTP).await? {
            let seed = open(&self.realm, &dek, &subject, TOTP, &c.sealed)?;
            let bytes = hex_decode(seed.expose()).ok_or(SessionError::Corrupt)?;
            out.totp.push(Secret::new(base32(&bytes)));
        }
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "account.credentials_exported",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(out)
    }
}
