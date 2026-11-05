//! The status list publisher over PostgreSQL and the authority signer, and the entry a
//! projection family takes when it opens.

use std::path::PathBuf;

use access_internal_api::events::{Event, Source};
use access_kernel::digest::Digest;
use access_kernel::status::CWT_CONTENT_TYPE;
use access_kernel::verify::key_scope::KeyUsage;
use access_store::Pool;
use access_store::projections::{Family, revoke_family};
use access_store::scope::DomainId;
use access_store::status::{self, List, Publication, Snapshot};

use super::{CAPACITY, ListSigner, Lists, list_uri};
use crate::CoreError;

/// Lists read through `access_app` and publications recorded through `access_sequencer`.
#[derive(Clone)]
pub struct PgLists {
    /// The `access_app` pool.
    pub app: Pool,
    /// The `access_sequencer` pool.
    pub sequencer: Pool,
}

fn scope(domain: Digest) -> DomainId {
    DomainId::from_bytes(domain.0)
}

impl Lists for PgLists {
    async fn lists(&self, domain: Digest) -> Result<Vec<List>, CoreError> {
        Ok(status::lists(&self.app, &scope(domain)).await?)
    }

    async fn snapshot(&self, domain: Digest, uri: &str) -> Result<Option<Snapshot>, CoreError> {
        Ok(status::snapshot(&self.app, &scope(domain), uri).await?)
    }

    async fn latest(&self, domain: Digest, uri: &str) -> Result<Option<Publication>, CoreError> {
        Ok(status::latest(&self.app, &scope(domain), uri).await?)
    }

    async fn record(&self, domain: Digest, p: &Publication) -> Result<bool, CoreError> {
        Ok(status::publish(&self.sequencer, &scope(domain), p).await?)
    }
}

/// The authority signer at a socket, opening a domain's keyring when it does not know it.
#[derive(Clone, Debug)]
pub struct SignerSocket(pub PathBuf);

impl ListSigner for SignerSocket {
    async fn sign(
        &self,
        domain: Digest,
        payload: Vec<u8>,
        at: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        use access_authority_signer::adapters::call;
        use access_authority_signer::protocol::{Request, Response};
        let request = Request::Sign {
            domain,
            usage: KeyUsage::StatusList,
            content_type: String::from(CWT_CONTENT_TYPE),
            payload,
            at,
        };
        for _ in 0..2 {
            match call(&self.0, &request).await {
                Ok(Response::Signed { sign1, excerpt }) => return Ok((sign1, excerpt)),
                Ok(Response::Error(code)) if code == "signer-unknown-domain" => {
                    if !crate::adapters::open_keyring(&self.0, domain).await {
                        return Err("signer-unknown-domain");
                    }
                }
                Ok(Response::Error(code)) => return Err(crate::adapters::signer_reason(&code)),
                Ok(_) => return Err("signer-error"),
                Err(_) => return Err("signer-unreachable"),
            }
        }
        Err("signer-unknown-domain")
    }
}

/// Opens a projection family of `domain` with its Token Status List entry (OP-150 m.3 (a),
/// §11.20): the next entry of the domain's newest list under `api_base`, a new list when that
/// one is full. Revoking the family (`access_store::projections::revoke_family`) sets the
/// entry; the publisher signs it in the next list. `None` when the family is already open.
///
/// # Errors
/// [`CoreError::Store`].
pub async fn open_family(
    sequencer: &Pool,
    api_base: &str,
    domain: Digest,
    family: &Family,
) -> Result<Option<(String, u64)>, CoreError> {
    Ok(
        status::open_family_with_entry(sequencer, &scope(domain), family, CAPACITY, |n| {
            list_uri(api_base, &domain, n)
        })
        .await?,
    )
}

/// Revokes every live projection family of `holder` at `pos`, the position of the Exercise or
/// Claim `source` that ended it (§9.9.3 k.6, P50), setting each family's status entry, and
/// returns one `projection-invalidated` event per family it revoked, effective `at`, for the
/// caller to deliver. A family another path revoked first gives no event here.
///
/// # Errors
/// [`CoreError::Store`].
pub async fn revoke_holder(
    sequencer: &Pool,
    domain: Digest,
    holder: &[u8; 16],
    (pos, source, at): (u64, Source, u64),
) -> Result<Vec<Event>, CoreError> {
    let d = scope(domain);
    let mut out = Vec::new();
    for f in status::live_families(sequencer, &d, holder).await? {
        if revoke_family(sequencer, &d, &f.family, pos).await? {
            out.push(Event::projection_invalidated(
                domain,
                source,
                Digest(f.root_exercise),
                at,
            ));
        }
    }
    Ok(out)
}
