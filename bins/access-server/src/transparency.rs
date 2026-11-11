//! The transparency routes over the store (§9.16, T19, OP-158 m.3 (c), (d)): the witnessed
//! checkpoints of a domain and the inclusion proof bundle of one of its records, opening only
//! the `artifacts` field (§17.6.1 rule 5).

use access_authority_sequencer::witness::Target;
use access_http::transparency::{Checkpoints, Declared, InclusionError, Listing};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::authority::{read_head, read_log};
use access_store::scope::DomainId;
use access_store::witness::{cosigns, latest_witnessed, leaf_hashes, witnessed_through};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_ledger::checkpoint::proof::{inclusion, tile, tile_width};

/// The only field an inclusion bundle opens (§17.6.1 rule 5, T19).
pub(crate) const OPENED: &str = "artifacts";

/// The store adapter.
pub(crate) struct PgCheckpoints {
    /// `access_app`.
    pub(crate) app: Pool,
    /// The declared witnesses.
    pub(crate) witnesses: Vec<Target>,
}

fn down<E>(_: E) -> InclusionError {
    InclusionError::Unavailable
}

/// The checkpoint note with its independent witnesses' cosignature lines.
async fn cosigned(
    app: &Pool,
    id: &DomainId,
    issued_at: u64,
    note: &str,
) -> Result<String, InclusionError> {
    let mut out = note.to_owned();
    for c in cosigns(app, id, issued_at).await.map_err(down)? {
        out.push_str(&c.line);
    }
    Ok(out)
}

impl Checkpoints for PgCheckpoints {
    async fn listing(&self, domain: Digest) -> Result<Option<Listing>, InclusionError> {
        let id = DomainId::from_bytes(domain.0);
        if read_head(&self.app, &id).await.is_err() {
            return Ok(None);
        }
        let through = witnessed_through(&self.app, &id).await.map_err(down)?;
        let latest = match latest_witnessed(&self.app, &id, None).await.map_err(down)? {
            Some(row) => Some((
                cosigned(&self.app, &id, row.issued_at, &row.note).await?,
                row.excerpt,
            )),
            None => None,
        };
        Ok(Some(Listing {
            witnessed_through: through,
            latest,
            witnesses: self
                .witnesses
                .iter()
                .map(|t| Declared {
                    vkey: t.vkey.clone(),
                    operator: t.operator.clone(),
                    independent: t.independent,
                })
                .collect(),
        }))
    }

    async fn inclusion(
        &self,
        domain: Digest,
        size: u64,
        pos: u64,
    ) -> Result<Vec<u8>, InclusionError> {
        let id = DomainId::from_bytes(domain.0);
        let row = latest_witnessed(&self.app, &id, Some(size))
            .await
            .map_err(down)?
            .ok_or(InclusionError::NotWitnessed)?;
        let record = read_log(&self.app, &id, pos, pos)
            .await
            .map_err(down)?
            .into_iter()
            .next()
            .ok_or(InclusionError::Unknown)?;
        let envelope = RecordEnvelope::from_bytes(&record.envelope).map_err(down)?;
        // §17.6.1 rule 5
        let disclosure = envelope.disclose(|name| name == OPENED).map_err(down)?;
        let leaves = leaf_hashes(&self.app, &id, 0, size).await.map_err(down)?;
        let path = inclusion(leaves.as_slice(), pos, size).map_err(|_| InclusionError::Unknown)?;
        let note = cosigned(&self.app, &id, row.issued_at, &row.note).await?;
        let bundle = Value::Map(vec![
            (Value::text("checkpoint"), Value::text(&note)),
            (
                Value::text("disclosure"),
                Value::Bytes(disclosure.to_bytes().map_err(down)?),
            ),
            (Value::text("excerpt"), Value::Bytes(row.excerpt)),
            (
                Value::text("path"),
                Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
            ),
            (Value::text("size"), Value::Unsigned(size)),
        ]);
        dcbor::encode(&bundle, Limits::CEILING).map_err(down)
    }

    async fn tile(
        &self,
        domain: Digest,
        level: u32,
        index: u64,
        width: u64,
    ) -> Result<Vec<u8>, InclusionError> {
        let id = DomainId::from_bytes(domain.0);
        let row = latest_witnessed(&self.app, &id, None)
            .await
            .map_err(down)?
            .ok_or(InclusionError::NotWitnessed)?;
        if tile_width(row.size, level, index) != width {
            return Err(InclusionError::Unknown);
        }
        let leaves = leaf_hashes(&self.app, &id, 0, row.size)
            .await
            .map_err(down)?;
        let hashes =
            tile(leaves.as_slice(), level, index, width).map_err(|_| InclusionError::Unknown)?;
        Ok(hashes.concat())
    }
}
