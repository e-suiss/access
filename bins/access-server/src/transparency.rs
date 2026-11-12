//! The transparency routes over the store (§9.16, T19, OP-158 m.3 (c), (d)): the witnessed
//! checkpoints of a domain and the inclusion proof bundle of one of its records
//! (`inclusion-bundle.cddl`), whose `record` is the record disclosure with only the
//! `artifacts` field opened (§17.6.1 rule 5).

use access_authority_sequencer::witness::Target;
use access_http::transparency::{Checkpoints, Declared, InclusionError, Listing};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::authority::{read_head, read_log};
use access_store::authority_checkpoint::AuthorityCheckpoint;
use access_store::scope::DomainId;
use access_store::witness::{cosigns, latest_witnessed, leaf_hashes, witnessed_through};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_ledger::checkpoint::proof::{consistency, inclusion, tile, tile_width};
use suiss_ledger::checkpoint::witness::Cosignature;

/// The only field an inclusion bundle opens (§17.6.1 rule 5, T19).
pub(crate) const OPENED: &str = "artifacts";

/// The field a re-anchor bundle opens beside [`OPENED`]: the artefact digest the Kernel checks
/// (CR-45 RA-5, `ARTEFACT_FIELD`).
const PQ_OPENED: &str = access_kernel::verify::key_scope::ARTEFACT_FIELD;

fn pq_cosigns(c: &access_store::pq_checkpoint::PqCheckpoint) -> Value {
    Value::Array(
        c.cosigns
            .iter()
            .map(|w| {
                Value::Map(vec![
                    (Value::text("name"), Value::text(&w.witness)),
                    (Value::text("timestamp"), Value::Unsigned(w.cosigned_at)),
                    (Value::text("sign1"), Value::Bytes(w.sign1.clone())),
                ])
            })
            .collect(),
    )
}

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

/// The checkpoint note with its witnesses' cosignature lines.
async fn cosigned(
    app: &Pool,
    id: &DomainId,
    row: &AuthorityCheckpoint,
) -> Result<String, InclusionError> {
    let mut out = row.note.clone();
    for c in cosigns(app, id, row.size, &row.root).await.map_err(down)? {
        let key = suiss_crypto::note::Verifier::parse(&c.vkey)
            .map_err(|_| InclusionError::Unavailable)?
            .id();
        out.push_str(
            &Cosignature {
                name: c.witness,
                timestamp: c.cosigned_at,
                signature: c.signature,
            }
            .line(key),
        );
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
            Some(row) => Some((cosigned(&self.app, &id, &row).await?, row.excerpt)),
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
        let mut cosignatures = Vec::new();
        for c in cosigns(&self.app, &id, row.size, &row.root)
            .await
            .map_err(down)?
        {
            cosignatures.push(Value::Map(vec![
                (Value::text("name"), Value::text(&c.witness)),
                (Value::text("timestamp"), Value::Unsigned(c.cosigned_at)),
                (Value::text("signature"), Value::Bytes(c.signature.to_vec())),
            ]));
        }
        // OP-158 m.3 (b)
        let bundle = Value::Map(vec![
            (Value::text("domain"), Value::Bytes(domain.0.to_vec())),
            (Value::text("position"), Value::Unsigned(pos)),
            (
                Value::text("record"),
                Value::Bytes(disclosure.to_bytes().map_err(down)?),
            ),
            (Value::text("checkpoint"), Value::text(&row.note)),
            (Value::text("cosignatures"), Value::Array(cosignatures)),
            (
                Value::text("inclusion"),
                Value::Array(path.iter().map(|h| Value::Bytes(h.to_vec())).collect()),
            ),
        ]);
        dcbor::encode(&bundle, Limits::CEILING).map_err(down)
    }

    // CR-45 RA-2, RA-3, OP-159 m.13
    async fn pq_list(&self, domain: Digest) -> Result<Vec<u8>, InclusionError> {
        let id = DomainId::from_bytes(domain.0);
        if read_head(&self.app, &id).await.is_err() {
            return Err(InclusionError::Unknown);
        }
        let rows = access_store::pq_checkpoint::list(&self.app, &id, None, 64)
            .await
            .map_err(down)?;
        let entries = rows
            .iter()
            .map(|c| {
                Value::Map(vec![
                    (Value::text("size"), Value::Unsigned(c.size)),
                    (Value::text("root"), Value::Bytes(c.root.to_vec())),
                    (Value::text("checkpoint"), Value::Bytes(c.sign1.clone())),
                    (Value::text("excerpt"), Value::Bytes(c.excerpt.clone())),
                    (Value::text("cosigns"), pq_cosigns(c)),
                ])
            })
            .collect();
        dcbor::encode(
            &Value::Map(vec![(Value::text("checkpoints"), Value::Array(entries))]),
            Limits::CEILING,
        )
        .map_err(down)
    }

    // CR-45 RA-4, RA-5, OP-159 m.13
    async fn pq_inclusion(
        &self,
        domain: Digest,
        size: u64,
        pos: u64,
    ) -> Result<Vec<u8>, InclusionError> {
        let id = DomainId::from_bytes(domain.0);
        let all = access_store::pq_checkpoint::list(&self.app, &id, None, 1024)
            .await
            .map_err(down)?;
        let cp = all
            .iter()
            .find(|c| c.size == size)
            .ok_or(InclusionError::Unknown)?;
        if cp.cosigns.is_empty() {
            return Err(InclusionError::NotWitnessed);
        }
        let record = read_log(&self.app, &id, pos, pos)
            .await
            .map_err(down)?
            .into_iter()
            .next()
            .ok_or(InclusionError::Unknown)?;
        let envelope = RecordEnvelope::from_bytes(&record.envelope).map_err(down)?;
        // §17.6.1 rule 5
        let disclosure = envelope
            .disclose(|name| name == OPENED || name == PQ_OPENED)
            .map_err(down)?;
        let leaves = leaf_hashes(&self.app, &id, 0, size).await.map_err(down)?;
        let path = inclusion(leaves.as_slice(), pos, size).map_err(|_| InclusionError::Unknown)?;
        let hashes =
            |h: &[[u8; 32]]| Value::Array(h.iter().map(|x| Value::Bytes(x.to_vec())).collect());
        // RA-4
        let previous = all.iter().map(|c| c.size).filter(|s| *s < size).max();
        let mut fields = vec![
            (Value::text("domain"), Value::Bytes(domain.0.to_vec())),
            (Value::text("position"), Value::Unsigned(pos)),
            (
                Value::text("record"),
                Value::Bytes(disclosure.to_bytes().map_err(down)?),
            ),
            (Value::text("path"), hashes(&path)),
            (Value::text("checkpoint"), Value::Bytes(cp.sign1.clone())),
            (Value::text("excerpt"), Value::Bytes(cp.excerpt.clone())),
            (Value::text("cosigns"), pq_cosigns(cp)),
        ];
        if let Some(from) = previous {
            let proof =
                consistency(leaves.as_slice(), from, size).map_err(|_| InclusionError::Unknown)?;
            fields.push((
                Value::text("consistency"),
                Value::Map(vec![
                    (Value::text("from"), Value::Unsigned(from)),
                    (Value::text("path"), hashes(&proof)),
                ]),
            ));
        }
        dcbor::encode(&Value::Map(fields), Limits::CEILING).map_err(down)
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
