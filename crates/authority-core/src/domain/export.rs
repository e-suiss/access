//! Record Export Package (AP-14, §9.16, §17.6.13): a self-verifying copy of a range of the
//! domain's Authority Record. Everything in it is a Kernel structure the log already holds:
//! record disclosures (full, or redacted to field commitments), the Merkle frontier before the
//! range, the checkpoint at its end, the version vectors and schema and Claim digests the records
//! cite, and the `access.audit_export` Exercise that made it. Bytes are deterministic CBOR.
//!
//! Anyone re-folds the checkpoint root from the package with the open Kernel alone (INV-27,
//! PI-6): [`verify`]. A redacted package declares `replay_coverage: "digest"`: chain, Merkle
//! root and record order verify, re-evaluation does not.

use std::collections::BTreeSet;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::record::{Disclosure, RecordEnvelope, RecordKind, check_link};
use access_kernel::schema::Spp;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_ledger::Hash;
use suiss_ledger::merkle::Frontier;

/// Digest context of a version vector in the package (the context checkpoints use, L0-ENC-22a).
pub const VERSIONS_CONTEXT: &str = "access/versions/v1";

/// The export action's name in the core namespace: an identifier the Kernel reads, unlike the
/// concept name `access.audit.export` (OP-151 m.19 (d)).
pub const EXPORT_ACTION: &str = "audit_export";

/// The namespace of the export intent's resource.
pub const AUDIT_NAMESPACE: &str = "access.audit";

/// Most records one package holds (PD); a larger range is several exports.
pub const MAX_RECORDS: u64 = 10_000;

/// How much of each record the package opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Every field opened: replay re-evaluates every decision.
    Full,
    /// Only the version vectors opened, every other field as its commitment: replay verifies
    /// chain, order and root only.
    Digest,
}

impl Coverage {
    /// The `replay_coverage` word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Digest => "digest",
        }
    }
}

/// The checkpoint at the end of the range: the log's Merkle root over `0..size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Records in the tree: the range's last position plus one.
    pub size: u64,
    /// RFC 9162 root.
    pub root: Hash,
    /// `recorded_at` of the last record.
    pub recorded_at: u64,
}

/// A Record Export Package (AP-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// `DomainID`.
    pub domain: Digest,
    /// First and last record position.
    pub range: (u64, u64),
    /// The Merkle frontier over the records before the range.
    pub prefix: Vec<Hash>,
    /// The records, in order.
    pub records: Vec<Disclosure>,
    /// The checkpoint at the end of the range.
    pub checkpoints: Vec<Checkpoint>,
    /// The version vectors the records cite, each with its digest.
    pub versions: Vec<(Value, Digest)>,
    /// Catalog digests of the SPPs the opened records carry.
    pub schemas: Vec<Digest>,
    /// The Claims ingested in the range: their ids when opened, else their leaf hashes.
    pub claims: Vec<Digest>,
    /// The `access.audit_export` Exercise that made it.
    pub export_exercise: Digest,
    /// Full or digest-level replay.
    pub replay_coverage: Coverage,
}

/// Why a package cannot be built or does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// A stored record or the package does not decode.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The range is empty, reversed or larger than [`MAX_RECORDS`].
    #[error("range")]
    Range,
    /// The records do not chain (TI-19, L0-ENC-27).
    #[error("chain")]
    Chain,
    /// The re-folded root is not the checkpoint's (INV-27).
    #[error("root")]
    Root,
    /// A fully opened range from Genesis does not fold (L2-REC-2).
    #[error("fold")]
    Fold,
}

fn versions_digest(v: &Value) -> Result<Digest, ExportError> {
    let bytes =
        dcbor::encode(v, Limits::CEILING).map_err(|_| ExportError::Malformed("versions"))?;
    Ok(suiss_crypto::digest::context_digest(
        VERSIONS_CONTEXT,
        &bytes,
    ))
}

/// Every SPP an opened value carries under an `spp` member.
fn spps(v: &Value, out: &mut BTreeSet<Digest>) {
    match v {
        Value::Map(entries) => {
            for (k, val) in entries {
                if k == &Value::text("spp")
                    && let Ok(s) = Spp::from_value(val)
                {
                    out.insert(s.catalog_digest());
                }
                spps(val, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| spps(i, out)),
        Value::Tag(_, inner) => spps(inner, out),
        _ => {}
    }
}

fn envelope(bytes: &[u8]) -> Result<RecordEnvelope, ExportError> {
    RecordEnvelope::from_bytes(bytes).map_err(|_| ExportError::Malformed("record"))
}

/// Builds the package of `log[from..=to]`, where `log` holds the domain's envelopes from
/// position 0 to at least `to`, opened per `coverage`, made by `export_exercise`.
///
/// # Errors
/// [`ExportError`].
pub fn build(
    domain: Digest,
    log: &[Vec<u8>],
    (from, to): (u64, u64),
    coverage: Coverage,
    export_exercise: Digest,
) -> Result<Package, ExportError> {
    let count = to
        .checked_sub(from)
        .and_then(|n| n.checked_add(1))
        .ok_or(ExportError::Range)?;
    if count > MAX_RECORDS || u64::try_from(log.len()).map_or(true, |n| n <= to) {
        return Err(ExportError::Range);
    }
    let mut frontier = Frontier::default();
    let mut records = Vec::new();
    let mut versions = Vec::<(Value, Digest)>::new();
    let mut schemas = BTreeSet::new();
    let mut claims = Vec::new();
    let mut last_at = 0;
    for (pos, bytes) in (0u64..).zip(log.iter()) {
        if pos > to {
            break;
        }
        let r = envelope(bytes)?;
        if r.header.pos != pos {
            return Err(ExportError::Chain);
        }
        if pos < from {
            frontier
                .push(
                    r.leaf_hash()
                        .map_err(|_| ExportError::Malformed("record"))?,
                )
                .map_err(|_| ExportError::Range)?;
            continue;
        }
        let disclosure = match coverage {
            Coverage::Full => r.disclose(|_| true),
            Coverage::Digest => r.disclose(|name| name == "versions"),
        }
        .map_err(|_| ExportError::Malformed("record"))?;
        if let Some(v) = disclosure.opened.get("versions")
            && !versions.iter().any(|(seen, _)| seen == &v.value)
        {
            versions.push((v.value.clone(), versions_digest(&v.value)?));
        }
        for f in disclosure.opened.values() {
            spps(&f.value, &mut schemas);
        }
        if r.header.kind == RecordKind::Claim {
            let id = disclosure
                .opened
                .get("claim")
                .and_then(|c| <Digest as Canonical>::from_value(&c.value).ok());
            match id {
                Some(id) => claims.push(id),
                None => claims.push(Digest(
                    disclosure
                        .leaf_hash()
                        .map_err(|_| ExportError::Malformed("record"))?,
                )),
            }
        }
        last_at = r.header.recorded_at;
        records.push(disclosure);
    }
    let prefix = frontier.nodes().to_vec();
    let mut tree = frontier;
    for d in &records {
        tree.push(
            d.leaf_hash()
                .map_err(|_| ExportError::Malformed("record"))?,
        )
        .map_err(|_| ExportError::Range)?;
    }
    Ok(Package {
        domain,
        range: (from, to),
        prefix,
        records,
        checkpoints: vec![Checkpoint {
            size: tree.size(),
            root: tree.root(),
            recorded_at: last_at,
        }],
        versions,
        schemas: schemas.into_iter().collect(),
        claims,
        export_exercise,
        replay_coverage: coverage,
    })
}

/// What a verified package proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The re-folded root.
    pub root: Hash,
    /// Its tree size.
    pub size: u64,
    /// Whether the records were folded into state from Genesis (a full range from 0).
    pub folded: bool,
}

/// Verifies a package with the open Kernel alone (INV-27, PI-6): the records are the range in
/// order, chain to each other in the domain, re-fold with the prefix to the checkpoint's root,
/// and, fully opened from Genesis, fold into state.
///
/// # Errors
/// [`ExportError`]: the difference is the evidence (G32).
pub fn verify(p: &Package) -> Result<Verified, ExportError> {
    let (from, to) = p.range;
    let count = to
        .checked_sub(from)
        .and_then(|n| n.checked_add(1))
        .ok_or(ExportError::Range)?;
    if u64::try_from(p.records.len()).ok() != Some(count) {
        return Err(ExportError::Range);
    }
    let mut tree = Frontier::from_parts(from, p.prefix.clone()).map_err(|_| ExportError::Root)?;
    let mut previous = None;
    let mut state: Option<access_kernel::fold::State> = None;
    let fold = from == 0 && p.replay_coverage == Coverage::Full;
    for (pos, d) in (from..).zip(&p.records) {
        if d.header.pos != pos {
            return Err(ExportError::Chain);
        }
        let core = d
            .leaf_core()
            .map_err(|_| ExportError::Malformed("record"))?;
        if let Some(prev) = &previous {
            check_link(prev, &core, &p.domain).map_err(|_| ExportError::Chain)?;
        } else if pos > 0 && d.header.domain != Some(p.domain) {
            return Err(ExportError::Chain);
        }
        tree.push(
            core.leaf_hash()
                .map_err(|_| ExportError::Malformed("record"))?,
        )
        .map_err(|_| ExportError::Root)?;
        if fold {
            if !d.withheld.is_empty() {
                return Err(ExportError::Fold);
            }
            let r = RecordEnvelope {
                header: d.header.clone(),
                fields: d.opened.clone(),
            };
            match state.as_mut() {
                None => {
                    if r.domain().map_err(|_| ExportError::Fold)? != p.domain {
                        return Err(ExportError::Chain);
                    }
                    state = Some(access_kernel::fold::genesis(&r).map_err(|_| ExportError::Fold)?);
                }
                Some(s) => access_kernel::fold::apply(s, &r).map_err(|_| ExportError::Fold)?,
            }
        }
        previous = Some(core);
    }
    let checkpoint = p.checkpoints.last().ok_or(ExportError::Root)?;
    if tree.size() != checkpoint.size || tree.root() != checkpoint.root {
        return Err(ExportError::Root);
    }
    Ok(Verified {
        root: checkpoint.root,
        size: checkpoint.size,
        folded: state.is_some(),
    })
}

/// The `type` of a package's first item.
pub const PACKAGE_TYPE: &str = "access-record-export";

fn digests(ds: &[Digest]) -> Value {
    Value::Array(ds.iter().map(Digest::to_value).collect())
}

fn item(v: &Value, out: &mut Vec<u8>) -> Result<(), ExportError> {
    out.extend(dcbor::encode(v, Limits::CEILING).map_err(|_| ExportError::Malformed("package"))?);
    Ok(())
}

fn count(n: usize) -> Value {
    Value::Unsigned(u64::try_from(n).unwrap_or(u64::MAX))
}

impl Package {
    /// The first item: everything but the records, Claim digests and checkpoints, with their
    /// counts.
    #[must_use]
    pub fn head(&self) -> Value {
        Value::Map(vec![
            (Value::text("type"), Value::text(PACKAGE_TYPE)),
            (Value::text("domain"), self.domain.to_value()),
            (
                Value::text("range"),
                Value::Array(vec![
                    Value::Unsigned(self.range.0),
                    Value::Unsigned(self.range.1),
                ]),
            ),
            (
                Value::text("prefix"),
                Value::Array(
                    self.prefix
                        .iter()
                        .map(|h| Value::Bytes(h.to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::text("versions"),
                Value::Array(
                    self.versions
                        .iter()
                        .map(|(v, d)| {
                            Value::Map(vec![
                                (Value::text("vector"), v.clone()),
                                (Value::text("digest"), d.to_value()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (Value::text("schemas"), digests(&self.schemas)),
            (
                Value::text("export_exercise"),
                self.export_exercise.to_value(),
            ),
            (
                Value::text("replay_coverage"),
                Value::text(self.replay_coverage.word()),
            ),
            (Value::text("records"), count(self.records.len())),
            (Value::text("claims"), count(self.claims.len())),
        ])
    }

    /// The package as a CBOR sequence (RFC 8742, §17.6.13): the head, each record, each Claim
    /// digest, then the checkpoints; every item deterministic CBOR.
    ///
    /// # Errors
    /// [`ExportError::Malformed`] when an item is outside the encoder's limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ExportError> {
        let mut out = Vec::new();
        item(&self.head(), &mut out)?;
        for r in &self.records {
            item(&r.to_value(), &mut out)?;
        }
        for c in &self.claims {
            item(&c.to_value(), &mut out)?;
        }
        let checkpoints = Value::Array(
            self.checkpoints
                .iter()
                .map(|c| {
                    Value::Map(vec![
                        (Value::text("size"), Value::Unsigned(c.size)),
                        (Value::text("root"), Value::Bytes(c.root.to_vec())),
                        (Value::text("recorded_at"), Value::Unsigned(c.recorded_at)),
                    ])
                })
                .collect(),
        );
        item(&checkpoints, &mut out)?;
        Ok(out)
    }

    /// Reads a package from its CBOR sequence.
    ///
    /// # Errors
    /// [`ExportError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ExportError> {
        let mut seq = Sequence { rest: bytes };
        let head = seq.next()?;
        if head.get("type") != Some(&Value::text(PACKAGE_TYPE)) {
            return Err(ExportError::Malformed("type"));
        }
        let get = |k: &'static str| head.get(k).ok_or(ExportError::Malformed(k));
        let array = |k: &'static str| match head.get(k) {
            Some(Value::Array(items)) => Ok(items.as_slice()),
            _ => Err(ExportError::Malformed(k)),
        };
        let range = match array("range")? {
            [a, b] => (uint(a)?, uint(b)?),
            _ => return Err(ExportError::Malformed("range")),
        };
        let replay_coverage = match get("replay_coverage")? {
            Value::Text(t) if t == "full" => Coverage::Full,
            Value::Text(t) if t == "digest" => Coverage::Digest,
            _ => return Err(ExportError::Malformed("replay_coverage")),
        };
        let records = uint(get("records")?)?;
        let claims = uint(get("claims")?)?;
        if records > MAX_RECORDS || claims > MAX_RECORDS {
            return Err(ExportError::Range);
        }
        let mut p = Self {
            domain: digest(get("domain")?)?,
            range,
            prefix: array("prefix")?
                .iter()
                .map(hash)
                .collect::<Result<_, _>>()?,
            records: Vec::new(),
            checkpoints: Vec::new(),
            versions: array("versions")?
                .iter()
                .map(|e| {
                    let vector = e.get("vector").ok_or(ExportError::Malformed("versions"))?;
                    let d = e.get("digest").ok_or(ExportError::Malformed("versions"))?;
                    Ok((vector.clone(), digest(d)?))
                })
                .collect::<Result<_, ExportError>>()?,
            schemas: array("schemas")?
                .iter()
                .map(digest)
                .collect::<Result<_, _>>()?,
            claims: Vec::new(),
            export_exercise: digest(get("export_exercise")?)?,
            replay_coverage,
        };
        for _ in 0..records {
            p.records.push(
                Disclosure::from_value(&seq.next()?)
                    .map_err(|_| ExportError::Malformed("record"))?,
            );
        }
        for _ in 0..claims {
            p.claims.push(digest(&seq.next()?)?);
        }
        let Value::Array(checkpoints) = seq.next()? else {
            return Err(ExportError::Malformed("checkpoints"));
        };
        for c in &checkpoints {
            let m = |k: &str| c.get(k).ok_or(ExportError::Malformed("checkpoint"));
            p.checkpoints.push(Checkpoint {
                size: uint(m("size")?)?,
                root: hash(m("root")?)?,
                recorded_at: uint(m("recorded_at")?)?,
            });
        }
        if !seq.rest.is_empty() {
            return Err(ExportError::Malformed("trailing"));
        }
        Ok(p)
    }
}

struct Sequence<'a> {
    rest: &'a [u8],
}

impl Sequence<'_> {
    fn next(&mut self) -> Result<Value, ExportError> {
        let (v, used) =
            dcbor::decode_prefix(self.rest, Limits::CEILING, &dcbor::TagAllowlist::only(&[]))
                .map_err(|_| ExportError::Malformed("item"))?;
        self.rest = self
            .rest
            .get(used..)
            .ok_or(ExportError::Malformed("item"))?;
        Ok(v)
    }
}

fn uint(x: &Value) -> Result<u64, ExportError> {
    match x {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(ExportError::Malformed("uint")),
    }
}

fn hash(x: &Value) -> Result<Hash, ExportError> {
    match x {
        Value::Bytes(b) => {
            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ExportError::Malformed("hash"))
        }
        _ => Err(ExportError::Malformed("hash")),
    }
}

fn digest(x: &Value) -> Result<Digest, ExportError> {
    <Digest as Canonical>::from_value(x).map_err(|_| ExportError::Malformed("digest"))
}

/// Records one chunk of a streamed package holds (OP-158 m.3 (g), PD): the stream itself has
/// no size limit; it reads and sends the range a chunk at a time.
pub const CHUNK: u64 = 10_000;

fn frame(name: &str, v: Value) -> Result<Vec<u8>, ExportError> {
    dcbor::encode(&Value::Map(vec![(Value::text(name), v)]), Limits::CEILING)
        .map_err(|_| ExportError::Malformed("frame"))
}

fn entries(e: Vec<(&str, Option<Value>)>) -> Value {
    Value::Map(
        e.into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), v)))
            .collect(),
    )
}

/// The disclosure of `r` a package of `coverage` carries: every field opened, or only the
/// version vectors with every other field as its commitment.
///
/// # Errors
/// [`ExportError::Malformed`].
pub fn disclosure(r: &RecordEnvelope, coverage: Coverage) -> Result<Disclosure, ExportError> {
    match coverage {
        Coverage::Full => r.disclose(|_| true),
        Coverage::Digest => r.disclose(|name| name == "versions"),
    }
    .map_err(|_| ExportError::Malformed("record"))
}

/// A Record Export Package written as it is read (`export.cddl`, OP-158 m.3 (g)): one header
/// frame, the Merkle frontier before the range, each record, then the checkpoints, version
/// vectors, schemas and Claims the records name, and an end frame with the re-folded root.
/// Every record is checked against the log as it goes (INV-27): its leaf is the stored one and
/// it chains to the one before; a stream that fails a check ends without its end frame.
pub struct Streamer {
    domain: Digest,
    to: u64,
    coverage: Coverage,
    tree: Frontier,
    previous: Option<access_kernel::record::LeafCore>,
    versions: Vec<Value>,
    schemas: BTreeSet<Digest>,
    claims: Vec<Digest>,
    records: u64,
}

impl Streamer {
    /// A stream of `domain`'s records `from..=to` opened per `coverage`, made by
    /// `export_exercise`, over the leaf hashes `prefix` of the records before `from`; the
    /// streamer and its header and frontier frames.
    ///
    /// # Errors
    /// [`ExportError::Range`] for a reversed range or a prefix of another length.
    pub fn start(
        domain: Digest,
        (from, to): (u64, u64),
        coverage: Coverage,
        export_exercise: Digest,
        prefix: &[Hash],
    ) -> Result<(Self, Vec<u8>), ExportError> {
        if to < from || u64::try_from(prefix.len()).ok() != Some(from) {
            return Err(ExportError::Range);
        }
        let mut tree = Frontier::default();
        for h in prefix {
            tree.push(*h).map_err(|_| ExportError::Range)?;
        }
        let header = entries(vec![
            ("domain", Some(domain.to_value())),
            (
                "range",
                Some(entries(vec![
                    ("from", Some(Value::Unsigned(from))),
                    ("to", Some(Value::Unsigned(to))),
                ])),
            ),
            (
                "export_exercise",
                Some(Value::Bytes(export_exercise.0.to_vec())),
            ),
            ("replay_coverage", Some(Value::text(coverage.word()))),
            ("chunk", Some(Value::Unsigned(CHUNK))),
        ]);
        let mut out = frame("header", header)?;
        out.extend(frame(
            "prefix",
            Value::Array(
                tree.nodes()
                    .iter()
                    .map(|h| Value::Bytes(h.to_vec()))
                    .collect(),
            ),
        )?);
        Ok((
            Self {
                domain,
                to,
                coverage,
                tree,
                previous: None,
                versions: Vec::new(),
                schemas: BTreeSet::new(),
                claims: Vec::new(),
                records: 0,
            },
            out,
        ))
    }

    /// The next position the stream expects.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.tree.size()
    }

    /// The frame of the stored record `envelope` whose stored leaf hash is `leaf`.
    ///
    /// # Errors
    /// [`ExportError::Chain`] when it is not the next record of the domain or its leaf is not
    /// the stored one; [`ExportError::Malformed`].
    pub fn push(&mut self, envelope: &[u8], leaf: &Hash) -> Result<Vec<u8>, ExportError> {
        let r =
            RecordEnvelope::from_bytes(envelope).map_err(|_| ExportError::Malformed("record"))?;
        let pos = r.header.pos;
        if pos != self.next() || pos > self.to {
            return Err(ExportError::Chain);
        }
        let d = disclosure(&r, self.coverage)?;
        let core = d
            .leaf_core()
            .map_err(|_| ExportError::Malformed("record"))?;
        let hash = core
            .leaf_hash()
            .map_err(|_| ExportError::Malformed("record"))?;
        if &hash != leaf {
            return Err(ExportError::Chain);
        }
        match &self.previous {
            Some(prev) => check_link(prev, &core, &self.domain).map_err(|_| ExportError::Chain)?,
            None if pos > 0 && r.header.domain != Some(self.domain) => {
                return Err(ExportError::Chain);
            }
            None => {}
        }
        if let Some(v) = d.opened.get("versions")
            && !self.versions.contains(&v.value)
        {
            self.versions.push(v.value.clone());
        }
        for f in d.opened.values() {
            spps(&f.value, &mut self.schemas);
        }
        if r.header.kind == RecordKind::Claim {
            let id = d
                .opened
                .get("claim")
                .and_then(|c| <Digest as Canonical>::from_value(&c.value).ok());
            self.claims.push(id.unwrap_or(Digest(hash)));
        }
        let redacted =
            (self.coverage == Coverage::Digest).then(|| Value::Bytes(core.field_root.to_vec()));
        let record = entries(vec![
            ("position", Some(Value::Unsigned(pos))),
            (
                "envelope",
                Some(Value::Bytes(
                    d.to_bytes().map_err(|_| ExportError::Malformed("record"))?,
                )),
            ),
            ("redacted", redacted),
        ]);
        self.tree.push(hash).map_err(|_| ExportError::Range)?;
        self.previous = Some(core);
        self.records = self.records.saturating_add(1);
        frame("record", record)
    }

    /// The closing frames: the signed checkpoint notes of sizes inside the range, the version
    /// vectors, schema and Claim digests the records named, and the end frame.
    ///
    /// # Errors
    /// [`ExportError::Range`] when records are missing; [`ExportError::Root`] when a checkpoint
    /// of the range's end size names another root (INV-27).
    pub fn finish(self, checkpoints: &[(u64, Hash, String)]) -> Result<Vec<u8>, ExportError> {
        if self.next() != self.to.saturating_add(1) {
            return Err(ExportError::Range);
        }
        let (size, root) = (self.tree.size(), self.tree.root());
        if checkpoints.iter().any(|(s, r, _)| *s == size && *r != root) {
            return Err(ExportError::Root);
        }
        let mut out = Vec::new();
        for (_, _, note) in checkpoints {
            out.extend(frame("checkpoint", Value::text(note))?);
        }
        for v in &self.versions {
            out.extend(frame(
                "versions",
                Value::Bytes(
                    dcbor::encode(v, Limits::CEILING)
                        .map_err(|_| ExportError::Malformed("versions"))?,
                ),
            )?);
        }
        for s in &self.schemas {
            out.extend(frame("schema", Value::Bytes(s.0.to_vec()))?);
        }
        for c in &self.claims {
            out.extend(frame("claim", Value::Bytes(c.0.to_vec()))?);
        }
        out.extend(frame(
            "end",
            entries(vec![
                ("records", Some(Value::Unsigned(self.records))),
                ("size", Some(Value::Unsigned(size))),
                ("root", Some(Value::Bytes(root.to_vec()))),
            ]),
        )?);
        Ok(out)
    }
}

/// What a streamed package says once read to its end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Streamed {
    /// First and last position.
    pub range: (u64, u64),
    /// `replay_coverage`.
    pub coverage: Coverage,
    /// The export Exercise.
    pub export_exercise: Digest,
    /// The records, in order.
    pub records: Vec<Disclosure>,
    /// The re-folded size and root, which the end frame names.
    pub size: u64,
    /// Its root.
    pub root: Hash,
    /// The checkpoint notes carried.
    pub checkpoints: Vec<String>,
}

fn member<'a>(v: &'a Value, k: &'static str) -> Result<&'a Value, ExportError> {
    v.get(k).ok_or(ExportError::Malformed(k))
}

/// Reads a streamed package and checks it with the open Kernel alone (INV-27, PI-6): the
/// records are the range in order, chain to each other in the domain, and re-fold with the
/// frontier to the root the end frame names; a stream cut before its end frame is refused.
///
/// # Errors
/// [`ExportError`].
pub fn read_stream(bytes: &[u8]) -> Result<Streamed, ExportError> {
    let mut seq = Sequence { rest: bytes };
    let mut frame = || -> Result<(String, Value), ExportError> {
        match seq.next()? {
            Value::Map(mut e) if e.len() == 1 => match e.pop() {
                Some((Value::Text(k), v)) => Ok((k, v)),
                _ => Err(ExportError::Malformed("frame")),
            },
            _ => Err(ExportError::Malformed("frame")),
        }
    };
    let (kind, header) = frame()?;
    if kind != "header" {
        return Err(ExportError::Malformed("header"));
    }
    let domain = digest(member(&header, "domain")?)?;
    let range = member(&header, "range")?;
    let (from, to) = (uint(member(range, "from")?)?, uint(member(range, "to")?)?);
    let coverage = match member(&header, "replay_coverage")? {
        Value::Text(t) if t == "full" => Coverage::Full,
        Value::Text(t) if t == "digest" => Coverage::Digest,
        _ => return Err(ExportError::Malformed("replay_coverage")),
    };
    let export_exercise = Digest(hash(member(&header, "export_exercise")?)?);
    let (kind, prefix) = frame()?;
    let Value::Array(nodes) = prefix else {
        return Err(ExportError::Malformed("prefix"));
    };
    if kind != "prefix" {
        return Err(ExportError::Malformed("prefix"));
    }
    let nodes = nodes.iter().map(hash).collect::<Result<Vec<_>, _>>()?;
    let mut tree = Frontier::from_parts(from, nodes).map_err(|_| ExportError::Root)?;
    let mut previous: Option<access_kernel::record::LeafCore> = None;
    let mut out = Streamed {
        range: (from, to),
        coverage,
        export_exercise,
        records: Vec::new(),
        size: 0,
        root: [0; 32],
        checkpoints: Vec::new(),
    };
    loop {
        let (kind, v) = frame()?;
        match kind.as_str() {
            "record" => {
                let Value::Bytes(b) = member(&v, "envelope")? else {
                    return Err(ExportError::Malformed("envelope"));
                };
                let d = Disclosure::from_bytes(b).map_err(|_| ExportError::Malformed("record"))?;
                if d.header.pos != tree.size() || uint(member(&v, "position")?)? != d.header.pos {
                    return Err(ExportError::Chain);
                }
                let core = d
                    .leaf_core()
                    .map_err(|_| ExportError::Malformed("record"))?;
                match &previous {
                    Some(prev) => {
                        check_link(prev, &core, &domain).map_err(|_| ExportError::Chain)?
                    }
                    None if d.header.pos > 0 && d.header.domain != Some(domain) => {
                        return Err(ExportError::Chain);
                    }
                    None => {}
                }
                tree.push(
                    core.leaf_hash()
                        .map_err(|_| ExportError::Malformed("record"))?,
                )
                .map_err(|_| ExportError::Root)?;
                previous = Some(core);
                out.records.push(d);
            }
            "checkpoint" => match v {
                Value::Text(t) => out.checkpoints.push(t),
                _ => return Err(ExportError::Malformed("checkpoint")),
            },
            "versions" | "schema" | "claim" => {}
            "end" => {
                let records = uint(member(&v, "records")?)?;
                out.size = uint(member(&v, "size")?)?;
                out.root = hash(member(&v, "root")?)?;
                let count = to.checked_sub(from).and_then(|n| n.checked_add(1));
                if Some(records) != count || u64::try_from(out.records.len()).ok() != count {
                    return Err(ExportError::Range);
                }
                if tree.size() != out.size || tree.root() != out.root {
                    return Err(ExportError::Root);
                }
                break;
            }
            _ => return Err(ExportError::Malformed("frame")),
        }
    }
    if !seq.rest.is_empty() {
        return Err(ExportError::Malformed("trailing"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
