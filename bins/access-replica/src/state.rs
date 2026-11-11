//! The replica's own copy (OP-158 m.3 (f), U22, OP-73): append-only files in its state
//! directory, never the provider's store.
//! - `records`: one entry per mirrored record: its position and leaf hash, the record with every
//!   field withheld (its commitments, which keep the leaf), and the whole record sealed under a
//!   key of its own.
//! - `deks`: those keys, 32 bytes at `32 × position`. Applying a redaction overwrites one; the
//!   record's leaf and commitments stay and the tree still verifies (crypto-shredding).
//! - `checkpoints`: each accepted checkpoint note; `acks`: each signed ack; `redactions`: each
//!   redaction received and each applied.
//!
//! An entry is on disk (fsync) before the ack that covers it leaves the process. A torn last
//! entry from a crash is cut off when the files are opened.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::record::{Disclosure, LeafCore, RecordEnvelope, check_link, field_commitment};
use suiss_crypto::envelope::{Dek, Sealed, open_body, seal_body};
use suiss_crypto::note::{Checkpoint, parse_note};
use suiss_crypto::secret::Secret;
use suiss_ledger::Hash;
use suiss_ledger::replica::Follower;

/// What the copy holds of one position.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// The whole record, as mirrored.
    Open(Vec<u8>),
    /// Redacted: only the record with its fields withheld.
    Redacted(Vec<u8>),
}

/// The replica's files for one domain.
pub(crate) struct Store {
    domain: Digest,
    records: File,
    deks: File,
    checkpoints: File,
    acks: File,
    redactions: File,
    offsets: Vec<u64>,
    last: Option<LeafCore>,
    /// The tree of the mirrored leaves.
    pub(crate) follower: Follower,
    /// The last accepted checkpoint note.
    pub(crate) note: Option<String>,
}

fn origin(domain: &Digest) -> String {
    format!("sha-256:{}", b64url_encode(&domain.0))
}

fn open(dir: &Path, name: &str, append: bool) -> Result<File, String> {
    let p = dir.join(name);
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(append)
        .write(!append)
        .open(&p)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn read_all(f: &mut File) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    f.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn context(domain: &Digest, pos: u64) -> Vec<u8> {
    let mut c = b"access-replica/v1".to_vec();
    c.extend_from_slice(&domain.0);
    c.extend_from_slice(&pos.to_be_bytes());
    c
}

/// The record with every opened field withheld: the same leaf, no content.
fn withheld(d: &Disclosure) -> Result<Disclosure, String> {
    let mut w = d.withheld.clone();
    for (name, field) in &d.opened {
        w.insert(
            name.clone(),
            field_commitment(name, field).map_err(|e| e.to_string())?,
        );
    }
    Ok(Disclosure {
        header: d.header.clone(),
        opened: std::collections::BTreeMap::new(),
        withheld: w,
    })
}

struct Entry {
    pos: u64,
    leaf: Hash,
    nonce: [u8; 12],
    withheld: Vec<u8>,
    sealed: Vec<u8>,
}

impl Entry {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let w = u32::try_from(self.withheld.len()).map_err(|_| "record too large")?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.pos.to_be_bytes());
        body.extend_from_slice(&self.leaf);
        body.extend_from_slice(&self.nonce);
        body.extend_from_slice(&w.to_be_bytes());
        body.extend_from_slice(&self.withheld);
        body.extend_from_slice(&self.sealed);
        let len = u32::try_from(body.len()).map_err(|_| "record too large")?;
        let mut out = len.to_be_bytes().to_vec();
        out.extend(body);
        Ok(out)
    }

    /// The entry at the start of `input` and its length; `None` for a torn tail.
    fn decode(input: &[u8]) -> Option<(Self, usize)> {
        let len = usize::try_from(u32::from_be_bytes(input.get(..4)?.try_into().ok()?)).ok()?;
        let end = len.checked_add(4)?;
        let body = input.get(4..end)?;
        let pos = u64::from_be_bytes(body.get(..8)?.try_into().ok()?);
        let leaf: Hash = body.get(8..40)?.try_into().ok()?;
        let nonce: [u8; 12] = body.get(40..52)?.try_into().ok()?;
        let w = usize::try_from(u32::from_be_bytes(body.get(52..56)?.try_into().ok()?)).ok()?;
        let split = 56_usize.checked_add(w)?;
        Some((
            Self {
                pos,
                leaf,
                nonce,
                withheld: body.get(56..split)?.to_vec(),
                sealed: body.get(split..)?.to_vec(),
            },
            end,
        ))
    }
}

impl Store {
    /// Opens (or starts) the copy of `domain` in `dir`, rebuilding the tree from the files.
    pub(crate) fn open(dir: &Path, domain: Digest) -> Result<Self, String> {
        let dir: PathBuf = dir.join(b64url_encode(&domain.0));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut s = Self {
            domain,
            records: open(&dir, "records", true)?,
            deks: open(&dir, "deks", false)?,
            checkpoints: open(&dir, "checkpoints", true)?,
            acks: open(&dir, "acks", true)?,
            redactions: open(&dir, "redactions", true)?,
            offsets: Vec::new(),
            last: None,
            follower: Follower::new(&origin(&domain)),
            note: None,
        };
        let notes = s.load_checkpoints()?;
        s.load_records(notes)?;
        Ok(s)
    }

    fn load_checkpoints(&mut self) -> Result<Vec<(u64, String)>, String> {
        let text = String::from_utf8(read_all(&mut self.checkpoints)?)
            .map_err(|_| "checkpoints: not text")?;
        let mut out = Vec::new();
        for line in text.lines() {
            let (size, note) = line.split_once(' ').ok_or("checkpoints: malformed")?;
            let note =
                String::from_utf8(b64url_decode(note).map_err(|_| "checkpoints: malformed")?)
                    .map_err(|_| "checkpoints: malformed")?;
            out.push((size.parse().map_err(|_| "checkpoints: malformed")?, note));
        }
        Ok(out)
    }

    fn load_records(&mut self, notes: Vec<(u64, String)>) -> Result<(), String> {
        let bytes = read_all(&mut self.records)?;
        let mut at = 0_usize;
        let mut notes = notes.into_iter().peekable();
        while let Some((e, used)) = bytes.get(at..).and_then(Entry::decode) {
            let d = Disclosure::from_bytes(&e.withheld).map_err(|_| "records: malformed")?;
            self.chain(&d, &e.leaf)?;
            self.offsets
                .push(u64::try_from(at).map_err(|_| "records: too large")?);
            at = at.checked_add(used).ok_or("records: too large")?;
            while let Some((size, note)) = notes.next_if(|(s, _)| *s == self.follower.size()) {
                self.accept_note(size, &note)?;
            }
        }
        if notes.next().is_some() {
            return Err("checkpoints: a checkpoint beyond the records".into());
        }
        let len = self.records.metadata().map_err(|e| e.to_string())?.len();
        let kept = u64::try_from(at).map_err(|_| "records: too large")?;
        if len > kept {
            self.records.set_len(kept).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn accept_note(&mut self, size: u64, note: &str) -> Result<(), String> {
        let parsed = parse_note(note).map_err(|e| e.to_string())?;
        let cp = Checkpoint::parse(&parsed.body).map_err(|e| e.to_string())?;
        if cp.size != size {
            return Err("checkpoints: size".into());
        }
        self.follower.accept_own(&cp).map_err(|e| e.to_string())?;
        self.note = Some(note.to_owned());
        Ok(())
    }

    /// Checks that `d` is the next record of the domain with leaf `leaf`, and grows the tree.
    fn chain(&mut self, d: &Disclosure, leaf: &Hash) -> Result<(), String> {
        let core = d.leaf_core().map_err(|e| e.to_string())?;
        let hash = core.leaf_hash().map_err(|e| e.to_string())?;
        if &hash != leaf || d.header.pos != self.follower.size() {
            return Err(format!("record {}: not the next record", d.header.pos));
        }
        match &self.last {
            Some(prev) => check_link(prev, &core, &self.domain)
                .map_err(|e| format!("record {}: {e}", d.header.pos))?,
            None if d.header.pos != 0 => return Err("the copy starts at position 0".into()),
            None => {
                if d.withheld.is_empty() {
                    let g = RecordEnvelope {
                        header: d.header.clone(),
                        fields: d.opened.clone(),
                    };
                    if g.domain().ok() != Some(self.domain) {
                        return Err("record 0 is not this domain's Genesis".into());
                    }
                }
            }
        }
        self.follower.append(hash).map_err(|e| e.to_string())?;
        self.last = Some(core);
        Ok(())
    }

    /// Appends the mirrored record `bytes` (a disclosure) as the next position. A write that
    /// fails leaves the files behind the tree: the caller stops and opens the copy again.
    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), String> {
        let d = Disclosure::from_bytes(bytes).map_err(|_| "record: malformed")?;
        let leaf = d.leaf_hash().map_err(|e| e.to_string())?;
        let w = withheld(&d)?.to_bytes().map_err(|_| "record: too large")?;
        let pos = d.header.pos;
        let slot = pos.checked_mul(32).ok_or("position too large")?;
        self.chain(&d, &leaf)?;
        let dek = Dek::generate().map_err(|e| e.to_string())?;
        self.deks
            .write_all_at(dek.secret().expose(), slot)
            .map_err(|e| format!("deks: {e}"))?;
        let Sealed { nonce, ciphertext } =
            seal_body(dek, &context(&self.domain, pos), bytes).map_err(|e| e.to_string())?;
        let entry = Entry {
            pos,
            leaf,
            nonce,
            withheld: w,
            sealed: ciphertext,
        };
        let offset = self.records.metadata().map_err(|e| e.to_string())?.len();
        self.records
            .write_all(&entry.encode()?)
            .map_err(|e| format!("records: {e}"))?;
        self.offsets.push(offset);
        Ok(())
    }

    /// Makes every appended record and key durable.
    pub(crate) fn sync(&self) -> Result<(), String> {
        self.records.sync_all().map_err(|e| e.to_string())?;
        self.deks.sync_all().map_err(|e| e.to_string())?;
        self.checkpoints.sync_all().map_err(|e| e.to_string())
    }

    /// Accepts the verified checkpoint `cp` with note `note` when the copy holds exactly its
    /// size: `true` when it is new. A checkpoint of a size the copy has passed is not
    /// accepted again.
    pub(crate) fn accept(&mut self, cp: &Checkpoint, note: &str) -> Result<bool, String> {
        if cp.size != self.follower.size()
            || self.follower.accepted().is_some_and(|(s, _)| s >= cp.size)
        {
            return Ok(false);
        }
        self.follower.accept_own(cp).map_err(|e| e.to_string())?;
        self.sync()?;
        let line = format!("{} {}\n", cp.size, b64url_encode(note.as_bytes()));
        self.checkpoints
            .write_all(line.as_bytes())
            .and_then(|()| self.checkpoints.sync_all())
            .map_err(|e| e.to_string())?;
        self.note = Some(note.to_owned());
        Ok(true)
    }

    /// Keeps a signed ack before it is sent.
    pub(crate) fn keep_ack(&mut self, signed: &[u8]) -> Result<(), String> {
        let line = format!("{}\n", b64url_encode(signed));
        self.acks
            .write_all(line.as_bytes())
            .and_then(|()| self.acks.sync_all())
            .map_err(|e| e.to_string())
    }

    /// Keeps a redaction the mirror delivered; the operator applies it (U22).
    pub(crate) fn received(&mut self, pos: u64, dek: &Hash) -> Result<(), String> {
        let line = format!("received {pos} {}\n", b64url_encode(dek));
        self.redactions
            .write_all(line.as_bytes())
            .and_then(|()| self.redactions.sync_all())
            .map_err(|e| e.to_string())
    }

    /// The redactions received and not applied yet.
    pub(crate) fn pending(&mut self) -> Result<Vec<u64>, String> {
        let mut f = self.redactions.try_clone().map_err(|e| e.to_string())?;
        let mut text = String::new();
        std::io::Seek::rewind(&mut f).map_err(|e| e.to_string())?;
        f.read_to_string(&mut text).map_err(|e| e.to_string())?;
        let mut received = std::collections::BTreeSet::new();
        let mut applied = std::collections::BTreeSet::new();
        for line in text.lines() {
            let mut parts = line.split(' ');
            let (kind, pos) = (
                parts.next(),
                parts.next().and_then(|p| p.parse::<u64>().ok()),
            );
            match (kind, pos) {
                (Some("received"), Some(p)) => drop(received.insert(p)),
                (Some("applied"), Some(p)) => drop(applied.insert(p)),
                _ => return Err("redactions: malformed".into()),
            }
        }
        Ok(received.difference(&applied).copied().collect())
    }

    /// Applies the redaction of `pos` to the copy: its key is overwritten and the record can no
    /// longer be read; its leaf and commitments stay (U22, T39). `false` when the copy does not
    /// hold `pos`.
    pub(crate) fn redact(&mut self, pos: u64) -> Result<bool, String> {
        if pos >= self.follower.size() {
            return Ok(false);
        }
        let filler = Dek::generate().map_err(|e| e.to_string())?;
        let slot = pos.checked_mul(32).ok_or("position too large")?;
        self.deks
            .write_all_at(filler.secret().expose(), slot)
            .and_then(|()| self.deks.sync_all())
            .map_err(|e| e.to_string())?;
        let line = format!("applied {pos}\n");
        self.redactions
            .write_all(line.as_bytes())
            .and_then(|()| self.redactions.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// What the copy holds of `pos`.
    pub(crate) fn read(&self, pos: u64) -> Result<Option<Held>, String> {
        let Some(offset) = usize::try_from(pos).ok().and_then(|i| self.offsets.get(i)) else {
            return Ok(None);
        };
        let mut head = [0_u8; 4];
        self.records
            .read_exact_at(&mut head, *offset)
            .map_err(|e| e.to_string())?;
        let len = u32::from_be_bytes(head);
        let total = usize::try_from(len)
            .ok()
            .and_then(|l| l.checked_add(4))
            .ok_or("records: malformed")?;
        let mut buf = vec![0_u8; total];
        self.records
            .read_exact_at(&mut buf, *offset)
            .map_err(|e| e.to_string())?;
        let (e, _) = Entry::decode(&buf).ok_or("records: malformed")?;
        let mut f = self.deks.try_clone().map_err(|e| e.to_string())?;
        std::io::Seek::seek(
            &mut f,
            std::io::SeekFrom::Start(pos.checked_mul(32).ok_or("position too large")?),
        )
        .map_err(|e| e.to_string())?;
        let mut key = Vec::new();
        f.take(32)
            .read_to_end(&mut key)
            .map_err(|e| e.to_string())?;
        let key: [u8; 32] = key.try_into().map_err(|_| "deks: short")?;
        let dek = Dek::from_secret(Secret::new(key));
        let sealed = Sealed {
            nonce: e.nonce,
            ciphertext: e.sealed,
        };
        Ok(Some(
            match open_body(&dek, &context(&self.domain, pos), &sealed) {
                Ok(plain) => Held::Open(plain.to_vec()),
                Err(_) => Held::Redacted(e.withheld),
            },
        ))
    }
}
