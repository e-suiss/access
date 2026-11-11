//! `export` (INV-27, PI-6, U13, T19, CMP-17, OP-158 m.3 (h)): a streamed Record Export Package
//! (`export.cddl`) verified without Suiss. The records follow each other in the domain and chain;
//! with the frontier before the range they rebuild the root the end frame names; every checkpoint
//! note the package carries is signed by the domain's log key, names a root the records rebuild
//! and, with `--cosigners`, the newest one is cosigned by a trusted witness. A package from
//! Genesis folds into state and every decision is re-evaluated at `q−1` as far as the record
//! carries its inputs; what does not replay is a divergence set, signed with `--sign`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::record::{Disclosure, LeafCore, check_link};
use access_verifier::replay::{Replay, SignedSet};
use suiss_crypto::dcbor::{self, Limits, TagAllowlist, Value};
use suiss_crypto::note::{Verifier, verify_checkpoint};
use suiss_crypto::secret::Secret;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{Signer as _, SoftSigner};
use suiss_ledger::merkle::Frontier;

use crate::args::{Options, Usage};
use crate::commands::Outcome;

/// Largest package this command reads.
const MAX_PACKAGE: u64 = 1 << 30;

/// The evaluator identity this build writes into a divergence set.
const EVALUATOR: &str = concat!("access-verify/", env!("CARGO_PKG_VERSION"));

fn reject(reason: &str) -> Outcome {
    Outcome::Reject(reason.to_owned())
}

struct Frames<'a> {
    rest: &'a [u8],
}

impl Frames<'_> {
    fn next(&mut self) -> Option<(String, Value)> {
        let (v, used) =
            dcbor::decode_prefix(self.rest, Limits::CEILING, &TagAllowlist::only(&[])).ok()?;
        self.rest = self.rest.get(used..)?;
        match v {
            Value::Map(mut e) if e.len() == 1 => match e.pop() {
                Some((Value::Text(k), v)) => Some((k, v)),
                _ => None,
            },
            _ => None,
        }
    }
}

fn uint(v: &Value, k: &str) -> Option<u64> {
    match v.get(k) {
        Some(Value::Unsigned(n)) => Some(*n),
        _ => None,
    }
}

fn hash(v: &Value) -> Option<[u8; 32]> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
}

/// What the stream holds once read to its end frame.
struct Read {
    domain: Digest,
    range: (u64, u64),
    digest: bool,
    roots: BTreeMap<u64, [u8; 32]>,
    notes: Vec<String>,
    size: u64,
    root: [u8; 32],
    replay: Replay,
}

/// Reads and checks the stream; `Err` is the reject reason.
fn read(bytes: &[u8]) -> Result<Read, &'static str> {
    let mut frames = Frames { rest: bytes };
    let (kind, header) = frames.next().ok_or("package")?;
    if kind != "header" {
        return Err("package");
    }
    let domain = header
        .get("domain")
        .and_then(|d| <Digest as access_kernel::codec::Canonical>::from_value(d).ok())
        .ok_or("package")?;
    let range = header.get("range").ok_or("package")?;
    let range = (
        uint(range, "from").ok_or("package")?,
        uint(range, "to").ok_or("package")?,
    );
    let digest = match header.get("replay_coverage") {
        Some(Value::Text(t)) if t == "full" => false,
        Some(Value::Text(t)) if t == "digest" => true,
        _ => return Err("package"),
    };
    let (kind, prefix) = frames.next().ok_or("package")?;
    let Value::Array(nodes) = prefix else {
        return Err("package");
    };
    if kind != "prefix" {
        return Err("package");
    }
    let nodes: Option<Vec<[u8; 32]>> = nodes.iter().map(hash).collect();
    let mut tree = Frontier::from_parts(range.0, nodes.ok_or("package")?).map_err(|_| "root")?;
    let mut previous: Option<LeafCore> = None;
    let mut out = Read {
        domain,
        range,
        digest,
        roots: BTreeMap::new(),
        notes: Vec::new(),
        size: 0,
        root: [0; 32],
        replay: Replay::new(),
    };
    loop {
        let (kind, v) = frames.next().ok_or("truncated")?;
        match kind.as_str() {
            "record" => {
                let Some(Value::Bytes(b)) = v.get("envelope") else {
                    return Err("package");
                };
                let d = Disclosure::from_bytes(b).map_err(|_| "record")?;
                if d.header.pos != tree.size() || uint(&v, "position") != Some(d.header.pos) {
                    return Err("order");
                }
                let core = d.leaf_core().map_err(|_| "record")?;
                match &previous {
                    Some(prev) => check_link(prev, &core, &domain).map_err(|_| "chain")?,
                    None if d.header.pos > 0 && d.header.domain != Some(domain) => {
                        return Err("chain");
                    }
                    None => {}
                }
                tree.push(core.leaf_hash().map_err(|_| "record")?)
                    .map_err(|_| "root")?;
                out.roots.insert(tree.size(), tree.root());
                out.replay.push(&d, true).map_err(|_| "fold")?;
                previous = Some(core);
            }
            "checkpoint" => match v {
                Value::Text(t) => out.notes.push(t),
                _ => return Err("package"),
            },
            "versions" | "schema" | "claim" => {}
            "end" => {
                out.size = uint(&v, "size").ok_or("package")?;
                out.root = v.get("root").and_then(hash).ok_or("package")?;
                let count = range.1.checked_sub(range.0).and_then(|n| n.checked_add(1));
                if uint(&v, "records") != count
                    || out.replay.coverage().records != count.unwrap_or(0)
                {
                    return Err("range");
                }
                if tree.size() != out.size || tree.root() != out.root {
                    return Err("root");
                }
                break;
            }
            _ => return Err("package"),
        }
    }
    if !frames.rest.is_empty() {
        return Err("trailing");
    }
    Ok(out)
}

fn cosigners(o: &Options) -> Result<Vec<Verifier>, Usage> {
    o.words("cosigners")
        .iter()
        .map(|c| match Verifier::parse(c) {
            Ok(v) if v.is_cosigner() => Ok(v),
            _ => Err(Usage(format!("--cosigners: not a witness vkey: {c}"))),
        })
        .collect()
}

/// An Ed25519 public key and a signature by it.
type Signed = ([u8; 32], [u8; 64]);

fn sign(o: &Options, bytes: &[u8]) -> Result<Option<Signed>, Usage> {
    if !o.has("sign") {
        return Ok(None);
    }
    let doc = Secret::new(o.file("sign")?);
    let signer = SoftSigner::ed25519_from_pkcs8(&doc)
        .map_err(|_| Usage("--sign: not a PKCS #8 Ed25519 key".into()))?;
    let suiss_crypto::cose::PublicKey::Ed25519(key) = signer.public_key() else {
        return Err(Usage("--sign: not an Ed25519 key".into()));
    };
    let sig = signer
        .sign(bytes)
        .map_err(|_| Usage("--sign: the key does not sign".into()))?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| Usage("--sign: not an Ed25519 signature".into()))?;
    Ok(Some((key, sig)))
}

fn write(path: &str, bytes: &[u8]) -> Result<(), Usage> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .map_err(|e| Usage(format!("--out {path}: {e}")))
}

pub(crate) fn export(o: &Options) -> Result<Outcome, Usage> {
    let bytes = crate::args::read_limited("package", o.text("package")?, MAX_PACKAGE)?;
    let log = Verifier::parse(o.text("log")?).map_err(|_| Usage("--log: not a vkey".into()))?;
    let trusted = cosigners(o)?;
    let now = o.uint("now")?;
    let read = match read(&bytes) {
        Ok(r) => r,
        Err(reason) => return Ok(reject(reason)),
    };
    let origin = format!("sha-256:{}", b64url_encode(&read.domain.0));
    let mut witnessed: Option<u64> = None;
    let mut checked = 0u64;
    for note in &read.notes {
        let Ok((cp, accepted)) = verify_checkpoint(&PureBackend, note, &origin, &log, &trusted)
        else {
            return Ok(reject("checkpoint"));
        };
        if read.roots.get(&cp.size).is_some_and(|r| *r != cp.root)
            || (cp.size == read.size && cp.root != read.root)
        {
            return Ok(reject("checkpoint-root"));
        }
        if accepted.iter().any(|a| a.timestamp.is_some()) {
            witnessed = witnessed.max(Some(cp.size));
        }
        checked = checked.saturating_add(1);
    }
    if !trusted.is_empty() && witnessed.is_none() {
        return Ok(reject("not-witnessed"));
    }
    let c = read.replay.coverage();
    let mut outputs = vec![
        ("domain", crate::args::hex(&read.domain.0)),
        ("range", format!("{}-{}", read.range.0, read.range.1)),
        ("size", read.size.to_string()),
        ("root", crate::args::hex(&read.root)),
        ("checkpoints", checked.to_string()),
        (
            "witnessed",
            witnessed.map_or_else(|| String::from("none"), |s| s.to_string()),
        ),
        (
            "replay_coverage",
            String::from(if read.digest || c.digest_only > 0 {
                "digest"
            } else {
                "full"
            }),
        ),
        ("decisions", c.decisions.to_string()),
        ("reevaluated", c.reevaluated.to_string()),
        ("digest_only", c.digest_only.to_string()),
    ];
    let Some(set) = read.replay.set(read.range, EVALUATOR, now) else {
        outputs.push(("divergent", String::from("0")));
        return Ok(Outcome::Accept(outputs));
    };
    let mut items = String::new();
    for i in &set.items {
        let _ = write!(
            items,
            "{}{}:{}:{}:{}",
            if items.is_empty() { "" } else { "," },
            i.position,
            i.kind.word(),
            i.reason.word(),
            crate::args::hex(&i.exercise.0),
        );
    }
    outputs.push(("divergent", set.items.len().to_string()));
    outputs.push(("items", items));
    let message = set
        .to_bytes()
        .map_err(|_| Usage("the divergence set does not encode".into()))?;
    if let Some((key, sig)) = sign(o, &message)? {
        let signed = SignedSet { set, key, sig }
            .to_bytes()
            .map_err(|_| Usage("the divergence set does not encode".into()))?;
        if let Some(path) = o.opt("out") {
            write(path, &signed)?;
        }
        outputs.push(("signed_by", crate::args::hex(&key)));
        outputs.push((
            "set",
            crate::args::hex(&suiss_crypto::digest::sha256(&signed)),
        ));
    }
    Ok(Outcome::Diverged(outputs))
}
