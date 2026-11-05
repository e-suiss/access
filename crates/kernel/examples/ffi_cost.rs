//! OQ-MD4, OP-150 m.1 (c): the cost of the Kernel calls the bindings expose, measured on the
//! committed vectors. Built natively it is the direct-Rust baseline; built for
//! `wasm32-wasip1` and run under a Wasm runtime it is the Wasm cost. `just bench-ffi` also
//! writes the inputs for the Node and Python runs. Informational, not a gate.

#![allow(
    clippy::print_stdout,
    reason = "a measurement tool; it reports JSON lines on stdout"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Instant;

use access_kernel::algebra::Catalog;
use access_kernel::binding::{evaluate, verify_cose_sign1};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::model::RequirementTerm;
use access_kernel::pap::{Expected, verify};
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey};
use access_kernel::verify::key_scope::DomainMetadata;
use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::{Limits, Value, decode};

type Fallible<T> = Result<T, String>;

fn unhex(text: &str) -> Fallible<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(|| format!("not hex: {text}"))
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(format!("odd hex: {text}"));
    }
    pairs
        .iter()
        .map(|[h, l]| Ok(digit(*h)? << 4 | digit(*l)?))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn load(dir: &Path, name: &str) -> Fallible<Json> {
    let path = dir.join(name);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{name}: {e}"))
}

fn field<'a>(v: &'a Json, key: &str) -> Fallible<&'a Json> {
    v.get(key).ok_or_else(|| format!("missing {key}"))
}

fn text<'a>(v: &'a Json, key: &str) -> Fallible<&'a str> {
    field(v, key)?
        .as_str()
        .ok_or_else(|| format!("{key} is not text"))
}

fn case<'a>(v: &'a Json, id: &str) -> Fallible<&'a Json> {
    field(v, "cases")?
        .as_array()
        .and_then(|cases| cases.iter().find(|c| c.get("id") == Some(&json!(id))))
        .ok_or_else(|| format!("no case {id}"))
}

fn cbor(bytes: &[u8]) -> Fallible<Value> {
    decode(bytes, Limits::CEILING).map_err(|e| e.to_string())
}

/// The `key-set` of a vector file: `{keys: {kid: key}, allowed: [alg]}`.
fn key_set(v: &Json) -> Fallible<Vec<u8>> {
    let mut set = KeySet::default();
    for (kid, key) in field(v, "keys")?.as_object().ok_or("keys is not a map")? {
        let kid: [u8; 32] = unhex(kid)?
            .try_into()
            .map_err(|_| String::from("kid is not 32 bytes"))?;
        let key = key.as_str().ok_or("key is not text")?;
        let key = PublicKey::from_bytes(&unhex(key)?).map_err(|e| format!("key: {e}"))?;
        set.insert(kid, key).map_err(|e| format!("key: {e}"))?;
    }
    for alg in field(v, "allowed")?
        .as_array()
        .ok_or("allowed is not a list")?
    {
        let alg = alg
            .as_i64()
            .and_then(Algorithm::from_cose)
            .ok_or("unknown alg")?;
        set.allowed.insert(alg);
    }
    set.to_bytes().map_err(|e| e.to_string())
}

fn decoded<T: Canonical>(c: &Json, key: &str) -> Fallible<T> {
    T::from_bytes(&unhex(text(c, key)?)?).map_err(|e| format!("{key}: {e}"))
}

fn values<T: Canonical>(c: &Json, key: &str) -> Fallible<Vec<T>> {
    match cbor(&unhex(text(c, key)?)?)? {
        Value::Array(items) => items
            .iter()
            .map(|v| T::from_value(v).map_err(|e| format!("{key}: {e}")))
            .collect(),
        _ => Err(format!("{key} is not an array")),
    }
}

fn number(c: &Json, key: &str) -> Fallible<u64> {
    field(c, key)?
        .as_u64()
        .ok_or_else(|| format!("{key} is not a number"))
}

fn flag(c: &Json, key: &str) -> Fallible<bool> {
    field(c, key)?
        .as_bool()
        .ok_or_else(|| format!("{key} is not a bool"))
}

/// Nanoseconds per call over `iters` calls after a warm-up.
fn time(iters: u32, mut f: impl FnMut() -> bool) -> Fallible<f64> {
    for _ in 0..iters {
        if !f() {
            return Err(String::from("the call failed on its own vector"));
        }
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    let ns = start.elapsed().as_nanos();
    Ok(f64::from(
        u32::try_from(ns.checked_div(u128::from(iters)).unwrap_or(0)).unwrap_or(u32::MAX),
    ))
}

struct Args {
    vectors: PathBuf,
    iters: u32,
    inputs: Option<PathBuf>,
}

fn args() -> Fallible<Args> {
    let mut out = Args {
        vectors: PathBuf::from("conformance/vectors/core/1"),
        iters: 2_000,
        inputs: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--vectors" => out.vectors = PathBuf::from(value),
            "--iters" => out.iters = value.parse().map_err(|e| format!("--iters: {e}"))?,
            "--inputs" => out.inputs = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    Ok(out)
}

fn main() -> Fallible<()> {
    let args = args()?;
    let runtime = if cfg!(target_family = "wasm") {
        "wasm32-wasip1"
    } else {
        "rust"
    };
    let report = |op: &str, ns: f64| {
        println!(
            "{}",
            json!({ "runtime": runtime, "op": op, "ns_per_call": ns, "iters": args.iters })
        );
    };

    let decisions = load(&args.vectors, "decision.json")?;
    let fuel = number(&decisions, "fuel")?;
    let input = unhex(text(case(&decisions, "allow")?, "input")?)?;
    report(
        "evaluate",
        time(args.iters, || evaluate(black_box(&input), fuel).is_ok())?,
    );

    let cose = load(&args.vectors, "cose.json")?;
    let content_type = text(&cose, "content_type")?.to_owned();
    let keys = key_set(&cose)?;
    let sign1 = unhex(text(case(&cose, "valid-ed25519")?, "sign1")?)?;
    report(
        "verify_cose_sign1",
        time(args.iters, || {
            verify_cose_sign1(black_box(&sign1), &keys, &content_type).is_ok()
        })?,
    );

    let paps = load(&args.vectors, "pap.json")?;
    let c = case(&paps, "valid")?;
    let metadata: DomainMetadata = decoded(&paps, "metadata")?;
    let catalog: Catalog = decoded(&paps, "catalog")?;
    let domain: Digest = decoded(c, "domain")?;
    let intent: IntentEnvelope = decoded(c, "intent")?;
    let satisfied: BTreeSet<RequirementTerm> = values(c, "satisfied")?.into_iter().collect();
    let mut remaining = BTreeMap::new();
    for pair in values::<PairValue>(c, "remaining")? {
        remaining.insert(pair.0, pair.1);
    }
    let understood: BTreeSet<String> = field(c, "understood")?
        .as_array()
        .ok_or("understood is not a list")?
        .iter()
        .filter_map(|u| u.as_str().map(str::to_owned))
        .collect();
    let (pap, excerpt, presentation, nonce) = (
        unhex(text(c, "sign1")?)?,
        unhex(text(c, "excerpt")?)?,
        unhex(text(c, "presentation")?)?,
        unhex(text(c, "nonce")?)?,
    );
    let expected = Expected {
        domain: &domain,
        intent: &intent,
        audience: text(c, "audience")?,
        nonce: &nonce,
        now: number(c, "now")?,
        catalog: &catalog,
        satisfied: &satisfied,
        remaining: &remaining,
        metadata_fresh: flag(c, "fresh")?,
        understood: &understood,
        last_refresh: None,
        online: flag(c, "online")?,
        skew_ms: number(c, "skew_ms")?,
        horizon_cap_ms: number(c, "horizon_cap_ms")?,
    };
    report(
        "pap_verify",
        time(args.iters, || {
            verify(
                &PureBackend,
                &metadata,
                black_box(&pap),
                &excerpt,
                &presentation,
                &expected,
            )
            .is_ok()
        })?,
    );

    if let Some(path) = args.inputs {
        let inputs = json!({
            "evaluate": { "input": hex(&input), "fuel": fuel },
            "verify_cose_sign1": { "sign1": hex(&sign1), "key_set": hex(&keys), "content_type": content_type },
        });
        std::fs::write(&path, inputs.to_string())
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// One `[budget-term digest, remaining]` entry of a PAP vector.
struct PairValue(Digest, u64);

impl Canonical for PairValue {
    fn to_value(&self) -> Value {
        Value::Array(vec![Canonical::to_value(&self.0), Value::Unsigned(self.1)])
    }

    fn from_value(v: &Value) -> Result<Self, access_kernel::codec::ModelError> {
        match v {
            Value::Array(items) => match items.as_slice() {
                [d, Value::Unsigned(n)] => Ok(Self(<Digest as Canonical>::from_value(d)?, *n)),
                _ => Err(access_kernel::codec::ModelError::Shape),
            },
            _ => Err(access_kernel::codec::ModelError::Shape),
        }
    }
}
