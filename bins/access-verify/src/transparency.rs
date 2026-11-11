//! Witnessed-time subcommands (U21, U68, T19, TI-RT5, §9.10 step 6, OP-158 m.3 (c)): a
//! record's inclusion proof bundle shows it existed by the earliest cosignature of a witness
//! the verifier trusts, and Domain Metadata is fresh when a checkpoint naming it was cosigned
//! within Δ. Only the cosigners passed with `--cosigners` count; the log's own signature never
//! dates anything.

use std::fmt::Write as _;

use access_kernel::codec::Canonical as _;
use access_kernel::record::Disclosure;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{Checkpoint, Verifier, verify_checkpoint};
use suiss_crypto::sig::PureBackend;

use crate::args::{Options, Usage};
use crate::commands::Outcome;

/// Digest context of the Domain Metadata a checkpoint names (OP-152 m.5 (h)).
const METADATA_CONTEXT: &str = "access/domain-metadata/v1";

/// Δ when none is given: without a declared Δ the metadata is fresh for an hour (TI-RT5, T29).
const DELTA_MS: u64 = 3_600_000;

fn reject(reason: &str) -> Outcome {
    Outcome::Reject(reason.to_owned())
}

/// The `--cosigners`: one or more witness verifier keys.
fn keys(o: &Options) -> Result<Vec<Verifier>, Usage> {
    let cosigners = o
        .words("cosigners")
        .iter()
        .map(|c| Verifier::parse(c).map_err(|_| Usage(format!("--cosigners: not a vkey: {c}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if cosigners.is_empty() || cosigners.iter().any(|c| !c.is_cosigner()) {
        return Err(Usage("--cosigners: one or more witness vkeys".into()));
    }
    Ok(cosigners)
}

/// The checkpoint and the trusted cosignature times of `note`.
fn cosigned(o: &Options, note: &str) -> Result<Result<(Checkpoint, Vec<u64>), Outcome>, Usage> {
    let log = Verifier::parse(o.text("log")?).map_err(|_| Usage("--log: not a vkey".into()))?;
    let cosigners = keys(o)?;
    Ok(
        match verify_checkpoint(&PureBackend, note, o.text("origin")?, &log, &cosigners) {
            Ok((cp, accepted)) => {
                let times: Vec<u64> = accepted.iter().filter_map(|a| a.timestamp).collect();
                if times.is_empty() {
                    Err(reject("not-witnessed"))
                } else {
                    Ok((cp, times))
                }
            }
            Err(e) => Err(reject(e.code())),
        },
    )
}

fn get<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.get(name)
}

/// The `cosignatures` of a bundle as note lines, for the `--cosigners` whose names match.
fn lines(v: &Value, cosigners: &[Verifier]) -> Option<String> {
    let Value::Array(items) = v else {
        return None;
    };
    let mut out = String::new();
    for c in items {
        let (Some(Value::Text(name)), Some(Value::Unsigned(ts)), Some(Value::Bytes(sig))) =
            (c.get("name"), c.get("timestamp"), c.get("signature"))
        else {
            return None;
        };
        let Some(key) = cosigners.iter().find(|k| k.name() == name) else {
            continue;
        };
        let mut raw = key.id().to_be_bytes().to_vec();
        raw.extend_from_slice(&ts.to_be_bytes());
        raw.extend_from_slice(sig);
        let _ = writeln!(
            out,
            "\u{2014} {name} {}",
            suiss_crypto::note::base64_encode(&raw)
        );
    }
    Some(out)
}

pub(crate) fn existed(o: &Options) -> Result<Outcome, Usage> {
    let Ok(bundle) = dcbor::decode(&o.file("bundle")?, Limits::CEILING) else {
        return Ok(reject("bundle"));
    };
    let (
        Some(Value::Text(note)),
        Some(Value::Bytes(record)),
        Some(Value::Array(path)),
        Some(cosignatures),
    ) = (
        get(&bundle, "checkpoint"),
        get(&bundle, "record"),
        get(&bundle, "inclusion"),
        get(&bundle, "cosignatures"),
    )
    else {
        return Ok(reject("bundle"));
    };
    let path: Option<Vec<[u8; 32]>> = path
        .iter()
        .map(|h| match h {
            Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok(),
            _ => None,
        })
        .collect();
    let (Some(path), Ok(disclosure)) = (path, Disclosure::from_bytes(record)) else {
        return Ok(reject("bundle"));
    };
    let cosigners = keys(o)?;
    let Some(extra) = lines(cosignatures, &cosigners) else {
        return Ok(reject("bundle"));
    };
    let (cp, times) = match cosigned(o, &format!("{note}{extra}"))? {
        Ok(v) => v,
        Err(out) => return Ok(out),
    };
    if disclosure
        .verify_inclusion(cp.size, &path, &cp.root)
        .is_err()
    {
        return Ok(reject("inclusion"));
    }
    let by = times.iter().copied().min().unwrap_or(u64::MAX);
    if let Some(before) = o.opt_uint("before")?
        && by > before
    {
        return Ok(reject("after"));
    }
    Ok(Outcome::Accept(vec![
        ("pos", disclosure.header.pos.to_string()),
        ("size", cp.size.to_string()),
        ("existed_by", by.to_string()),
        (
            "opened",
            disclosure
                .opened
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("withheld", disclosure.withheld.len().to_string()),
    ]))
}

pub(crate) fn fresh(o: &Options) -> Result<Outcome, Usage> {
    let metadata = o.file("metadata")?;
    let note = String::from_utf8(o.file("note")?)
        .map_err(|_| Usage("--note: the file is not UTF-8".to_owned()))?;
    let (cp, times) = match cosigned(o, &note)? {
        Ok(v) => v,
        Err(out) => return Ok(out),
    };
    let digest = suiss_crypto::digest::context_digest(METADATA_CONTEXT, &metadata);
    let named = format!(
        "metadata sha-256:{}",
        access_kernel::json::b64url_encode(&digest.0)
    );
    if !cp.extensions.contains(&named) {
        return Ok(reject("metadata-not-named"));
    }
    let now = o.uint("now")?;
    let delta = o.opt_uint("delta-ms")?.unwrap_or(DELTA_MS);
    let newest = times
        .iter()
        .copied()
        .max()
        .unwrap_or_default()
        .saturating_mul(1000);
    if now.saturating_sub(newest) > delta {
        return Ok(reject("stale"));
    }
    Ok(Outcome::Accept(vec![("witnessed_at", newest.to_string())]))
}
