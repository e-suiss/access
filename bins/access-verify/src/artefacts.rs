//! Authority artefact subcommands (§9.8, §9.10, §9.12.2, L2-PAP-3, L2-RCP-3, L2-RPT-3,
//! L2-STL-3, L2-CKP-3): PAP uses, receipts, offline reports, status lists and checkpoints.

use access_kernel::binding::{self, Error};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::status::StatusRef;
use access_kernel::verify::key_scope::DomainMetadata;
use access_verifier::status::StatusList;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::base64_encode;

use crate::args::{Options, Usage, hex};
use crate::commands::Outcome;

fn reject(e: &Error) -> Outcome {
    Outcome::Reject(e.name())
}

fn digest(o: &Options, name: &str) -> Result<Vec<u8>, Usage> {
    Digest(o.hash(name)?)
        .to_bytes()
        .map_err(|_| Usage(format!("--{name} cannot be encoded")))
}

/// The `--metadata` bytes, verified first against `--trusted` when it is given.
fn metadata(o: &Options) -> Result<Result<Vec<u8>, Error>, Usage> {
    let metadata = o.file("metadata")?;
    if o.has("trusted") {
        return Ok(binding::verify_metadata(&metadata, &o.file("trusted")?));
    }
    Ok(Ok(metadata))
}

fn field(v: &Value, name: &str) -> String {
    match v.get(name) {
        Some(Value::Unsigned(n)) => n.to_string(),
        Some(Value::Bytes(b)) => hex(b),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Unsigned(n) => n.to_string(),
                Value::Array(pair) => pair
                    .iter()
                    .map(|p| match p {
                        Value::Bytes(b) => hex(b),
                        Value::Unsigned(n) => n.to_string(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join(":"),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => String::new(),
    }
}

fn map_out(bytes: &[u8], names: &[&'static str]) -> Outcome {
    match dcbor::decode(bytes, Limits::CEILING) {
        Ok(v) => Outcome::Accept(names.iter().map(|n| (*n, field(&v, n))).collect()),
        Err(_) => Outcome::Reject("input".to_owned()),
    }
}

pub(crate) fn pap(o: &Options) -> Result<Outcome, Usage> {
    let metadata = match metadata(o)? {
        Ok(m) => m,
        Err(e) => return Ok(reject(&e)),
    };
    let nonce = crate::args::unhex(o.text("nonce")?)
        .ok_or_else(|| Usage("--nonce is not lowercase hex".to_owned()))?;
    let result = binding::verify_pap(
        &metadata,
        &o.file("pap")?,
        &o.file("excerpt")?,
        &o.file("presentation")?,
        &digest(o, "domain")?,
        &o.file("intent")?,
        o.text("audience")?,
        &nonce,
        o.uint("now")?,
        &o.file("catalog")?,
        &o.file("satisfied")?,
        &o.file("remaining")?,
        o.boolean("fresh")?,
        o.words("understood"),
        o.opt_uint("last-refresh")?,
        o.boolean("online")?,
        o.uint("skew-ms")?,
        o.uint("horizon-cap-ms")?,
    );
    Ok(match result {
        Ok(p) => Outcome::Accept(vec![("pap", hex(&p))]),
        Err(e) => reject(&e),
    })
}

fn slices(bytes: &[u8]) -> Option<std::collections::BTreeMap<Digest, u64>> {
    let Value::Array(items) = dcbor::decode(bytes, Limits::CEILING).ok()? else {
        return None;
    };
    let mut out = std::collections::BTreeMap::new();
    for item in &items {
        let Value::Array(pair) = item else {
            return None;
        };
        let [term, Value::Unsigned(n)] = pair.as_slice() else {
            return None;
        };
        if out.insert(Digest::from_value(term)?, *n).is_some() {
            return None;
        }
    }
    Some(out)
}

/// A foreign PAP used in `--domain` (§9.15A.2, OP-143 m.13 (d), INV-17): the `--acceptance`
/// content must be a live `foreign-authority` gate of the PAP's domain for `--class`; then the
/// metadata under its pinned binding keys, its freshness, L2-PAP-3 with this domain as the
/// audience, the holder key, the class and the cutoff, in that order.
pub(crate) fn foreign(o: &Options) -> Result<Outcome, Usage> {
    use access_kernel::foreign::{self, ForeignGate, Presented, Use};
    let input = || Outcome::Reject("input".to_owned());
    let Ok(content) = dcbor::decode(&o.file("acceptance")?, Limits::CEILING) else {
        return Ok(input());
    };
    let gate = match ForeignGate::of(&content) {
        Ok(Some(g)) => g,
        Ok(None) => return Ok(Outcome::Reject("foreign-not-accepted".to_owned())),
        Err(_) => return Ok(input()),
    };
    let pap = o.file("pap")?;
    let (class, now) = (o.text("class")?, o.uint("now")?);
    if foreign::claimed_domain(&pap) != Some(gate.issuer.domain)
        || !gate.opens(&gate.issuer.domain, class, now)
    {
        return Ok(Outcome::Reject("foreign-not-accepted".to_owned()));
    }
    let nonce = crate::args::unhex(o.text("nonce")?)
        .ok_or_else(|| Usage("--nonce is not lowercase hex".to_owned()))?;
    let domain = Digest(o.hash("domain")?);
    let (Ok(intent), Ok(catalog), Ok(actor_key), Some(remaining)) = (
        access_kernel::intent::IntentEnvelope::from_bytes(&o.file("intent")?),
        access_kernel::algebra::Catalog::from_bytes(&o.file("catalog")?),
        access_kernel::verify::cose::PublicKey::from_bytes(&o.file("actor-key")?),
        slices(&o.file("remaining")?),
    ) else {
        return Ok(input());
    };
    let (metadata, excerpt, presentation) = (
        o.file("metadata")?,
        o.file("excerpt")?,
        o.file("presentation")?,
    );
    let verified = foreign::verify(
        &access_kernel::verify::PureBackend,
        &gate,
        &Presented {
            metadata: &metadata,
            pap: &pap,
            excerpt: &excerpt,
            presentation: &presentation,
        },
        &Use {
            domain: &domain,
            intent: &intent,
            nonce: &nonce,
            now,
            catalog: &catalog,
            actor_key: &actor_key,
            class,
            remaining: &remaining,
        },
    );
    Ok(match verified {
        Ok((p, _)) => match p.to_bytes() {
            Ok(bytes) => Outcome::Accept(vec![
                ("pap", hex(&bytes)),
                ("foreign_domain", hex(&gate.issuer.domain.0)),
            ]),
            Err(_) => input(),
        },
        Err(e) => Outcome::Reject(e.code().to_owned()),
    })
}

pub(crate) fn receipt(o: &Options) -> Result<Outcome, Usage> {
    let metadata = match metadata(o)? {
        Ok(m) => m,
        Err(e) => return Ok(reject(&e)),
    };
    let result = binding::verify_receipt(
        &metadata,
        &o.file("receipt")?,
        &o.file("excerpt")?,
        &digest(o, "domain")?,
        o.text("audience")?,
        &digest(o, "intent")?,
        o.uint("now")?,
    );
    Ok(match result {
        Ok(r) => Outcome::Accept(vec![("receipt", hex(&r))]),
        Err(e) => reject(&e),
    })
}

pub(crate) fn report(o: &Options) -> Result<Outcome, Usage> {
    Ok(match binding::verify_report(&o.file("report")?) {
        Ok(s) => map_out(&s, &["head", "next_seq", "drawn"]),
        Err(e) => reject(&e),
    })
}

pub(crate) fn checkpoint(o: &Options) -> Result<Outcome, Usage> {
    let note = String::from_utf8(o.file("note")?)
        .map_err(|_| Usage("--note: the file is not UTF-8".to_owned()))?;
    let result = binding::verify_checkpoint(
        &note,
        o.text("origin")?,
        o.text("log")?,
        o.words("cosigners"),
    );
    Ok(match result {
        Ok(c) => match dcbor::decode(&c, Limits::CEILING) {
            Ok(v) => {
                let root = match v.get("root") {
                    Some(Value::Bytes(b)) => base64_encode(b),
                    _ => String::new(),
                };
                Outcome::Accept(vec![
                    ("size", field(&v, "size")),
                    ("root", root),
                    ("extensions", field(&v, "extensions")),
                    ("cosigned", field(&v, "cosigned")),
                ])
            }
            Err(_) => Outcome::Reject("input".to_owned()),
        },
        Err(e) => reject(&e),
    })
}

fn reference(o: &Options) -> Result<StatusRef, Usage> {
    Ok(StatusRef {
        idx: o.uint("idx")?,
        uri: o.text("uri")?.to_owned(),
    })
}

fn reference_bytes(o: &Options) -> Result<Vec<u8>, Usage> {
    reference(o)?
        .to_bytes()
        .map_err(|_| Usage("--uri cannot be encoded".to_owned()))
}

pub(crate) fn status(o: &Options) -> Result<Outcome, Usage> {
    if o.has("payload") {
        if [
            "metadata",
            "trusted",
            "token",
            "excerpt",
            "now",
            "max-age-ms",
        ]
        .iter()
        .any(|n| o.has(n))
        {
            return Err(Usage(
                "--payload looks up an inflated list; it takes only --list, --uri and --idx"
                    .to_owned(),
            ));
        }
        return Ok(
            match binding::status_lookup(
                &o.file("payload")?,
                &o.file("list")?,
                &reference_bytes(o)?,
            ) {
                Ok(invalid) => Outcome::Accept(vec![("invalid", invalid.to_string())]),
                Err(e) => reject(&e),
            },
        );
    }
    let metadata = match metadata(o)? {
        Ok(m) => m,
        Err(e) => return Ok(reject(&e)),
    };
    let Ok(metadata) = DomainMetadata::from_bytes(&metadata) else {
        return Ok(Outcome::Reject("input".to_owned()));
    };
    let list = match StatusList::verify(&metadata, &o.file("token")?, &o.file("excerpt")?) {
        Ok(l) => l,
        Err(e) => return Ok(Outcome::Reject(e.code().to_owned())),
    };
    let recorded = list.recorded_at().unwrap_or(u64::MAX);
    if let Some(max) = o.opt_uint("max-age-ms")? {
        let fresh = o
            .uint("now")?
            .checked_sub(recorded)
            .is_some_and(|age| age <= max);
        if !fresh {
            return Ok(Outcome::Reject("status-stale".to_owned()));
        }
    }
    Ok(match list.is_invalid(&reference(o)?) {
        Ok(invalid) => Outcome::Accept(vec![
            ("invalid", invalid.to_string()),
            ("iat", recorded.to_string()),
            ("as_of", list.token().as_of.to_string()),
        ]),
        Err(e) => Outcome::Reject(e.code().to_owned()),
    })
}
