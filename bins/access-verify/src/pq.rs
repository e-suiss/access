//! Post-quantum anchors (CR-45 RA-5, RA-7, OP-159 m.3 (h)): after a domain retires its
//! classical algorithm, a classical artefact is accepted only with an RA-5 inclusion bundle
//! against a post-quantum checkpoint signed by the anchor the verifier pinned beforehand
//! (`--pq-anchors`, `pq-anchor.cddl`). Without an anchor for the domain the answer is
//! `pq-anchor-missing`; a chain of classical signatures never replaces it.

use access_kernel::codec::Canonical as _;
use access_kernel::record::Disclosure;
use access_kernel::verify::pq::PqAnchor;
use access_kernel::verify::reanchor::{PqBundle, PqCosign, accept_retired};
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::args::{Options, Usage};
use crate::commands::Outcome;

fn reject(reason: &str) -> Outcome {
    Outcome::Reject(reason.to_owned())
}

/// The anchors of a `pq-anchor-file`; a file that is not one is a usage error, never an empty
/// pin set.
pub(crate) fn anchors(bytes: &[u8]) -> Result<Vec<PqAnchor>, Usage> {
    let bad = || Usage("--pq-anchors: not a pq-anchor-file".to_owned());
    let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| bad())?;
    let Value::Map(entries) = &v else {
        return Err(bad());
    };
    let (mut version, mut list) = (None, None);
    for (k, val) in entries {
        match (k, val) {
            (Value::Text(t), Value::Unsigned(n)) if t == "v" => version = Some(*n),
            (Value::Text(t), Value::Array(a)) if t == "anchors" => list = Some(a),
            _ => return Err(bad()),
        }
    }
    let (Some(1), Some(list)) = (version, list) else {
        return Err(bad());
    };
    if list.is_empty() {
        return Err(bad());
    }
    list.iter()
        .map(|a| PqAnchor::from_value(a).map_err(|_| bad()))
        .collect()
}

fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(entries) = v else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
        .map(|(_, v)| v)
}

struct Owned {
    record: Disclosure,
    path: Vec<[u8; 32]>,
    checkpoint: Vec<u8>,
    cosigns: Vec<(String, u64, Vec<u8>)>,
}

fn bundle(bytes: &[u8]) -> Option<Owned> {
    let v = dcbor::decode(bytes, Limits::CEILING).ok()?;
    let (
        Some(Value::Bytes(record)),
        Some(Value::Array(path)),
        Some(Value::Bytes(checkpoint)),
        Some(Value::Array(cosigns)),
    ) = (
        field(&v, "record"),
        field(&v, "path"),
        field(&v, "checkpoint"),
        field(&v, "cosigns"),
    )
    else {
        return None;
    };
    let path = path
        .iter()
        .map(|h| match h {
            Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).ok(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let cosigns = cosigns
        .iter()
        .map(
            |c| match (field(c, "name"), field(c, "timestamp"), field(c, "sign1")) {
                (Some(Value::Text(n)), Some(Value::Unsigned(t)), Some(Value::Bytes(s))) => {
                    Some((n.clone(), *t, s.clone()))
                }
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>()?;
    Some(Owned {
        record: Disclosure::from_bytes(record).ok()?,
        path,
        checkpoint: checkpoint.clone(),
        cosigns,
    })
}

/// `pq-bundle`: a classical artefact of `--domain` with exact-content digest `--artefact`,
/// accepted after its algorithm's retirement only through `--bundle` reaching a pinned anchor.
pub(crate) fn pq_bundle(o: &Options) -> Result<Outcome, Usage> {
    let pinned = match o.opt("pq-anchors") {
        Some(_) => anchors(&o.file("pq-anchors")?)?,
        None => Vec::new(),
    };
    let domain = access_kernel::digest::Digest(o.hash("domain")?);
    let artefact = access_kernel::digest::Digest(o.hash("artefact")?);
    let origin = o.text("origin")?;
    let owned = match o.opt("bundle") {
        Some(_) => match bundle(&o.file("bundle")?) {
            Some(b) => Some(b),
            None => return Ok(reject("bundle")),
        },
        None => None,
    };
    let cosigns: Vec<PqCosign<'_>> = owned
        .as_ref()
        .map(|b| {
            b.cosigns
                .iter()
                .map(|(n, t, s)| PqCosign::new(n, *t, s))
                .collect()
        })
        .unwrap_or_default();
    let b = owned
        .as_ref()
        .map(|b| PqBundle::new(&b.record, &b.path, &b.checkpoint, &cosigns));
    // CR-45 RA-7, L0-SIG-81
    Ok(
        match accept_retired(
            &AwsLcBackend,
            &pinned,
            (&domain, origin),
            &artefact,
            b.as_ref(),
        ) {
            Ok(()) => Outcome::Accept(vec![("existed", String::from("anchored"))]),
            Err(access_kernel::verify::key_scope::KeyScopeError::PqAnchorMissing) => {
                reject("pq-anchor-missing")
            }
            Err(_) => reject("superseded"),
        },
    )
}

/// `out` of an artefact command of `--domain` (CR-45 RA-7, L0-SIG-81, OP-159 m.3 (h)): when
/// the Domain Metadata shows the classical algorithm retired, the artefact whose exact-content
/// digest `artefact` gives is accepted only through `--pq-bundle` reaching a pinned
/// `--pq-anchors` anchor; without either it stays `pq-anchor-missing`.
pub(crate) fn retired(
    o: &Options,
    out: Outcome,
    artefact: impl FnOnce() -> Result<Option<access_kernel::digest::Digest>, Usage>,
) -> Result<Outcome, Usage> {
    if !matches!(&out, Outcome::Reject(r) if r.contains("pq-anchor-missing"))
        || !o.has("pq-anchors")
    {
        return Ok(out);
    }
    let pinned = anchors(&o.file("pq-anchors")?)?;
    if !o.has("pq-bundle") {
        return Ok(reject("pq-bundle-missing"));
    }
    let Some(owned) = bundle(&o.file("pq-bundle")?) else {
        return Ok(reject("bundle"));
    };
    let Some(digest) = artefact()? else {
        return Ok(reject("artefact"));
    };
    let domain = access_kernel::digest::Digest(o.hash("domain")?);
    let cosigns: Vec<PqCosign<'_>> = owned
        .cosigns
        .iter()
        .map(|(n, t, s)| PqCosign::new(n, *t, s))
        .collect();
    let b = PqBundle::new(&owned.record, &owned.path, &owned.checkpoint, &cosigns);
    Ok(
        match accept_retired(
            &AwsLcBackend,
            &pinned,
            (&domain, o.text("origin")?),
            &digest,
            Some(&b),
        ) {
            Ok(()) => Outcome::Accept(vec![("existed", String::from("anchored"))]),
            Err(access_kernel::verify::key_scope::KeyScopeError::PqAnchorMissing) => {
                reject("pq-anchor-missing")
            }
            Err(_) => reject("superseded"),
        },
    )
}

/// The `--artefact` digest.
pub(crate) fn given(o: &Options) -> Result<Option<access_kernel::digest::Digest>, Usage> {
    Ok(Some(access_kernel::digest::Digest(o.hash("artefact")?)))
}

/// The digest the decision record commits for the receipt `sign1` (TI-12) after checking it
/// names `domain`, `audience` and `intent`.
pub(crate) fn receipt_digest(
    sign1: &[u8],
    (domain, audience, intent): (
        &access_kernel::digest::Digest,
        &str,
        &access_kernel::digest::Digest,
    ),
) -> Option<access_kernel::digest::Digest> {
    let payload = suiss_crypto::cose::parse_sign1(sign1).ok()?.payload?;
    let r = access_kernel::receipt::Receipt::from_bytes(&payload).ok()?;
    if r.domain != *domain || r.audience != audience || r.intent != *intent {
        return None;
    }
    access_kernel::receipt::digest(&r).ok()
}
