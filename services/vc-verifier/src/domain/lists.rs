//! The trusted lists from the parser worker's `tl.read` summaries (Ek B 4834; OP-155 m.3 (p)):
//! the EU `LoTL` and the national lists it points to. The XML is parsed only in the parser
//! worker; this module reads its deterministic CBOR summaries. A list counts only when its
//! document's SHA-256 is one of the operator's pinned snapshot digests: the `XAdES` signature is
//! not verified here, so authenticity comes from the pinned, checksummed snapshot.

use suiss_crypto::dcbor::{self, Limits, Value};

use super::time::rfc3339_ms;
use super::trust::{Service, TrustedLists};

/// The `LoTL` `TSLType`.
pub const LOTL_TYPE: &str = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

/// One list as read: its document's SHA-256 and the worker's summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// SHA-256 of the XML document as fetched.
    pub digest: [u8; 32],
    /// Where it was fetched from.
    pub location: String,
    /// The `tl.read` summary.
    pub summary: Vec<u8>,
}

/// Why the lists are not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    /// A document's digest is not pinned.
    #[error("trusted-list-unpinned")]
    Unpinned,
    /// A summary is not in the `tl.read` shape, or a date is unreadable.
    #[error("trusted-list-malformed")]
    Malformed,
    /// The first document is not the `LoTL`, or a list is not one the `LoTL` points to.
    #[error("trusted-list-unlisted")]
    Unlisted,
}

fn text(v: &Value, key: &str) -> Result<String, ListError> {
    match v.get(key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(ListError::Malformed),
    }
}

fn certs(v: &Value) -> Result<Vec<Vec<u8>>, ListError> {
    match v.get("certificates") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(ListError::Malformed),
            })
            .collect(),
        _ => Err(ListError::Malformed),
    }
}

fn items<'v>(v: &'v Value, key: &str) -> Result<&'v [Value], ListError> {
    match v.get(key) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(ListError::Malformed),
    }
}

/// Assembles the lists: `lotl` first, then the national lists; every document pinned.
///
/// # Errors
/// [`ListError`].
pub fn assemble(
    lotl: &Document,
    lists: &[Document],
    pins: &[[u8; 32]],
) -> Result<TrustedLists, ListError> {
    let mut all = vec![lotl];
    all.extend(lists.iter());
    if all.iter().any(|d| !pins.contains(&d.digest)) {
        return Err(ListError::Unpinned);
    }
    let decode =
        |d: &Document| dcbor::decode(&d.summary, Limits::CEILING).map_err(|_| ListError::Malformed);
    let root = decode(lotl)?;
    if text(&root, "tsl_type")? != LOTL_TYPE {
        return Err(ListError::Unlisted);
    }
    let pointed: Vec<String> = items(&root, "pointers")?
        .iter()
        .map(|p| text(p, "location"))
        .collect::<Result<_, _>>()?;
    let sequence = match root.get("sequence") {
        Some(Value::Unsigned(n)) => *n,
        _ => return Err(ListError::Malformed),
    };
    let mut next_update = rfc3339_ms(&text(&root, "next_update")?).ok_or(ListError::Malformed)?;
    let mut services = Vec::new();
    for d in lists {
        if !pointed.contains(&d.location) {
            return Err(ListError::Unlisted);
        }
        let v = decode(d)?;
        let n = rfc3339_ms(&text(&v, "next_update")?).ok_or(ListError::Malformed)?;
        next_update = next_update.min(n);
        for s in items(&v, "services")? {
            services.push(Service {
                provider: text(s, "provider")?,
                service_type: text(s, "service_type")?,
                status: text(s, "status")?,
                certificates: certs(s)?,
            });
        }
    }
    Ok(TrustedLists {
        sequence,
        next_update_ms: next_update,
        digests: all.iter().map(|d| d.digest.to_vec()).collect(),
        signature_verified: false,
        pinned: true,
        services,
    })
}
