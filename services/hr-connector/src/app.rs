//! One connector run (OP-156 m.3 (q), IDP-35): the HR system's pages are read, mapped to
//! records and pushed to Access's HR batch API as `idp.hr.import` writes, each drafted, signed
//! by the connector Instance's key and committed. The connector decides nothing: Access reads
//! every record, refuses a bad batch whole, and states nothing a domain did not accept. A run
//! that cannot reach Access stops; the next run pushes everything again and an unchanged record
//! changes nothing.

use access_kernel::json::{b64url_decode, b64url_encode};
use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::vendor::Vendor;
use crate::domain::{Batch, batches};
use crate::ports::{Access, Fault, Pull, Random, Sign};

/// One configured connector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connector {
    /// Its name, as `idp.hr.connector_register` registered it.
    pub name: String,
    /// The HR system it reads.
    pub vendor: Vendor,
    /// The realm's slug.
    pub realm: String,
    /// The Access HR source it pushes to.
    pub source: String,
}

/// What one run did: counts only, never a record's content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Records read from the HR system.
    pub read: u32,
    /// People left out: no id or no work address.
    pub left_out: u32,
    /// Records Access took.
    pub pushed: u32,
    /// Records of batches Access refused.
    pub refused: u32,
    /// Batches sent.
    pub batches: u32,
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The HR system or Access gave no usable answer.
    #[error(transparent)]
    Fault(#[from] Fault),
    /// A page was not the vendor's listing.
    #[error("not the vendor's listing")]
    Listing,
    /// No randomness or no signature.
    #[error("no signature")]
    Signature,
}

fn digest(v: &Value) -> Result<[u8; 32], Fault> {
    v.as_str()
        .and_then(|s| b64url_decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or(Fault::Malformed)
}

/// The HR batch route of `c`.
#[must_use]
pub fn batch_path(c: &Connector) -> String {
    format!(
        "/admin/v1/realms/{}/hr-sources/{}/records:batch",
        c.realm, c.source
    )
}

async fn push<A: Access, S: Sign, R: Random>(
    c: &Connector,
    (access, sign, random): (&A, &S, &R),
    batch: &Batch,
) -> Result<bool, RunError> {
    let body = json!({
        "file": b64url_encode(&batch.digest()),
        "records": batch.records,
        "content": batch.content,
    });
    let draft = access
        .draft(
            &c.realm,
            json!({ "operation": "importHrBatch", "key": c.source, "body": body }),
        )
        .await?;
    let domain = digest(draft.get("domain").unwrap_or(&Value::Null))?;
    let intent = digest(draft.get("intent_digest").unwrap_or(&Value::Null))?;
    let pep = draft
        .get("pep")
        .and_then(Value::as_str)
        .ok_or(Fault::Malformed)?;
    let nonce = random.bytes().ok_or(RunError::Signature)?;
    let ais = sign
        .ais(domain, &nonce, intent, pep)
        .ok_or(RunError::Signature)?;
    let (status, answer) = access
        .commit(
            &batch_path(c),
            draft.get("body").cloned().unwrap_or(Value::Null),
            (&ais, &b64url_encode(&nonce)),
        )
        .await?;
    let code = answer
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("refused")
        .to_owned();
    match status {
        200 => Ok(true),
        400 | 403 | 409 | 422 => {
            tracing::warn!(
                event = "hr.connector.failed",
                vendor = c.vendor.name(),
                reason = code.as_str(),
                "Access refused an HR batch"
            );
            Ok(false)
        }
        s => Err(Fault::Refused(s, code).into()),
    }
}

/// Runs `c` once.
///
/// # Errors
/// [`RunError`]; batches pushed before stay pushed.
pub async fn run<P: Pull, A: Access, S: Sign, R: Random>(
    c: &Connector,
    (pull, access, sign, random): (&P, &A, &S, &R),
) -> Result<Report, RunError> {
    let mut report = Report::default();
    let mut records = Vec::new();
    for page in pull.pages().await? {
        let (mut r, left) = c.vendor.records(&page).map_err(|_| RunError::Listing)?;
        report.read = report
            .read
            .saturating_add(u32::try_from(r.len()).unwrap_or(u32::MAX))
            .saturating_add(left);
        report.left_out = report.left_out.saturating_add(left);
        records.append(&mut r);
    }
    for batch in batches(&records) {
        report.batches = report.batches.saturating_add(1);
        if push(c, (access, sign, random), &batch).await? {
            report.pushed = report.pushed.saturating_add(batch.records);
        } else {
            report.refused = report.refused.saturating_add(batch.records);
        }
    }
    Ok(report)
}
