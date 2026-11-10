//! Resource incarnations (OP-156 m.3 (k), INV-32, EI-23, §7.9.10.4, E14): a domain product
//! declares a resource's lifecycle under its own issuer key with a `resource_lifecycle` Claim
//! (create, delete, reincarnate). Access does not say whether a resource exists; it only keeps
//! the highest incarnation seen per `(domain, namespace, path)` and refuses at ingest a create or
//! reincarnate that does not go above it (`incarnation-reused`). A Grant on incarnation n does
//! not cover n + 1: the Kernel compares the whole `ResourceRef`.

use access_authority_ingest::domain::Refusal;
use access_kernel::claim::Statement;
use access_kernel::claim::body::BODY_CONTEXT;
use access_kernel::model::{EqValue, Id, ResourceRef};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use crate::CoreError;
use crate::app::Authority;
use access_authority_sequencer::ports::DomainLog;

use crate::ports::{Binding, Reader, Salts};

/// The Claim class.
pub const CLASS: &str = "resource_lifecycle";

/// The refusal of a create or reincarnate that reuses an incarnation.
pub const REUSED: Refusal = Refusal("incarnation-reused");

/// The refusal of a lifecycle Claim whose body or value is not one.
pub const MALFORMED: Refusal = Refusal("claim-value");

/// What happened to the resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The resource exists from this incarnation on.
    Create,
    /// This incarnation ended.
    Delete,
    /// The same id came back as a new incarnation.
    Reincarnate,
}

impl Event {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Reincarnate => "reincarnate",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Create, Self::Delete, Self::Reincarnate]
            .into_iter()
            .find(|e| e.name() == s)
    }
}

/// One declared lifecycle fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    /// The resource and the incarnation the fact is about.
    pub resource: ResourceRef,
    /// What happened.
    pub event: Event,
}

/// One recorded fact, as the `resource-incarnation` search shows it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fact {
    /// The incarnation.
    pub incarnation: u64,
    /// `create`, `delete` or `reincarnate`.
    pub event: String,
    /// The Claim.
    pub claim: Id,
    /// Its issuer.
    pub issuer: Id,
    /// Its record.
    pub pos: u64,
}

/// What the `resource-incarnation` search reports for one resource (advisory).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Incarnations {
    /// The resource's namespace.
    pub namespace: String,
    /// Its path.
    pub path: Vec<String>,
    /// The highest incarnation seen; `None` when nothing was declared.
    pub highest: Option<u64>,
    /// Every recorded fact, in record order.
    pub facts: Vec<Fact>,
}

fn reference(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b':' | b'-')
        })
}

/// Reads a `resource_lifecycle` Claim (`product-seam.cddl`): the body
/// `{namespace, path: [+ tstr], incarnation, event}` and its digest in the Claim's value.
///
/// # Errors
/// [`MALFORMED`].
pub fn read(statement: &Statement, body: Option<&[u8]>) -> Result<Lifecycle, Refusal> {
    let bytes = body.ok_or(MALFORMED)?;
    let value = dcbor::decode(bytes, Limits::CEILING).map_err(|_| MALFORMED)?;
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(CLASS), value.clone()]),
        Limits::CEILING,
    )
    .map_err(|_| MALFORMED)?;
    let digest = context_digest(BODY_CONTEXT, &tagged);
    if statement.value != Some(EqValue::Bytes(digest.0.to_vec())) {
        return Err(MALFORMED);
    }
    let Value::Map(entries) = &value else {
        return Err(MALFORMED);
    };
    if entries.len() != 4 {
        return Err(MALFORMED);
    }
    let namespace = match value.get("namespace") {
        Some(Value::Text(t)) if reference(t) => t.clone(),
        _ => return Err(MALFORMED),
    };
    let path = match value.get("path") {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= 32 => items
            .iter()
            .map(|i| match i {
                Value::Text(t) => Ok(t.clone()),
                _ => Err(MALFORMED),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(MALFORMED),
    };
    let incarnation = match value.get("incarnation") {
        Some(Value::Unsigned(n)) if i64::try_from(*n).is_ok() => *n,
        _ => return Err(MALFORMED),
    };
    let event = match value.get("event") {
        Some(Value::Text(t)) => Event::parse(t).ok_or(MALFORMED)?,
        _ => return Err(MALFORMED),
    };
    Ok(Lifecycle {
        resource: ResourceRef {
            namespace,
            path,
            incarnation,
        },
        event,
    })
}

/// The fact of an already recorded Claim, for the registry to keep again (L2-CLM-4); `None` for
/// any other class.
#[must_use]
pub fn recorded(statement: &Statement, body: Option<&[u8]>) -> Option<Lifecycle> {
    (statement.class == CLASS)
        .then(|| read(statement, body).ok())
        .flatten()
}

/// INV-32, E14: whether `l` reuses an incarnation, given the highest one seen. A create or a
/// reincarnate must go above every incarnation declared before, a deleted one included; a
/// delete only records that its incarnation ended.
#[must_use]
pub fn reuses(l: &Lifecycle, highest: Option<u64>) -> bool {
    match l.event {
        Event::Delete => false,
        Event::Create | Event::Reincarnate => highest.is_some_and(|h| l.resource.incarnation <= h),
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The ingest gate of a `resource_lifecycle` Claim (OP-156 m.3 (k)): `Ok(None)` for any other
    /// class, the fact when it may be recorded, or its refusal.
    ///
    /// # Errors
    /// [`CoreError`] when the registry cannot be read: nothing is recorded (fail closed).
    pub(crate) async fn lifecycle_gate(
        &self,
        statement: &Statement,
        body: Option<&[u8]>,
    ) -> Result<Result<Option<Lifecycle>, Refusal>, CoreError> {
        if statement.class != CLASS {
            return Ok(Ok(None));
        }
        let l = match read(statement, body) {
            Ok(l) => l,
            Err(r) => return Ok(Err(r)),
        };
        let highest = self
            .reader
            .highest_incarnation(&l.resource.namespace, &l.resource.path)
            .await?;
        Ok(if reuses(&l, highest) {
            Err(REUSED)
        } else {
            Ok(Some(l))
        })
    }

    /// The `resource-incarnation` report of one resource.
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn incarnations(
        &self,
        namespace: &str,
        path: &[String],
    ) -> Result<Incarnations, CoreError> {
        let facts = self.reader.incarnations(namespace, path).await?;
        Ok(Incarnations {
            namespace: namespace.to_owned(),
            path: path.to_vec(),
            highest: facts.iter().map(|f| f.incarnation).max(),
            facts,
        })
    }
}

#[cfg(test)]
mod tests;
