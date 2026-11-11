//! `access-cli incident contain` (§12.2.4, TN-48, SI-4, SI-22, OP-157 m.3 (i), Ek B 5582).
//!
//! The command declares a Party compromised as the realm's accepted declarant: an unsigned
//! `party_compromise` Claim over the PEP channel to Claim Ingest. Everything after that is an
//! attributable step of its own, which Access takes when the Claim is admitted:
//! 1. the Claim, and the end of the Party's Instances set up inside the window;
//! 2. on the identity plane, device keys of the ended Instances, the `session_epoch` raise and
//!    the end of refresh families, audited as `incident.contained`;
//! 3. the CAEP `session-revoked` and `device-compliance-change` events.
//!
//! Without `--occurred-at` the window starts 72 hours before the declaration. The command then
//! writes the window still open: projections issued before the declaration are accepted until
//! their `ValidityContract` horizon, at most the connectivity ceiling of their variant.

use std::path::Path;

use access_kernel::claim::{Channel, PARTY_COMPROMISE, Statement, Unsigned};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::{EqValue, Id, Window};
use access_kernel::tier::Tier;
use access_kernel::validity::ProfileVariant;
use access_kernel::validity::ceiling;
use clap::{Args, Subcommand};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use serde_json::{Value, json};

use super::{note, out};
use crate::config::{File, Incident};
use crate::exit::{self, Code};
use crate::http::{Https, Request, Transport};

/// The Claim Ingest path (CMP-8).
pub(crate) const INGEST: &str = "/access/v1/claims:ingest";

/// `incident` arguments.
#[derive(Debug, Args)]
pub(crate) struct IncidentArgs {
    #[command(subcommand)]
    pub(crate) verb: IncidentVerb,
}

/// What to do.
#[derive(Debug, Subcommand)]
pub(crate) enum IncidentVerb {
    /// Declares a Party compromised and writes the containment steps and the window still open.
    Contain {
        /// The compromised Party (base64url).
        #[arg(long, value_name = "ID")]
        party: String,
        /// When the compromise began, Unix milliseconds; without it, 72 hours before now.
        #[arg(long, value_name = "MS")]
        occurred_at: Option<u64>,
    },
}

/// One declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declaration {
    /// The public listener, `https://host[:port]`.
    pub(crate) api: String,
    /// The realm's governing domain.
    pub(crate) domain: Digest,
    /// The accepted declarant Party.
    pub(crate) declarant: Id,
    /// The compromised Party.
    pub(crate) party: Id,
    /// When the compromise began, if known.
    pub(crate) occurred_at: Option<u64>,
    /// The PEP certificate's leaf, DER: the channel the Claim is attributed to.
    pub(crate) leaf: Vec<u8>,
}

/// Why the containment did not go through.
#[derive(Debug, thiserror::Error)]
pub(crate) enum IncidentError {
    /// The Claim could not be encoded.
    #[error("the claim could not be encoded")]
    Encode,
    /// No answer came.
    #[error("{0}")]
    Http(#[from] crate::http::HttpError),
    /// Claim Ingest refused the declaration or did not admit it.
    #[error("claim ingest answered {status}: {detail}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The problem code or the disposition.
        detail: String,
    },
}

fn id16(text: &str) -> Option<Id> {
    let b = b64url_decode(text).ok()?;
    <[u8; 16]>::try_from(b.as_slice()).ok().map(Id)
}

fn digest(text: &str) -> Option<Digest> {
    let b = b64url_decode(text).ok()?;
    <[u8; 32]>::try_from(b.as_slice()).ok().map(Digest)
}

/// The unsigned `party_compromise` Claim (CDDL `unsigned-claim`), issued at `issued_at`.
///
/// # Errors
/// [`IncidentError::Encode`].
pub(crate) fn claim_bytes(d: &Declaration, issued_at: u64) -> Result<Vec<u8>, IncidentError> {
    let value = d
        .occurred_at
        .map(|t| i64::try_from(t).map(EqValue::Int))
        .transpose()
        .map_err(|_| IncidentError::Encode)?;
    Unsigned {
        statement: Statement {
            domain: d.domain,
            issuer: d.declarant,
            subject: d.party,
            class: String::from(PARTY_COMPROMISE),
            value,
            issued_at,
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            assurance: std::collections::BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        channel: Channel::Pep(suiss_crypto::digest::sha256(&d.leaf)),
    }
    .to_bytes()
    .map_err(|_| IncidentError::Encode)
}

const VARIANTS: [ProfileVariant; 5] = [
    ProfileVariant::OnlineStrict,
    ProfileVariant::BoundedStaleness,
    ProfileVariant::RevalidateOnReconnect,
    ProfileVariant::CheckpointedOffline,
    ProfileVariant::CheckpointContinuation,
];

const fn variant_name(v: ProfileVariant) -> &'static str {
    match v {
        ProfileVariant::OnlineStrict => "online-strict",
        ProfileVariant::BoundedStaleness => "bounded-staleness",
        ProfileVariant::RevalidateOnReconnect => "revalidate-on-reconnect",
        ProfileVariant::CheckpointedOffline => "checkpointed-offline",
        ProfileVariant::CheckpointContinuation => "checkpoint-continuation",
    }
}

/// The window still open after a declaration at `at` (§13.7.2): for each connectivity variant,
/// the latest moment a projection issued before `at` may still be accepted, and the latest of all.
#[must_use]
pub(crate) fn open_window(at: u64) -> Value {
    let mut by_variant = Vec::new();
    let mut latest = at;
    for v in VARIANTS {
        let longest = [Tier::Ct0, Tier::Ct1, Tier::Ct2, Tier::Ct3]
            .into_iter()
            .filter_map(|t| ceiling::policy(v, t))
            .map(|c| c.horizon_ms)
            .max();
        if let Some(h) = longest {
            let until = at.saturating_add(h);
            latest = latest.max(until);
            by_variant.push(json!({ "variant": variant_name(v), "until": until }));
        }
    }
    json!({
        "from": at,
        "until": latest,
        "by_variant": by_variant,
        "note": "Projections issued before the declaration are accepted until their ValidityContract horizon; Access cannot recall them sooner.",
    })
}

/// The report of a declaration admitted at `at` with `verdict` (the Claim Ingest answer).
#[must_use]
pub(crate) fn report(d: &Declaration, at: u64, verdict: &Value) -> Value {
    let from = access_internal_api::events::compromise_from(d.occurred_at, at);
    json!({
        "party": b64url_encode(&d.party.0),
        "declared_at": at,
        "window": {
            "from": from,
            "until": at,
            "occurred_at": d.occurred_at,
            "assumed": d.occurred_at.is_none(),
        },
        "steps": [
            {
                "step": 1,
                "what": "party_compromise claim; the Party's Instances set up in the window end",
                "by": "authority",
                "claim": verdict.get("claim"),
                "position": verdict.get("position"),
            },
            {
                "step": 2,
                "what": "device keys, session_epoch, refresh families (incident.contained)",
                "by": "identity",
            },
            {
                "step": 3,
                "what": "CAEP session-revoked and device-compliance-change",
                "by": "identity",
            },
        ],
        "open_window": open_window(at),
    })
}

/// Declares `d` at `at` through `t`: one Claim Ingest call, sent once under `idempotency`.
///
/// # Errors
/// [`IncidentError`]; a quarantined Claim is refused, since it contains nothing.
pub(crate) async fn contain<T: Transport>(
    t: &T,
    d: &Declaration,
    at: u64,
    idempotency: &str,
) -> Result<Value, IncidentError> {
    let claim = claim_bytes(d, at)?;
    let body = json!({
        "domain": format!("sha-256:{}", b64url_encode(&d.domain.0)),
        "carrier": "unsigned",
        "claim": b64url_encode(&claim),
    });
    let r = t
        .send(Request {
            method: "POST",
            url: format!("{}{INGEST}", d.api.trim_end_matches('/')),
            headers: vec![(String::from("Idempotency-Key"), idempotency.to_owned())],
            body: Some(("application/json", body.to_string().into_bytes())),
        })
        .await?;
    let v = r.json();
    let text = |n: &str| v.get(n).and_then(Value::as_str).map(String::from);
    if r.status != 200 {
        return Err(IncidentError::Refused {
            status: r.status,
            detail: text("code").unwrap_or_default(),
        });
    }
    if text("disposition").as_deref() != Some("admit") {
        return Err(IncidentError::Refused {
            status: r.status,
            detail: text("disposition").unwrap_or_default(),
        });
    }
    Ok(report(d, at, &v))
}

fn section(config: &Path) -> Result<Incident, Code> {
    let file = File::load(config).map_err(|e| {
        note(&format!("access-cli: {e}"));
        exit::CONFIG
    })?;
    file.incident.ok_or_else(|| {
        note("access-cli: the incident section is required");
        exit::CONFIG
    })
}

fn leaf(path: &Path) -> Result<Vec<u8>, Code> {
    let pem = std::fs::read(path).map_err(|e| {
        note(&format!("access-cli: {}: {e}", path.display()));
        exit::CONFIG
    })?;
    CertificateDer::pem_slice_iter(&pem)
        .next()
        .and_then(Result::ok)
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| {
            note("access-cli: the PEP certificate file holds no certificate");
            exit::CONFIG
        })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Runs `incident`.
pub(crate) async fn run(config: &Path, args: IncidentArgs) -> Code {
    let IncidentVerb::Contain { party, occurred_at } = args.verb;
    let Some(party) = id16(&party) else {
        note("access-cli: --party is a base64url Party id");
        return exit::USAGE;
    };
    let c = match section(config) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let (Some(domain), Some(declarant)) = (digest(&c.domain), id16(&c.declarant)) else {
        note("access-cli: incident.domain and incident.declarant are base64url ids");
        return exit::CONFIG;
    };
    if !c.api.starts_with("https://") {
        note("access-cli: incident.api must be an https URL");
        return exit::CONFIG;
    }
    let leaf = match leaf(&c.pep_cert_file) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let https = match Https::with_client(&c.ca_file, &c.pep_cert_file, &c.pep_key_file) {
        Ok(h) => h,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let d = Declaration {
        api: c.api,
        domain,
        declarant,
        party,
        occurred_at,
        leaf,
    };
    let Ok(key) = access_crypto::random::bytes::<16>() else {
        return exit::FAILED;
    };
    match contain(&https, &d, now_ms(), &b64url_encode(&key)).await {
        Ok(r) => out(&format!("{r}\n")),
        Err(e) => {
            note(&format!("access-cli: {e}"));
            match e {
                IncidentError::Refused { .. } | IncidentError::Http(_) => exit::REMOTE,
                IncidentError::Encode => exit::FAILED,
            }
        }
    }
}

#[cfg(test)]
mod tests;
