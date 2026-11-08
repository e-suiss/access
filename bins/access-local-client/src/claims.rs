//! A `party_compromise` Claim over the PEP channel (§9.13, L2-CLM-5, OP-149 m.26 (c)): the
//! unsigned Claim a product's PEP hands to `POST /access/v1/claims:ingest` with its client
//! certificate. The realm's bootstrap accepted the declarant Party it names as issuer; once
//! admitted, the domain produces `party.compromised` (OP-149 m.7).

use std::collections::BTreeMap;

use access_kernel::claim::{Channel, PARTY_COMPROMISE, Statement, Unsigned};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::{EqValue, Id, Window};
use serde_json::{Value, json};

use crate::ClientError;
use crate::dpop::random_text;
use crate::http::Http;

/// What the declaration names.
pub struct Compromise<'a> {
    /// The deployment's API base, e.g. `https://access-server:8443`.
    pub api_base: &'a str,
    /// The realm's governing domain.
    pub domain: Digest,
    /// The accepted declarant Party (the bootstrap's `compromise.issuer`).
    pub issuer: Id,
    /// The compromised Party.
    pub party: Id,
    /// When the compromise began, Unix milliseconds; without it the window starts 72 hours
    /// before the declaration (OP-149 m.17 (d)).
    pub occurred_at: Option<u64>,
    /// The PEP certificate's leaf, DER: the channel the Claim is attributed to.
    pub pep_leaf_der: &'a [u8],
}

/// The Claim's canonical bytes (CDDL `unsigned-claim`).
///
/// # Errors
/// [`ClientError::Encode`].
pub fn claim_bytes(c: &Compromise<'_>, issued_at_ms: u64) -> Result<Vec<u8>, ClientError> {
    let thumb = suiss_crypto::digest::sha256(c.pep_leaf_der);
    let value = match c.occurred_at {
        Some(t) => Some(EqValue::Int(
            i64::try_from(t).map_err(|_| ClientError::Encode)?,
        )),
        None => None,
    };
    let unsigned = Unsigned {
        statement: Statement {
            domain: c.domain,
            issuer: c.issuer,
            subject: c.party,
            class: String::from(PARTY_COMPROMISE),
            value,
            issued_at: issued_at_ms,
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        channel: Channel::Pep(thumb),
    };
    unsigned.to_bytes().map_err(|_| ClientError::Encode)
}

/// The `ClaimSubmission` body.
#[must_use]
pub fn submission(domain: &Digest, claim: &[u8]) -> Value {
    json!({
        "domain": format!("sha-256:{}", b64url_encode(&domain.0)),
        "carrier": "unsigned",
        "claim": b64url_encode(claim),
    })
}

/// Hands the declaration to Claim Ingest; `http` carries the PEP certificate. The answer is
/// the `ClaimVerdict`, or the problem Access answered with.
///
/// # Errors
/// [`ClientError`].
pub async fn declare(http: &Http, c: &Compromise<'_>) -> Result<Value, ClientError> {
    let now_ms = crate::dpop::now_s().saturating_mul(1000);
    let claim = claim_bytes(c, now_ms)?;
    let body = submission(&c.domain, &claim).to_string();
    let key = random_text::<16>()?;
    let r = http
        .request(
            "POST",
            &format!("{}/access/v1/claims:ingest", c.api_base),
            &[("Idempotency-Key", key.as_str())],
            Some(("application/json", body.as_bytes())),
        )
        .await?;
    if r.status == 200 {
        Ok(r.json())
    } else {
        Err(ClientError::Unexpected {
            step: "claims:ingest",
            status: r.status,
            body: r.text(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // L2-CLM-5, OP-149 m.26 (c)
    #[test]
    fn the_claim_reads_back_over_its_channel() {
        let leaf = [0xc3_u8; 40];
        let c = Compromise {
            api_base: "https://access-server:8443",
            domain: Digest([1; 32]),
            issuer: Id([2; 16]),
            party: Id([3; 16]),
            occurred_at: Some(5_000),
            pep_leaf_der: &leaf,
        };
        let bytes = claim_bytes(&c, 9_000).unwrap();
        let channel = Channel::Pep(suiss_crypto::digest::sha256(&leaf));
        let u = access_kernel::claim::unsigned(&bytes, &Digest([1; 32]), &channel).unwrap();
        assert_eq!(u.statement.class, PARTY_COMPROMISE);
        assert_eq!(
            (u.statement.issuer, u.statement.subject),
            (Id([2; 16]), Id([3; 16]))
        );
        assert_eq!(u.statement.value, Some(EqValue::Int(5_000)));
        assert_eq!(u.statement.issued_at, 9_000);
        assert!(access_kernel::claim::unsigned(&bytes, &Digest([9; 32]), &channel).is_err());
        assert!(
            access_kernel::claim::unsigned(&bytes, &Digest([1; 32]), &Channel::Pep([0; 32]))
                .is_err()
        );
        let s = submission(&c.domain, &bytes);
        assert_eq!(s["carrier"], "unsigned");
        assert!(s["domain"].as_str().unwrap().starts_with("sha-256:"));
        let none = Compromise {
            occurred_at: None,
            ..c
        };
        let u = access_kernel::claim::unsigned(
            &claim_bytes(&none, 9_000).unwrap(),
            &Digest([1; 32]),
            &channel,
        )
        .unwrap();
        assert_eq!(u.statement.value, None);
    }
}
