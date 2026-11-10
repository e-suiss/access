//! How a twin reaches Access (PI-14, B21, OP-62): one HTTP call at a time over Access's public
//! listener, on the endpoints of [`ENDPOINTS`] only. The transport authenticates the twin as its
//! own PEP (its client certificate); the wire reports what came back and never decides.

use std::future::Future;

use access_sdk::transport::Answer;

/// An HTTP method the twin uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// The method's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One call to Access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The method.
    pub method: Method,
    /// The path, its template filled in.
    pub path: String,
    /// The endpoint template of [`ENDPOINTS`] the path fills in.
    pub endpoint: &'static str,
    /// `Authorization: Bearer`, for the platform routes (RFC 7523 client assertion).
    pub bearer: Option<String>,
    /// `Idempotency-Key` (OP-65).
    pub idempotency_key: Option<String>,
    /// A JSON body; empty for `GET`.
    pub body: Vec<u8>,
}

/// The transport: Access's public listener with the twin's client certificate.
pub trait Wire: Send + Sync {
    /// Sends one call; a fault is reported, never decided.
    fn send(&self, call: Call) -> impl Future<Output = Answer> + Send;
}

/// One public endpoint the twin calls: an `OpenAPI` path of `sdks/openapi/` or an ADP protocol
/// binding (L1-ADP-5, L1-ADP-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The method.
    pub method: Method,
    /// The path template.
    pub path: &'static str,
}

/// `POST`: a pairing challenge per realm of a tenant (OP-149 m.4).
pub const PAIRING_CHALLENGES: &str = "/access/v1/tenants/{tenant}/pairing/challenges";
/// `POST`: the product's own signed Exercises for those realms (OP-149 m.16 (a)).
pub const PAIRING: &str = "/access/v1/tenants/{tenant}/pairing";
/// `POST`: a Schema Publication Package (L1-ADP-18).
pub const PUBLICATIONS: &str = "/access/v1/publications";
/// `POST`: where the product's own publication stands (L1-ADP-18).
pub const PUBLICATION_STATUS: &str = "/access/v1/publications:status";
/// `POST`: one Claim through Claim Ingest (CMP-8).
pub const CLAIMS_INGEST: &str = "/access/v1/claims:ingest";
/// `POST`: one ADP evaluation (L1-ADP-5).
pub const EVALUATION: &str = "/access/v1/evaluation";
/// `GET`: a domain's signed Domain Metadata (L1-ADP-11, §9.15.1).
pub const DOMAIN_METADATA: &str = "/.well-known/access-domain-metadata/{domain}";

/// Every endpoint the twin calls; `cargo xtask check no-privileged-path` finds each one in the
/// public contracts (PI-14).
pub const ENDPOINTS: [Endpoint; 7] = [
    Endpoint {
        method: Method::Post,
        path: PAIRING_CHALLENGES,
    },
    Endpoint {
        method: Method::Post,
        path: PAIRING,
    },
    Endpoint {
        method: Method::Post,
        path: PUBLICATIONS,
    },
    Endpoint {
        method: Method::Post,
        path: PUBLICATION_STATUS,
    },
    Endpoint {
        method: Method::Post,
        path: CLAIMS_INGEST,
    },
    Endpoint {
        method: Method::Post,
        path: EVALUATION,
    },
    Endpoint {
        method: Method::Get,
        path: DOMAIN_METADATA,
    },
];

/// `template` with each `{name}` replaced by its value from `values`; `None` when a placeholder
/// has no value or a value would leave its path segment.
#[must_use]
pub fn fill(template: &str, values: &[(&str, &str)]) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let (head, tail) = rest.split_at(open);
        out.push_str(head);
        let close = tail.find('}')?;
        let name = tail.get(1..close)?;
        let value = values.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)?;
        if value.is_empty() || value.contains(['/', '?', '#']) {
            return None;
        }
        out.push_str(value);
        rest = tail.get(close.checked_add(1)?..)?;
    }
    out.push_str(rest);
    Some(out)
}

/// A call of `method` on `endpoint` (one of [`ENDPOINTS`]) filled with `values`.
#[must_use]
pub fn call(
    method: Method,
    endpoint: &'static str,
    values: &[(&str, &str)],
    body: Vec<u8>,
) -> Option<Call> {
    ENDPOINTS
        .iter()
        .any(|e| e.method == method && e.path == endpoint)
        .then_some(())?;
    Some(Call {
        method,
        path: fill(endpoint, values)?,
        endpoint,
        bearer: None,
        idempotency_key: None,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // PI-14
    #[test]
    fn a_call_names_only_a_listed_endpoint() {
        assert!(call(Method::Post, EVALUATION, &[], Vec::new()).is_some());
        assert!(call(Method::Get, EVALUATION, &[], Vec::new()).is_none());
        assert!(call(Method::Post, "/internal/v1/anything", &[], Vec::new()).is_none());
    }

    #[test]
    fn a_template_fills_one_segment_per_placeholder() {
        assert_eq!(
            fill(PAIRING, &[("tenant", "tnt_1")]).as_deref(),
            Some("/access/v1/tenants/tnt_1/pairing")
        );
        assert_eq!(fill(PAIRING, &[("tenant", "a/b")]), None);
        assert_eq!(fill(PAIRING, &[]), None);
    }
}
