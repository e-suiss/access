//! The experience use cases (OP-63): plan the reads a hub needs, send the reader's signed reads
//! to each domain and assemble the hub. Nothing here holds or writes authority (CMP-16, XI-3).

use access_sdk::transport::Answer;
use futures_util::future::join_all;

use crate::contract::{DomainRef, Hub, HubRequest, Kind, Plan, PlanRequest, SignedRead};
use crate::domain::Malformed;
use crate::domain::hub::{DomainReads, Read, assemble, results};
use crate::domain::plan::{domain_of, is_read, party_of, read};
use crate::ports::{Clock, Random, Upstream};

/// Most domains one hub reads.
pub const MAX_DOMAINS: usize = 16;

/// The experience service.
pub struct Experience<U, C, N> {
    upstream: U,
    clock: C,
    random: N,
    pep: String,
}

impl<U: Upstream, C: Clock, N: Random> Experience<U, C, N> {
    /// The service: `pep` is the name Access authenticates it by, which every AIS it forwards
    /// must carry (XI-18).
    pub fn new(upstream: U, clock: C, random: N, pep: String) -> Self {
        Self {
            upstream,
            clock,
            random,
            pep,
        }
    }

    /// The PEP name.
    #[must_use]
    pub fn pep(&self) -> &str {
        &self.pep
    }

    /// The reads to sign for `req`.
    ///
    /// # Errors
    /// [`Malformed`] for a bad Party or domain, too many domains, or no randomness.
    pub fn plan(&self, req: &PlanRequest) -> Result<Plan, Malformed> {
        if req.domains.is_empty() || req.domains.len() > MAX_DOMAINS {
            return Err(Malformed("domains"));
        }
        let viewer = party_of(&req.viewer)?;
        let kinds = req.kinds.clone().unwrap_or_else(|| Kind::ALL.to_vec());
        let now = self.clock.now();
        let mut reads = Vec::new();
        for d in &req.domains {
            let domain = domain_of(&d.domain)?;
            for kind in &kinds {
                let nonce = self.random.nonce().ok_or(Malformed("random"))?;
                reads.push(read(domain, *kind, viewer, nonce, now)?);
            }
        }
        Ok(Plan {
            pep: self.pep.clone(),
            reads,
        })
    }

    async fn one(&self, r: &SignedRead) -> Read {
        let Ok(body) = serde_json::to_vec(&r.body) else {
            return Read::Unknown;
        };
        match self.upstream.search(&r.domain, r.kind, body).await {
            Answer::Response(resp) if resp.status == 200 => {
                match serde_json::from_slice(&resp.body)
                    .ok()
                    .as_ref()
                    .and_then(results)
                {
                    Some(v) => Read::Answered(v),
                    None => Read::Unknown,
                }
            }
            _ => Read::Unknown,
        }
    }

    /// The hub for `req`: each signed read goes to its domain as signed; a read that is not a
    /// hub read for this viewer is refused before anything is sent (XI-22).
    ///
    /// # Errors
    /// [`Malformed`] for a bad viewer, too many reads, or a body that is not a hub read.
    pub async fn hub(&self, req: &HubRequest) -> Result<Hub, Malformed> {
        party_of(&req.viewer)?;
        if req.reads.len() > MAX_DOMAINS.saturating_mul(Kind::ALL.len()) {
            return Err(Malformed("reads"));
        }
        for r in &req.reads {
            domain_of(&r.domain)?;
            if !is_read(&r.body, &r.domain, r.kind, &req.viewer) {
                return Err(Malformed("read"));
            }
        }
        let answers = join_all(req.reads.iter().map(|r| self.one(r))).await;
        let mut domains: Vec<DomainReads> = Vec::new();
        for (r, read) in req.reads.iter().zip(answers) {
            match domains.iter_mut().find(|d| d.domain.domain == r.domain) {
                Some(d) => d.reads.push((r.kind, read)),
                None => domains.push(DomainReads {
                    domain: DomainRef {
                        domain: r.domain.clone(),
                        label: r.label.clone(),
                    },
                    reads: vec![(r.kind, read)],
                }),
            }
        }
        let mut hub = assemble(&req.viewer, req.depth, self.clock.now(), &domains);
        // OP-156 m.3 (t)
        if let Some(realm) = req.realm.as_deref() {
            hub.attention = self.attention(realm, &req.viewer).await;
        }
        Ok(hub)
    }

    /// The Needs Attention link of `realm`'s coordinator for `viewer`: none when the realm names
    /// no coordinator, or Access or the coordinator does not answer (OP-156 m.3 (t)).
    async fn attention(&self, realm: &str, viewer: &str) -> Option<crate::contract::Attention> {
        let slug_ok = (2..=63).contains(&realm.len())
            && realm.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && realm
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !slug_ok {
            return None;
        }
        let json = |a: Answer| match a {
            Answer::Response(r) if r.status == 200 => {
                serde_json::from_slice::<serde_json::Value>(&r.body).ok()
            }
            _ => None,
        };
        let endpoint = crate::domain::hub::attention::coordinator_of(&json(
            self.upstream.discovery(realm).await,
        )?)?;
        let answer = json(self.upstream.attention(&endpoint, viewer).await)?;
        crate::domain::hub::attention::answered(&endpoint, &answer)
    }
}
