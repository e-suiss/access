//! One product client call from request to reply (OP-149 m.4, m.5, m.28 (c)).

use access_authority_core::CoreError;
use access_authority_core::adapters::{KeyAnswer, PartyAnswer};
use access_authority_core::keys::AsOf;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use serde_json::{Value, json};

use super::domain::{self, BadRequest, TENANT_PAGE};
use super::ports::{Exercises, KeyDirectory, Subjects, Tenants};

/// The form of a key or Party lookup answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The canonical `COSE_Sign1` under usage `key-lookup` or `party-lookup`.
    Cose,
    /// The same content as JSON, unsigned, with the consistency token.
    Json,
}

/// What the transport sends back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// 200 with a JSON body.
    Json(Value),
    /// 200 with a signed lookup answer: keys (OP-149 m.5) or Parties (m.28 (c)).
    Keys {
        /// The body: JSON, or the `COSE_Sign1` bytes.
        body: Vec<u8>,
        /// Its form.
        form: Form,
        /// The key excerpt of a signed answer (CR-58 m.1).
        excerpt: Option<Vec<u8>>,
        /// The ledger position, the `ETag`.
        position: u64,
        /// `Cache-Control`.
        cache: &'static str,
    },
    /// 400: the request is refused.
    Bad(&'static str),
    /// 401: no authenticated client.
    Unauthenticated,
    /// 404 with a stable code.
    NotFound(&'static str),
    /// 503, with a stable, non-secret reason when there is one.
    Unavailable(Option<&'static str>),
    /// 429.
    Limited,
}

/// The product client API of one deployment.
pub struct Service<K, T, S> {
    keys: K,
    tenants: T,
    subjects: S,
    region: String,
}

fn failed(e: &CoreError) -> Reply {
    match e {
        CoreError::Protocol(code) => Reply::Bad(code),
        CoreError::Limited => Reply::Limited,
        _ => Reply::Unavailable(crate::adp::app::unavailable_reason(e)),
    }
}

impl<K: KeyDirectory, T: Tenants, S> Service<K, T, S> {
    /// A service over `keys`, `tenants` and `subjects` in `region`.
    pub const fn new(keys: K, tenants: T, subjects: S, region: String) -> Self {
        Self {
            keys,
            tenants,
            subjects,
            region,
        }
    }

    async fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        form: Form,
    ) -> Result<KeyAnswer, Reply> {
        self.keys
            .lookup(domain, kids, as_of, form == Form::Cose)
            .await
            .map_err(|e| failed(&e))
    }

    fn keys_reply(answer: &KeyAnswer, form: Form) -> Reply {
        let (body, excerpt) = match (&answer.signed, form) {
            (Some((sign1, excerpt)), Form::Cose) => (sign1.clone(), Some(excerpt.clone())),
            (None, Form::Cose) => return Reply::Unavailable(Some("signer")),
            (_, Form::Json) => (domain::lookup_json(answer).to_string().into_bytes(), None),
        };
        Reply::Keys {
            body,
            form,
            excerpt,
            position: answer.lookup.pos,
            cache: domain::cache_control(answer),
        }
    }

    /// `GET /access/v1/keys/{kid}?domain=…&as_of=…` (OP-149 m.5): a kid not held at the
    /// position is a 404.
    pub async fn key(
        &self,
        client: Option<String>,
        kid: &str,
        domain: Option<&str>,
        as_of: Option<&str>,
        form: Form,
    ) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(kid) = domain::kid(kid) else {
            return Reply::Bad("kid");
        };
        let Some(domain) = domain.and_then(crate::adp::adapters::domain_id) else {
            return Reply::Bad("domain");
        };
        let as_of = match domain::as_of(as_of) {
            Ok(a) => a,
            Err(BadRequest(code)) => return Reply::Bad(code),
        };
        match self.lookup(domain, vec![kid], as_of, form).await {
            Ok(a) if a.lookup.keys.is_empty() => Reply::NotFound("key-unknown"),
            Ok(a) => Self::keys_reply(&a, form),
            Err(r) => r,
        }
    }

    /// `POST /access/v1/keys:batchGet` (OP-149 m.5): kids not held at the position are listed
    /// as `unknown`.
    pub async fn keys(&self, client: Option<String>, body: &[u8], form: Form) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let (domain, kids, as_of) = match domain::batch(body) {
            Ok(b) => b,
            Err(BadRequest(code)) => return Reply::Bad(code),
        };
        match self.lookup(domain, kids, as_of, form).await {
            Ok(a) => Self::keys_reply(&a, form),
            Err(r) => r,
        }
    }

    async fn party_lookup(
        &self,
        domain: Digest,
        parties: Vec<Id>,
        as_of: AsOf,
        form: Form,
    ) -> Result<PartyAnswer, Reply> {
        self.keys
            .parties(domain, parties, as_of, form == Form::Cose)
            .await
            .map_err(|e| failed(&e))
    }

    fn parties_reply(answer: &PartyAnswer, form: Form) -> Reply {
        let (body, excerpt) = match (&answer.signed, form) {
            (Some((sign1, excerpt)), Form::Cose) => (sign1.clone(), Some(excerpt.clone())),
            (None, Form::Cose) => return Reply::Unavailable(Some("signer")),
            (_, Form::Json) => (
                domain::party_lookup_json(answer).to_string().into_bytes(),
                None,
            ),
        };
        Reply::Keys {
            body,
            form,
            excerpt,
            position: answer.lookup.pos,
            cache: domain::party_cache_control(answer),
        }
    }

    /// `GET /access/v1/parties/{party}?domain=…&as_of=…` (OP-149 m.28 (c)): a Party not
    /// admitted at the position is a 404.
    pub async fn party(
        &self,
        client: Option<String>,
        party: &str,
        domain: Option<&str>,
        as_of: Option<&str>,
        form: Form,
    ) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(party) = domain::party_id(party) else {
            return Reply::Bad("party");
        };
        let Some(domain) = domain.and_then(crate::adp::adapters::domain_id) else {
            return Reply::Bad("domain");
        };
        let as_of = match domain::as_of(as_of) {
            Ok(a) => a,
            Err(BadRequest(code)) => return Reply::Bad(code),
        };
        match self.party_lookup(domain, vec![party], as_of, form).await {
            Ok(a) if a.lookup.parties.is_empty() => Reply::NotFound("party-unknown"),
            Ok(a) => Self::parties_reply(&a, form),
            Err(r) => r,
        }
    }

    /// `POST /access/v1/parties:batchGet` (OP-149 m.28 (c)): Parties not admitted at the
    /// position are listed as `unknown`.
    pub async fn parties(&self, client: Option<String>, body: &[u8], form: Form) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let (domain, parties, as_of) = match domain::party_batch(body) {
            Ok(b) => b,
            Err(BadRequest(code)) => return Reply::Bad(code),
        };
        match self.party_lookup(domain, parties, as_of, form).await {
            Ok(a) => Self::parties_reply(&a, form),
            Err(r) => r,
        }
    }

    /// `GET /access/v1/tenants/{tenant}/snapshot` (OP-149 m.4, OP-147 m.4).
    pub async fn snapshot(&self, client: Option<String>, tenant: &str) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(id) = self.tenants.internal(tenant) else {
            return Reply::NotFound("tenant-unknown");
        };
        match self.tenants.tenant(id).await {
            Ok(Some(t)) => Reply::Json(domain::snapshot(tenant, &t, &self.region)),
            Ok(None) => Reply::NotFound("tenant-unknown"),
            Err(_) => Reply::Unavailable(None),
        }
    }

    /// `GET /access/v1/tenants?cursor=…` (OP-149 m.4): one page of snapshots in a stable
    /// order; `next_cursor` is absent on the last page.
    pub async fn tenants(&self, client: Option<String>, cursor: Option<&str>) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let after = match cursor.filter(|c| !c.is_empty()) {
            None => None,
            Some(c) => match self.tenants.internal(c) {
                Some(id) => Some(id),
                None => return Reply::Bad("cursor"),
            },
        };
        let Ok(page) = self.tenants.after(after, TENANT_PAGE).await else {
            return Reply::Unavailable(None);
        };
        let mut items = Vec::with_capacity(page.len());
        let mut last = None;
        for t in &page {
            let Some(id) = self.tenants.external(t.id) else {
                return Reply::Unavailable(None);
            };
            items.push(domain::snapshot(&id, t, &self.region));
            last = Some(id);
        }
        let full = u32::try_from(page.len()).is_ok_and(|n| n == TENANT_PAGE);
        let mut body = json!({ "tenants": items });
        if let (true, Some(next), Value::Object(m)) = (full, last, &mut body) {
            m.insert("next_cursor".into(), next.into());
        }
        Reply::Json(body)
    }
}

impl<K: KeyDirectory + Exercises, T: Tenants, S: Subjects> Service<K, T, S> {
    /// `POST /access/v1/tenants/{tenant}/subjects:resolve` (OP-149 A11): between the realm's
    /// `PartyID`s and the pairwise `sub` the named client sees, one direction per call; what does
    /// not resolve is listed as `unknown`. A Party's `sub` for the client is the one its tokens
    /// carry, assigned now when the client has not seen the subject yet (MD-10).
    pub async fn resolve(&self, client: Option<String>, tenant: &str, body: &[u8]) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(id) = self.tenants.internal(tenant) else {
            return Reply::NotFound("tenant-unknown");
        };
        let req = match domain::resolve_request(body) {
            Ok(r) => r,
            Err(BadRequest(code)) => return Reply::Bad(code),
        };
        match self
            .subjects
            .resolve(id, req.realm, &req.client_id, req.lookup.clone())
            .await
        {
            Ok(Some(found)) => Reply::Json(domain::resolution_json(&req, &found)),
            Ok(None) => Reply::NotFound("client-unknown"),
            Err(_) => Reply::Unavailable(None),
        }
    }

    /// `GET /access/v1/exercises/{id}?domain=…` (OP-149 m.9): an allowed Exercise, with the
    /// receipt the decision point issued when kept; 404 for one the domain never allowed.
    pub async fn exercise(
        &self,
        client: Option<String>,
        exercise: &str,
        domain: Option<&str>,
    ) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(id) = domain::kid(exercise).map(Digest) else {
            return Reply::Bad("exercise");
        };
        let Some(domain) = domain.and_then(crate::adp::adapters::domain_id) else {
            return Reply::Bad("domain");
        };
        match self.keys.exercise(domain, id).await {
            Ok(Some(r)) => Reply::Json(domain::exercise_json(&domain, &r)),
            Ok(None) => Reply::NotFound("exercise-unknown"),
            Err(e) => failed(&e),
        }
    }

    /// `GET /access/v1/exercises/{id}/agency?domain=…` (OP-149 m.11): the chain the actor
    /// acted on behalf of, read from the receipt the decision point issued, with that receipt
    /// so the chain can be verified offline. An Exercise allowed before receipts were kept has
    /// no chain to answer with.
    pub async fn agency(
        &self,
        client: Option<String>,
        exercise: &str,
        domain: Option<&str>,
    ) -> Reply {
        if client.is_none() {
            return Reply::Unauthenticated;
        }
        let Some(id) = domain::kid(exercise).map(Digest) else {
            return Reply::Bad("exercise");
        };
        let Some(domain) = domain.and_then(crate::adp::adapters::domain_id) else {
            return Reply::Bad("domain");
        };
        match self.keys.exercise(domain, id).await {
            Ok(Some(r)) => match domain::agency_json(&domain, &r) {
                Ok(Some(v)) => Reply::Json(v),
                Ok(None) => Reply::NotFound("receipt-unavailable"),
                Err(_) => Reply::Unavailable(None),
            },
            Ok(None) => Reply::NotFound("exercise-unknown"),
            Err(e) => failed(&e),
        }
    }
}
