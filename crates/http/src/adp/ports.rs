//! What the ADP surface needs (OP-63): a decision point, which reads its own trusted time
//! under the domain's lock (OP-141 m.18 (c)).

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::app::lab::{Explanation, Replay};
use access_authority_core::app::publishing::{Draft, PublishError, Published, Status};
use access_authority_core::app::{Incoming, Response, Scope};
use access_authority_core::query::{Hit, Query};
use access_kernel::digest::Digest;
use access_kernel::model::Id;

/// Evaluates one request (the authority core of the request's domain).
pub trait Pdp: Send + Sync {
    /// The decision for `inc`.
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send;

    /// The explanation of the recorded decision at `record` (OP-141 m.36); none by default.
    fn explain_recorded(
        &self,
        inc: Incoming,
        record: u64,
        scope: Scope,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
        let _ = (inc, record, scope);
        std::future::ready(Err(CoreError::Protocol("explain-record")))
    }

    /// The eligibility of `subject` for the anonymous `check` `inc` (OP-149 m.10); none by
    /// default.
    fn eligible(
        &self,
        inc: Incoming,
        subject: Id,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
        let _ = (inc, subject);
        std::future::ready(Err(CoreError::Protocol("eligibility")))
    }

    /// One page of a search (OP-141 m.22); none by default.
    fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> impl Future<Output = Result<Page, CoreError>> + Send {
        let _ = (inc, query, page);
        std::future::ready(Err(CoreError::Protocol("search")))
    }

    /// The current binding-signed Domain Metadata of `domain` (§9.15.1, OP-143 m.4); none by
    /// default, and never an unsigned document.
    fn metadata(&self, domain: Digest) -> impl Future<Output = Option<Vec<u8>>> + Send {
        let _ = domain;
        std::future::ready(None)
    }

    /// The Record Export Package bytes of the allowed `access.audit_export` Exercise `inc`
    /// names (AP-14), audited before they leave (U53, OP-44); none by default.
    fn export(&self, inc: Incoming) -> impl Future<Output = Result<Vec<u8>, CoreError>> + Send {
        let _ = inc;
        std::future::ready(Err(CoreError::Protocol("export")))
    }

    /// The decision lab's structured explanation of the `check` `inc` (§8.17.10.4), whose
    /// selection part is the second half of a two-part reason (E-5); none by default.
    fn lab_explain(
        &self,
        inc: Incoming,
    ) -> impl Future<Output = Result<Explanation, CoreError>> + Send {
        let _ = inc;
        std::future::ready(Err(CoreError::Protocol("lab")))
    }

    /// The recorded decision at `record` evaluated again (INV-27), for an auditor; none by
    /// default.
    fn lab_replay(
        &self,
        inc: Incoming,
        record: u64,
    ) -> impl Future<Output = Result<Replay, CoreError>> + Send {
        let _ = (inc, record);
        std::future::ready(Err(CoreError::Protocol("lab")))
    }

    /// Publishes `draft` as the actor of the `check` `inc` and offers it to `domains`
    /// (L1-ADP-18, X21); none by default.
    fn publish(
        &self,
        inc: Incoming,
        draft: Draft,
        package: Digest,
        domains: Vec<Digest>,
    ) -> impl Future<Output = Result<PublishAnswer, CoreError>> + Send {
        let _ = (inc, draft, package, domains);
        std::future::ready(Err(CoreError::Protocol("publication")))
    }

    /// Where the caller's own publication stands in `domains` (L1-ADP-18); none by default.
    fn publication_status(
        &self,
        inc: Incoming,
        namespace: String,
        fingerprint: Digest,
        domains: Vec<Digest>,
    ) -> impl Future<Output = Result<Option<Status>, CoreError>> + Send {
        let _ = (inc, namespace, fingerprint, domains);
        std::future::ready(Err(CoreError::Protocol("publication")))
    }
}

/// A publish answer: kept (and whether newly), or refused before anything was kept.
pub type PublishAnswer = Result<(Published, bool), PublishError>;

/// Results and the next page token.
pub type Page = (Vec<Hit>, Option<String>);

impl<P: Pdp> Pdp for Arc<P> {
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        (**self).evaluate(inc)
    }

    fn explain_recorded(
        &self,
        inc: Incoming,
        record: u64,
        scope: Scope,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
        (**self).explain_recorded(inc, record, scope)
    }

    fn eligible(
        &self,
        inc: Incoming,
        subject: Id,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
        (**self).eligible(inc, subject)
    }

    fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> impl Future<Output = Result<Page, CoreError>> + Send {
        (**self).search(inc, query, page)
    }

    fn metadata(&self, domain: Digest) -> impl Future<Output = Option<Vec<u8>>> + Send {
        (**self).metadata(domain)
    }

    fn export(&self, inc: Incoming) -> impl Future<Output = Result<Vec<u8>, CoreError>> + Send {
        (**self).export(inc)
    }

    fn lab_explain(
        &self,
        inc: Incoming,
    ) -> impl Future<Output = Result<Explanation, CoreError>> + Send {
        (**self).lab_explain(inc)
    }

    fn lab_replay(
        &self,
        inc: Incoming,
        record: u64,
    ) -> impl Future<Output = Result<Replay, CoreError>> + Send {
        (**self).lab_replay(inc, record)
    }

    fn publish(
        &self,
        inc: Incoming,
        draft: Draft,
        package: Digest,
        domains: Vec<Digest>,
    ) -> impl Future<Output = Result<PublishAnswer, CoreError>> + Send {
        (**self).publish(inc, draft, package, domains)
    }

    fn publication_status(
        &self,
        inc: Incoming,
        namespace: String,
        fingerprint: Digest,
        domains: Vec<Digest>,
    ) -> impl Future<Output = Result<Option<Status>, CoreError>> + Send {
        (**self).publication_status(inc, namespace, fingerprint, domains)
    }
}
