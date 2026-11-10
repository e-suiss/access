//! One LDAP connection's operations (§10.6.3, IDP-16): bind, search, unbind, abandon, `StartTLS`,
//! `WhoAmI` and RFC 3062 password modify. Add, Delete, `ModifyDN`, Modify and Compare answer
//! `unwillingToPerform` (53). An anonymous connection reads the root DSE and nothing else; an
//! unauthenticated bind is refused; a simple bind without TLS on the `StartTLS` listener answers
//! `confidentialityRequired` (13). Every semantic decision is access-server's: the gateway holds
//! no credential and no directory.

use std::time::{SystemTime, UNIX_EPOCH};

use access_edge_core::channel::ChannelError;
use access_edge_core::{EdgeCore, EdgeError};
use access_internal_api::edge::Call;
use access_internal_api::edge::ldap::{
    Authenticate, Authenticated, DirectoryPage, DirectoryRead, Entry, MAX_PAGE, MAX_RESULTS,
    Mechanism, Outcome, Scope,
};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapExtendedRequest, LdapExtendedResponse,
    LdapMsg, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest, LdapPasswordModifyResponse,
    LdapResult, LdapResultCode, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
    OID_PASSWORD_MODIFY, OID_WHOAMI,
};

use crate::dse::{self, OID_STARTTLS, SUBSCHEMA};
use crate::translate;

/// What the connection does after an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Read the next message.
    Continue,
    /// Close the connection.
    Close,
    /// Send the answer in the clear, then start TLS.
    StartTls,
}

/// The connection's bind.
#[derive(Clone)]
struct Bound {
    handle: Vec<u8>,
    subject: [u8; 16],
    dn: String,
}

/// One connection.
pub struct Session<'a> {
    core: &'a EdgeCore,
    starttls: bool,
    tls: bool,
    chain: Vec<Vec<u8>>,
    bound: Option<Bound>,
}

fn result(code: LdapResultCode, message: &str) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message: String::from(message),
        referral: Vec::new(),
    }
}

fn reply(msgid: i32, op: LdapOp) -> LdapMsg {
    LdapMsg {
        msgid,
        op,
        ctrl: Vec::new(),
    }
}

fn bind_answer(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    reply(
        msgid,
        LdapOp::BindResponse(LdapBindResponse {
            res: result(code, message),
            saslcreds: None,
        }),
    )
}

fn extended(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    reply(
        msgid,
        LdapOp::ExtendedResponse(LdapExtendedResponse {
            res: result(code, message),
            name: None,
            value: None,
        }),
    )
}

fn done(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    reply(msgid, LdapOp::SearchResultDone(result(code, message)))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn entry(e: Entry) -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn: e.dn,
        attributes: e
            .attributes
            .into_iter()
            .map(|(atype, vals)| LdapPartialAttribute {
                atype,
                vals: vals.into_iter().map(String::into_bytes).collect(),
            })
            .collect(),
    }
}

fn refusal_code(e: &EdgeError) -> Option<&str> {
    match e {
        EdgeError::Channel(ChannelError::Refused { code, .. }) => Some(code.as_str()),
        _ => None,
    }
}

impl<'a> Session<'a> {
    /// A connection over `core`; `tls` says whether it is already protected, `chain` is the
    /// client certificate chain its TLS session verified, and `starttls` whether this listener
    /// offers `StartTLS`.
    #[must_use]
    pub const fn new(core: &'a EdgeCore, starttls: bool, tls: bool, chain: Vec<Vec<u8>>) -> Self {
        Self {
            core,
            starttls,
            tls,
            chain,
            bound: None,
        }
    }

    /// The connection is now protected by TLS with `chain`.
    pub fn secured(&mut self, chain: Vec<Vec<u8>>) {
        self.tls = true;
        self.chain = chain;
    }

    async fn audit(&self, event: &str, outcome: &str) {
        if self.core.audit(event, outcome, None).await.is_err() {
            crate::log("audit event not recorded");
        }
    }

    /// A message was refused before decoding (BER limits).
    pub async fn refused_ber(&self) {
        self.audit("ldap.ber", "refused").await;
    }

    /// The answers to `msg`, and what the connection does next.
    pub async fn handle(&mut self, msg: LdapMsg) -> (Vec<LdapMsg>, Next) {
        let id = msg.msgid;
        match msg.op {
            LdapOp::BindRequest(b) => (vec![self.bind(id, b).await], Next::Continue),
            LdapOp::UnbindRequest => (Vec::new(), Next::Close),
            LdapOp::AbandonRequest(_) => (Vec::new(), Next::Continue),
            LdapOp::SearchRequest(s) => (self.search(id, &s, &msg.ctrl).await, Next::Continue),
            LdapOp::ExtendedRequest(x) => self.extended(id, &x).await,
            LdapOp::AddRequest(_) => self.write(id, LdapOp::AddResponse).await,
            LdapOp::DelRequest(_) => self.write(id, LdapOp::DelResponse).await,
            LdapOp::ModifyDNRequest(_) => self.write(id, LdapOp::ModifyDNResponse).await,
            LdapOp::ModifyRequest(_) => self.write(id, LdapOp::ModifyResponse).await,
            LdapOp::CompareRequest(_) => (
                vec![reply(
                    id,
                    LdapOp::CompareResult(result(
                        LdapResultCode::UnwillingToPerform,
                        "compare is not offered",
                    )),
                )],
                Next::Continue,
            ),
            _ => (
                vec![extended(0, LdapResultCode::ProtocolError, "not a request")],
                Next::Close,
            ),
        }
    }

    // IDP-16, §10.6.3
    async fn write(&self, id: i32, op: fn(LdapResult) -> LdapOp) -> (Vec<LdapMsg>, Next) {
        self.audit("ldap.write", "refused").await;
        (
            vec![reply(
                id,
                op(result(
                    LdapResultCode::UnwillingToPerform,
                    "the directory is read-only",
                )),
            )],
            Next::Continue,
        )
    }

    async fn bind(&mut self, id: i32, b: LdapBindRequest) -> LdapMsg {
        self.bound = None;
        match b.cred {
            LdapBindCred::Simple(secret) => self.simple(id, &b.dn, secret).await,
            LdapBindCred::SASL(sasl) if sasl.mechanism.eq_ignore_ascii_case("EXTERNAL") => {
                if !self.tls || self.chain.is_empty() || !sasl.credentials.is_empty() {
                    self.audit("ldap.bind", "refused").await;
                    return bind_answer(
                        id,
                        LdapResultCode::InappropriateAuthentication,
                        "EXTERNAL needs a client certificate",
                    );
                }
                let q = Authenticate {
                    realm: String::new(),
                    mechanism: Mechanism::External,
                    name: None,
                    secret: None,
                    chain: self.chain.clone(),
                    rotate: false,
                };
                self.authenticate(id, q).await
            }
            LdapBindCred::SASL(_) => {
                self.audit("ldap.bind", "refused").await;
                bind_answer(
                    id,
                    LdapResultCode::AuthMethodNotSupported,
                    "only SASL EXTERNAL is offered",
                )
            }
        }
    }

    async fn simple(&mut self, id: i32, dn: &str, secret: String) -> LdapMsg {
        if secret.is_empty() {
            if dn.is_empty() {
                return bind_answer(id, LdapResultCode::Success, "");
            }
            self.audit("ldap.bind", "refused").await;
            return bind_answer(
                id,
                LdapResultCode::UnwillingToPerform,
                "unauthenticated bind is refused",
            );
        }
        if !self.tls {
            self.audit("ldap.bind", "refused").await;
            return bind_answer(
                id,
                LdapResultCode::ConfidentialityRequired,
                "start TLS before a simple bind",
            );
        }
        let q = Authenticate {
            realm: String::new(),
            mechanism: Mechanism::Simple,
            name: Some(String::from(dn)),
            secret: Some(secret.into_bytes()),
            chain: Vec::new(),
            rotate: false,
        };
        self.authenticate(id, q).await
    }

    async fn call<T>(
        &self,
        call: Call,
        body: Vec<u8>,
        decode: fn(&[u8]) -> Result<T, access_internal_api::edge::WireError>,
    ) -> Result<T, EdgeError> {
        let answer = self.core.raw(call, &body).await?;
        decode(&answer).map_err(|_| EdgeError::Malformed)
    }

    async fn check(&self, mut q: Authenticate) -> Result<Authenticated, EdgeError> {
        q.realm = String::from(self.core.realm(None)?);
        self.call(Call::Authenticate, q.encode(), Authenticated::decode)
            .await
    }

    async fn authenticate(&mut self, id: i32, q: Authenticate) -> LdapMsg {
        let Ok(a) = self.check(q).await else {
            return bind_answer(id, LdapResultCode::Unavailable, "directory unavailable");
        };
        let (Some(subject), Some(handle), Some(dn)) = (a.subject, a.bind, a.dn) else {
            return bind_answer(id, LdapResultCode::InvalidCredentials, "");
        };
        if self
            .core
            .issue(None, subject, "ldap-bind", now_ms(), None)
            .await
            .is_err()
        {
            return bind_answer(id, LdapResultCode::Unavailable, "directory unavailable");
        }
        self.bound = Some(Bound {
            handle,
            subject,
            dn,
        });
        bind_answer(id, LdapResultCode::Success, "")
    }

    async fn extended(&mut self, id: i32, x: &LdapExtendedRequest) -> (Vec<LdapMsg>, Next) {
        match x.name.as_str() {
            OID_WHOAMI => {
                let who = self
                    .bound
                    .as_ref()
                    .map_or_else(String::new, |b| format!("dn:{}", b.dn));
                let answer = reply(
                    id,
                    LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: result(LdapResultCode::Success, ""),
                        name: None,
                        value: Some(who.into_bytes()),
                    }),
                );
                (vec![answer], Next::Continue)
            }
            OID_STARTTLS if self.tls => (
                vec![extended(
                    id,
                    LdapResultCode::OperationsError,
                    "TLS is already on",
                )],
                Next::Continue,
            ),
            OID_STARTTLS if self.starttls => {
                let answer = reply(
                    id,
                    LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: result(LdapResultCode::Success, ""),
                        name: Some(String::from(OID_STARTTLS)),
                        value: None,
                    }),
                );
                (vec![answer], Next::StartTls)
            }
            OID_PASSWORD_MODIFY => (vec![self.password(id, x).await], Next::Continue),
            _ => (
                vec![extended(
                    id,
                    LdapResultCode::ProtocolError,
                    "extended operation not offered",
                )],
                Next::Continue,
            ),
        }
    }

    // §10.6.3, RFC 3062: only the LDAP credential just presented changes
    async fn password(&mut self, id: i32, x: &LdapExtendedRequest) -> LdapMsg {
        let Some(bound) = self.bound.clone() else {
            return extended(id, LdapResultCode::InsufficentAccessRights, "bind first");
        };
        let Ok(req) = LdapPasswordModifyRequest::try_from(x) else {
            return extended(id, LdapResultCode::ProtocolError, "malformed request");
        };
        if req
            .user_identity
            .as_deref()
            .is_some_and(|u| !u.eq_ignore_ascii_case(&bound.dn))
        {
            return extended(
                id,
                LdapResultCode::InsufficentAccessRights,
                "only the bound entry's app password changes",
            );
        }
        if req.new_password.is_some() {
            return extended(
                id,
                LdapResultCode::UnwillingToPerform,
                "the directory chooses the new app password",
            );
        }
        let Some(old) = req.old_password else {
            return extended(
                id,
                LdapResultCode::UnwillingToPerform,
                "the current app password is required",
            );
        };
        let q = Authenticate {
            realm: String::new(),
            mechanism: Mechanism::Simple,
            name: Some(bound.dn.clone()),
            secret: Some(old.into_bytes()),
            chain: Vec::new(),
            rotate: true,
        };
        let Ok(a) = self.check(q).await else {
            return extended(id, LdapResultCode::Unavailable, "directory unavailable");
        };
        let fresh = a
            .secret
            .and_then(|s| String::from_utf8(s).ok())
            .filter(|_| a.subject == Some(bound.subject));
        let Some(fresh) = fresh else {
            return extended(id, LdapResultCode::InvalidCredentials, "");
        };
        if let Some(handle) = a.bind {
            self.bound = Some(Bound { handle, ..bound });
        }
        reply(
            id,
            LdapOp::ExtendedResponse(
                LdapPasswordModifyResponse {
                    res: result(LdapResultCode::Success, ""),
                    gen_password: Some(fresh),
                }
                .into(),
            ),
        )
    }

    async fn search(
        &mut self,
        id: i32,
        s: &LdapSearchRequest,
        ctrl: &[LdapControl],
    ) -> Vec<LdapMsg> {
        let base = s.base.trim();
        let attrs = translate::attributes(&s.attrs);
        if base.is_empty() && s.scope == LdapSearchScope::Base {
            let e = dse::select(
                dse::root(self.core.realm(None).unwrap_or_default(), self.starttls),
                &attrs,
                s.typesonly,
            );
            return vec![
                reply(id, LdapOp::SearchResultEntry(e)),
                done(id, LdapResultCode::Success, ""),
            ];
        }
        let Some(bound) = self.bound.clone() else {
            return vec![done(
                id,
                LdapResultCode::InsufficentAccessRights,
                "bind first",
            )];
        };
        if base.eq_ignore_ascii_case(SUBSCHEMA) {
            if s.scope != LdapSearchScope::Base {
                return vec![done(id, LdapResultCode::Success, "")];
            }
            return vec![
                reply(
                    id,
                    LdapOp::SearchResultEntry(dse::select(dse::subschema(), &attrs, s.typesonly)),
                ),
                done(id, LdapResultCode::Success, ""),
            ];
        }
        self.directory(id, s, ctrl, &bound, attrs).await
    }

    async fn directory(
        &mut self,
        id: i32,
        s: &LdapSearchRequest,
        ctrl: &[LdapControl],
        bound: &Bound,
        attributes: Vec<String>,
    ) -> Vec<LdapMsg> {
        let Ok(filter) = translate::filter(&s.filter) else {
            return vec![done(
                id,
                LdapResultCode::UnwillingToPerform,
                "filter too deep or too large",
            )];
        };
        let realm = String::from(self.core.realm(None).unwrap_or_default());
        let base = if s.base.trim().is_empty() {
            format!("o={realm}")
        } else {
            s.base.clone()
        };
        let scope = match s.scope {
            LdapSearchScope::Base => Scope::Base,
            LdapSearchScope::OneLevel => Scope::One,
            LdapSearchScope::Subtree | LdapSearchScope::Children => Scope::Sub,
        };
        let size_limit = u32::try_from(s.sizelimit)
            .ok()
            .filter(|n| *n > 0)
            .map_or(MAX_RESULTS, |n| n.min(MAX_RESULTS));
        let paged = ctrl.iter().find_map(|c| match c {
            LdapControl::SimplePagedResults { size, cookie } => Some((*size, cookie.clone())),
            _ => None,
        });
        if let Some((0, _)) = paged {
            return vec![paged_done(id, LdapResultCode::Success, "", Vec::new())];
        }
        let (target, mut cookie) = match &paged {
            Some((size, c)) => (
                u32::try_from(*size).map_or(MAX_PAGE, |n| n.clamp(1, MAX_PAGE)),
                (!c.is_empty()).then(|| c.clone()),
            ),
            None => (size_limit, None),
        };
        let mut out = Vec::new();
        let mut sent = 0_u32;
        let outcome = loop {
            let q = DirectoryRead {
                realm: realm.clone(),
                bind: bound.handle.clone(),
                base: base.clone(),
                scope,
                filter: filter.clone(),
                attributes: attributes.clone(),
                types_only: s.typesonly,
                size_limit,
                page_size: target.saturating_sub(sent).clamp(1, MAX_PAGE),
                cookie: cookie.take(),
            };
            let page: DirectoryPage = match self
                .call(Call::DirectoryRead, q.encode(), DirectoryPage::decode)
                .await
            {
                Ok(p) => p,
                Err(e) => return self.failed(id, &e, paged.is_some(), out),
            };
            sent = sent.saturating_add(u32::try_from(page.entries.len()).unwrap_or(u32::MAX));
            out.extend(
                page.entries
                    .into_iter()
                    .map(|e| reply(id, LdapOp::SearchResultEntry(entry(e)))),
            );
            cookie = page.cookie;
            if page.outcome != Outcome::Done || cookie.is_none() || sent >= target {
                break page.outcome;
            }
        };
        let (code, message) = match outcome {
            Outcome::Done => (LdapResultCode::Success, ""),
            Outcome::SizeLimit => (LdapResultCode::SizeLimitExceeded, ""),
            Outcome::TimeLimit => (LdapResultCode::TimeLimitExceeded, ""),
            Outcome::NoSuchObject => (LdapResultCode::NoSuchObject, ""),
        };
        out.push(if paged.is_some() {
            paged_done(id, code, message, cookie.unwrap_or_default())
        } else {
            done(id, code, message)
        });
        out
    }

    fn failed(
        &mut self,
        id: i32,
        e: &EdgeError,
        paged: bool,
        mut out: Vec<LdapMsg>,
    ) -> Vec<LdapMsg> {
        let (code, message) = match refusal_code(e) {
            Some("edge-bind") => {
                self.bound = None;
                (
                    LdapResultCode::InsufficentAccessRights,
                    "the bind is no longer valid",
                )
            }
            Some("edge-cookie") => (
                LdapResultCode::UnwillingToPerform,
                "paged results cookie is invalid",
            ),
            Some(_) => (LdapResultCode::UnwillingToPerform, ""),
            None => (LdapResultCode::Unavailable, "directory unavailable"),
        };
        out.push(if paged {
            paged_done(id, code, message, Vec::new())
        } else {
            done(id, code, message)
        });
        out
    }
}

fn paged_done(id: i32, code: LdapResultCode, message: &str, cookie: Vec<u8>) -> LdapMsg {
    LdapMsg {
        msgid: id,
        op: LdapOp::SearchResultDone(result(code, message)),
        ctrl: vec![LdapControl::SimplePagedResults { size: 0, cookie }],
    }
}
