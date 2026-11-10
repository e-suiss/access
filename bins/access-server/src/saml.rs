//! The SAML identity provider and WS-Federation in access-server (OP-155 m.3 (c) to (f); §10.6.1;
//! IDI-7; IDP-15; MD-10; Golden SAML HL-35).
//!
//! access-server keeps the cookies and every decision that needs the session or the store. A
//! browser request opens a flow; running it attests the live session (if any) to the flow with a
//! fresh one-use handle and forwards the raw binding values to the SAML gateway. The gateway has
//! the parser worker read and verify the message and redeems the handle with `session_attest`;
//! only then does this module decide, sign through the identity signer's `saml` key, audit every
//! signature, and keep the outcome in the flow. The browser is shown only that outcome.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use access_edge_core::saml::{Facts, Kind};
use access_http::edge::SessionAttest;
use access_http::login::{SamlFront, SamlOpening, SamlOutcome};
use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::ports::AccountDb as _;
use access_identity_admin::app::saml::{read_document, sp_id};
use access_identity_edge::EdgeError;
use access_identity_edge::domain::{Gateway, Refusal};
use access_identity_oauth::ports::RealmEntry;
use access_identity_saml::alg::SigAlg;
use access_identity_saml::assertion::{self, Issue, Random, Released};
use access_identity_saml::binding;
use access_identity_saml::dsig::{self, SignError, Signature, XmlSigner};
use access_identity_saml::encrypt::XmlEnc;
use access_identity_saml::metadata::{self, Endpoints};
use access_identity_saml::request::{self, Accepted, Refusal as Shown};
use access_identity_saml::sp::{NameIdFormat, Source, Sp, b64};
use access_identity_saml::uri;
use access_identity_saml::wire::{self, Attest, Binding, Done, Forward, SpAnswer};
use access_identity_saml::wsfed;
use access_identity_session::app::sessions::SessionView;
use access_identity_session::domain::assurance::Aal;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::saml::{SamlAlg, SamlRequest, SamlResponse, SamlSig, Step};
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::saml::{FlowRow, FlowSession};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::KeyStore;

use crate::login::RealmKeks;

/// How long a flow stays open (a sign-in, with a login in between).
const FLOW_MS: u64 = 10 * 60_000;

/// How long a forwarded handle may wait for the gateway's `session_attest`.
const HANDLE_MS: u64 = 60_000;

/// Longest the gateway may take to answer a forward.
const FORWARD_DEADLINE: Duration = Duration::from_secs(15);

/// Largest forward answer read.
const MAX_ANSWER: usize = 16 * 1024;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn signed(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// The process's random source (OP-63: RNG is a port).
pub(crate) struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), SignError> {
        aws_lc_rs::rand::fill(out).map_err(|_| SignError(String::from("random")))
    }
}

fn random32() -> Option<[u8; 32]> {
    let mut b = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut b).ok()?;
    Some(b)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    suiss_crypto::digest::sha256(b)
}

async fn signer_call(socket: &Path, r: SamlRequest) -> Result<SamlResponse, SignError> {
    match access_identity_signer::adapters::call(socket, &Request::Saml(r)).await {
        Ok(Response::Saml(s)) => Ok(s),
        Ok(Response::Error(code)) => Err(SignError(code)),
        _ => Err(SignError(String::from("signer-unavailable"))),
    }
}

/// Opens the realm's SAML key of `p256`'s algorithm (MD-6: on the first opt-in).
pub(crate) async fn open_key(socket: &Path, realm: RealmId, p256: bool) -> Result<(), SignError> {
    let alg = if p256 {
        SamlAlg::P256
    } else {
        SamlAlg::Rsa3072
    };
    signer_call(
        socket,
        SamlRequest::Open {
            realm: Realm(*realm.as_bytes()),
            alg,
        },
    )
    .await
    .map(|_| ())
}

/// `idp.saml.cert_emergency`: a new key signs at once.
pub(crate) async fn emergency(socket: &Path, realm: RealmId, p256: bool) -> Result<(), SignError> {
    let alg = if p256 {
        SamlAlg::P256
    } else {
        SamlAlg::Rsa3072
    };
    open_key(socket, realm, p256).await?;
    signer_call(
        socket,
        SamlRequest::Rotate {
            realm: Realm(*realm.as_bytes()),
            alg,
            step: Step::Emergency,
        },
    )
    .await
    .map(|_| ())
}

/// The realm's SAML key behind [`XmlSigner`]; it counts its signatures for the audit log.
struct RealmSigner<'a> {
    socket: &'a Path,
    realm: RealmId,
    signatures: std::sync::atomic::AtomicU32,
}

fn sig_of(alg: SigAlg) -> SamlSig {
    match alg {
        SigAlg::RsaSha256 => SamlSig::RsaSha256,
        SigAlg::RsaSha384 => SamlSig::RsaSha384,
        SigAlg::RsaSha512 => SamlSig::RsaSha512,
        SigAlg::EcdsaSha256 => SamlSig::EcdsaSha256,
    }
}

impl XmlSigner for RealmSigner<'_> {
    async fn sign(&self, signed_info: Vec<u8>, alg: SigAlg) -> Result<Signature, SignError> {
        let ask = |data: Vec<u8>| SamlRequest::Sign {
            realm: Realm(*self.realm.as_bytes()),
            sig: sig_of(alg),
            data,
        };
        let mut answer = signer_call(self.socket, ask(signed_info.clone())).await;
        if matches!(&answer, Err(SignError(c)) if c == "signer-saml-no-key") {
            open_key(self.socket, self.realm, alg.ecdsa()).await?;
            answer = signer_call(self.socket, ask(signed_info)).await;
        }
        match answer? {
            SamlResponse::Signed {
                signature, cert, ..
            } => {
                self.signatures
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Signature {
                    value: signature,
                    certificate: cert,
                })
            }
            SamlResponse::Keys(_) => Err(SignError(String::from("signer-frame"))),
        }
    }
}

/// Where the SAML gateway listens for forwards.
#[derive(Clone, Debug)]
pub(crate) struct GatewayAddr(pub(crate) String);

/// The SAML identity provider of this process.
pub(crate) struct Saml {
    app: Pool,
    signer: PathBuf,
    gateway: Option<GatewayAddr>,
    hsm: Arc<KeyStore>,
    keks: RealmKeks,
}

impl Saml {
    /// The service over the application pool, the identity signer, the gateway's forward
    /// address, the HSM (for `RelayState` MACs) and the realms' vault keys.
    pub(crate) const fn new(
        app: Pool,
        signer: PathBuf,
        gateway: Option<GatewayAddr>,
        hsm: Arc<KeyStore>,
        keks: RealmKeks,
    ) -> Self {
        Self {
            app,
            signer,
            gateway,
            hsm,
            keks,
        }
    }
}

fn values_value(values: &[(String, String)]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|(k, v)| Value::Array(vec![Value::text(k), Value::text(v)]))
            .collect(),
    )
}

fn values_of(v: &Value) -> Vec<(String, String)> {
    let Some(Value::Array(list)) = v.get("values") else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|p| match p {
            Value::Array(kv) => match kv.as_slice() {
                [Value::Text(k), Value::Text(v)] => Some((k.clone(), v.clone())),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn get<'a>(values: &'a [(String, String)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn encode_outcome(o: &SamlOutcome) -> Vec<u8> {
    let v = match o {
        SamlOutcome::Post { action, fields } => map(vec![
            ("kind", Value::text("post")),
            ("action", Value::text(action)),
            ("fields", values_value(fields)),
        ]),
        SamlOutcome::Redirect(url) => map(vec![
            ("kind", Value::text("redirect")),
            ("url", Value::text(url)),
        ]),
        SamlOutcome::Soap(e) => map(vec![
            ("kind", Value::text("soap")),
            ("envelope", Value::text(e)),
        ]),
        SamlOutcome::Login => map(vec![("kind", Value::text("login"))]),
        SamlOutcome::Error(c) => map(vec![
            ("kind", Value::text("error")),
            ("code", Value::text(c)),
        ]),
        SamlOutcome::SignedOut => map(vec![("kind", Value::text("signed_out"))]),
    };
    dcbor::encode(&v, Limits::CEILING).unwrap_or_default()
}

fn decode_outcome(b: &[u8]) -> SamlOutcome {
    let Ok(v) = dcbor::decode(b, Limits::CEILING) else {
        return SamlOutcome::Error(String::from("saml-flow-corrupt"));
    };
    let text = |k: &str| match v.get(k) {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    };
    let fields = match v.get("fields") {
        Some(f) => values_of(&map(vec![("values", f.clone())])),
        None => Vec::new(),
    };
    match text("kind").as_str() {
        "post" => SamlOutcome::Post {
            action: text("action"),
            fields,
        },
        "redirect" => SamlOutcome::Redirect(text("url")),
        "soap" => SamlOutcome::Soap(text("envelope")),
        "login" => SamlOutcome::Login,
        "signed_out" => SamlOutcome::SignedOut,
        _ => SamlOutcome::Error(text("code")),
    }
}

fn error(code: &str) -> SamlOutcome {
    SamlOutcome::Error(String::from(code))
}

/// The pairwise sector of a registration: its affiliation's or its own entity ID's, never a
/// key (MD-10, IDP-24).
fn sector(sp: &Sp) -> [u8; 16] {
    let (tag, id) = match &sp.affiliation {
        Some(a) => ("affiliation", a.as_str()),
        None => ("entity", sp.entity_id.as_str()),
    };
    let mut input = format!("access/saml-sector/{tag}\0").into_bytes();
    input.extend_from_slice(id.as_bytes());
    let d = sha256(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

const fn aal_of(a: Aal) -> i16 {
    match a {
        Aal::Aal1 => 1,
        Aal::Aal2 => 2,
        Aal::Aal3 => 3,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

/// What a decision needs besides the flow.
struct Ctx<'a> {
    tenant: TenantId,
    realm: RealmId,
    slug: &'a str,
    issuer: String,
    now: u64,
}

impl Saml {
    async fn tx(&self, tenant: TenantId, realm: RealmId) -> Result<TenantTx, SamlOutcome> {
        TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(|_| error("saml-unavailable"))
    }

    async fn forward(&self, f: &Forward) -> Result<Done, String> {
        let Some(GatewayAddr(addr)) = &self.gateway else {
            return Err(String::from("saml-gateway-unavailable"));
        };
        let body = f.encode();
        let exchange = async {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            let head = format!(
                "POST {} HTTP/1.1\r\nHost: saml-gateway\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                wire::FORWARD_PATH,
                wire::CONTENT_TYPE,
                body.len()
            );
            s.write_all(head.as_bytes()).await.ok()?;
            s.write_all(&body).await.ok()?;
            let mut answer = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                let n = s.read(&mut chunk).await.ok()?;
                if n == 0 {
                    break;
                }
                answer.extend_from_slice(chunk.get(..n)?);
                if answer.len() > MAX_ANSWER {
                    return None;
                }
            }
            access_edge_core::channel::parse(&answer).ok()
        };
        let answer = tokio::time::timeout(FORWARD_DEADLINE, exchange)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| String::from("saml-gateway-unavailable"))?;
        Done::decode(&answer).map_err(|_| String::from("saml-gateway-unavailable"))
    }

    async fn audit(t: &mut TenantTx, event: &str, target: &str, correlation: &str) -> bool {
        t.audit(&AuditEvent {
            event_type: event,
            actor: "saml-idp",
            target,
            correlation,
        })
        .await
        .is_ok()
    }

    /// The live session a flow attested, checked again now: not ended, its epoch current, its
    /// subject active.
    async fn live(t: &mut TenantTx, s: &FlowSession, now: u64) -> bool {
        matches!(
            t.session_by_id(s.session).await,
            Ok(Some(row)) if row.ended_ms.is_none()
                && row.session_epoch == row.subject_epoch
                && row.session_epoch == s.epoch
                && row.expires_ms > signed(now)
                && row.subject_status == "active"
        )
    }

    async fn proven_email(&self, ctx: &Ctx<'_>, subject: [u8; 16]) -> Option<String> {
        let vault = self.keks.vault(ctx.realm)?;
        let mut tx: PgTx = PgAccounts::sealed(self.app.clone(), vault)
            .begin(ctx.tenant, ctx.realm)
            .await
            .ok()?;
        let proven = tx.0.proven_emails(subject).await.ok()?;
        let first = *proven.first()?;
        let rows = tx.0.identifiers(subject).await.ok()?;
        let row = rows.into_iter().find(|r| r.id == first)?;
        let value = tx.reveal(subject, &row.stored).await.ok().flatten();
        let _ = tx.0.commit().await;
        value
    }

    fn endpoints(ctx: &Ctx<'_>) -> Endpoints {
        Endpoints::of(&ctx.issuer)
    }

    fn signer(&self, realm: RealmId) -> RealmSigner<'_> {
        RealmSigner {
            socket: &self.signer,
            realm,
            signatures: std::sync::atomic::AtomicU32::new(0),
        }
    }

    async fn sp_by_entity(t: &mut TenantTx, entity: &str) -> Option<Sp> {
        let row = t.saml_sp_by_entity(entity).await.ok()??;
        if !row.live {
            return None;
        }
        read_document(&row.definition).map(|(_, sp)| sp)
    }

    async fn sp_by_name(t: &mut TenantTx, name: &str) -> Option<Sp> {
        let id = sp_id(name);
        let row = t
            .saml_sps()
            .await
            .ok()?
            .into_iter()
            .find(|r| r.sp_id == id && r.live)?;
        read_document(&row.definition).map(|(_, sp)| sp)
    }

    /// The `NameID` of `subject` for `sp`, or the status to send instead.
    async fn name_id(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        sp: &Sp,
        format: NameIdFormat,
        subject: [u8; 16],
        allow_create: bool,
    ) -> Result<String, request::Status> {
        let invalid = request::Status::InvalidNameIdPolicy;
        match format {
            NameIdFormat::Transient => assertion::new_value(&OsRandom).map_err(|_| invalid),
            NameIdFormat::Email => self.proven_email(ctx, subject).await.ok_or(invalid),
            NameIdFormat::Persistent | NameIdFormat::Unspecified => {
                let sector = sector(sp);
                if !allow_create {
                    return t
                        .saml_pairwise_existing(subject, sector)
                        .await
                        .ok()
                        .flatten()
                        .ok_or(invalid);
                }
                let candidate = assertion::new_value(&OsRandom).map_err(|_| invalid)?;
                t.pairwise(subject, sector, &candidate)
                    .await
                    .map_err(|_| invalid)
            }
        }
    }

    async fn released(
        &self,
        ctx: &Ctx<'_>,
        sp: &Sp,
        subject: [u8; 16],
        name_id: &str,
    ) -> Vec<Released> {
        let mut email = None;
        let mut out = Vec::new();
        for a in &sp.attributes {
            let values = match a.source {
                Some(Source::Email) => {
                    if email.is_none() {
                        email = Some(self.proven_email(ctx, subject).await);
                    }
                    email.clone().flatten().into_iter().collect()
                }
                Some(Source::NameId | Source::Subject) => vec![String::from(name_id)],
                None => a.values.clone(),
            };
            out.push(Released {
                name: a.name.clone(),
                name_format: a.name_format.unwrap_or(sp.attribute_name_format).uri(),
                friendly_name: a.friendly_name.clone(),
                values,
            });
        }
        out
    }

    fn post(action: &str, response: &str, relay: Option<&str>) -> SamlOutcome {
        let mut fields = vec![(
            String::from("SAMLResponse"),
            b64::encode(response.as_bytes()),
        )];
        if let Some(r) = relay {
            fields.push((String::from("RelayState"), String::from(r)));
        }
        SamlOutcome::Post {
            action: String::from(action),
            fields,
        }
    }

    /// Issues the signed Response of an accepted request for the attested session, auditing
    /// every signature (Ek B 4947, Golden SAML).
    #[allow(clippy::too_many_arguments, reason = "one issuance, its inputs named")]
    async fn issue(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        sp: &Sp,
        session: &FlowSession,
        acs: &str,
        in_response_to: Option<String>,
        format: NameIdFormat,
        allow_create: bool,
        correlation: &str,
    ) -> Result<String, request::Status> {
        let name_id = self
            .name_id(t, ctx, sp, format, session.subject, allow_create)
            .await?;
        let i = Issue {
            idp: Self::endpoints(ctx).entity_id,
            acs: String::from(acs),
            idp_initiated: in_response_to.is_none(),
            in_response_to,
            now: ctx.now,
            auth_time: u64::try_from(session.auth_time_ms).unwrap_or(0),
            aal: u8::try_from(session.aal).unwrap_or(1),
            sp_name_qualifier: (format == NameIdFormat::Persistent).then(|| {
                sp.affiliation
                    .clone()
                    .unwrap_or_else(|| sp.entity_id.clone())
            }),
            attributes: self.released(ctx, sp, session.subject, &name_id).await,
            name_id,
            format,
        };
        let signer = self.signer(ctx.realm);
        let xml = if sp.protocol.wsfed() {
            wsfed::wresult(sp, &i, &signer, &OsRandom).await
        } else {
            assertion::issue(sp, &i, &signer, &OsRandom, &XmlEnc(&OsRandom)).await
        }
        .map_err(|_| request::Status::NoPassive)?;
        let target = hex(&session.subject);
        let count = signer.signatures.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..count {
            // Ek B 4947, HL-35
            if !Self::audit(t, "saml.signed", &target, correlation).await {
                return Err(request::Status::NoPassive);
            }
        }
        Ok(xml)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one AuthnRequest decision read top to bottom"
    )]
    async fn decide_sso(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        flow: &FlowRow,
        values: &[(String, String)],
        facts: Option<Facts>,
        redirect_signed: bool,
        correlation: &str,
    ) -> Option<SamlOutcome> {
        let Some(facts) = facts else {
            return Some(error("saml-message"));
        };
        let Some(sp) = Self::sp_by_entity(t, &facts.issuer).await else {
            return Some(error(Shown::UnknownSp.code()));
        };
        let relay = match get(values, "RelayState") {
            Some(r) if flow.binding == "redirect" => binding::form_decode(r),
            other => other.map(String::from),
        };
        if request::relay_state(relay.as_deref()).is_err() {
            return Some(error(Shown::RelayState.code()));
        }
        let e = Self::endpoints(ctx);
        let accepted: Accepted = match request::decide(
            &sp,
            &facts,
            redirect_signed,
            &[e.sso.clone(), e.ecp.clone()],
            ctx.now,
        ) {
            Ok(a) => a,
            Err(r) => return Some(error(r.code())),
        };
        let soap = flow.binding == "soap";
        let deliver = |xml: &str| {
            if soap {
                SamlOutcome::Soap(assertion::ecp_envelope(xml, &accepted.acs.url))
            } else {
                Self::post(&accepted.acs.url, xml, relay.as_deref())
            }
        };
        let status_to = |st: request::Status| -> SamlOutcome {
            let i = Issue {
                idp: e.entity_id.clone(),
                acs: accepted.acs.url.clone(),
                in_response_to: Some(accepted.in_response_to.clone()),
                now: ctx.now,
                auth_time: ctx.now,
                aal: 1,
                name_id: String::new(),
                format: accepted.format,
                sp_name_qualifier: None,
                attributes: Vec::new(),
                idp_initiated: false,
            };
            assertion::status(&i, &OsRandom, st.codes())
                .map_or_else(|_| error("saml-unavailable"), |x| deliver(&x))
        };
        let session = match &flow.session {
            Some(s) if Self::live(t, s, ctx.now).await => Some(*s),
            _ => None,
        };
        let fresh = |s: &FlowSession| {
            u64::try_from(s.auth_time_ms).is_ok_and(|a| {
                a.saturating_add(access_identity_saml::time::REQUEST_MAX_AGE_MS) >= ctx.now
            })
        };
        let outcome = match (session, accepted.status) {
            (_, Some(st)) => status_to(st),
            (None, None) if accepted.passive => status_to(request::Status::NoPassive),
            (None, None) => return Some(SamlOutcome::Login),
            (Some(s), None) if accepted.force && !fresh(&s) => {
                if accepted.passive {
                    status_to(request::Status::NoPassive)
                } else {
                    return Some(SamlOutcome::Login);
                }
            }
            (Some(s), None) => {
                if !accepted.requesters.is_empty() {
                    // Ek B 4947: RequesterID to the audit log
                    for r in &accepted.requesters {
                        let target = hex(&sha256(r.as_bytes()));
                        if !Self::audit(t, "saml.requester", &target, correlation).await {
                            return Some(error("saml-unavailable"));
                        }
                    }
                }
                match self
                    .issue(
                        t,
                        ctx,
                        &sp,
                        &s,
                        &accepted.acs.url,
                        Some(accepted.in_response_to.clone()),
                        accepted.format,
                        accepted.allow_create,
                        correlation,
                    )
                    .await
                {
                    Ok(xml) => deliver(&xml),
                    Err(st) => status_to(st),
                }
            }
        };
        match t
            .saml_request_seen(&sp.entity_id, &facts.id, false, signed(ctx.now))
            .await
        {
            Ok(true) => Some(outcome),
            Ok(false) => Some(error(Shown::Replay.code())),
            Err(_) => Some(error("saml-unavailable")),
        }
    }

    fn relay_ok(&self, realm: RealmId, sp: &Sp, relay: &str, mac: Option<&str>) -> bool {
        let Some(mac) = mac else {
            return false;
        };
        let label = format!("saml-relay/{}", hex(realm.as_bytes()));
        let key = match self.hsm.mac(&label) {
            Ok(k) => k,
            Err(_) => match self.hsm.generate_mac(&label) {
                Ok(k) => k,
                Err(_) => return false,
            },
        };
        let mut message = sp.entity_id.as_bytes().to_vec();
        message.push(0);
        message.extend_from_slice(relay.as_bytes());
        let Ok(tag) = key.mac(&message) else {
            return false;
        };
        let expected = access_kernel::json::b64url_encode(&tag);
        aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), mac.as_bytes())
            .is_ok()
    }

    async fn decide_unsolicited(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        flow: &FlowRow,
        values: &[(String, String)],
        correlation: &str,
    ) -> Option<SamlOutcome> {
        let Some(sp) = Self::sp_by_name(t, get(values, "sp").unwrap_or_default()).await else {
            return Some(error(Shown::UnknownSp.code()));
        };
        let acs = match request::unsolicited(&sp) {
            Ok(a) => a.url.clone(),
            Err(r) => return Some(error(r.code())),
        };
        let relay = get(values, "RelayState");
        if request::relay_state(relay).is_err() {
            return Some(error(Shown::RelayState.code()));
        }
        // IDP-15
        if let Some(r) = relay
            && !self.relay_ok(ctx.realm, &sp, r, get(values, "rs_mac"))
        {
            return Some(error(Shown::RelayState.code()));
        }
        let Some(s) = flow.session else {
            return Some(SamlOutcome::Login);
        };
        if !Self::live(t, &s, ctx.now).await {
            return Some(SamlOutcome::Login);
        }
        match self
            .issue(
                t,
                ctx,
                &sp,
                &s,
                &acs,
                None,
                sp.nameid_format,
                true,
                correlation,
            )
            .await
        {
            Ok(xml) => Some(Self::post(&acs, &xml, relay)),
            Err(_) => Some(error("saml-nameid-unavailable")),
        }
    }

    async fn decide_wsfed(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        flow: &FlowRow,
        values: &[(String, String)],
        correlation: &str,
    ) -> Option<SamlOutcome> {
        let Some(req) = wsfed::Request::of(|k| get(values, k).map(String::from)) else {
            return Some(error("wsfed-request-malformed"));
        };
        let sp = match &req.realm {
            Some(r) => Self::sp_by_entity(t, r).await,
            None => None,
        };
        if req.action == wsfed::Action::SignOut {
            let back = sp.as_ref().and_then(|sp| wsfed::reply(sp, &req).ok());
            return Some(back.map_or(SamlOutcome::SignedOut, |u| {
                SamlOutcome::Redirect(String::from(u))
            }));
        }
        let Some(sp) = sp.filter(|s| s.protocol.wsfed()) else {
            return Some(error(Shown::UnknownSp.code()));
        };
        let reply = match wsfed::reply(&sp, &req) {
            Ok(u) => String::from(u),
            Err(r) => return Some(error(r.code())),
        };
        let Some(s) = flow.session else {
            return Some(SamlOutcome::Login);
        };
        if !Self::live(t, &s, ctx.now).await {
            return Some(SamlOutcome::Login);
        }
        match self
            .issue(
                t,
                ctx,
                &sp,
                &s,
                &reply,
                None,
                sp.nameid_format,
                true,
                correlation,
            )
            .await
        {
            Ok(wresult) => {
                let mut fields = vec![
                    (String::from("wa"), String::from(uri::WA_SIGNIN)),
                    (String::from("wresult"), wresult),
                ];
                if let Some(c) = req.context {
                    fields.push((String::from("wctx"), c));
                }
                Some(SamlOutcome::Post {
                    action: reply,
                    fields,
                })
            }
            Err(_) => Some(error("saml-nameid-unavailable")),
        }
    }

    async fn decide_slo(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        flow: &FlowRow,
        values: &[(String, String)],
        facts: Option<Facts>,
        redirect_signed: bool,
    ) -> Option<SamlOutcome> {
        if flow.binding == "wsfed" {
            return self.decide_wsfed(t, ctx, flow, values, "-").await;
        }
        let facts = facts.filter(|f| f.kind == Kind::Logout)?;
        let sp = Self::sp_by_entity(t, &facts.issuer).await?;
        let verified =
            redirect_signed || matches!(facts.signed, access_edge_core::saml::Signed::Verified(_));
        if !sp.certificates.is_empty() && !verified {
            return Some(SamlOutcome::SignedOut);
        }
        if !t
            .saml_request_seen(&sp.entity_id, &facts.id, true, signed(ctx.now))
            .await
            .unwrap_or(false)
        {
            return Some(SamlOutcome::SignedOut);
        }
        let wanted = if flow.binding == "redirect" {
            access_identity_saml::sp::Binding::Redirect
        } else {
            access_identity_saml::sp::Binding::Post
        };
        let Some(end) = sp
            .slo
            .iter()
            .find(|e| e.binding == wanted)
            .or_else(|| sp.slo.first())
        else {
            return Some(SamlOutcome::SignedOut);
        };
        let relay = match get(values, "RelayState") {
            Some(r) if flow.binding == "redirect" => binding::form_decode(r),
            other => other.map(String::from),
        };
        let id = assertion::new_id(&OsRandom).ok()?;
        let e = Self::endpoints(ctx);
        let mut response =
            assertion::logout_response(&e.entity_id, &end.url, &facts.id, &id, ctx.now);
        let signer = self.signer(ctx.realm);
        let outcome = if end.binding == access_identity_saml::sp::Binding::Redirect {
            let url = binding::redirect(
                &signer,
                &end.url,
                "SAMLResponse",
                &response.canonical(),
                relay.as_deref(),
                sp.alg(),
            )
            .await
            .ok()?;
            SamlOutcome::Redirect(url)
        } else {
            dsig::sign(
                &signer,
                &mut response,
                "ID",
                Some(1),
                sp.alg(),
                sp.key_info_certificate,
            )
            .await
            .ok()?;
            Self::post(&end.url, &response.canonical(), relay.as_deref())
        };
        let count = signer.signatures.load(std::sync::atomic::Ordering::SeqCst);
        for _ in 0..count {
            if !Self::audit(t, "saml.signed", "logout", "-").await {
                return None;
            }
        }
        Some(outcome)
    }

    /// Decides the flow `flow` with the gateway's verified facts; `None` keeps it open (a
    /// login comes first).
    #[allow(clippy::too_many_arguments, reason = "one decision, its inputs named")]
    async fn decide(
        &self,
        t: &mut TenantTx,
        ctx: &Ctx<'_>,
        flow: &FlowRow,
        facts: Option<Facts>,
        redirect_signed: bool,
        correlation: &str,
    ) -> SamlOutcome {
        let Ok(v) = dcbor::decode(&flow.params, Limits::CEILING) else {
            return error("saml-flow-corrupt");
        };
        let values = values_of(&v);
        match (flow.kind.as_str(), flow.binding.as_str()) {
            ("slo", _) => self
                .decide_slo(t, ctx, flow, &values, facts, redirect_signed)
                .await
                .unwrap_or(SamlOutcome::SignedOut),
            (_, "unsolicited") => self
                .decide_unsolicited(t, ctx, flow, &values, correlation)
                .await
                .unwrap_or_else(|| error("saml-unavailable")),
            (_, "wsfed") => self
                .decide_wsfed(t, ctx, flow, &values, correlation)
                .await
                .unwrap_or_else(|| error("saml-unavailable")),
            _ => self
                .decide_sso(t, ctx, flow, &values, facts, redirect_signed, correlation)
                .await
                .unwrap_or_else(|| error("saml-unavailable")),
        }
    }

    async fn rotate_if_due(
        &self,
        t: &mut TenantTx,
        realm: RealmId,
        keys: &[access_identity_signer::saml::KeyInfo],
        now: u64,
    ) {
        use access_identity_signer::saml::Phase;
        let Ok(Some((p, _))) = t.saml_cert_policy().await else {
            return;
        };
        let day = 86_400_000_u64;
        let overlap = u64::try_from(p.overlap_days)
            .unwrap_or(14)
            .saturating_mul(day);
        let rotate = u64::try_from(p.rotate_days)
            .unwrap_or(365)
            .saturating_mul(day);
        let alg = if p.p256 {
            SamlAlg::P256
        } else {
            SamlAlg::Rsa3072
        };
        let of = |ph: Phase| keys.iter().find(|k| k.alg == alg && k.phase == ph);
        let step = if let Some(r) = of(Phase::Retiring) {
            (r.since.saturating_add(overlap) <= now).then_some(Step::Remove)
        } else if let Some(pb) = of(Phase::Published) {
            (pb.since.saturating_add(overlap) <= now).then_some(Step::Switch)
        } else {
            of(Phase::Active).and_then(|a| {
                (a.since.saturating_add(rotate.saturating_sub(overlap)) <= now).then_some(Step::Add)
            })
        };
        if let Some(step) = step {
            let _ = signer_call(
                &self.signer,
                SamlRequest::Rotate {
                    realm: Realm(*realm.as_bytes()),
                    alg,
                    step,
                },
            )
            .await;
        }
    }

    async fn certificates(&self, entry: &RealmEntry) -> Option<Vec<Vec<u8>>> {
        let realm = Realm(*entry.realm.as_bytes());
        let mut keys = match signer_call(&self.signer, SamlRequest::Keys(realm))
            .await
            .ok()?
        {
            SamlResponse::Keys(k) => k,
            SamlResponse::Signed { .. } => return None,
        };
        if keys.is_empty() {
            open_key(&self.signer, entry.realm, false).await.ok()?;
            if let SamlResponse::Keys(k) = signer_call(&self.signer, SamlRequest::Keys(realm))
                .await
                .ok()?
            {
                keys = k;
            }
        }
        if let Ok(mut t) = TenantTx::begin(&self.app, entry.tenant, entry.realm).await {
            self.rotate_if_due(&mut t, entry.realm, &keys, now_ms())
                .await;
            let _ = t.commit().await;
        }
        Some(
            keys.into_iter()
                .filter(|k| k.alg == SamlAlg::Rsa3072)
                .map(|k| k.cert)
                .collect(),
        )
    }
}

impl SamlFront for Saml {
    async fn metadata(&self, entry: &RealmEntry) -> Option<String> {
        let certs = self.certificates(entry).await?;
        let e = Endpoints::of(entry.issuer.as_str());
        let signer = self.signer(entry.realm);
        let doc = metadata::signed(&e, &certs, now_ms(), &signer, &OsRandom)
            .await
            .ok()?;
        let mut t = TenantTx::begin(&self.app, entry.tenant, entry.realm)
            .await
            .ok()?;
        // Ek B 4947, 4994
        if !Self::audit(&mut t, "saml.signed", "metadata", "-").await {
            return None;
        }
        t.commit().await.ok()?;
        Some(doc)
    }

    async fn wsfed_metadata(&self, entry: &RealmEntry) -> Option<String> {
        let certs = self.certificates(entry).await?;
        Some(metadata::wsfed(
            &Endpoints::of(entry.issuer.as_str()),
            &certs,
        ))
    }

    async fn open(&self, entry: &RealmEntry, opening: SamlOpening) -> Result<String, String> {
        let unavailable = || String::from("saml-unavailable");
        let key = random32().ok_or_else(unavailable)?;
        let params = dcbor::encode(
            &map(vec![("values", values_value(&opening.values))]),
            Limits::CEILING,
        )
        .map_err(|_| String::from("saml-request-too-large"))?;
        let now = now_ms();
        let mut t = TenantTx::begin(&self.app, entry.tenant, entry.realm)
            .await
            .map_err(|_| unavailable())?;
        t.open_saml_flow(
            &sha256(&key),
            opening.binding.name(),
            if opening.slo { "slo" } else { "sso" },
            &params,
            signed(now),
            signed(now.saturating_add(FLOW_MS)),
        )
        .await
        .map_err(|_| unavailable())?;
        t.commit().await.map_err(|_| unavailable())?;
        Ok(access_kernel::json::b64url_encode(&key))
    }

    async fn run(
        &self,
        entry: &RealmEntry,
        key: &str,
        session: Option<SessionView>,
        correlation: &str,
    ) -> SamlOutcome {
        let Ok(raw) = access_kernel::json::b64url_decode(key) else {
            return error("saml-flow-expired");
        };
        let flow_hash = sha256(&raw);
        let now = now_ms();
        let Some(handle) = random32() else {
            return error("saml-unavailable");
        };
        let mut t = match self.tx(entry.tenant, entry.realm).await {
            Ok(t) => t,
            Err(o) => return o,
        };
        let flow = match t.saml_flow(&flow_hash).await {
            Ok(Some(f)) if f.outcome.is_none() && f.expires_ms > signed(now) => f,
            Ok(_) => return error("saml-flow-expired"),
            Err(_) => return error("saml-unavailable"),
        };
        let attested = session.as_ref().map(|v| FlowSession {
            session: v.id,
            subject: v.subject,
            epoch: v.session_epoch,
            auth_time_ms: signed(v.auth_time_ms),
            aal: aal_of(v.assurance.aal),
        });
        let ok = t
            .attest_saml_flow(
                &flow_hash,
                &sha256(&handle),
                signed(now.saturating_add(HANDLE_MS)),
                attested.as_ref(),
                signed(now),
            )
            .await;
        if !matches!(ok, Ok(true)) || t.commit().await.is_err() {
            return error("saml-flow-expired");
        }
        let Ok(v) = dcbor::decode(&flow.params, Limits::CEILING) else {
            return error("saml-flow-corrupt");
        };
        let values = values_of(&v);
        let binding = match flow.binding.as_str() {
            "redirect" => Binding::Redirect,
            "post" => Binding::Post,
            "soap" => Binding::Soap,
            "unsolicited" => Binding::Unsolicited,
            _ => Binding::Wsfed,
        };
        let message = match binding {
            Binding::Soap => get(&values, "body").map(String::from),
            _ => get(&values, "SAMLRequest").map(String::from),
        };
        let f = Forward {
            realm: entry.slug.clone(),
            handle,
            binding,
            message,
            relay_state: get(&values, "RelayState").map(String::from),
            sig_alg: get(&values, "SigAlg").map(String::from),
            signature: get(&values, "Signature").map(String::from),
        };
        match self.forward(&f).await {
            Ok(Done::Done) => {}
            Ok(Done::Refused(code)) | Err(code) => return SamlOutcome::Error(code),
        }
        let _ = correlation;
        let Ok(mut t) = TenantTx::begin(&self.app, entry.tenant, entry.realm).await else {
            return error("saml-unavailable");
        };
        let outcome = match t.saml_flow(&flow_hash).await {
            Ok(Some(f)) => f.outcome.map_or(SamlOutcome::Login, |o| decode_outcome(&o)),
            _ => error("saml-unavailable"),
        };
        let _ = t.commit().await;
        outcome
    }
}

impl Saml {
    async fn attest_issue(
        &self,
        g: &Gateway,
        handle: [u8; 32],
        facts: Option<Vec<u8>>,
        redirect_signed: bool,
    ) -> Result<Vec<u8>, EdgeError> {
        let now = now_ms();
        let unavailable = |e: access_store::StoreError| EdgeError::Unavailable(e.to_string());
        let mut t = TenantTx::begin(&self.app, g.tenant, g.realm)
            .await
            .map_err(unavailable)?;
        // IDI-7
        let Some((flow_hash, flow)) = t
            .saml_flow_by_handle(&sha256(&handle), signed(now))
            .await
            .map_err(unavailable)?
        else {
            return Err(EdgeError::Refused(Refusal::Attest));
        };
        let facts = match facts {
            Some(b) => Some(Facts::decode(&b).map_err(|_| EdgeError::Refused(Refusal::Malformed))?),
            None => None,
        };
        let issuer = access_store::idp::governance(&mut t)
            .await
            .map_err(unavailable)?
            .and_then(|g| g.issuer)
            .ok_or_else(|| EdgeError::Unavailable(String::from("realm issuer")))?;
        let ctx = Ctx {
            tenant: g.tenant,
            realm: g.realm,
            slug: &g.slug,
            issuer,
            now,
        };
        let _ = ctx.slug;
        let outcome = self
            .decide(&mut t, &ctx, &flow, facts, redirect_signed, &g.uri.name)
            .await;
        if outcome != SamlOutcome::Login {
            t.decide_saml_flow(&flow_hash, &encode_outcome(&outcome), signed(now))
                .await
                .map_err(unavailable)?;
        }
        t.commit().await.map_err(unavailable)?;
        Ok(wire::decided())
    }

    async fn attest_sp(&self, g: &Gateway, entity: &str) -> Result<Vec<u8>, EdgeError> {
        let mut t = TenantTx::begin(&self.app, g.tenant, g.realm)
            .await
            .map_err(|e| EdgeError::Unavailable(e.to_string()))?;
        let sp = Self::sp_by_entity(&mut t, entity).await;
        let _ = t.commit().await;
        Ok(SpAnswer {
            found: sp.is_some(),
            certs: sp.as_ref().map(Sp::certs).unwrap_or_default(),
            requests_signed: sp.as_ref().is_some_and(|s| s.authn_requests_signed),
        }
        .encode())
    }
}

impl SessionAttest for Saml {
    fn attest<'a>(
        &'a self,
        g: &'a Gateway,
        body: &'a [u8],
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<Vec<u8>, EdgeError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let a = Attest::decode(body).map_err(|_| EdgeError::Refused(Refusal::Malformed))?;
            match a {
                Attest::Sp { realm, entity } => {
                    access_identity_edge::domain::in_scope(g, &realm)?;
                    self.attest_sp(g, &entity).await
                }
                Attest::Issue {
                    realm,
                    handle,
                    facts,
                    redirect_signed,
                } => {
                    access_identity_edge::domain::in_scope(g, &realm)?;
                    self.attest_issue(g, handle, facts, redirect_signed).await
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // MD-10, IDP-24: an affiliation shares one sector; every other SP has its own.
    #[test]
    fn sectors_follow_the_affiliation() {
        let sp = |e: &str, a: Option<&str>| {
            let mut s = Sp::from_json(&serde_json::json!({
                "entity_id": e,
                "acs": [{ "url": "https://sp.test/acs", "index": 0, "binding": "post" }],
            }))
            .unwrap();
            s.affiliation = a.map(String::from);
            s
        };
        assert_ne!(
            sector(&sp("https://a.test", None)),
            sector(&sp("https://b.test", None))
        );
        assert_eq!(
            sector(&sp("https://a.test", Some("urn:aff"))),
            sector(&sp("https://b.test", Some("urn:aff")))
        );
        let o = SamlOutcome::Post {
            action: String::from("https://sp.test/acs"),
            fields: vec![(String::from("SAMLResponse"), String::from("x"))],
        };
        assert_eq!(decode_outcome(&encode_outcome(&o)), o);
    }
}
