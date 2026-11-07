//! The realm-admin REST resources over the `idp.*` write path (OP-151 m.2 M1, TN-110, TN-112):
//! each write operation compiles its JSON body into exactly one [`Change`], and each resource
//! reads back as a JSON view with no credential field (TN-61). The view's `ETag` is the
//! position of the decision that last changed it.

use std::collections::BTreeSet;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::SUBJECT_PREFIX;

use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Window;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::realm::{self as resources, AccountRow, GroupRow, UpstreamRow};
use access_store::idp::{self, ClientRow};
use serde_json::{Map, Value as Json, json};
use suiss_crypto::dcbor::{self, Limits, Value};

use super::Admin;
use crate::AdminError;
use crate::domain::realm::Binding;
use crate::domain::{
    Attribute, AuthMethod, Branding, Change, ClaimName, Client, ClientId, Color, Group, Invalid,
    Members, MembershipIssuer, Name, RedirectUri, RpId, SessionPolicy, SigninMethod, SigninPolicy,
    Upstream,
};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// The longest validity a write's intent may ask for.
pub const MAX_VALIDITY_MS: u64 = 15 * 60_000;

/// The validity a prepared write gets when its body names none.
pub const DEFAULT_VALIDITY_MS: u64 = 10 * 60_000;

/// The body member that carries a write's intent validity.
pub const VALIDITY: &str = "validity";

/// A management write operation (the manifest's operation ids).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `createClient`.
    CreateClient,
    /// `putClient`.
    PutClient,
    /// `retireClient`.
    RetireClient,
    /// `rotateClientSecret`.
    RotateClientSecret,
    /// `putGroup`: create or update.
    PutGroup,
    /// `retireGroup`.
    RetireGroup,
    /// `addGroupMembers`.
    AddGroupMembers,
    /// `removeGroupMembers`.
    RemoveGroupMembers,
    /// `suspendAccount`.
    SuspendAccount,
    /// `reactivateAccount`.
    ReactivateAccount,
    /// `putUpstreamIdp`: register or update.
    PutUpstream,
    /// `retireUpstreamIdp`.
    RetireUpstream,
    /// `putSigninPolicy`.
    PutSigninPolicy,
    /// `putSessionPolicy`.
    PutSessionPolicy,
    /// `putBranding`.
    PutBranding,
    /// `putRpId`.
    PutRpId,
    /// `putMapper`: set or remove.
    PutMapper,
}

impl Op {
    /// The operation with this manifest id.
    #[must_use]
    pub fn from_operation(id: &str) -> Option<Self> {
        Some(match id {
            "createClient" => Self::CreateClient,
            "putClient" | "patchClient" => Self::PutClient,
            "retireClient" => Self::RetireClient,
            "rotateClientSecret" => Self::RotateClientSecret,
            "putGroup" | "patchGroup" => Self::PutGroup,
            "retireGroup" => Self::RetireGroup,
            "addGroupMembers" => Self::AddGroupMembers,
            "removeGroupMembers" => Self::RemoveGroupMembers,
            "suspendAccount" => Self::SuspendAccount,
            "reactivateAccount" => Self::ReactivateAccount,
            "putUpstreamIdp" | "patchUpstreamIdp" => Self::PutUpstream,
            "retireUpstreamIdp" => Self::RetireUpstream,
            "putSigninPolicy" | "patchSigninPolicy" => Self::PutSigninPolicy,
            "putSessionPolicy" | "patchSessionPolicy" => Self::PutSessionPolicy,
            "putBranding" | "patchBranding" => Self::PutBranding,
            "putRpId" => Self::PutRpId,
            "putMapper" => Self::PutMapper,
            _ => return None,
        })
    }
}

fn obj(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<&'a str, Invalid> {
    m.get(k).and_then(Json::as_str).ok_or(Invalid::Body)
}

fn opt_text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<Option<&'a str>, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s)),
        Some(_) => Err(Invalid::Body),
    }
}

fn flag(m: &Map<String, Json>, k: &str) -> Result<bool, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(Invalid::Body),
    }
}

fn texts<'a>(m: &'a Map<String, Json>, k: &str) -> Result<Vec<&'a str>, Invalid> {
    match m.get(k) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(a)) => a.iter().map(|v| v.as_str().ok_or(Invalid::Body)).collect(),
        Some(_) => Err(Invalid::Body),
    }
}

/// Only `allowed` members (and the validity and AIS) may appear.
fn only(m: &Map<String, Json>, allowed: &[&str]) -> Result<(), Invalid> {
    if m.keys()
        .all(|k| allowed.contains(&k.as_str()) || k == VALIDITY || k == "ais")
    {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

fn uris(list: &[&str]) -> Result<Vec<RedirectUri>, Invalid> {
    list.iter().map(|u| RedirectUri::parse(u)).collect()
}

fn ms_text(v: &Json) -> Result<u64, Invalid> {
    match v {
        Json::String(s) => s.parse().map_err(|_| Invalid::Body),
        Json::Number(n) => n.as_u64().ok_or(Invalid::Body),
        _ => Err(Invalid::Body),
    }
}

/// RFC 3339 in UTC with milliseconds (OP-65).
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    let nanos = i128::from(ms).saturating_mul(1_000_000);
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn parse_rfc3339(s: &str) -> Result<u64, Invalid> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Invalid::Validity)?;
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(ms).map_err(|_| Invalid::Validity)
}

/// The intent validity a write's body names: `{"not_before", "not_after"}` in RFC 3339, at
/// most [`MAX_VALIDITY_MS`] long.
///
/// # Errors
/// [`Invalid::Validity`].
pub fn validity(body: &Json) -> Result<Window, Invalid> {
    let v = body
        .get(VALIDITY)
        .and_then(Json::as_object)
        .ok_or(Invalid::Validity)?;
    let from = parse_rfc3339(
        v.get("not_before")
            .and_then(Json::as_str)
            .ok_or(Invalid::Validity)?,
    )?;
    let until = parse_rfc3339(
        v.get("not_after")
            .and_then(Json::as_str)
            .ok_or(Invalid::Validity)?,
    )?;
    if until <= from || until.saturating_sub(from) > MAX_VALIDITY_MS {
        return Err(Invalid::Validity);
    }
    Ok(Window { from, until })
}

/// The validity member for `now`: from one minute before to [`DEFAULT_VALIDITY_MS`] after.
#[must_use]
pub fn default_validity(now_ms: u64) -> Json {
    json!({
        "not_before": rfc3339(now_ms.saturating_sub(60_000)),
        "not_after": rfc3339(now_ms.saturating_add(DEFAULT_VALIDITY_MS)),
    })
}

fn client(id: ClientId, m: &Map<String, Json>) -> Result<Client, Invalid> {
    only(
        m,
        &[
            "client_id",
            "display_name",
            "token_endpoint_auth_method",
            "jwks_uri",
            "redirect_uris",
            "post_logout_redirect_uris",
            "backchannel_logout_uri",
            "require_pushed_authorization_requests",
            "status",
            "platform_product",
        ],
    )?;
    // OP-149 m.4: platform product fields are read-only here
    if m.get("platform_product").is_some_and(|v| !v.is_null()) {
        return Err(Invalid::PlatformTenant);
    }
    let method = opt_text(m, "token_endpoint_auth_method")?.unwrap_or("none");
    Ok(Client {
        id,
        display_name: String::from(text(m, "display_name")?),
        auth: AuthMethod::from_parts(method, opt_text(m, "jwks_uri")?)?,
        redirect_uris: uris(&texts(m, "redirect_uris")?)?,
        post_logout_redirect_uris: uris(&texts(m, "post_logout_redirect_uris")?)?,
        backchannel_logout_uri: opt_text(m, "backchannel_logout_uri")?.map(String::from),
        require_par: flag(m, "require_pushed_authorization_requests")?,
        platform: None,
    })
}

fn subject(ids: &IdKey, s: &str) -> Result<[u8; 16], Invalid> {
    ids.decode(SUBJECT_PREFIX, s)
        .map_err(|_| Invalid::NoAccount)
}

fn key_of(key: Option<&str>) -> Result<&str, Invalid> {
    key.ok_or(Invalid::Body)
}

/// Compiles one write operation's body into its one [`Change`] (TN-110). `key` is the path's
/// natural key; a create carries the `client_id` its prepare step assigned.
///
/// # Errors
/// [`Invalid`].
#[expect(
    clippy::too_many_lines,
    reason = "one match over the operations; each arm is the operation's body contract"
)]
pub fn compile(op: Op, key: Option<&str>, body: &Json, ids: &IdKey) -> Result<Change, Invalid> {
    let m = obj(body)?;
    Ok(match op {
        Op::CreateClient => {
            let id = ClientId::parse(text(m, "client_id")?)?;
            Change::ClientRegister(client(id, m)?)
        }
        Op::PutClient => {
            let id = ClientId::parse(key_of(key)?)?;
            if opt_text(m, "client_id")?.is_some_and(|c| c != id.as_str()) {
                return Err(Invalid::ClientId);
            }
            Change::ClientUpdate(client(id, m)?)
        }
        Op::RetireClient => {
            only(m, &[])?;
            Change::ClientRetire(ClientId::parse(key_of(key)?)?)
        }
        Op::RotateClientSecret => {
            only(m, &[])?;
            Change::ClientSecretRotate(ClientId::parse(key_of(key)?)?)
        }
        Op::PutGroup => {
            only(m, &["name", "display_name", "membership_issuer", "status"])?;
            let name = Name::parse(key_of(key)?)?;
            if opt_text(m, "name")?.is_some_and(|n| n != name.as_str()) {
                return Err(Invalid::Name);
            }
            let issuer = opt_text(m, "membership_issuer")?
                .map_or(Ok(MembershipIssuer::Admin), MembershipIssuer::parse)?;
            Change::GroupCreate(Group {
                name,
                display_name: String::from(text(m, "display_name")?),
                issuer,
            })
        }
        Op::RetireGroup => {
            only(m, &[])?;
            Change::GroupRetire(Name::parse(key_of(key)?)?)
        }
        Op::AddGroupMembers | Op::RemoveGroupMembers => {
            only(m, &["account_ids"])?;
            let subjects = texts(m, "account_ids")?
                .iter()
                .map(|s| subject(ids, s))
                .collect::<Result<BTreeSet<_>, _>>()?;
            let members = Members {
                group: Name::parse(key_of(key)?)?,
                subjects,
            };
            if op == Op::AddGroupMembers {
                Change::GroupMembersAdd(members)
            } else {
                Change::GroupMembersRemove(members)
            }
        }
        Op::SuspendAccount | Op::ReactivateAccount => {
            only(m, &[])?;
            let s = subject(ids, key_of(key)?)?;
            if op == Op::SuspendAccount {
                Change::AccountSuspend(s)
            } else {
                Change::AccountReactivate(s)
            }
        }
        Op::PutUpstream => {
            only(
                m,
                &[
                    "name",
                    "issuer",
                    "client_id",
                    "client_secret_ref",
                    "jwks_uri",
                    "ssf",
                    "status",
                ],
            )?;
            let name = Name::parse(key_of(key)?)?;
            if opt_text(m, "name")?.is_some_and(|n| n != name.as_str()) {
                return Err(Invalid::Name);
            }
            Change::UpstreamRegister(Upstream {
                name,
                issuer: String::from(text(m, "issuer")?),
                client_id: String::from(text(m, "client_id")?),
                client_secret_ref: opt_text(m, "client_secret_ref")?.map(String::from),
                jwks_uri: String::from(text(m, "jwks_uri")?),
                ssf: match m.get("ssf") {
                    None | Some(Json::Null) => None,
                    Some(v) => Some(
                        crate::domain::realm::TransmitterConfig::parse(v)
                            .map_err(|_| Invalid::Upstream)?,
                    ),
                },
            })
        }
        Op::RetireUpstream => {
            only(m, &[])?;
            Change::UpstreamRetire(Name::parse(key_of(key)?)?)
        }
        Op::PutSigninPolicy => {
            only(
                m,
                &[
                    "methods",
                    "required_fields",
                    "mfa_required",
                    "domain_allow",
                    "domain_deny",
                ],
            )?;
            let set = |k| -> Result<BTreeSet<String>, Invalid> {
                Ok(texts(m, k)?.into_iter().map(String::from).collect())
            };
            Change::SigninPolicy(SigninPolicy {
                methods: texts(m, "methods")?
                    .into_iter()
                    .map(SigninMethod::parse)
                    .collect::<Result<_, _>>()?,
                required_fields: set("required_fields")?,
                mfa_required: flag(m, "mfa_required")?,
                domain_allow: set("domain_allow")?,
                domain_deny: set("domain_deny")?,
            })
        }
        Op::PutSessionPolicy => {
            only(m, &["absolute_ms", "idle_ms", "binding"])?;
            Change::SessionPolicy(SessionPolicy {
                absolute_ms: ms_text(m.get("absolute_ms").ok_or(Invalid::Body)?)?,
                idle_ms: ms_text(m.get("idle_ms").ok_or(Invalid::Body)?)?,
                binding: Binding::parse(text(m, "binding")?).ok_or(Invalid::SessionPolicy)?,
            })
        }
        Op::PutBranding => {
            only(
                m,
                &[
                    "display_name",
                    "logo_uri",
                    "primary_color",
                    "background_color",
                    "csp_origins",
                ],
            )?;
            Change::Branding(Branding {
                display_name: opt_text(m, "display_name")?.map(String::from),
                logo_uri: opt_text(m, "logo_uri")?.map(String::from),
                primary_color: opt_text(m, "primary_color")?
                    .map(Color::parse)
                    .transpose()?,
                background_color: opt_text(m, "background_color")?
                    .map(Color::parse)
                    .transpose()?,
                csp_origins: texts(m, "csp_origins")?
                    .into_iter()
                    .map(String::from)
                    .collect(),
            })
        }
        Op::PutRpId => {
            only(m, &["rp_id", "acknowledge_passkey_loss"])?;
            Change::RpId(RpId::parse(text(m, "rp_id")?)?)
        }
        Op::PutMapper => {
            only(m, &["claim", "source"])?;
            let claim = ClaimName::parse(key_of(key)?)?;
            Change::MapperSet {
                claim,
                source: opt_text(m, "source")?.map(Attribute::parse).transpose()?,
            }
        }
    })
}

/// The passkey loss an RP ID change acknowledges: `acknowledge_passkey_loss` as the decimal
/// count (IDI-4).
#[must_use]
pub fn acknowledged_passkeys(body: &Json) -> Option<u64> {
    body.get("acknowledge_passkey_loss")
        .and_then(|v| ms_text(v).ok())
}

/// A client's view: no secret, ever (CR-38).
#[must_use]
pub fn client_view(c: &ClientRow) -> Json {
    json!({
        "client_id": c.client_id,
        "display_name": c.display_name,
        "token_endpoint_auth_method": c.auth_method,
        "jwks_uri": c.jwks_uri,
        "redirect_uris": c.redirect_uris,
        "post_logout_redirect_uris": c.post_logout_redirect_uris,
        "backchannel_logout_uri": c.backchannel_logout_uri,
        "require_pushed_authorization_requests": c.require_par,
        "platform_product": c.platform_product,
        "status": if c.active { "active" } else { "retired" },
    })
}

/// A group's view.
#[must_use]
pub fn group_view(g: &GroupRow) -> Json {
    json!({
        "name": g.name,
        "display_name": g.display_name,
        "membership_issuer": g.membership_issuer,
        "status": if g.active { "active" } else { "retired" },
    })
}

/// An upstream provider's view: the secret only by its reference.
#[must_use]
pub fn upstream_view(u: &UpstreamRow) -> Json {
    json!({
        "name": u.name,
        "issuer": u.issuer,
        "client_id": u.client_id,
        "client_secret_ref": u.client_secret_ref,
        "jwks_uri": u.jwks_uri,
        "ssf": u.ssf.as_deref().and_then(|s| serde_json::from_str::<Json>(s).ok()),
        "status": if u.active { "active" } else { "retired" },
    })
}

/// An account's view: its state, never a credential (TN-61, §12.3.1).
#[must_use]
pub fn account_view(a: &AccountRow, ids: &IdKey) -> Json {
    json!({
        "account_id": ids.encode(SUBJECT_PREFIX, a.subject).unwrap_or_default(),
        "status": a.status,
        "status_at": rfc3339(a.status_at_ms),
        "created_at": rfc3339(a.created_at_ms),
    })
}

/// Deterministic CBOR of a stored policy as JSON: maps, text, booleans, arrays; integers up to
/// 2^53 as numbers.
#[must_use]
pub fn cbor_json(v: &Value) -> Json {
    match v {
        Value::Unsigned(n) if *n <= (1 << 53) => json!(n),
        Value::Unsigned(n) => json!(n.to_string()),
        Value::Text(s) => json!(s),
        Value::Bool(b) => json!(b),
        Value::Bytes(b) => json!(b64url_encode(b)),
        Value::Array(a) => Json::Array(a.iter().map(cbor_json).collect()),
        Value::Map(m) => Json::Object(
            m.iter()
                .filter_map(|(k, v)| match k {
                    Value::Text(k) => Some((k.clone(), cbor_json(v))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Negative(_) | Value::Tag(..) => Json::Null,
    }
}

fn stored(bytes: Option<&[u8]>, default: &Value) -> Json {
    bytes
        .and_then(|b| dcbor::decode(b, Limits::CEILING).ok())
        .map_or_else(|| cbor_json(default), |v| cbor_json(&v))
}

/// The default sign-in requirements (TN-132): email, no MFA requirement, open registration.
#[must_use]
pub fn default_signin() -> SigninPolicy {
    SigninPolicy {
        methods: BTreeSet::from([SigninMethod::Email, SigninMethod::Passkey]),
        required_fields: BTreeSet::from([String::from("email")]),
        mfa_required: false,
        domain_allow: BTreeSet::new(),
        domain_deny: BTreeSet::new(),
    }
}

/// What one read returned: views with their `ETag` positions, and the natural key the next page
/// starts after.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Read {
    /// The views and their positions.
    pub items: Vec<(Json, u64)>,
    /// The last item's natural key, when the page is full.
    pub last: Option<String>,
}

/// A readable collection or singleton.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Clients.
    Clients,
    /// Groups.
    Groups,
    /// Accounts.
    Accounts,
    /// Upstream identity providers.
    Upstreams,
    /// The realm settings singleton.
    Settings,
}

#[cfg(test)]
mod tests;

fn full<T>(rows: &[T], limit: u32, key: impl Fn(&T) -> String) -> Option<String> {
    (u32::try_from(rows.len()).ok() == Some(limit))
        .then(|| rows.last().map(key))
        .flatten()
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// A `PUT` upsert by natural key (OP-65): a group or upstream provider that exists is
    /// updated, otherwise created. Prepare and commit resolve alike; a state change between
    /// them changes the intent, and the commit is refused.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn resolve(
        &self,
        tenant: TenantId,
        realm: RealmId,
        change: Change,
    ) -> Result<Change, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let resolved = match change {
            Change::GroupCreate(g)
                if resources::group(&mut t, g.name.as_str()).await?.is_some() =>
            {
                Change::GroupUpdate(g)
            }
            Change::UpstreamRegister(u)
                if resources::upstream(&mut t, u.name.as_str())
                    .await?
                    .is_some() =>
            {
                Change::UpstreamUpdate(u)
            }
            other => other,
        };
        t.commit().await?;
        Ok(resolved)
    }

    /// Reads one resource (`key`) or one page of a collection after `after` (TN-113: the
    /// transaction's realm scope is the filter; nothing outside it is visible).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn read(
        &self,
        tenant: TenantId,
        realm: RealmId,
        kind: Kind,
        key: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Read, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let read = self.read_in(&mut t, kind, key, after, limit).await;
        t.commit().await?;
        read
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match over the readable kinds, each arm its read"
    )]
    async fn read_in(
        &self,
        t: &mut TenantTx,
        kind: Kind,
        key: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Read, AdminError> {
        let after_text = after.unwrap_or("");
        Ok(match (kind, key) {
            (Kind::Clients, Some(k)) => {
                let c = idp::client(t, k).await?;
                let at = resources::client_position(t, k).await?;
                Read {
                    items: c
                        .zip(at)
                        .map(|(c, p)| (client_view(&c), p))
                        .into_iter()
                        .collect(),
                    last: None,
                }
            }
            (Kind::Clients, None) => {
                let rows = resources::clients(t, after_text, limit).await?;
                Read {
                    last: full(&rows, limit, |(c, _)| c.client_id.clone()),
                    items: rows.iter().map(|(c, p)| (client_view(c), *p)).collect(),
                }
            }
            (Kind::Groups, Some(k)) => Read {
                items: resources::group(t, k)
                    .await?
                    .map(|g| (group_view(&g), g.position))
                    .into_iter()
                    .collect(),
                last: None,
            },
            (Kind::Groups, None) => {
                let rows = resources::groups(t, after_text, limit).await?;
                Read {
                    last: full(&rows, limit, |g| g.name.clone()),
                    items: rows.iter().map(|g| (group_view(g), g.position)).collect(),
                }
            }
            (Kind::Upstreams, Some(k)) => Read {
                items: resources::upstream(t, k)
                    .await?
                    .map(|u| (upstream_view(&u), u.position))
                    .into_iter()
                    .collect(),
                last: None,
            },
            (Kind::Upstreams, None) => {
                let rows = resources::upstreams(t, after_text, limit).await?;
                Read {
                    last: full(&rows, limit, |u| u.name.clone()),
                    items: rows
                        .iter()
                        .map(|u| (upstream_view(u), u.position))
                        .collect(),
                }
            }
            (Kind::Accounts, Some(k)) => {
                let Ok(s) = self.ids.decode(SUBJECT_PREFIX, k) else {
                    return Ok(Read::default());
                };
                Read {
                    items: resources::account(t, s)
                        .await?
                        .map(|a| (account_view(&a, self.ids), 0))
                        .into_iter()
                        .collect(),
                    last: None,
                }
            }
            (Kind::Accounts, None) => {
                let start = match after {
                    Some(a) => b64url_decode(a)
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        .unwrap_or([0xff; 16]),
                    None => [0; 16],
                };
                let rows = resources::accounts(t, start, limit).await?;
                Read {
                    last: full(&rows, limit, |a| b64url_encode(&a.subject)),
                    items: rows
                        .iter()
                        .map(|a| (account_view(a, self.ids), 0))
                        .collect(),
                }
            }
            (Kind::Settings, _) => {
                let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                let p = resources::policies(t).await?;
                let branding = idp::branding(t).await?;
                let mappers = idp::mappers(t).await?;
                let view = json!({
                    "jose_alg": s.jose_alg,
                    "argon2": {
                        "m_kib": s.argon2_m_kib, "t": s.argon2_t, "p": s.argon2_p
                    },
                    "rp_id": s.rp_id,
                    "cimd": { "enabled": s.cimd_enabled, "domains": s.cimd_domains },
                    "signin_policy": stored(p.signin.as_deref(), &default_signin().to_value()),
                    "session_policy":
                        stored(p.session.as_deref(), &SessionPolicy::DEFAULT.to_value()),
                    "branding": stored(branding.as_deref(), &Branding::default().to_value()),
                    "mappers": mappers.iter().map(|(c, s)| json!({"claim": c, "source": s}))
                        .collect::<Vec<_>>(),
                });
                Read {
                    items: vec![(view, p.position.unwrap_or(0))],
                    last: None,
                }
            }
        })
    }
}
