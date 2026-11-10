//! The SCIM server's use cases (RFC 7644 §3; OP-155 m.3 (g), IDP-23, TN-75, TN-76): each request
//! runs in one transaction of the client's realm with its audit row, events and Claim orders. A
//! User is an account: it is created, moved along TN-49 and its identifier released through the
//! account use cases, and its attributes are sealed under its subject's profile key. A client
//! sees and changes only its own resources; a group has one membership issuer, the client that
//! created it, so a second writer finds nothing to change (§10.6.2).

pub mod claims;
pub mod clients;
pub mod outbound;

use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_crypto::scim_cursor::{CursorError, CursorKey};
use access_identity_account::AccountError;
use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::app::accounts::{status_claim, status_moved};
use access_identity_account::app::sealing::new_subject_key;
use access_identity_account::app::vault::{self, PiiClass, Vault};
use access_identity_account::app::{Actor, Realm, events};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::ports::{AccountDb, AccountTx};
use access_identity_events::domain::catalog::{IdentityEvent, IdentityKind, ScimResource};
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scim::{ResourceRow, ResourceWrite};
use serde_json::{Map, Value, json};
use suiss_crypto::envelope::Sealed;

use crate::domain::discovery::{DEFAULT_PAGE, MAX_PAGE, MAX_RESULTS};
use crate::domain::filter;
use crate::domain::patch;
use crate::domain::project::{self, Selection};
use crate::domain::resource::{self, rfc3339};
use crate::domain::schema::Kind;
use crate::domain::tolerance::{Profile, Rule};
use crate::domain::{ScimError, ScimType};
pub use crate::ports::{Clock, Vaults};

/// The field a User's sealed attributes are bound to.
pub const SEALED_FIELD: &str = "scim_user";

/// The list message schema.
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// A user resource and its account: `(resource id, subject)`.
type UserSubject = ([u8; 16], [u8; 16]);

/// Most resources a filter that no index answers is evaluated over before it is `tooMany`.
pub const MAX_SCAN: i64 = 10_000;

/// The realm a request reached.
#[derive(Clone)]
pub struct RealmRef {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// The realm's SCIM base URL, for `meta.location`.
    pub base: String,
}

/// The authenticated client of a request.
#[derive(Clone)]
pub struct Client {
    /// Its realm.
    pub realm: RealmRef,
    /// Its name.
    pub name: String,
    /// Its tolerance profile.
    pub profile: Profile,
    /// Its issuer Party.
    pub issuer: [u8; 16],
}

/// A list request's parameters, as sent.
#[derive(Clone, Debug, Default)]
pub struct ListQuery {
    /// `filter`.
    pub filter: Option<String>,
    /// `startIndex`.
    pub start_index: Option<String>,
    /// `count`.
    pub count: Option<String>,
    /// `cursor` (RFC 9865); `Some("")` asks for the first cursor page.
    pub cursor: Option<String>,
    /// `attributes`.
    pub attributes: Option<String>,
    /// `excludedAttributes`.
    pub excluded: Option<String>,
    /// `sortBy`: not served.
    pub sort_by: Option<String>,
}

/// An answer: the status, the body and the headers it carries.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// The body; `Null` for `204`.
    pub body: Value,
    /// `ETag`.
    pub etag: Option<String>,
    /// `Location`.
    pub location: Option<String>,
    /// `Set-Txn` (RFC 9967): the transaction the request's SET events carry.
    pub txn: Option<String>,
}

/// The SCIM service.
pub struct Scim<V, C> {
    app: Pool,
    vaults: V,
    clock: C,
    cursors: CursorKey,
    ids: Arc<IdKey>,
}

fn unavailable(e: impl std::fmt::Display) -> ScimError {
    tracing::warn!(error = %e, "scim request failed");
    ScimError::UNAVAILABLE
}

fn account(e: AccountError) -> ScimError {
    match e {
        AccountError::IdentifierTaken => ScimError::UNIQUENESS,
        AccountError::Transition(_) => ScimError::bad(
            ScimType::InvalidValue,
            "The account cannot move to that state",
        ),
        other => unavailable(other),
    }
}

/// The text form of a resource id: 32 lower-case hex digits.
#[must_use]
pub fn id_text(id: &[u8; 16]) -> String {
    id.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    })
}

/// The id of a text form; `None` for anything else, which answers 404.
#[must_use]
pub fn parse_id(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *slot = u8::from_str_radix(text.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

/// The weak `ETag` of a version.
#[must_use]
pub fn etag(version: u64) -> String {
    format!("W/\"{version}\"")
}

fn new_id() -> Result<[u8; 16], ScimError> {
    access_crypto::random::bytes::<16>().map_err(unavailable)
}

fn txn() -> Result<String, ScimError> {
    Ok(id_text(&new_id()?))
}

fn check_match(if_match: Option<&str>, version: u64) -> Result<(), ScimError> {
    match if_match {
        None => Ok(()),
        Some(m) if m.trim() == "*" => Ok(()),
        Some(m) if m.split(',').any(|t| t.trim() == etag(version)) => Ok(()),
        Some(_) => Err(ScimError::PRECONDITION),
    }
}

fn scim_resource(kind: Kind) -> ScimResource {
    match kind {
        Kind::User => ScimResource::User,
        Kind::Group => ScimResource::Group,
        Kind::Device => ScimResource::Device,
    }
}

fn active_of(resource: &Value) -> bool {
    resource.get("active").and_then(Value::as_bool) != Some(false)
}

fn member_ids(resource: &Value) -> Vec<[u8; 16]> {
    resource
        .get("members")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|m| m.get("value").and_then(Value::as_str).and_then(parse_id))
                .collect()
        })
        .unwrap_or_default()
}

impl<V: Vaults, C: Clock> Scim<V, C> {
    /// The service over the `access_app` pool `app`.
    pub const fn new(app: Pool, vaults: V, clock: C, cursors: CursorKey, ids: Arc<IdKey>) -> Self {
        Self {
            app,
            vaults,
            clock,
            cursors,
            ids,
        }
    }

    fn vault(&self, r: &RealmRef) -> Result<Vault, ScimError> {
        self.vaults
            .vault(r.tenant, r.realm)
            .ok_or(ScimError::UNAVAILABLE)
    }

    async fn begin(&self, r: &RealmRef) -> Result<(PgTx, Vault), ScimError> {
        let vault = self.vault(r)?;
        let tx = PgAccounts::sealed(self.app.clone(), vault.clone())
            .begin(r.tenant, r.realm)
            .await
            .map_err(account)?;
        Ok((tx, vault))
    }

    /// The live client of `realm` whose bearer secret is `secret` (§13.2: a client acts only in
    /// its realm). An unknown, rotated-out or retired secret is `401`.
    ///
    /// # Errors
    /// [`ScimError::UNAUTHORIZED`]; [`ScimError::UNAVAILABLE`].
    pub async fn authenticate(&self, realm: &RealmRef, secret: &str) -> Result<Client, ScimError> {
        if secret.is_empty() || secret.len() > 256 {
            return Err(ScimError::UNAUTHORIZED);
        }
        let digest = suiss_crypto::digest::sha256(secret.as_bytes());
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(unavailable)?;
        let c = access_store::scim::client_by_secret(&mut t, &digest)
            .await
            .map_err(unavailable)?;
        t.commit().await.map_err(unavailable)?;
        let c = c.ok_or(ScimError::UNAUTHORIZED)?;
        let profile = match c.profile.as_deref() {
            None => Profile::strict(),
            Some(p) => crate::domain::tolerance::shipped(p).ok_or(ScimError::UNAVAILABLE)?,
        };
        Ok(Client {
            realm: realm.clone(),
            name: c.name,
            profile,
            issuer: c.issuer,
        })
    }

    fn location(c: &Client, kind: Kind, id: &[u8; 16]) -> String {
        format!("{}/{}/{}", c.realm.base, kind.endpoint(), id_text(id))
    }

    fn representation(c: &Client, kind: Kind, row: &ResourceRow, stored: &Value) -> Value {
        let mut r = stored.as_object().cloned().unwrap_or_default();
        r.insert(String::from("id"), Value::from(id_text(&row.id)));
        r.insert(
            String::from("meta"),
            json!({
                "resourceType": kind.name(),
                "created": rfc3339(row.created_ms),
                "lastModified": rfc3339(row.modified_ms),
                "location": Self::location(c, kind, &row.id),
                "version": etag(row.version),
            }),
        );
        Value::Object(r)
    }

    async fn stored(tx: &mut PgTx, vault: &Vault, row: &ResourceRow) -> Result<Value, ScimError> {
        if let Some(b) = &row.body {
            return serde_json::from_str(b).map_err(unavailable);
        }
        let (Some(subject), Some((nonce, ciphertext))) = (row.subject, &row.sealed) else {
            return Err(ScimError::UNAVAILABLE);
        };
        let Some(dek) = vault::class_key(&mut tx.0, vault, subject, PiiClass::Profile, false)
            .await
            .map_err(account)?
        else {
            return Err(ScimError::NOT_FOUND);
        };
        let text = vault::open(
            &tx.0,
            &dek,
            subject,
            PiiClass::Profile,
            SEALED_FIELD,
            &Sealed {
                nonce: *nonce,
                ciphertext: ciphertext.clone(),
            },
        )
        .map_err(account)?;
        serde_json::from_str(&text).map_err(unavailable)
    }

    async fn with_groups(
        tx: &mut PgTx,
        c: &Client,
        row: &ResourceRow,
        mut repr: Value,
    ) -> Result<Value, ScimError> {
        if row.kind != Kind::User.stored() {
            return Ok(repr);
        }
        let groups = access_store::scim::groups_of(&mut tx.0, &c.name, &id_text(&row.id))
            .await
            .map_err(unavailable)?;
        if !groups.is_empty()
            && let Some(o) = repr.as_object_mut()
        {
            let list: Vec<Value> = groups
                .iter()
                .map(|(g, name, _)| {
                    json!({
                        "value": id_text(g),
                        "$ref": Self::location(c, Kind::Group, g),
                        "display": name,
                        "type": "direct",
                    })
                })
                .collect();
            o.insert(String::from("groups"), Value::Array(list));
        }
        Ok(repr)
    }

    fn external_index(
        c: &Client,
        vault: &Vault,
        kind: Kind,
        resource: &Value,
    ) -> Result<Option<[u8; 32]>, ScimError> {
        let Some(ext) = resource.get("externalId").and_then(Value::as_str) else {
            return Ok(None);
        };
        let key = format!("scim\0{}\0{}\0{ext}", c.name, kind.stored());
        vault
            .index_of(c.realm.tenant.as_bytes(), c.realm.realm.as_bytes(), &key)
            .map(Some)
            .map_err(account)
    }

    async fn audit(
        tx: &mut PgTx,
        c: &Client,
        event_type: &str,
        target: &str,
        correlation: &str,
    ) -> Result<(), ScimError> {
        let actor = format!("scim:{}", c.name);
        tx.audit(&AuditEvent {
            event_type,
            actor: &actor,
            target,
            correlation,
        })
        .await
        .map_err(account)
    }

    async fn event(
        &self,
        tx: &mut PgTx,
        c: &Client,
        kind: Kind,
        id: &[u8; 16],
        provisioned: bool,
    ) -> Result<(), ScimError> {
        let event_id = access_crypto::random::bytes::<32>().map_err(unavailable)?;
        let k = if provisioned {
            IdentityKind::ScimProvisioned
        } else {
            IdentityKind::ScimDeprovisioned
        };
        let e = IdentityEvent::scim(
            k,
            event_id,
            c.realm.realm.as_bytes(),
            (&c.name, scim_resource(kind), &id_text(id)),
            self.clock.now_ms(),
        );
        access_identity_events::app::emit(&mut tx.0, &e)
            .await
            .map_err(unavailable)
    }

    fn naming<'a>(&'a self, c: &Client, vault: &'a Vault) -> Realm<'a> {
        Realm {
            tenant: c.realm.tenant,
            realm: c.realm.realm,
            kek: &*vault.kek,
            ids: &self.ids,
        }
    }

    async fn check_members(
        tx: &mut PgTx,
        c: &Client,
        resource: &Value,
        own: Option<[u8; 16]>,
    ) -> Result<Vec<([u8; 16], [u8; 16])>, ScimError> {
        let ids = member_ids(resource);
        let declared = resource
            .get("members")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if ids.len() != declared || own.is_some_and(|o| ids.contains(&o)) {
            return Err(ScimError::bad(
                ScimType::InvalidValue,
                "A member is not a resource of this client",
            ));
        }
        let users = access_store::scim::user_subjects(&mut tx.0, &c.name, &ids)
            .await
            .map_err(unavailable)?;
        for id in &ids {
            if users.iter().any(|(u, _)| u == id) {
                continue;
            }
            let group =
                access_store::scim::resource(&mut tx.0, &c.name, Kind::Group.stored(), *id, false)
                    .await
                    .map_err(unavailable)?;
            if group.is_none() {
                return Err(ScimError::bad(
                    ScimType::InvalidValue,
                    "A member is not a resource of this client",
                ));
            }
        }
        Ok(users)
    }

    async fn membership_claims(
        &self,
        tx: &mut PgTx,
        c: &Client,
        group: [u8; 16],
        (before, after): (&[UserSubject], &[UserSubject]),
    ) -> Result<(), ScimError> {
        let at = self.clock.now_ms();
        for (u, subject) in after {
            if !before.iter().any(|(b, _)| b == u) {
                claims::queue(
                    tx,
                    &c.name,
                    &claims::member(*subject, &c.name, group, at, false),
                )
                .await
                .map_err(account)?;
            }
        }
        for (u, subject) in before {
            if !after.iter().any(|(a, _)| a == u) {
                claims::queue(
                    tx,
                    &c.name,
                    &claims::member(*subject, &c.name, group, at, true),
                )
                .await
                .map_err(account)?;
            }
        }
        Ok(())
    }

    async fn hr_claims(
        &self,
        tx: &mut PgTx,
        c: &Client,
        subject: [u8; 16],
        change: (Option<&Value>, Option<&Value>),
    ) -> Result<(), ScimError> {
        for o in claims::hr(subject, &c.name, change, self.clock.now_ms()) {
            claims::queue(tx, &c.name, &o).await.map_err(account)?;
        }
        Ok(())
    }

    async fn move_status(
        &self,
        tx: &mut PgTx,
        c: &Client,
        vault: &Vault,
        subject: [u8; 16],
        active: bool,
        correlation: &str,
    ) -> Result<(), ScimError> {
        let row = tx
            .subject(subject, true)
            .await
            .map_err(account)?
            .ok_or(ScimError::NOT_FOUND)?;
        let from = AccountStatus::parse(&row.status).ok_or(ScimError::UNAVAILABLE)?;
        let to = if active {
            AccountStatus::Active
        } else {
            AccountStatus::Deactivated
        };
        if from == to
            || (!active
                && from.deactivation()
                    == access_identity_account::domain::status::Deactivation::AlreadyDone)
        {
            return Ok(());
        }
        if active && from != AccountStatus::Deactivated {
            return Ok(());
        }
        from.transition(to).map_err(|e| account(e.into()))?;
        if !tx.set_status(subject, from, to).await.map_err(account)? {
            return Err(ScimError::UNAVAILABLE);
        }
        let actor = format!("scim:{}", c.name);
        let who = Actor {
            actor: &actor,
            correlation,
        };
        // TN-75, TN-50, Ek B 4860
        status_moved(tx, &self.naming(c, vault), subject, (from, to), &who)
            .await
            .map_err(account)
    }

    /// `POST /{Users,Groups,Devices}`.
    ///
    /// # Errors
    /// [`ScimError`].
    #[expect(
        clippy::too_many_lines,
        reason = "a User through the account use cases and a Group or Device, in one transaction"
    )]
    pub async fn create(&self, c: &Client, kind: Kind, body: &Value) -> Result<Answer, ScimError> {
        let canon = resource::canonical(kind, body, &c.profile)?;
        let (mut tx, vault) = self.begin(&c.realm).await?;
        let id = new_id()?;
        let txn = txn()?;
        let external_index = Self::external_index(c, &vault, kind, &canon)?;
        let base = ResourceWrite {
            id,
            client: &c.name,
            kind: kind.stored(),
            subject: None,
            external_index,
            display_name: None,
            body: None,
            sealed: None,
            version: 1,
        };
        let created = match kind {
            Kind::User => {
                let user_name = canon
                    .get("userName")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ScimError::bad(ScimType::InvalidValue, "userName is missing"))?;
                let ident = Identifier::new(IdentifierKind::Username, user_name)
                    .map_err(|_| ScimError::bad(ScimType::InvalidValue, "userName is invalid"))?;
                if tx
                    .subject_by_identifier(ident.value())
                    .await
                    .map_err(account)?
                    .is_some()
                {
                    return Err(ScimError::UNIQUENESS);
                }
                let realm = self.naming(c, &vault);
                let wrapped = new_subject_key(&realm).map_err(account)?;
                let status = if active_of(&canon) {
                    AccountStatus::Active
                } else {
                    AccountStatus::Deactivated
                };
                let subject = tx
                    .insert_subject(status, vault.kek.id(), &wrapped)
                    .await
                    .map_err(account)?;
                if !tx.add_identifier(subject, &ident).await.map_err(account)? {
                    return Err(ScimError::UNIQUENESS);
                }
                let text = serde_json::to_string(&canon).map_err(unavailable)?;
                let dek = vault::class_key(&mut tx.0, &vault, subject, PiiClass::Profile, true)
                    .await
                    .map_err(account)?
                    .ok_or(ScimError::UNAVAILABLE)?;
                let sealed = vault::seal(
                    &tx.0,
                    &dek,
                    subject,
                    PiiClass::Profile,
                    SEALED_FIELD,
                    text.as_bytes(),
                )
                .map_err(account)?;
                let w = ResourceWrite {
                    subject: Some(subject),
                    sealed: Some((&sealed.nonce, sealed.ciphertext.as_slice())),
                    ..base
                };
                if !access_store::scim::insert_resource(&mut tx.0, &w)
                    .await
                    .map_err(unavailable)?
                {
                    return Err(ScimError::UNIQUENESS);
                }
                events::created(&mut tx, &realm, subject)
                    .await
                    .map_err(account)?;
                // TN-49, Ek B 4860
                status_claim(&mut tx, subject, status)
                    .await
                    .map_err(account)?;
                // IDP-35, Ek B 4925
                self.hr_claims(&mut tx, c, subject, (None, Some(&canon)))
                    .await?;
                realm.external(subject).map_err(account)?
            }
            Kind::Group | Kind::Device => {
                let users = if kind == Kind::Group {
                    Self::check_members(&mut tx, c, &canon, None).await?
                } else {
                    Vec::new()
                };
                let text = serde_json::to_string(&canon).map_err(unavailable)?;
                let display = canon.get("displayName").and_then(Value::as_str);
                let w = ResourceWrite {
                    display_name: display,
                    body: Some(&text),
                    ..base
                };
                if !access_store::scim::insert_resource(&mut tx.0, &w)
                    .await
                    .map_err(unavailable)?
                {
                    return Err(ScimError::UNIQUENESS);
                }
                if kind == Kind::Group {
                    self.membership_claims(&mut tx, c, id, (&[], &users))
                        .await?;
                }
                id_text(&id)
            }
        };
        Self::audit(&mut tx, c, "scim.provisioned", &created, &txn).await?;
        self.event(&mut tx, c, kind, &id, true).await?;
        // IDP-29
        outbound::queue_all(&mut tx, (&c.name, kind, id), outbound::Operation::Create)
            .await
            .map_err(account)?;
        let row = access_store::scim::resource(&mut tx.0, &c.name, kind.stored(), id, false)
            .await
            .map_err(unavailable)?
            .ok_or(ScimError::UNAVAILABLE)?;
        let repr = Self::representation(c, kind, &row, &canon);
        tx.commit().await.map_err(account)?;
        let none = Selection::default();
        Ok(Answer {
            status: 201,
            body: project::project(kind, &repr, &none, &none),
            etag: Some(etag(row.version)),
            location: Some(Self::location(c, kind, &id)),
            txn: Some(txn),
        })
    }

    async fn load(
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        kind: Kind,
        id: &str,
        lock: bool,
    ) -> Result<(ResourceRow, Value), ScimError> {
        let id = parse_id(id).ok_or(ScimError::NOT_FOUND)?;
        let row = access_store::scim::resource(&mut tx.0, &c.name, kind.stored(), id, lock)
            .await
            .map_err(unavailable)?
            .ok_or(ScimError::NOT_FOUND)?;
        let stored = Self::stored(tx, vault, &row).await?;
        Ok((row, stored))
    }

    /// `GET /{Users,Groups,Devices}/{id}`; a deleted resource is `404`, never `410` (TN-76).
    ///
    /// # Errors
    /// [`ScimError`].
    pub async fn get(
        &self,
        c: &Client,
        kind: Kind,
        id: &str,
        q: &ListQuery,
    ) -> Result<Answer, ScimError> {
        let attributes = project::selection(kind, q.attributes.as_deref())?;
        let excluded = project::selection(kind, q.excluded.as_deref())?;
        let (mut tx, vault) = self.begin(&c.realm).await?;
        let (row, stored) = Self::load(&mut tx, &vault, c, kind, id, false).await?;
        let repr = Self::representation(c, kind, &row, &stored);
        let repr = Self::with_groups(&mut tx, c, &row, repr).await?;
        tx.commit().await.map_err(account)?;
        Ok(Answer {
            status: 200,
            body: project::project(kind, &repr, &attributes, &excluded),
            etag: Some(etag(row.version)),
            location: Some(Self::location(c, kind, &row.id)),
            txn: None,
        })
    }

    fn page_size(q: &ListQuery) -> Result<usize, ScimError> {
        match q.count.as_deref() {
            None => Ok(DEFAULT_PAGE),
            Some(n) => match n.parse::<i64>() {
                Ok(v) if v <= 0 => Ok(0),
                Ok(v) => Ok(usize::try_from(v).unwrap_or(MAX_PAGE).min(MAX_PAGE)),
                Err(_) => Err(ScimError::bad(
                    ScimType::InvalidCount,
                    "count is not a number",
                )),
            },
        }
    }

    fn list_context(c: &Client, kind: Kind, q: &ListQuery) -> Vec<u8> {
        let mut ctx = Vec::new();
        for part in [
            c.name.as_str(),
            kind.stored(),
            q.filter.as_deref().unwrap_or(""),
        ] {
            ctx.extend_from_slice(part.as_bytes());
            ctx.push(0);
        }
        ctx
    }

    async fn candidates(
        &self,
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        kind: Kind,
        expr: Option<&access_parse::scim::protocol::Expr>,
    ) -> Result<Vec<(ResourceRow, Value)>, ScimError> {
        if let Some(e) = expr {
            if kind == Kind::User
                && let Some(name) = filter::equality(e, "userName")
            {
                let ident = Identifier::new(IdentifierKind::Username, name).ok();
                let subject = match ident {
                    Some(i) => tx.subject_by_identifier(i.value()).await.map_err(account)?,
                    None => None,
                };
                let id = match subject {
                    Some(s) => access_store::scim::user_of_subject(&mut tx.0, &c.name, s)
                        .await
                        .map_err(unavailable)?,
                    None => None,
                };
                return self
                    .rows(tx, vault, c, kind, id.into_iter().collect())
                    .await;
            }
            if let Some(ext) = filter::equality(e, "externalId") {
                let probe = json!({ "externalId": ext });
                let id = match Self::external_index(c, vault, kind, &probe)? {
                    Some(i) => {
                        access_store::scim::by_external(&mut tx.0, &c.name, kind.stored(), &i)
                            .await
                            .map_err(unavailable)?
                    }
                    None => None,
                };
                return self
                    .rows(tx, vault, c, kind, id.into_iter().collect())
                    .await;
            }
            if let Some(id) = filter::equality(e, "id") {
                return self
                    .rows(tx, vault, c, kind, parse_id(id).into_iter().collect())
                    .await;
            }
        }
        let rows = access_store::scim::page(
            &mut tx.0,
            &c.name,
            kind.stored(),
            None,
            MAX_SCAN.saturating_add(1),
        )
        .await
        .map_err(unavailable)?;
        if usize::try_from(MAX_SCAN).is_ok_and(|m| rows.len() > m) {
            return Err(ScimError::bad(
                ScimType::TooMany,
                "The filter selects more resources than the server evaluates",
            ));
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let stored = Self::stored(tx, vault, &row).await?;
            out.push((row, stored));
        }
        Ok(out)
    }

    async fn rows(
        &self,
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        kind: Kind,
        ids: Vec<[u8; 16]>,
    ) -> Result<Vec<(ResourceRow, Value)>, ScimError> {
        let mut out = Vec::new();
        for id in ids {
            if let Some(row) =
                access_store::scim::resource(&mut tx.0, &c.name, kind.stored(), id, false)
                    .await
                    .map_err(unavailable)?
            {
                let stored = Self::stored(tx, vault, &row).await?;
                out.push((row, stored));
            }
        }
        Ok(out)
    }

    /// `GET /{Users,Groups,Devices}`: index pages by default, RFC 9865 cursor pages on request;
    /// at most 1000 results, pages of at most 200 (OP-155 m.3 (g)).
    ///
    /// # Errors
    /// [`ScimError`].
    #[expect(
        clippy::too_many_lines,
        reason = "the filter, both paging methods and the list message, read in order"
    )]
    pub async fn list(&self, c: &Client, kind: Kind, q: &ListQuery) -> Result<Answer, ScimError> {
        if q.sort_by.is_some() {
            return Err(ScimError::NOT_IMPLEMENTED);
        }
        if q.cursor.is_some() && q.start_index.is_some() {
            return Err(ScimError::bad(
                ScimType::InvalidValue,
                "cursor and startIndex do not go together",
            ));
        }
        let expr = q
            .filter
            .as_deref()
            .map(|f| filter::parse(kind, f, &c.profile))
            .transpose()?;
        let attributes = project::selection(kind, q.attributes.as_deref())?;
        let mut excluded = project::selection(kind, q.excluded.as_deref())?;
        if kind == Kind::Group
            && c.profile.has(Rule::GroupMembersOmitted)
            && attributes.is_empty()
            && excluded.is_empty()
        {
            excluded = project::selection(kind, Some("members"))?;
        }
        let size = Self::page_size(q)?;
        let now = self.clock.now_ms();
        let context = Self::list_context(c, kind, q);
        let after = match q.cursor.as_deref() {
            None | Some("") => None,
            Some(text) => {
                let pos = self
                    .cursors
                    .open(&context, text, now)
                    .map_err(|e| match e {
                        CursorError::Invalid => {
                            ScimError::bad(ScimType::InvalidCursor, "The cursor is invalid")
                        }
                        CursorError::Expired => {
                            ScimError::bad(ScimType::ExpiredCursor, "The cursor has expired")
                        }
                    })?;
                Some(<[u8; 16]>::try_from(pos.as_slice()).map_err(|_| {
                    ScimError::bad(ScimType::InvalidCursor, "The cursor is invalid")
                })?)
            }
        };
        let (mut tx, vault) = self.begin(&c.realm).await?;
        let mut matched: Vec<(ResourceRow, Value)> = self
            .candidates(&mut tx, &vault, c, kind, expr.as_ref())
            .await?
            .into_iter()
            .filter(|(row, stored)| {
                let repr = Self::representation(c, kind, row, stored);
                expr.as_ref().is_none_or(|e| filter::eval(kind, e, &repr))
            })
            .collect();
        if expr.is_some() && matched.len() > MAX_RESULTS {
            return Err(ScimError::bad(
                ScimType::TooMany,
                "The filter selects more than 1000 resources",
            ));
        }
        matched.sort_by_key(|a| a.0.id);
        let total = if expr.is_some() {
            matched.len()
        } else {
            usize::try_from(
                access_store::scim::count(&mut tx.0, &c.name, kind.stored())
                    .await
                    .map_err(unavailable)?,
            )
            .unwrap_or(usize::MAX)
        };
        let (page, start, next): (Vec<(ResourceRow, Value)>, Option<usize>, Option<String>) = if q
            .cursor
            .is_some()
        {
            let rest: Vec<(ResourceRow, Value)> = matched
                .into_iter()
                .filter(|(row, _)| after.is_none_or(|a| row.id > a))
                .collect();
            let more = rest.len() > size;
            let page: Vec<_> = rest.into_iter().take(size).collect();
            let next = match page.last() {
                Some((row, _)) if more => Some(self.cursors.seal(&context, &row.id, now)),
                _ => None,
            };
            (page, None, next)
        } else {
            let start = q
                .start_index
                .as_deref()
                .map_or(Ok(1), str::parse::<i64>)
                .map_err(|_| ScimError::bad(ScimType::InvalidValue, "startIndex is not a number"))?
                .max(1);
            let skip = usize::try_from(start.saturating_sub(1)).unwrap_or(usize::MAX);
            (
                matched.into_iter().skip(skip).take(size).collect(),
                Some(usize::try_from(start).unwrap_or(1)),
                None,
            )
        };
        let mut resources = Vec::with_capacity(page.len());
        for (row, stored) in &page {
            let repr = Self::representation(c, kind, row, stored);
            let repr = Self::with_groups(&mut tx, c, row, repr).await?;
            resources.push(project::project(kind, &repr, &attributes, &excluded));
        }
        tx.commit().await.map_err(account)?;
        let mut body = Map::new();
        body.insert(String::from("schemas"), json!([LIST_SCHEMA]));
        let omit_total = q.cursor.is_some() && c.profile.has(Rule::ListWithoutTotal);
        if !omit_total {
            body.insert(String::from("totalResults"), Value::from(total));
        }
        body.insert(String::from("itemsPerPage"), Value::from(resources.len()));
        if let Some(s) = start {
            body.insert(String::from("startIndex"), Value::from(s));
        }
        if let Some(n) = next {
            body.insert(String::from("nextCursor"), Value::from(n));
        }
        body.insert(String::from("Resources"), Value::Array(resources));
        Ok(Answer {
            status: 200,
            body: Value::Object(body),
            etag: None,
            location: None,
            txn: None,
        })
    }

    async fn write_back(
        &self,
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        (kind, row): (Kind, &ResourceRow),
        next: &Value,
    ) -> Result<u64, ScimError> {
        let external_index = Self::external_index(c, vault, kind, next)?;
        let text = serde_json::to_string(next).map_err(unavailable)?;
        let version = row.version.checked_add(1).ok_or(ScimError::UNAVAILABLE)?;
        let sealed = match row.subject {
            Some(subject) => {
                let dek = vault::class_key(&mut tx.0, vault, subject, PiiClass::Profile, true)
                    .await
                    .map_err(account)?
                    .ok_or(ScimError::NOT_FOUND)?;
                Some(
                    vault::seal(
                        &tx.0,
                        &dek,
                        subject,
                        PiiClass::Profile,
                        SEALED_FIELD,
                        text.as_bytes(),
                    )
                    .map_err(account)?,
                )
            }
            None => None,
        };
        let w = ResourceWrite {
            id: row.id,
            client: &c.name,
            kind: kind.stored(),
            subject: row.subject,
            external_index,
            display_name: next.get("displayName").and_then(Value::as_str),
            body: row.subject.is_none().then_some(text.as_str()),
            sealed: sealed.as_ref().map(|s| (&s.nonce, s.ciphertext.as_slice())),
            version,
        };
        if !access_store::scim::update_resource(&mut tx.0, &w, row.version)
            .await
            .map_err(unavailable)?
        {
            return Err(ScimError::UNIQUENESS);
        }
        Ok(version)
    }

    async fn changed(
        &self,
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        (kind, row): (Kind, &ResourceRow),
        (before, after): (&Value, &Value),
        txn: &str,
    ) -> Result<(), ScimError> {
        match kind {
            Kind::User => {
                let subject = row.subject.ok_or(ScimError::UNAVAILABLE)?;
                let user_name =
                    |v: &Value| v.get("userName").and_then(Value::as_str).map(str::to_owned);
                if user_name(before) != user_name(after)
                    && let Some(new) = user_name(after)
                {
                    let ident = Identifier::new(IdentifierKind::Username, &new).map_err(|_| {
                        ScimError::bad(ScimType::InvalidValue, "userName is invalid")
                    })?;
                    if !tx.add_identifier(subject, &ident).await.map_err(account)? {
                        return Err(ScimError::UNIQUENESS);
                    }
                    if let Some(old) = user_name(before) {
                        let index = vault
                            .index_of(c.realm.tenant.as_bytes(), c.realm.realm.as_bytes(), &old)
                            .map_err(account)?;
                        tx.0.release_identifier(subject, &index, &vault::folded(&old))
                            .await
                            .map_err(unavailable)?;
                    }
                }
                if active_of(before) != active_of(after) {
                    self.move_status(tx, c, vault, subject, active_of(after), txn)
                        .await?;
                }
                self.hr_claims(tx, c, subject, (Some(before), Some(after)))
                    .await?;
            }
            Kind::Group => {
                let old =
                    access_store::scim::user_subjects(&mut tx.0, &c.name, &member_ids(before))
                        .await
                        .map_err(unavailable)?;
                let new = Self::check_members(tx, c, after, Some(row.id)).await?;
                self.membership_claims(tx, c, row.id, (&old, &new)).await?;
            }
            Kind::Device => {}
        }
        Ok(())
    }

    async fn update(
        &self,
        c: &Client,
        kind: Kind,
        id: &str,
        if_match: Option<&str>,
        next: impl FnOnce(&Value) -> Result<Value, ScimError>,
    ) -> Result<Answer, ScimError> {
        let (mut tx, vault) = self.begin(&c.realm).await?;
        let (row, before) = Self::load(&mut tx, &vault, c, kind, id, true).await?;
        check_match(if_match, row.version)?;
        let after = next(&before)?;
        let txn = txn()?;
        let version = if after == before {
            row.version
        } else {
            let v = self
                .write_back(&mut tx, &vault, c, (kind, &row), &after)
                .await?;
            self.changed(&mut tx, &vault, c, (kind, &row), (&before, &after), &txn)
                .await?;
            let target = match row.subject {
                Some(s) => self.naming(c, &vault).external(s).map_err(account)?,
                None => id_text(&row.id),
            };
            let deprovisioned = kind == Kind::User && active_of(&before) && !active_of(&after);
            let event_type = if deprovisioned {
                "scim.deprovisioned"
            } else {
                "scim.provisioned"
            };
            Self::audit(&mut tx, c, event_type, &target, &txn).await?;
            self.event(&mut tx, c, kind, &row.id, !deprovisioned)
                .await?;
            let op = if deprovisioned {
                outbound::Operation::Deactivate
            } else {
                outbound::Operation::Replace
            };
            outbound::queue_all(&mut tx, (&c.name, kind, row.id), op)
                .await
                .map_err(account)?;
            v
        };
        let row = access_store::scim::resource(&mut tx.0, &c.name, kind.stored(), row.id, false)
            .await
            .map_err(unavailable)?
            .ok_or(ScimError::UNAVAILABLE)?;
        let _ = version;
        let repr = Self::representation(c, kind, &row, &after);
        let repr = Self::with_groups(&mut tx, c, &row, repr).await?;
        tx.commit().await.map_err(account)?;
        let none = Selection::default();
        Ok(Answer {
            status: 200,
            body: project::project(kind, &repr, &none, &none),
            etag: Some(etag(row.version)),
            location: Some(Self::location(c, kind, &row.id)),
            txn: Some(txn),
        })
    }

    /// `PUT /{Users,Groups,Devices}/{id}`.
    ///
    /// # Errors
    /// [`ScimError`].
    pub async fn replace(
        &self,
        c: &Client,
        kind: Kind,
        id: &str,
        body: &Value,
        if_match: Option<&str>,
    ) -> Result<Answer, ScimError> {
        let canon = resource::canonical(kind, body, &c.profile)?;
        self.update(c, kind, id, if_match, |_| Ok(canon)).await
    }

    /// `PATCH /{Users,Groups,Devices}/{id}`: all operations or none; a no-op keeps the version
    /// and `meta.lastModified` (§10.6.2).
    ///
    /// # Errors
    /// [`ScimError`].
    pub async fn patch(
        &self,
        c: &Client,
        kind: Kind,
        id: &str,
        body: &Value,
        if_match: Option<&str>,
    ) -> Result<Answer, ScimError> {
        let ops = patch::parse(body, &c.profile)?;
        self.update(c, kind, id, if_match, |before| {
            patch::apply(kind, before, &ops, &c.profile)
        })
        .await
    }

    /// `DELETE /{Users,Groups,Devices}/{id}`: a soft delete and a tombstone; a deleted User's
    /// account is deprovisioned and its user name released, its id stays taken and later reads
    /// answer 404 (OP-73, INV-32, TN-75, TN-76).
    ///
    /// # Errors
    /// [`ScimError`].
    pub async fn delete(
        &self,
        c: &Client,
        kind: Kind,
        id: &str,
        if_match: Option<&str>,
    ) -> Result<Answer, ScimError> {
        let (mut tx, vault) = self.begin(&c.realm).await?;
        let (row, before) = Self::load(&mut tx, &vault, c, kind, id, true).await?;
        check_match(if_match, row.version)?;
        let txn = txn()?;
        if !access_store::scim::delete_resource(&mut tx.0, &c.name, row.id, row.version)
            .await
            .map_err(unavailable)?
        {
            return Err(ScimError::PRECONDITION);
        }
        let at = self.clock.now_ms();
        let target = match (kind, row.subject) {
            (Kind::User, Some(subject)) => {
                // TN-75, TN-50, Ek B 4860
                self.move_status(&mut tx, c, &vault, subject, false, &txn)
                    .await?;
                if let Some(name) = before.get("userName").and_then(Value::as_str) {
                    let index = vault
                        .index_of(c.realm.tenant.as_bytes(), c.realm.realm.as_bytes(), name)
                        .map_err(account)?;
                    tx.0.release_identifier(subject, &index, &vault::folded(name))
                        .await
                        .map_err(unavailable)?;
                }
                self.hr_claims(&mut tx, c, subject, (Some(&before), None))
                    .await?;
                let me = id_text(&row.id);
                for (g, _, _) in access_store::scim::groups_of(&mut tx.0, &c.name, &me)
                    .await
                    .map_err(unavailable)?
                {
                    self.drop_member(&mut tx, &vault, c, g, &me).await?;
                    claims::queue(
                        &mut tx,
                        &c.name,
                        &claims::member(subject, &c.name, g, at, true),
                    )
                    .await
                    .map_err(account)?;
                }
                self.naming(c, &vault).external(subject).map_err(account)?
            }
            (Kind::Group, _) => {
                let old =
                    access_store::scim::user_subjects(&mut tx.0, &c.name, &member_ids(&before))
                        .await
                        .map_err(unavailable)?;
                self.membership_claims(&mut tx, c, row.id, (&old, &[]))
                    .await?;
                id_text(&row.id)
            }
            _ => id_text(&row.id),
        };
        Self::audit(&mut tx, c, "scim.deprovisioned", &target, &txn).await?;
        self.event(&mut tx, c, kind, &row.id, false).await?;
        outbound::queue_all(
            &mut tx,
            (&c.name, kind, row.id),
            outbound::Operation::Delete,
        )
        .await
        .map_err(account)?;
        tx.commit().await.map_err(account)?;
        Ok(Answer {
            status: 204,
            body: Value::Null,
            etag: None,
            location: None,
            txn: Some(txn),
        })
    }

    async fn drop_member(
        &self,
        tx: &mut PgTx,
        vault: &Vault,
        c: &Client,
        group: [u8; 16],
        member: &str,
    ) -> Result<(), ScimError> {
        let Some(row) =
            access_store::scim::resource(&mut tx.0, &c.name, Kind::Group.stored(), group, true)
                .await
                .map_err(unavailable)?
        else {
            return Ok(());
        };
        let mut body = Self::stored(tx, vault, &row).await?;
        if let Some(Value::Array(items)) = body.get_mut("members") {
            items.retain(|m| m.get("value").and_then(Value::as_str) != Some(member));
            if items.is_empty()
                && let Some(o) = body.as_object_mut()
            {
                o.remove("members");
            }
        }
        self.write_back(tx, vault, c, (Kind::Group, &row), &body)
            .await
            .map(drop)
    }
}

impl<V: Vaults, C: Clock> outbound::Local for Scim<V, C> {
    fn read<'a>(
        &'a self,
        tenant: TenantId,
        realm: RealmId,
        push: &'a outbound::Push,
    ) -> outbound::Pending<'a, Option<Value>> {
        Box::pin(async move {
            let r = RealmRef {
                tenant,
                realm,
                base: String::new(),
            };
            let (mut tx, vault) = self.begin(&r).await.ok()?;
            let row = access_store::scim::resource(
                &mut tx.0,
                &push.client,
                push.kind.stored(),
                push.local,
                false,
            )
            .await
            .ok()??;
            let stored = Self::stored(&mut tx, &vault, &row).await.ok()?;
            tx.commit().await.ok()?;
            Some(stored)
        })
    }
}
