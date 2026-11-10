//! The outbound SCIM client (IDP-29, §10.6.2, Ek B 4823, 5036): the realm's provisioned users and
//! groups are pushed to each live target registered by `idp.scim.outbound_register`, in order,
//! through the identity outbox. Each push and the target's answer go to the outbound log; a
//! transient failure is queued again, at most [`MAX_ATTEMPTS`] times. A target's answer is a
//! report, not authority and not a Claim: Access does not state that the account exists there.
//! There are no application-specific connectors: a target speaks SCIM 2.0 or is not a target.

use std::future::Future;
use std::pin::Pin;

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::ports::AccountTx;
use access_store::Pool;
use access_store::events::SealedKey;
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx, ack, cursor, poll};
use access_store::scim::{PushLog, TargetRow};
use serde_json::{Value, json};

use crate::app::{id_text, parse_id};
use crate::domain::schema::Kind;

/// The identity outbox kind of a push order.
pub const OUTBOX_KIND: &str = "scim_push";

/// The outbound worker's outbox cursor.
pub const CONSUMER: &str = "scim-outbound";

/// Most attempts of one push.
pub const MAX_ATTEMPTS: u8 = 5;

/// Longest target answer read.
pub const MAX_ANSWER: usize = 64 * 1024;

/// What a push does at the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Created, or replaced once it is linked.
    Create,
    /// Replaced.
    Replace,
    /// Made inactive.
    Deactivate,
    /// Deleted at the target.
    Delete,
}

impl Operation {
    const fn byte(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Replace => 2,
            Self::Deactivate => 3,
            Self::Delete => 4,
        }
    }

    const fn of(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Create),
            2 => Some(Self::Replace),
            3 => Some(Self::Deactivate),
            4 => Some(Self::Delete),
            _ => None,
        }
    }

    /// The logged name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Replace => "replace",
            Self::Deactivate => "deactivate",
            Self::Delete => "delete",
        }
    }
}

/// One push order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push {
    /// The target.
    pub target: String,
    /// `User` or `Group`.
    pub kind: Kind,
    /// The local resource.
    pub local: [u8; 16],
    /// The client that owns it.
    pub client: String,
    /// What to do.
    pub operation: Operation,
    /// Which attempt this is.
    pub attempt: u8,
}

impl Push {
    /// The outbox payload.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let kind = match self.kind {
            Kind::User => 1,
            Kind::Group => 2,
            Kind::Device => 3,
        };
        let mut out = vec![self.operation.byte(), kind, self.attempt];
        out.extend_from_slice(&self.local);
        for s in [&self.target, &self.client] {
            out.push(u8::try_from(s.len()).unwrap_or(0));
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// The order of an outbox payload.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let (head, rest) = b.split_first_chunk::<3>()?;
        let (local, rest) = rest.split_first_chunk::<16>()?;
        let (&tl, rest) = rest.split_first()?;
        let (target, rest) = rest.split_at_checked(usize::from(tl))?;
        let (&cl, rest) = rest.split_first()?;
        let (client, rest) = rest.split_at_checked(usize::from(cl))?;
        if !rest.is_empty() {
            return None;
        }
        let kind = match head[1] {
            1 => Kind::User,
            2 => Kind::Group,
            _ => return None,
        };
        Some(Self {
            operation: Operation::of(head[0])?,
            kind,
            attempt: head[2],
            local: *local,
            target: String::from_utf8(target.to_vec()).ok()?,
            client: String::from_utf8(client.to_vec()).ok()?,
        })
    }
}

/// Queues `operation` of the local resource for every live target of the realm (IDP-29).
///
/// # Errors
/// [`access_identity_account::AccountError`].
pub async fn queue_all(
    tx: &mut PgTx,
    (client, kind, local): (&str, Kind, [u8; 16]),
    operation: Operation,
) -> Result<(), access_identity_account::AccountError> {
    if kind == Kind::Device {
        return Ok(());
    }
    let targets = access_store::scim::targets(&mut tx.0).await?;
    for t in targets.into_iter().filter(|t| t.live) {
        let p = Push {
            target: t.name,
            kind,
            local,
            client: String::from(client),
            operation,
            attempt: 1,
        };
        tx.outbox(OUTBOX_KIND, &p.to_bytes()).await?;
    }
    Ok(())
}

/// The future a port answers with.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A target's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Its status.
    pub status: u16,
    /// Its body, up to [`MAX_ANSWER`] bytes.
    pub body: Vec<u8>,
}

/// The guarded outbound HTTP client (SSRF checks, timeouts, `https` only).
pub trait Sender: Send + Sync {
    /// Sends `method url` with the bearer `secret` and the JSON `body`; `None` when the target
    /// could not be reached.
    fn send<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        secret: &'a [u8],
        body: Option<&'a [u8]>,
    ) -> Pending<'a, Option<Reply>>;
}

/// Opens a target's sealed secret under the realm KEK.
pub trait Secrets: Send + Sync {
    /// The secret of target `id`; `None` when it cannot be opened (fail closed).
    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>>;
}

/// The outbound worker.
pub struct Worker<S, K, L> {
    /// `access_app`.
    pub app: Pool,
    /// `access_outbox_reader`.
    pub reader: Pool,
    /// The HTTP client.
    pub sender: S,
    /// The target secrets.
    pub secrets: K,
    /// What reads a local resource: the SCIM service.
    pub local: L,
}

/// Reads the representation a local resource is pushed with.
pub trait Local: Send + Sync {
    /// The resource's attributes without `id`, `meta` and `groups`; `None` once it is gone.
    fn read<'a>(
        &'a self,
        tenant: TenantId,
        realm: RealmId,
        push: &'a Push,
    ) -> Pending<'a, Option<Value>>;
}

fn outbound_body(kind: Kind, mut v: Value, members: &[(String, String)]) -> Value {
    if let Some(o) = v.as_object_mut() {
        for k in ["id", "meta", "groups", "externalId"] {
            o.remove(k);
        }
        if kind == Kind::Group {
            let m: Vec<Value> = members
                .iter()
                .map(|(_, remote)| json!({ "value": remote }))
                .collect();
            if m.is_empty() {
                o.remove("members");
            } else {
                o.insert(String::from("members"), Value::Array(m));
            }
        }
    }
    v
}

fn retryable(r: Option<&Reply>) -> bool {
    r.is_none_or(|r| r.status == 429 || r.status >= 500)
}

impl<S: Sender, K: Secrets, L: Local> Worker<S, K, L> {
    async fn target(
        &self,
        tenant: TenantId,
        realm: RealmId,
        name: &str,
    ) -> Result<Option<TargetRow>, access_store::StoreError> {
        let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
        let x = access_store::scim::targets(&mut t)
            .await?
            .into_iter()
            .find(|x| x.name == name && x.live);
        t.commit().await?;
        Ok(x)
    }

    async fn links(
        &self,
        tenant: TenantId,
        realm: RealmId,
        p: &Push,
        members: &[[u8; 16]],
    ) -> Result<(Option<String>, Vec<(String, String)>), access_store::StoreError> {
        let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
        let own = access_store::scim::link(&mut t, &p.target, kind_name(p.kind), p.local).await?;
        let mut linked = Vec::new();
        for m in members {
            if let Some(r) = access_store::scim::link(&mut t, &p.target, "user", *m).await? {
                linked.push((id_text(m), r));
            }
        }
        t.commit().await?;
        Ok((own, linked))
    }

    /// Pushes one order and logs the answer; `true` when it is done or failed for good.
    ///
    /// # Errors
    /// [`access_store::StoreError`].
    pub async fn push(
        &self,
        tenant: TenantId,
        realm: RealmId,
        p: &Push,
    ) -> Result<(), access_store::StoreError> {
        let Some(target) = self.target(tenant, realm, &p.target).await? else {
            return Ok(());
        };
        let id = crate::app::clients::target_id(&target.name);
        let Some(secret) = self.secrets.open(tenant, realm, &id, &target.secret) else {
            return self.log(tenant, realm, p, None, "failed").await;
        };
        let local = self.local.read(tenant, realm, p).await;
        let members: Vec<[u8; 16]> = local
            .as_ref()
            .and_then(|v| v.get("members"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.get("value").and_then(Value::as_str).and_then(parse_id))
                    .collect()
            })
            .unwrap_or_default();
        let (remote, linked) = self.links(tenant, realm, p, &members).await?;
        let base = target.base_url.trim_end_matches('/');
        let endpoint = format!("{base}/{}", p.kind.endpoint());
        let reply = match (p.operation, &remote, local) {
            (Operation::Delete, Some(r), _) => {
                self.sender
                    .send("DELETE", &format!("{endpoint}/{r}"), &secret, None)
                    .await
            }
            (Operation::Delete, None, _) | (_, _, None) => {
                return self.log(tenant, realm, p, None, "done").await;
            }
            (op, remote, Some(v)) => {
                let mut body = outbound_body(p.kind, v, &linked);
                if op == Operation::Deactivate
                    && let Some(o) = body.as_object_mut()
                {
                    o.insert(String::from("active"), Value::Bool(false));
                }
                if let Some(o) = body.as_object_mut() {
                    o.insert(String::from("externalId"), Value::from(id_text(&p.local)));
                }
                let bytes = serde_json::to_vec(&body).unwrap_or_default();
                match remote {
                    Some(r) => {
                        self.sender
                            .send("PUT", &format!("{endpoint}/{r}"), &secret, Some(&bytes))
                            .await
                    }
                    None => {
                        self.sender
                            .send("POST", &endpoint, &secret, Some(&bytes))
                            .await
                    }
                }
            }
        };
        if remote.is_none()
            && let Some(r) = &reply
            && r.status == 201
            && let Some(rid) = serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_owned))
            && (1..=256).contains(&rid.len())
        {
            let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
            access_store::scim::put_link(&mut t, &p.target, kind_name(p.kind), p.local, &rid)
                .await?;
            t.commit().await?;
        }
        let outcome = match &reply {
            Some(r)
                if (200..300).contains(&r.status)
                    || (p.operation == Operation::Delete && r.status == 404) =>
            {
                "done"
            }
            r if retryable(r.as_ref()) && p.attempt < MAX_ATTEMPTS => "retry",
            _ => "failed",
        };
        self.log(tenant, realm, p, reply.map(|r| r.status), outcome)
            .await
    }

    async fn log(
        &self,
        tenant: TenantId,
        realm: RealmId,
        p: &Push,
        status: Option<u16>,
        outcome: &str,
    ) -> Result<(), access_store::StoreError> {
        let mut t = TenantTx::begin(&self.app, tenant, realm).await?;
        access_store::scim::log_push(
            &mut t,
            &PushLog {
                target: &p.target,
                kind: kind_name(p.kind),
                local: p.local,
                operation: p.operation.name(),
                status,
                outcome,
                attempt: u32::from(p.attempt),
            },
        )
        .await?;
        if outcome == "retry" {
            let next = Push {
                attempt: p.attempt.saturating_add(1),
                ..p.clone()
            };
            t.outbox(OUTBOX_KIND, &next.to_bytes()).await?;
        }
        t.commit().await
    }

    /// Pushes the queued orders after the cursor.
    ///
    /// # Errors
    /// [`access_store::StoreError`].
    pub async fn step(&self) -> Result<u32, access_store::StoreError> {
        let mut at = cursor(&self.reader, CONSUMER).await?;
        let mut n = 0_u32;
        for e in poll(&self.reader, at, 64).await? {
            if e.kind == OUTBOX_KIND
                && let Some(p) = Push::from_bytes(&e.payload)
            {
                self.push(e.tenant, e.realm, &p).await?;
                n = n.saturating_add(1);
            }
            at = Cursor {
                xid: e.xid,
                id: e.id,
            };
            ack(&self.reader, CONSUMER, at).await?;
        }
        Ok(n)
    }

    /// Steps every `every` until `stop` turns true.
    pub async fn run(&self, every: std::time::Duration, stop: &tokio::sync::watch::Receiver<bool>) {
        let mut stop = stop.clone();
        loop {
            if let Err(error) = self.step().await {
                tracing::warn!(%error, "scim outbound step failed");
            }
            let _ = tokio::time::timeout(every, stop.changed()).await;
            if *stop.borrow() {
                return;
            }
        }
    }
}

const fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::User => "user",
        Kind::Group | Kind::Device => "group",
    }
}
