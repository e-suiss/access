//! The realm's Linux client in access-server (OP-156 m.3 (p), IDP-32, MD-8).
//!
//! A host is a live `idp.linux.host_register` row named by its client certificate. Who may sign
//! in to it is derived, never stored: every principal of a live `ssh.login` Grant held by name
//! on the host's server group. NSS ids are handed out once per name and never reused. A console
//! sign-in is allowed when the person the access token names holds such a Grant naming the user
//! without a constraint only `sshd` enforces; a `sudo` step-up also needs a sign-in in the last
//! five minutes at the host's tier (CT2: phishing resistant and user verifying; CT3: also
//! device-bound and non-custodial). Push and passwords never reach a tier (IDP-8).

use std::collections::BTreeMap;

use access_http::linux::{LinuxFront, LinuxReply};
use access_http::problem::codes::realm as r;
use access_identity_oauth::app::oauth::RealmHolder;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::domain::assurance::AssuranceVector;
use access_identity_ssh::domain::projection::grant_principals;
use access_identity_ssh::domain::schema::{self, FORCE_COMMAND, SOURCE_ADDRESS};
use access_identity_webauthn::domain::cose::CoseKey;
use access_internal_api::linux::{LinuxGrants, Member};
use access_internal_api::ssh::SshGrants;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::{CanonicalAuthority, Id, ResourceSelector};
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::identity::TenantTx;
use access_store::linux::LinuxHostRow;
use serde_json::{Value, json};

/// The host's horizon past the snapshot: the CT1 `online-strict` ceiling (OP-156 m.12 (b)).
pub(crate) const HORIZON_MS: u64 = 24 * 3_600_000;

/// How recent the sign-in behind a `sudo` step-up must be.
pub(crate) const STEP_UP_MS: u64 = 5 * 60_000;

/// Most Grants one snapshot reads.
const MEMBERS: u32 = 1000;

/// Whether `name` is a Linux name the channel carries: `[a-z_][a-z0-9_-]{0,31}`.
fn linux_name(name: &str) -> bool {
    let mut b = name.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == b'_')
        && name.len() <= 32
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// Whether the Grant may sign in at a console: it carries no constraint only `sshd` enforces.
fn console_ok(a: &CanonicalAuthority) -> bool {
    !a.authority.params.contains_key(FORCE_COMMAND)
        && !a.authority.params.contains_key(SOURCE_ADDRESS)
}

fn covers_group(selector: &ResourceSelector, group: &str) -> bool {
    access_kernel::algebra::resource_le(
        &ResourceSelector::Exact(schema::host_group(group)),
        selector,
    )
}

fn in_force(a: &CanonicalAuthority, now: u64) -> bool {
    let w = &a.constraints.validity;
    w.from <= now && now < w.until
}

/// Whether the session reaches the host's `sudo` tier (IDP-8, §13.7.3).
fn reaches(v: &AssuranceVector, ct: u8) -> bool {
    let ct2 = v.phishing_resistant && v.uv && !v.app_controlled_factor;
    match ct {
        2 => ct2,
        3 => ct2 && v.hardware_bound && v.non_custodial && !v.synced,
        _ => false,
    }
}

/// One user as the snapshot serves them.
struct Entry {
    until_ms: u64,
    console: bool,
}

/// The Linux client over the application pool and the authority plane in this process.
pub(crate) struct Linux<P> {
    app: Pool,
    plane: P,
}

fn unavailable<T: core::fmt::Display>(e: T) -> LinuxReply {
    tracing::warn!(error = %e, "linux client unavailable");
    LinuxReply::Unavailable
}

impl<P> Linux<P>
where
    P: LinuxGrants + SshGrants + Send + Sync + 'static,
{
    pub(crate) const fn new(app: Pool, plane: P) -> Self {
        Self { app, plane }
    }

    async fn begin(&self, realm: &RealmEntry) -> Result<(TenantTx, u64), String> {
        let now = access_store::authority::server_time(&self.app)
            .await
            .map_err(|e| e.to_string())?;
        let t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(|e| e.to_string())?;
        Ok((t, now))
    }

    /// The live host the certificate names and the realm's domain.
    async fn host(
        t: &mut TenantTx,
        certificate: &str,
    ) -> Result<Option<(LinuxHostRow, Digest)>, String> {
        let Some(host) = t
            .linux_host_by_certificate(certificate)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let Some(g) = access_store::idp::governance(t)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        Ok(Some((host, Digest(*g.domain.as_bytes()))))
    }

    async fn snapshot(&self, realm: &RealmEntry, certificate: &str) -> Result<LinuxReply, String> {
        let (mut t, now) = self.begin(realm).await?;
        let Some((host, domain)) = Self::host(&mut t, certificate).await? else {
            return Ok(LinuxReply::Refused(&r::LINUX_HOST_UNKNOWN));
        };
        let group_live = t
            .ssh_host_groups()
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .any(|g| g.name == host.host_group && g.live);
        let members = if group_live {
            LinuxGrants::members(
                &self.plane,
                domain,
                schema::login_ref(),
                schema::host_group(&host.host_group),
                MEMBERS,
            )
            .await
            .map_err(|e| e.0)?
        } else {
            Vec::new()
        };
        let mut users: BTreeMap<String, Entry> = BTreeMap::new();
        for Member { authority, .. } in &members {
            if !in_force(authority, now) {
                continue;
            }
            let Ok(principals) = grant_principals(authority) else {
                continue;
            };
            let console = console_ok(authority);
            for p in principals.into_iter().filter(|p| linux_name(p)) {
                let e = users.entry(p).or_insert(Entry {
                    until_ms: 0,
                    console: false,
                });
                e.until_ms = e.until_ms.max(authority.constraints.validity.until);
                e.console |= console;
            }
        }
        let gid = t
            .linux_id("group", &host.host_group)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("linux id taken")?;
        let mut out = Vec::new();
        for (name, e) in &users {
            let uid = t
                .linux_id("user", name)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("linux id taken")?;
            out.push(json!({
                "name": name,
                "uid": uid,
                "gid": gid,
                "dir": format!("/home/{name}"),
                "shell": host.shell,
                "until_ms": e.until_ms,
                "console": e.console,
            }));
        }
        t.commit().await.map_err(|e| e.to_string())?;
        let groups = if linux_name(&host.host_group) {
            vec![
                json!({ "name": host.host_group, "gid": gid, "members": users.keys().collect::<Vec<_>>() }),
            ]
        } else {
            Vec::new()
        };
        Ok(LinuxReply::Ok(json!({
            "now_ms": now,
            "horizon_ms": now.saturating_add(HORIZON_MS),
            "nss_ttl_s": host.nss_ttl_s,
            "console_ttl_s": host.console_ttl_s,
            "users": out,
            "groups": groups,
        })))
    }

    /// Whether the person's Party holds a live console-capable `ssh.login` Grant naming `user`
    /// on the host's server group.
    async fn granted(
        &self,
        domain: Digest,
        party: Id,
        host: &LinuxHostRow,
        user: &str,
        now: u64,
    ) -> Result<bool, String> {
        let held = SshGrants::holdings(&self.plane, domain, party, schema::login_ref())
            .await
            .map_err(|e| e.0)?;
        Ok(held.iter().any(|h| {
            let a = &h.authority;
            in_force(a, now)
                && console_ok(a)
                && covers_group(&a.authority.resource, &host.host_group)
                && grant_principals(a).is_ok_and(|p| p.contains(user))
        }))
    }

    async fn credentials(
        t: &mut TenantTx,
        realm: &RealmEntry,
        subject: &[u8; 16],
    ) -> Result<Vec<Value>, String> {
        let Some(handle) = t.user_handle(*subject).await.map_err(|e| e.to_string())? else {
            return Ok(Vec::new());
        };
        let rp_id = access_store::idp::settings(t)
            .await
            .map_err(|e| e.to_string())?
            .and_then(|s| s.rp_id)
            .unwrap_or_else(|| {
                String::from(
                    realm
                        .issuer
                        .authority()
                        .split(':')
                        .next()
                        .unwrap_or_default(),
                )
            });
        let mut out = Vec::new();
        for p in t.passkeys(&handle).await.map_err(|e| e.to_string())? {
            if p.deleted_s.is_some() || p.backup_eligible {
                continue;
            }
            let (alg, key) = match CoseKey::from_bytes(&p.public_key) {
                Ok(CoseKey::P256 { point, .. }) => (-7, point.to_vec()),
                Ok(CoseKey::Ed25519 { x, .. }) => (-8, x.to_vec()),
                _ => continue,
            };
            out.push(json!({
                "id": b64url_encode(&p.raw_id),
                "alg": alg,
                "public_key": b64url_encode(&key),
                "rp_id": rp_id,
                "sign_count": u32::try_from(p.sign_count).unwrap_or(0),
            }));
        }
        Ok(out)
    }

    async fn decide(
        &self,
        realm: &RealmEntry,
        certificate: &str,
        holder: &RealmHolder,
        body: &Value,
        sudo: bool,
    ) -> Result<LinuxReply, String> {
        let user = body
            .get("user")
            .and_then(Value::as_str)
            .filter(|u| linux_name(u));
        let keys_ok = body
            .as_object()
            .is_some_and(|m| m.keys().all(|k| k == "user" || (sudo && k == "command")));
        let command = body
            .get("command")
            .and_then(Value::as_str)
            .and_then(|c| b64url_decode(c).ok())
            .filter(|c| c.len() == 32);
        let (Some(user), true) = (user, keys_ok) else {
            return Ok(LinuxReply::Refused(&r::INVALID_LINUX_REQUEST));
        };
        if sudo && command.is_none() {
            return Ok(LinuxReply::Refused(&r::INVALID_LINUX_REQUEST));
        }
        let (mut t, now) = self.begin(realm).await?;
        let Some((host, domain)) = Self::host(&mut t, certificate).await? else {
            return Ok(LinuxReply::Refused(&r::LINUX_HOST_UNKNOWN));
        };
        let party = access_store::idp::subject_party(&mut t, &holder.subject)
            .await
            .map_err(|e| e.to_string())?;
        let allowed = match party {
            Some(p) => self.granted(domain, Id(p), &host, user, now).await?,
            None => false,
        };
        let target = format!("{}:{user}", host.name);
        let step_up = !sudo
            || (now.saturating_sub(holder.auth_time_ms) <= STEP_UP_MS
                && holder
                    .assurance
                    .as_ref()
                    .is_some_and(|v| reaches(v, host.sudo_ct)));
        let actor = b64url_encode(&holder.subject);
        let ok = allowed && step_up;
        t.audit(&AuditEvent {
            event_type: match (ok, sudo) {
                (true, false) => "linux.signin",
                (true, true) => "linux.sudo",
                (false, _) => "linux.signin_failed",
            },
            actor: &actor,
            target: &target,
            correlation: "-",
        })
        .await
        .map_err(|e| e.to_string())?;
        let credentials = if allowed && !sudo {
            Self::credentials(&mut t, realm, &holder.subject).await?
        } else {
            Vec::new()
        };
        t.commit().await.map_err(|e| e.to_string())?;
        if allowed && !step_up {
            return Ok(LinuxReply::Refused(&r::LINUX_STEP_UP));
        }
        Ok(LinuxReply::Ok(json!({
            "outcome": if allowed { "allow" } else { "deny" },
            "credentials": credentials,
        })))
    }
}

impl<P> LinuxFront for Linux<P>
where
    P: LinuxGrants + SshGrants + Send + Sync + 'static,
{
    async fn nss(&self, realm: &RealmEntry, host: &str) -> LinuxReply {
        self.snapshot(realm, host).await.unwrap_or_else(unavailable)
    }

    async fn sign_in(
        &self,
        realm: &RealmEntry,
        host: &str,
        holder: RealmHolder,
        body: Value,
    ) -> LinuxReply {
        self.decide(realm, host, &holder, &body, false)
            .await
            .unwrap_or_else(unavailable)
    }

    async fn sudo(
        &self,
        realm: &RealmEntry,
        host: &str,
        holder: RealmHolder,
        body: Value,
    ) -> LinuxReply {
        self.decide(realm, host, &holder, &body, true)
            .await
            .unwrap_or_else(unavailable)
    }
}
