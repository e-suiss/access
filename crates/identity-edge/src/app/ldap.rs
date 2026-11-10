//! The LDAP gateway's calls (§10.6.3, IDP-16, OP-155 m.3 (n)): `authenticate` and
//! `directory_read`. Every call stays in the gateway's realm (IDP-26). Only the LDAP credential
//! class binds, never the primary password; SASL EXTERNAL runs the realm's certificate sign-in
//! rules (§10.2.5). A bind gets a handle and a search page a cookie, both MAC'd with the realm's
//! index key, so neither can be forged or carried to another gateway or another search.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::app::Realm;
use access_identity_account::app::hasher::Hasher;
use access_identity_account::app::ldap::{self, Context};
use access_identity_account::app::vault::Vault;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::ports::{AccountDb as _, AccountTx as _, Clock, Entropy};
use access_identity_x509::app::Revocation;
use access_identity_x509::domain::cert::Cert;
use access_identity_x509::domain::login::{Rule, ca_issuer, identifier};
use access_identity_x509::domain::path::verify;
use access_identity_x509::ports::CaTrust;
use access_internal_api::edge::ldap::{
    Authenticate, Authenticated, DirectoryPage, DirectoryRead, MAX_DIRECTORY_BODY, MAX_ITEMS,
    MAX_RESULTS, Mechanism, Outcome,
};
use access_store::Pool;
use access_store::audit::AuditEvent;

use crate::EdgeError;
use crate::domain::directory::{
    Dn, Group, Person, Selection, Tree, Truth, group_uuid, in_scope, matches, narrowing, person_dn,
};
use crate::domain::{self, Gateway, Refusal};
use crate::ports::Vaults;

/// How long a bind handle holds.
pub const BIND_TTL_MS: u64 = 8 * 60 * 60 * 1000;

/// How long a paging cookie holds (OP-155 m.3 (n)).
pub const COOKIE_TTL_MS: u64 = 10 * 60 * 1000;

/// Longest a search may take (OP-155 m.3 (n)).
pub const TIME_LIMIT: Duration = Duration::from_secs(10);

/// Most accounts one directory tree holds.
pub const MAX_PEOPLE: i64 = 20_000;

/// Bytes of one answer the entries may take; the rest is the map around them.
const ENTRY_BUDGET: usize = MAX_DIRECTORY_BODY.saturating_sub(4096);

const BIND_CREDENTIAL: u8 = 1;
const BIND_CERTIFICATE: u8 = 2;

/// What SASL EXTERNAL needs: revocation with its kept answers, and the governing domain's CA
/// Acceptances (§10.2.5).
pub struct Certificates {
    /// Revocation checking.
    pub revocation: Arc<Revocation>,
    /// The governing domain's CA Acceptances.
    pub trust: Arc<dyn CaTrust>,
}

/// The LDAP calls over the realms' account tables.
pub struct Ldap<V> {
    vaults: V,
    app: Pool,
    hasher: Arc<Hasher>,
    entropy: Arc<dyn Entropy + Send + Sync>,
    clock: Arc<dyn Clock + Send + Sync>,
    ids: Arc<IdKey>,
    certificates: Option<Certificates>,
}

impl<V> core::fmt::Debug for Ldap<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ldap").finish_non_exhaustive()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

fn be64(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(<[u8; 8]>::try_from(b).ok()?))
}

/// The opened bind handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handle {
    kind: u8,
    subject: [u8; 16],
    credential: [u8; 16],
}

impl<V: Vaults> Ldap<V> {
    /// The service. `ids` names subjects in notices; `certificates` is `None` when this process
    /// does not check client certificates, and SASL EXTERNAL then binds nobody.
    #[must_use]
    pub fn new(
        vaults: V,
        app: Pool,
        (hasher, entropy, clock): (
            Arc<Hasher>,
            Arc<dyn Entropy + Send + Sync>,
            Arc<dyn Clock + Send + Sync>,
        ),
        ids: Arc<IdKey>,
        certificates: Option<Certificates>,
    ) -> Self {
        Self {
            vaults,
            app,
            hasher,
            entropy,
            clock,
            ids,
            certificates,
        }
    }

    fn vault(&self, g: &Gateway) -> Result<Vault, EdgeError> {
        self.vaults
            .vault(g.tenant, g.realm)
            .ok_or_else(|| EdgeError::Unavailable(String::from("vault")))
    }

    async fn begin(&self, g: &Gateway) -> Result<PgTx, EdgeError> {
        Ok(PgAccounts::sealed(self.app.clone(), self.vault(g)?)
            .begin(g.tenant, g.realm)
            .await?)
    }

    fn mac(&self, g: &Gateway, label: &str, parts: &[&[u8]]) -> Result<[u8; 32], EdgeError> {
        let mut m = Vec::new();
        for p in parts {
            m.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
            m.extend_from_slice(p);
        }
        let text = format!("access/ldap/{label}/v1:{}", hex(&m));
        self.vault(g)?
            .index_of(g.tenant.as_bytes(), g.realm.as_bytes(), &text)
            .map_err(|_| EdgeError::Unavailable(String::from("vault")))
    }

    fn handle(&self, g: &Gateway, h: Handle, now: u64) -> Result<Vec<u8>, EdgeError> {
        let expires = now.saturating_add(BIND_TTL_MS).to_be_bytes();
        let nonce = self
            .entropy
            .salt()
            .map_err(|_| EdgeError::Unavailable(String::from("random")))?;
        let uri = g.uri.uri();
        let tag = self.mac(
            g,
            "bind",
            &[
                uri.as_bytes(),
                &[h.kind],
                &h.subject,
                &h.credential,
                &expires,
                &nonce,
            ],
        )?;
        let mut out = vec![1, h.kind];
        for p in [&h.subject[..], &h.credential, &expires, &nonce, &tag] {
            out.extend_from_slice(p);
        }
        Ok(out)
    }

    fn open_handle(&self, g: &Gateway, b: &[u8], now: u64) -> Result<Handle, EdgeError> {
        let bad = || EdgeError::Refused(Refusal::Bind);
        if b.len() != 90 || b.first() != Some(&1) {
            return Err(bad());
        }
        let kind = *b.get(1).ok_or_else(bad)?;
        let subject = <[u8; 16]>::try_from(b.get(2..18).ok_or_else(bad)?).map_err(|_| bad())?;
        let credential = <[u8; 16]>::try_from(b.get(18..34).ok_or_else(bad)?).map_err(|_| bad())?;
        let expires = b.get(34..42).ok_or_else(bad)?;
        let nonce = b.get(42..58).ok_or_else(bad)?;
        let tag = b.get(58..90).ok_or_else(bad)?;
        let uri = g.uri.uri();
        let want = self.mac(
            g,
            "bind",
            &[
                uri.as_bytes(),
                &[kind],
                &subject,
                &credential,
                expires,
                nonce,
            ],
        )?;
        if !access_crypto::Secret::new(want).ct_eq_bytes(tag)
            || be64(expires).is_none_or(|e| e <= now)
        {
            return Err(bad());
        }
        Ok(Handle {
            kind,
            subject,
            credential,
        })
    }

    async fn uid_of(&self, tx: &mut PgTx, subject: [u8; 16]) -> Result<Option<String>, EdgeError> {
        let people = self.people(tx, Some(subject)).await?;
        Ok(people.into_iter().next().map(|p| p.uid))
    }

    async fn people(
        &self,
        tx: &mut PgTx,
        only: Option<[u8; 16]>,
    ) -> Result<Vec<Person>, EdgeError> {
        let rows = tx.0.directory_identifiers(only, MAX_PEOPLE).await?;
        let mut by: BTreeMap<[u8; 16], (Option<String>, Option<String>)> = BTreeMap::new();
        for r in rows {
            let Some(value) = tx.reveal(r.subject, &r.stored).await? else {
                continue;
            };
            let slot = by.entry(r.subject).or_default();
            match r.kind.as_str() {
                "username" if slot.0.is_none() => slot.0 = Some(value),
                "email" if slot.1.is_none() => slot.1 = Some(value),
                _ => {}
            }
        }
        Ok(by
            .into_iter()
            .filter_map(|(subject, (user, mail))| {
                let uid = user.or_else(|| mail.clone())?;
                Some(Person { subject, uid, mail })
            })
            .collect())
    }

    async fn audit(
        tx: &mut PgTx,
        g: &Gateway,
        event_type: &'static str,
        subject: Option<[u8; 16]>,
    ) -> Result<(), EdgeError> {
        let actor = g.uri.uri();
        let target = subject.map_or_else(|| String::from("unknown"), |s| hex(&s));
        tx.audit(&AuditEvent {
            event_type,
            actor: &actor,
            target: &target,
            correlation: &g.uri.name,
        })
        .await?;
        Ok(())
    }

    /// `authenticate`: one LDAP bind (§10.6.3). A simple bind needs an LDAP credential, as
    /// `dn=token` or under its holder's DN; SASL EXTERNAL needs a client certificate the realm's
    /// certificate sign-in accepts. An unknown name and a wrong secret answer the same.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn authenticate(
        &self,
        g: &Gateway,
        q: &Authenticate,
    ) -> Result<Authenticated, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        match q.mechanism {
            Mechanism::Simple => self.simple(g, q).await,
            Mechanism::External => self.external(g, q).await,
        }
    }

    async fn simple(&self, g: &Gateway, q: &Authenticate) -> Result<Authenticated, EdgeError> {
        let name = q.name.as_deref().unwrap_or_default();
        let token = q
            .secret
            .as_deref()
            .and_then(|s| core::str::from_utf8(s).ok())
            .unwrap_or_default();
        let named = if name.trim().eq_ignore_ascii_case("dn=token") {
            None
        } else {
            match person_uid(&g.slug, name) {
                Some(uid) => Some(uid),
                None => return Ok(Authenticated::default()),
            }
        };
        let mut tx = self.begin(g).await?;
        let bound = ldap::verify(&mut tx, &self.hasher, token).await?;
        let bound = match (bound, named) {
            (Some(b), Some(uid)) => {
                let holder = tx.subject_by_identifier(&uid).await?;
                (holder == Some(b.subject)).then_some(b)
            }
            (b, None) => b,
            (None, Some(_)) => None,
        };
        let Some(bound) = bound else {
            Self::audit(&mut tx, g, "login.ldap.failed", None).await?;
            tx.commit().await?;
            return Ok(Authenticated::default());
        };
        let now = tx.server_time().await?;
        let secret = if q.rotate {
            let realm = Realm {
                tenant: g.tenant,
                realm: g.realm,
                kek: &*self.vault(g)?.kek,
                ids: &self.ids,
            };
            let notifier = OutboxNotifier::new(&realm, &*self.entropy, &*self.clock);
            let actor = g.uri.uri();
            let cx = Context {
                actor: &actor,
                correlation: &g.uri.name,
                at_ms: now,
            };
            let rotated =
                ldap::rotate(&mut tx, &self.hasher, &*self.entropy, &notifier, bound, cx).await?;
            let Ok(issued) = rotated else {
                tx.commit().await?;
                return Ok(Authenticated::default());
            };
            Some(issued.token.expose().as_bytes().to_vec())
        } else {
            None
        };
        self.bound(
            g,
            tx,
            Handle {
                kind: BIND_CREDENTIAL,
                subject: bound.subject,
                credential: bound.credential,
            },
            now,
            secret,
        )
        .await
    }

    async fn bound(
        &self,
        g: &Gateway,
        mut tx: PgTx,
        h: Handle,
        now: u64,
        secret: Option<Vec<u8>>,
    ) -> Result<Authenticated, EdgeError> {
        let Some(uid) = self.uid_of(&mut tx, h.subject).await? else {
            Self::audit(&mut tx, g, "login.ldap.failed", Some(h.subject)).await?;
            tx.commit().await?;
            return Ok(Authenticated::default());
        };
        Self::audit(&mut tx, g, "login.ldap.succeeded", Some(h.subject)).await?;
        tx.commit().await?;
        Ok(Authenticated {
            subject: Some(h.subject),
            bind: Some(self.handle(g, h, now)?),
            dn: Some(person_dn(&g.slug, &uid).text()),
            secret,
        })
    }

    async fn external(&self, g: &Gateway, q: &Authenticate) -> Result<Authenticated, EdgeError> {
        let mut tx = self.begin(g).await?;
        let refused = |mut tx: PgTx| async move {
            Self::audit(&mut tx, g, "login.ldap.failed", None).await?;
            tx.commit().await?;
            Ok::<_, EdgeError>(Authenticated::default())
        };
        let Some(certs) = &self.certificates else {
            return refused(tx).await;
        };
        let setting = tx.0.certificate_login().await?.filter(|r| r.enabled);
        let domain = access_store::idp::governance(&mut tx.0)
            .await?
            .map(|d| *d.domain.as_bytes());
        let (Some(setting), Some(domain)) = (setting, domain) else {
            return refused(tx).await;
        };
        let Some(rule) = Rule::parse(&setting.rule) else {
            return refused(tx).await;
        };
        let now = tx.server_time().await?;
        let Ok(path) = verify(&q.chain, &setting.anchors, now / 1000) else {
            return refused(tx).await;
        };
        let Some(Ok(issuer)) = setting.anchors.get(path.anchor).map(|a| ca_issuer(a)) else {
            return refused(tx).await;
        };
        if !certs
            .trust
            .accepted(domain, issuer)
            .await
            .map_err(|_| EdgeError::Unavailable(String::from("acceptance")))?
        {
            return refused(tx).await;
        }
        // MD-8
        if certs
            .revocation
            .check(&path, &setting.anchors, now / 1000)
            .await
            .is_err()
        {
            return refused(tx).await;
        }
        let Ok(leaf) = Cert::parse(path.leaf()) else {
            return refused(tx).await;
        };
        let Ok(id) = identifier(&leaf, rule) else {
            return refused(tx).await;
        };
        let Some(subject) = tx.subject_by_identifier(&id).await? else {
            return refused(tx).await;
        };
        if !live(&mut tx, subject).await? {
            return refused(tx).await;
        }
        self.bound(
            g,
            tx,
            Handle {
                kind: BIND_CERTIFICATE,
                subject,
                credential: [0; 16],
            },
            now,
            None,
        )
        .await
    }

    /// `directory_read`: one page of a search of the realm's tree on behalf of a live bind
    /// (§10.6.3). A paging cookie belongs to its search and lives 10 minutes; the search returns
    /// at most 5000 entries and takes at most 10 s.
    ///
    /// # Errors
    /// [`EdgeError`]; [`Refusal::Bind`] for a forged, expired or dead bind,
    /// [`Refusal::Cookie`] for a cookie of another search, tampered or expired.
    pub async fn directory_read(
        &self,
        g: &Gateway,
        q: &DirectoryRead,
    ) -> Result<DirectoryPage, EdgeError> {
        domain::in_scope(g, &q.realm)?;
        match tokio::time::timeout(TIME_LIMIT, self.read(g, q)).await {
            Ok(page) => page,
            Err(_) => Ok(DirectoryPage {
                entries: Vec::new(),
                outcome: Outcome::TimeLimit,
                cookie: None,
            }),
        }
    }

    fn digest(h: &Handle, q: &DirectoryRead) -> [u8; 32] {
        let mut m = Vec::new();
        m.extend_from_slice(&h.subject);
        m.extend_from_slice(q.base.as_bytes());
        m.push(0);
        m.extend_from_slice(q.scope.name().as_bytes());
        m.push(0);
        m.extend_from_slice(&q.filter.encode());
        for a in &q.attributes {
            m.extend_from_slice(a.as_bytes());
            m.push(0);
        }
        m.push(u8::from(q.types_only));
        m.extend_from_slice(&q.size_limit.to_be_bytes());
        suiss_crypto::digest::sha256(&m)
    }

    fn cookie(
        &self,
        g: &Gateway,
        digest: &[u8; 32],
        position: u32,
        now: u64,
    ) -> Result<Vec<u8>, EdgeError> {
        let expires = now.saturating_add(COOKIE_TTL_MS).to_be_bytes();
        let nonce = self
            .entropy
            .salt()
            .map_err(|_| EdgeError::Unavailable(String::from("random")))?;
        let pos = position.to_be_bytes();
        let tag = self.mac(g, "cookie", &[digest, &pos, &expires, &nonce])?;
        let mut out = vec![1];
        for p in [&pos[..], &expires, &nonce, &tag] {
            out.extend_from_slice(p);
        }
        Ok(out)
    }

    fn open_cookie(
        &self,
        g: &Gateway,
        digest: &[u8; 32],
        c: &[u8],
        now: u64,
    ) -> Result<u32, EdgeError> {
        let bad = || EdgeError::Refused(Refusal::Cookie);
        if c.len() != 61 || c.first() != Some(&1) {
            return Err(bad());
        }
        let pos = c.get(1..5).ok_or_else(bad)?;
        let expires = c.get(5..13).ok_or_else(bad)?;
        let nonce = c.get(13..29).ok_or_else(bad)?;
        let tag = c.get(29..61).ok_or_else(bad)?;
        let want = self.mac(g, "cookie", &[digest, pos, expires, nonce])?;
        if !access_crypto::Secret::new(want).ct_eq_bytes(tag)
            || be64(expires).is_none_or(|e| e <= now)
        {
            return Err(bad());
        }
        Ok(u32::from_be_bytes(
            <[u8; 4]>::try_from(pos).map_err(|_| bad())?,
        ))
    }

    async fn read(&self, g: &Gateway, q: &DirectoryRead) -> Result<DirectoryPage, EdgeError> {
        let mut tx = self.begin(g).await?;
        let now = tx.server_time().await?;
        let handle = self.open_handle(g, &q.bind, now)?;
        let alive = live(&mut tx, handle.subject).await?
            && (handle.kind != BIND_CREDENTIAL
                || tx
                    .0
                    .ldap_credential_active(handle.subject, handle.credential)
                    .await?);
        if !alive {
            return Err(Refusal::Bind.into());
        }
        let digest = Self::digest(&handle, q);
        let position = match &q.cookie {
            Some(c) => self.open_cookie(g, &digest, c, now)?,
            None => 0,
        };
        let none = DirectoryPage {
            entries: Vec::new(),
            outcome: Outcome::NoSuchObject,
            cookie: None,
        };
        let Some(base) = Dn::parse(&q.base) else {
            return Ok(none);
        };
        let suffix = crate::domain::directory::suffix(&g.slug);
        if !base.under(&suffix) {
            return Ok(none);
        }
        let tree = self.tree(g, tx, &q.filter).await?;
        if !tree.has(&base) {
            return Ok(none);
        }
        self.page(g, q, &tree, &base, (&digest, position, now))
    }

    async fn tree(
        &self,
        g: &Gateway,
        mut tx: PgTx,
        filter: &access_internal_api::edge::ldap::Filter,
    ) -> Result<Tree, EdgeError> {
        let people = match narrowing(filter) {
            Some(v) => match tx.subject_by_identifier(&v).await? {
                Some(s) => self.people(&mut tx, Some(s)).await?,
                None => Vec::new(),
            },
            None => self.people(&mut tx, None).await?,
        };
        let members = tx.0.directory_members().await?;
        let groups =
            tx.0.directory_groups()
                .await?
                .into_iter()
                .map(|r| Group {
                    uuid: group_uuid(g.tenant.as_bytes(), g.realm.as_bytes(), &r.name),
                    members: members
                        .iter()
                        .filter(|(n, _)| *n == r.name)
                        .map(|(_, s)| *s)
                        .collect(),
                    name: r.name,
                    display_name: r.display_name,
                })
                .collect::<Vec<_>>();
        tx.commit().await?;
        Ok(Tree::build(&g.slug, &people, &groups))
    }

    fn page(
        &self,
        g: &Gateway,
        q: &DirectoryRead,
        tree: &Tree,
        base: &Dn,
        (digest, position, now): (&[u8; 32], u32, u64),
    ) -> Result<DirectoryPage, EdgeError> {
        let selection = Selection::new(&q.attributes, q.types_only);
        let hits: Vec<_> = tree
            .entries
            .iter()
            .filter(|e| in_scope(&e.dn, base, q.scope) && matches(e, &q.filter) == Truth::True)
            .collect();
        let limit = q.size_limit.min(MAX_RESULTS);
        let limit = if limit == 0 { MAX_RESULTS } else { limit };
        let start = usize::try_from(position).unwrap_or(usize::MAX);
        let room = usize::try_from(limit.saturating_sub(position)).unwrap_or(0);
        let want = room
            .min(usize::try_from(q.page_size).unwrap_or(0))
            .min(MAX_ITEMS);
        let mut entries = Vec::new();
        let mut bytes = 0_usize;
        for e in hits.iter().skip(start) {
            if entries.len() >= want {
                break;
            }
            let rendered = selection.render(e);
            let size = rendered
                .attributes
                .iter()
                .flat_map(|(n, v)| {
                    v.iter()
                        .map(move |x| x.len().saturating_add(n.len()).saturating_add(8))
                })
                .sum::<usize>()
                .saturating_add(rendered.dn.len());
            if !entries.is_empty() && bytes.saturating_add(size) > ENTRY_BUDGET {
                break;
            }
            bytes = bytes.saturating_add(size);
            entries.push(rendered);
        }
        let next = start.saturating_add(entries.len());
        let reached = next >= usize::try_from(limit).unwrap_or(usize::MAX);
        let more = next < hits.len();
        let (outcome, cookie) = if more && !reached {
            let pos = u32::try_from(next).unwrap_or(u32::MAX);
            (Outcome::Done, Some(self.cookie(g, digest, pos, now)?))
        } else if more && reached {
            (Outcome::SizeLimit, None)
        } else {
            (Outcome::Done, None)
        };
        Ok(DirectoryPage {
            entries,
            outcome,
            cookie,
        })
    }
}

async fn live(tx: &mut PgTx, subject: [u8; 16]) -> Result<bool, EdgeError> {
    Ok(tx
        .subject(subject, false)
        .await?
        .and_then(|s| AccountStatus::parse(&s.status))
        .is_some_and(AccountStatus::can_authenticate))
}

/// The uid a bind DN names: exactly `uid=<uid>,ou=people,o=<slug>`.
#[must_use]
pub fn person_uid(slug: &str, name: &str) -> Option<String> {
    let dn = Dn::parse(name)?;
    let [(t, uid), rest @ ..] = dn.0.as_slice() else {
        return None;
    };
    let parent = Dn(rest.to_vec());
    (t == "uid" && parent == person_dn(slug, "x").parent()).then(|| uid.clone())
}
