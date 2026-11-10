//! The one client resolver (IDP-1, IDI-10, OP-154 m.3 (i), OP-155 m.3 (j)): a local id is read
//! from the realm's registry; a URL id goes to OpenID Federation first when the realm is a
//! federation leaf, then to CIMD, and never to the local or DCR registry. A CIMD document is fetched
//! outside any transaction, through the guarded outbound client, checked, and kept as the
//! client's snapshot; a failure cancels the request and writes nothing (AG-4, §11.3.5).

use crate::domain::cimd::{
    self, ACCEPT, CimdError, LOGO_TYPES, MAX_DOCUMENT, MAX_LOGO, change, client_id_url,
    domain_admitted, keep_s, logo_bytes, logo_type,
};
use crate::domain::client::{CimdFacts, Client, ClientIdKind};
use crate::domain::request::Params;
use crate::ports::Unavailable;
use crate::ports::oauth::{FetchRefused, OAuthDb, OAuthTx};
use access_store::clients::{CimdRow, CimdSnapshot};

use super::{Env, OAuth, Realm, unsigned};

/// Why a URL `client_id` did not resolve; each is `invalid_client` and cancels the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// An OpenID Federation request (`trust_chain`) whose chain does not resolve, or a realm
    /// that is no federation leaf.
    Federation,
    /// The realm does not accept CIMD clients.
    Disabled,
    /// The URL's domain is not one the realm's policy admits (AS-A2).
    Domain,
    /// Not a Client Identifier URL.
    Url,
    /// The fetch was refused or got no answer.
    Fetch(FetchRefused),
    /// An answer other than `200`.
    Status,
    /// The document is refused.
    Document(CimdError),
}

/// The retire reason of a client the policy no longer admits.
const fn retire_reason(enabled: bool) -> &'static str {
    if enabled { "domain_policy" } else { "disabled" }
}

fn admitted(enabled: bool, domains: &[String], url: &str) -> bool {
    enabled && cimd::host(url).is_some_and(|h| domain_admitted(domains, &h))
}

/// The client a stored CIMD snapshot describes; `None` when the document no longer checks.
fn of_row(row: &CimdRow) -> Option<Client> {
    let doc = cimd::parse(&row.document, &row.client_id).ok()?;
    let facts = CimdFacts {
        metadata_hash: row.document_hash,
        first_seen_ms: unsigned(row.first_seen_ms),
        visual_changed_ms: row.visual_changed_ms.map(unsigned),
        logo: row.logo.is_some(),
        native: doc.application_type == cimd::ApplicationType::Native,
    };
    Some(Client::from_cimd(row.client_uuid, &doc, facts))
}

/// The `openid_relying_party` metadata a chain resolved, as the client document of `id`; `None`
/// when the chain has none or it does not check as a client document.
fn federated_metadata(c: &access_identity_oidf::Chain, id: &str) -> Option<String> {
    use access_kernel::json::Json;
    let Some(Json::Object(m)) = c.metadata_of("openid_relying_party") else {
        return None;
    };
    let mut m = m.clone();
    m.retain(|(k, _)| k != "client_id");
    m.push((String::from("client_id"), Json::Str(String::from(id))));
    let text = access_crypto::jose::output::to_string(&Json::Object(m));
    cimd::parse(text.as_bytes(), id).ok()?;
    Some(text)
}

/// The client a live OIDF snapshot describes (IDP-20: it still asks the person).
fn of_oidf(row: &access_store::oidf::OidfClientRow) -> Option<Client> {
    let doc = cimd::parse(&row.metadata, &row.client_id).ok()?;
    let facts = CimdFacts {
        metadata_hash: row.metadata_hash,
        first_seen_ms: row.first_seen_ms,
        visual_changed_ms: None,
        logo: false,
        native: doc.application_type == cimd::ApplicationType::Native,
    };
    let mut c = Client::from_cimd(row.client_uuid, &doc, facts);
    c.trust = crate::domain::client::TrustLevel::Oidf;
    Some(c)
}

impl<E: Env> OAuth<E> {
    /// Makes the client a request names resolvable (IDP-1): for a URL `client_id`, its CIMD
    /// snapshot is fresh after this, or the request is refused. A local id needs nothing.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn prepare_client(
        &self,
        realm: &Realm,
        params: &Params,
    ) -> Result<Result<(), Refusal>, Unavailable> {
        let Some(id) = params.get("client_id") else {
            return Ok(Ok(()));
        };
        // OP-154 m.3 (r)
        if ClientIdKind::of(id) == ClientIdKind::Local || id.starts_with("spiffe://") {
            return Ok(Ok(()));
        }
        // IDP-1, OP-155 m.3 (j)
        if access_identity_oidf::statement::entity_id_ok(id)
            && let Some(decided) = self.prepare_federated(realm, params, id).await?
        {
            return Ok(decided);
        }
        if client_id_url(id).is_err() {
            return Ok(Err(Refusal::Url));
        }
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let (enabled, domains) = tx.cimd_policy().await?;
        let row = tx.cimd_client(id).await?;
        if !admitted(enabled, &domains, id) {
            if let Some(r) = row {
                tx.retire_cimd_client(r.client_uuid, retire_reason(enabled), now)
                    .await?;
                tx.commit().await?;
            }
            return Ok(Err(if enabled {
                Refusal::Domain
            } else {
                Refusal::Disabled
            }));
        }
        if row
            .as_ref()
            .is_some_and(|r| unsigned(r.fresh_until_ms) > now && of_row(r).is_some())
        {
            return Ok(Ok(()));
        }
        tx.commit().await?;
        let fetched = match self.fetch_document(realm, id).await {
            Ok(f) => f,
            Err(r) => {
                tracing::info!(reason = ?r, "CIMD client refused");
                return Ok(Err(r));
            }
        };
        let (doc, bytes, max_age_s, logo) = fetched;
        let fetched_ms = self.now()?;
        let snapshot = CimdSnapshot {
            document: &bytes,
            document_hash: suiss_crypto::digest::sha256(&bytes),
            authority_hash: doc.authority_hash,
            visual_hash: doc.visual_hash,
            logo: logo.as_ref().map(|(b, t)| (b.as_slice(), *t)),
            fetched_ms,
            fresh_until_ms: fetched_ms.saturating_add(keep_s(max_age_s).saturating_mul(1000)),
        };
        let mut tx = self.begin(realm).await?;
        match tx.cimd_client(id).await? {
            Some(r) => {
                let moved = change(
                    (r.authority_hash, r.visual_hash),
                    (doc.authority_hash, doc.visual_hash),
                );
                // AG-5
                if moved == cimd::Change::Authority {
                    tx.end_client_consents(r.client_uuid, "metadata_changed", fetched_ms)
                        .await?;
                }
                tx.refresh_cimd_client(r.client_uuid, &snapshot, moved == cimd::Change::Visual)
                    .await?;
            }
            None => {
                tx.insert_cimd_client(id, &snapshot).await?;
            }
        }
        tx.commit().await?;
        Ok(Ok(()))
    }

    /// The OpenID Federation step of the resolver (IDP-1, IDP-19, OP-155 m.3 (j)): in a realm that
    /// is a federation leaf, a URL `client_id` whose trust chain resolves to a pinned anchor is
    /// the client its chain's `openid_relying_party` metadata describes. `None` lets CIMD try,
    /// unless the request named its own `trust_chain`: a chain that does not hold then refuses.
    async fn prepare_federated(
        &self,
        realm: &Realm,
        params: &Params,
        id: &str,
    ) -> Result<Option<Result<(), Refusal>>, Unavailable> {
        use access_identity_oidf::chain::{self, FRESHNESS_MS};
        let offered = params.get("trust_chain");
        let now = self.now()?;
        let mut tx = self.begin(realm).await?;
        let fed = tx.federation().await?;
        if !fed.enabled {
            tx.commit().await?;
            // IDI-10, OP-154 m.3 (i)
            return Ok(offered.map(|_| Err(Refusal::Federation)));
        }
        let anchors = crate::adapters::oidf::anchors(&tx.trust_anchors().await?);
        let row = tx.oidf_client(id).await?;
        tx.commit().await?;
        if offered.is_none()
            && row.as_ref().is_some_and(|r| {
                now < r.chain_exp_ms && now.saturating_sub(r.fetched_ms) <= FRESHNESS_MS
            })
        {
            return Ok(Some(Ok(())));
        }
        let resolved = match offered {
            Some(tc) => chain::parse_trust_chain_json(tc.as_bytes()).and_then(|jwts| {
                let refs: Vec<&str> = jwts.iter().map(String::as_str).collect();
                chain::verify_chain(&refs, &anchors, now)
            }),
            None => {
                let fetch = crate::adapters::oidf::GuardedFetch {
                    documents: self.env.documents(),
                    realm: realm.realm,
                };
                access_identity_oidf::app::resolve(&fetch, id, anchors, now).await
            }
        };
        let snapshot = resolved
            .ok()
            .filter(|c| c.leaf.sub == id)
            .and_then(|c| federated_metadata(&c, id).map(|m| (c, m)));
        let Some((c, metadata)) = snapshot else {
            tracing::info!("OIDF client chain did not resolve");
            if let Some(r) = &row {
                let mut tx = self.begin(realm).await?;
                tx.retire_oidf_client(r.client_uuid, "chain_lost", now)
                    .await?;
                tx.commit().await?;
            }
            return Ok(offered.map(|_| Err(Refusal::Federation)));
        };
        let marks: Vec<String> = c
            .trust_marks
            .iter()
            .map(|m| m.trust_mark_type.clone())
            .collect();
        let snap = access_store::oidf::OidfSnapshot {
            metadata: metadata.as_bytes(),
            metadata_hash: suiss_crypto::digest::sha256(metadata.as_bytes()),
            anchor: &c.anchor,
            trust_marks: &marks,
            registration: access_store::oidf::OidfRegistration::Resolved,
            fetched_ms: now,
            chain_exp_ms: c.exp_ms,
        };
        let mut tx = self.begin(realm).await?;
        let existing = tx.oidf_client(id).await?.map(|r| r.client_uuid);
        tx.put_oidf_client(existing, id, &snap).await?;
        tx.commit().await?;
        Ok(Some(Ok(())))
    }

    /// AS-M11…M13, §11.3.4, §11.3.6: fetches and checks the document at `url`, every URL it
    /// names, and its logo.
    async fn fetch_document(
        &self,
        realm: &Realm,
        url: &str,
    ) -> Result<
        (
            cimd::Document,
            Vec<u8>,
            Option<u64>,
            Option<(Vec<u8>, &'static str)>,
        ),
        Refusal,
    > {
        let docs = self.env.documents();
        docs.vet(url).await.map_err(Refusal::Fetch)?;
        let f = docs
            .fetch(realm.realm, url, ACCEPT, MAX_DOCUMENT)
            .await
            .map_err(Refusal::Fetch)?;
        if f.status != 200 {
            return Err(Refusal::Status);
        }
        let doc = cimd::parse(&f.body, url).map_err(Refusal::Document)?;
        for embedded in &doc.fetched {
            docs.vet(embedded)
                .await
                .map_err(|_| Refusal::Document(CimdError::Embedded))?;
        }
        let logo = match &doc.logo_uri {
            Some(u) => {
                let accept = LOGO_TYPES.join(", ");
                match docs.fetch(realm.realm, u, &accept, MAX_LOGO).await {
                    Ok(l) if l.status == 200 => l
                        .content_type
                        .as_deref()
                        .and_then(logo_type)
                        .filter(|t| logo_bytes(t, &l.body))
                        .map(|t| (l.body, t)),
                    _ => None,
                }
            }
            None => None,
        };
        Ok((doc, f.body, f.max_age_s, logo))
    }

    /// The client `client_id` names in this transaction (IDP-1): the local registry for a local
    /// id; for a URL id only its live CIMD snapshot while the realm's policy admits it, never the
    /// local registry (IDI-10).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub(crate) async fn client_of(
        &self,
        tx: &mut <E::Db as OAuthDb>::Tx,
        client_id: &str,
    ) -> Result<Option<Client>, Unavailable> {
        match ClientIdKind::of(client_id) {
            // IDI-10, OP-154 m.3 (j)
            ClientIdKind::Local if client_id.starts_with(crate::domain::dcr::CLIENT_PREFIX) => {
                self.dcr_client_of(tx, client_id).await
            }
            ClientIdKind::Local => match tx.client(client_id).await?.and_then(Client::from_row) {
                // OP-155 m.3 (k)
                Some(c) => self.profiled(tx, c).await,
                None => Ok(None),
            },
            ClientIdKind::Url => {
                // IDP-1, OP-155 m.3 (j)
                if access_identity_oidf::statement::entity_id_ok(client_id)
                    && tx.federation().await?.enabled
                    && let Some(r) = tx.oidf_client(client_id).await?
                {
                    return Ok((self.now()? < r.chain_exp_ms)
                        .then(|| of_oidf(&r))
                        .flatten());
                }
                if client_id_url(client_id).is_err() {
                    return Ok(None);
                }
                let (enabled, domains) = tx.cimd_policy().await?;
                if !admitted(enabled, &domains, client_id) {
                    return Ok(None);
                }
                Ok(tx.cimd_client(client_id).await?.as_ref().and_then(of_row))
            }
        }
    }
}
