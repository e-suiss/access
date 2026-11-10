//! The organization SSO setup portal on the hosted Frontend API (TN-134, OP-155 m.3 (i)): a
//! one-use, 72-hour setup link opens the identity provider wizard, the organization's domains
//! and their verification, the SCIM address and the connection test. The link is bound to the
//! first browser that submits a step; another browser finds it spent. What the portal writes is
//! a connection draft: only the organization root's `idp.upstream.register` (CT3) and its
//! Acceptance put a connection into effect (TN-95). Organization names are attacker input,
//! answered as text.

use access_identity_oauth::ports::RealmEntry;
use access_identity_session::domain::session::set_cookie;
use access_identity_session::ports::Clock;
use access_kernel::json::b64url_encode;
use access_store::StoreError;
use access_store::identity::TenantTx;
use access_store::org_sso::{DraftShape, NewDraft, SetupLink};
use serde::Deserialize;
use serde_json::json;

use super::{Hosted, Reply};
use crate::domain::message::TextId;
use crate::domain::sso_setup::{self, Draft, Protocol, SETUP_COOKIE};
use crate::ports::{Kits, Messages, RealmKit};
use access_identity_account::domain::login::Problem;

/// No such setup link.
pub const SETUP_LINK_GONE: Problem = Problem {
    status: 404,
    code: "setup-link-gone",
    title: "This setup link does not exist",
    retry_after_s: None,
};

/// The setup link expired, was finished, or is bound to another browser (TN-134).
pub const SETUP_LINK_SPENT: Problem = Problem {
    status: 410,
    code: "setup-link-spent",
    title: "This setup link has expired or was already used",
    retry_after_s: None,
};

/// A step that is not one, or a draft that is not well formed.
pub const INVALID_SETUP_STEP: Problem = Problem {
    status: 400,
    code: "invalid-setup-step",
    title: "That setup step is not valid",
    retry_after_s: None,
};

/// The connection is a draft until an owner enacts it, so there is nothing to test yet.
pub const CONNECTION_NOT_ENACTED: Problem = Problem {
    status: 409,
    code: "connection-not-enacted",
    title: "An owner has to turn the connection on before it can be tested",
    retry_after_s: None,
};

const UNAVAILABLE: Problem = Problem {
    status: 503,
    code: "unavailable",
    title: "Try again shortly",
    retry_after_s: Some(5),
};

/// How long the browser cookie lives: the link's whole lifetime (72 hours).
const COOKIE_MAX_AGE_S: u64 = 72 * 3_600;

/// `POST /v1/sso-setup/{link}`: one wizard step.
#[derive(Debug, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupStep {
    /// Drafts the connection the wizard filled in.
    Connection {
        /// The wizard used.
        provider: String,
        /// Its protocol.
        protocol: Protocol,
        /// The OIDC issuer.
        #[serde(default)]
        issuer: Option<String>,
        /// The client id at the OIDC issuer.
        #[serde(default)]
        client_id: Option<String>,
        /// The SAML identity provider's entity ID.
        #[serde(default)]
        entity_id: Option<String>,
        /// The SAML identity provider's metadata URL.
        #[serde(default)]
        metadata_url: Option<String>,
    },
    /// Asks for the connection test.
    Test,
    /// Ends the portal: the link is spent.
    Finish,
}

fn store_failed(e: &StoreError) -> Reply {
    tracing::warn!(error = %e, "setup portal step failed");
    Reply::problem(UNAVAILABLE)
}

fn spent() -> Reply {
    let mut r = Reply::problem(SETUP_LINK_SPENT);
    r.body = super::Body::Json(json!({
        "type": format!("urn:suiss:access:problem:{}", SETUP_LINK_SPENT.code),
        "title": SETUP_LINK_SPENT.title,
        "status": SETUP_LINK_SPENT.status,
        "text": TextId::SsoSetupExpired,
    }));
    r
}

fn digest(s: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(s.as_bytes())
}

/// The connection that is enacted for the organization, if any. Enterprise upstream
/// connections are the federation broker's (OP-155 m.2 P4); until it names one for the
/// organization the answer is none, and the test is refused.
fn enacted(_org: &[u8; 16]) -> Option<String> {
    None
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn setup_tx(&self, kit: &RealmKit) -> Result<TenantTx, Reply> {
        TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|e| store_failed(&e))
    }

    /// `GET /v1/sso-setup/{link}` (TN-134): what the link opens, without spending it: the
    /// organization, the wizards, the values to copy, the domains and how each is verified, the
    /// SCIM address, the drafts and the steps done. A link bound to another browser, finished
    /// or expired is spent.
    pub async fn sso_setup(&self, entry: &RealmEntry, browser: Option<&str>, link: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let mut t = match self.setup_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let row = match t.setup_link(&digest(link)).await {
            Ok(Some(r)) => r,
            Ok(None) => return Reply::problem(SETUP_LINK_GONE),
            Err(e) => return store_failed(&e),
        };
        if !usable(&row, browser) {
            return spent();
        }
        let view = match self.portal_view(&mut t, &kit, &row).await {
            Ok(v) => v,
            Err(e) => return store_failed(&e),
        };
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        Reply::json(200, view)
    }

    async fn portal_view(
        &self,
        t: &mut TenantTx,
        kit: &RealmKit,
        row: &SetupLink,
    ) -> Result<serde_json::Value, StoreError> {
        let org = t.org(row.org).await?.filter(|o| !o.ended);
        let Some(org) = org else {
            return Ok(json!({ "text": TextId::SsoSetupExpired }));
        };
        let domains = t.open_domain_claims(Some(org.id)).await?;
        let verified = t.hrd_domains(org.id).await?;
        let drafts = t.sso_drafts(org.id).await?;
        let scim = t.scim_sources(org.id).await?;
        let connection = sso_setup::connection_name(&org.party);
        let wizards = sso_setup::wizards().unwrap_or_default();
        Ok(json!({
            "organization": {
                "id": b64url_encode(&org.party),
                "display_name": org.display_name,
            },
            "expires_at": access_identity_account::app::privacy::rfc3339(row.expires_ms),
            "opened": row.browser.is_some(),
            "connection": connection,
            "values": sso_setup::values(&kit.issuer, &connection),
            "wizards": wizards,
            "domains": domains.iter().map(|d| json!({
                "domain": d.domain,
                "method": d.method,
                "verified": verified.contains(&d.domain),
                "txt_name": format!("_suiss-access.{}", d.domain),
            })).collect::<Vec<_>>(),
            "scim": { "bound": !scim.is_empty() },
            "drafts": drafts
                .iter()
                .filter(|d| !d.withdrawn && d.setup_link == Some(row.id))
                .map(|d| json!({
                    "protocol": d.protocol,
                    "provider": d.provider,
                    "issuer": d.issuer,
                    "client_id": d.client_id,
                    "entity_id": d.entity_id,
                    "metadata_url": d.metadata_url,
                }))
                .collect::<Vec<_>>(),
            "test": if enacted(&org.party).is_some() { "ready" } else { "after_enactment" },
            "texts": {
                "title": TextId::SsoSetupTitle,
                "choose": TextId::SsoSetupChoose,
                "configure": TextId::SsoSetupConfigure,
                "test": TextId::SsoSetupTest,
                "done": TextId::SsoSetupDone,
            },
        }))
    }

    /// `POST /v1/sso-setup/{link}` (TN-134): one wizard step. The first step binds the link to
    /// this browser with a cookie; another browser then finds it spent. A connection step
    /// writes a draft only; the test needs the connection enacted by an owner; finishing spends
    /// the link.
    pub async fn submit_sso_setup(
        &self,
        entry: &RealmEntry,
        browser: Option<&str>,
        link: &str,
        step: SetupStep,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let mut t = match self.setup_tx(&kit).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        let row = match t.setup_link(&digest(link)).await {
            Ok(Some(r)) => r,
            Ok(None) => return Reply::problem(SETUP_LINK_GONE),
            Err(e) => return store_failed(&e),
        };
        if !usable(&row, browser) {
            return spent();
        }
        let mut cookie = None;
        if row.browser.is_none() {
            let secret = match access_crypto::random::bytes::<32>() {
                Ok(b) => b64url_encode(&b),
                Err(_) => return Reply::problem(UNAVAILABLE),
            };
            match t.open_setup_link(row.id, &digest(&secret)).await {
                Ok(true) => {}
                Ok(false) => return spent(),
                Err(e) => return store_failed(&e),
            }
            cookie = Some(set_cookie(SETUP_COOKIE, &secret, Some(COOKIE_MAX_AGE_S)));
        }
        let reply = match step {
            c @ SetupStep::Connection { .. } => match draft_of(c) {
                Some((provider, draft)) => {
                    match draft_connection(&mut t, &row, &provider, &draft).await {
                        Ok(r) => r,
                        Err(e) => return store_failed(&e),
                    }
                }
                None => return Reply::problem(INVALID_SETUP_STEP),
            },
            SetupStep::Test => {
                let party = match t.org(row.org).await {
                    Ok(Some(o)) => o.party,
                    Ok(None) => return Reply::problem(SETUP_LINK_GONE),
                    Err(e) => return store_failed(&e),
                };
                match enacted(&party) {
                    Some(c) => Reply::json(200, json!({ "connection": c })),
                    None => Reply::problem(CONNECTION_NOT_ENACTED),
                }
            }
            SetupStep::Finish => match t.finish_setup_link(row.id).await {
                Ok(true) => Reply::json(200, json!({ "finished": true })),
                Ok(false) => return spent(),
                Err(e) => return store_failed(&e),
            },
        };
        if let Err(e) = t.commit().await {
            return store_failed(&e);
        }
        reply.cookie(cookie)
    }
}

/// The wizard and the well-formed draft a connection step names.
fn draft_of(step: SetupStep) -> Option<(String, Draft)> {
    let SetupStep::Connection {
        provider,
        protocol,
        issuer,
        client_id,
        entity_id,
        metadata_url,
    } = step
    else {
        return None;
    };
    let draft = match (protocol, issuer, client_id, entity_id, metadata_url) {
        (Protocol::Oidc, Some(issuer), Some(client_id), None, None) => {
            Draft::Oidc { issuer, client_id }
        }
        (Protocol::Saml, None, None, Some(entity_id), Some(metadata_url)) => Draft::Saml {
            entity_id,
            metadata_url,
        },
        _ => return None,
    };
    let known = sso_setup::wizards()
        .unwrap_or_default()
        .iter()
        .any(|w| w.provider == provider && w.protocols.contains(&protocol));
    (known && draft.ok()).then_some((provider, draft))
}

/// Records the draft through the link, allowed by the link's own Exercise (TN-134).
async fn draft_connection(
    t: &mut TenantTx,
    row: &SetupLink,
    provider: &str,
    draft: &Draft,
) -> Result<Reply, StoreError> {
    let shape = match draft {
        Draft::Oidc { issuer, client_id } => DraftShape::Oidc { issuer, client_id },
        Draft::Saml {
            entity_id,
            metadata_url,
        } => DraftShape::Saml {
            entity_id,
            metadata_url,
        },
    };
    t.insert_connection_draft(&NewDraft {
        org: row.org,
        shape,
        provider: Some(provider),
        drafted_by: [0; 16],
        exercise: &row.exercise,
        setup_link: Some(row.id),
    })
    .await?;
    Ok(Reply::json(
        201,
        json!({ "drafted": true, "text": TextId::SsoSetupTest }),
    ))
}

/// Whether `row` may still be used by the browser holding `cookie` (TN-134): not expired, not
/// finished, and unopened or opened by this browser.
fn usable(row: &SetupLink, cookie: Option<&str>) -> bool {
    !row.expired
        && !row.finished
        && row
            .browser
            .is_none_or(|b| cookie.is_some_and(|c| digest(c) == b))
}
