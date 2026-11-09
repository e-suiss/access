//! A vault Resource (§11.13, MD-13, OP-154 m.3 (t)): the realm's configuration of one upstream
//! for connected accounts. It is the outbound `Connection` of the industry model: the
//! upstream's OAuth metadata, the realm's client there, the scopes it may ask for, the
//! `scope_mapping` from the domain's SPP actions to upstream scopes, and the registered
//! executors that may receive a released token. Its inbound half is the domain's PEP, PRM and
//! SPP actions, not a second policy store. Nothing in it is authority: `scope_mapping` only
//! says which upstream scopes an action needs (§9.9.6, AGI-2).

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::IdpAction;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::ActionRef;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use crate::domain::catalog::{Catalog, MAX_SCOPES, Upstream, name_ok};

/// Most actions one Resource maps.
pub const MAX_ACTIONS: usize = 64;

/// Most registered executors one Resource names.
pub const MAX_EXECUTORS: usize = 16;

/// Where the upstream's definition comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// A shipped catalog entry (`idp.vault.resource_enable`).
    Catalog,
    /// The realm's own upstream (`idp.vault.resource_register`, reserved).
    Realm,
}

impl Origin {
    /// Its stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Catalog => "catalog",
            Self::Realm => "realm",
        }
    }
}

/// One SPP action and the upstream scopes it needs (`scope_mapping`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappedAction {
    /// The action's namespace.
    pub namespace: String,
    /// Its name.
    pub name: String,
    /// Its major version.
    pub major: u64,
    /// Its Action Schema digest, base64url.
    pub schema: String,
    /// The upstream scopes a call of it needs.
    pub scopes: BTreeSet<String>,
}

impl MappedAction {
    /// Whether this is `action`.
    #[must_use]
    pub fn is(&self, action: &ActionRef) -> bool {
        self.namespace == action.namespace
            && self.name == action.name
            && self.major == action.major
            && self.schema == b64url_encode(&action.schema.0)
    }
}

/// A realm's Resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// The realm's name for it.
    pub name: String,
    /// Where its upstream comes from.
    pub origin: Origin,
    /// The upstream, its placeholders filled in.
    pub upstream: Upstream,
    /// The realm's client at the upstream.
    pub client_id: String,
    /// The `secret://…` reference of that client's secret; the secret is never stored.
    pub client_secret_ref: String,
    /// The upstream scopes a connection may hold.
    pub scopes: BTreeSet<String>,
    /// `scope_mapping`: the actions a release may be for, each with the scopes it needs.
    pub actions: Vec<MappedAction>,
    /// The registered executors (PEPs, by their certificate's `x5t#S256`) a token may go to.
    pub executors: BTreeSet<String>,
}

/// Why a Resource is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// Malformed: a member, a name, a scope, an action or an executor outside the rules.
    #[error("invalid vault resource")]
    Resource,
    /// The catalog has no such upstream.
    #[error("unknown upstream")]
    Upstream,
}

fn text<'a>(m: &'a Map<String, Json>, k: &str) -> Result<&'a str, Invalid> {
    m.get(k).and_then(Json::as_str).ok_or(Invalid::Resource)
}

fn texts(m: &Map<String, Json>, k: &str) -> Result<BTreeSet<String>, Invalid> {
    match m.get(k) {
        None => Ok(BTreeSet::new()),
        Some(Json::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(String::from).ok_or(Invalid::Resource))
            .collect(),
        Some(_) => Err(Invalid::Resource),
    }
}

fn secret_ref_ok(s: &str) -> bool {
    s.strip_prefix("secret://").is_some_and(|r| {
        (1..=246).contains(&r.len())
            && r.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'))
    })
}

fn executor_ok(s: &str) -> bool {
    s.len() == 43 && b64url_decode(s).is_ok_and(|b| b.len() == 32)
}

fn action(v: &Json) -> Result<MappedAction, Invalid> {
    let o = v.as_object().ok_or(Invalid::Resource)?;
    if o.keys().any(|k| {
        !matches!(
            k.as_str(),
            "namespace" | "name" | "major" | "schema" | "scopes"
        )
    }) {
        return Err(Invalid::Resource);
    }
    let schema = text(o, "schema")?;
    if !b64url_decode(schema).is_ok_and(|b| b.len() == 32) {
        return Err(Invalid::Resource);
    }
    Ok(MappedAction {
        namespace: String::from(text(o, "namespace")?),
        name: String::from(text(o, "name")?),
        major: o
            .get("major")
            .and_then(Json::as_u64)
            .ok_or(Invalid::Resource)?,
        schema: String::from(schema),
        scopes: texts(o, "scopes")?,
    })
}

const MEMBERS: [&str; 8] = [
    "upstream",
    "custom",
    "params",
    "client_id",
    "client_secret_ref",
    "scopes",
    "actions",
    "executors",
];

impl Resource {
    /// The Resource `name` from its `putVaultResource` body: `upstream` names a catalog entry
    /// (with `params` for its placeholders), or `custom` is the realm's own upstream in the
    /// catalog format.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn from_json(name: &str, body: &Json, catalog: &Catalog) -> Result<Self, Invalid> {
        let m = body.as_object().ok_or(Invalid::Resource)?;
        if m.keys().any(|k| !MEMBERS.contains(&k.as_str())) {
            return Err(Invalid::Resource);
        }
        let (origin, upstream) = match (m.get("upstream"), m.get("custom")) {
            (Some(Json::String(id)), None) => {
                let params: BTreeMap<String, String> = match m.get("params") {
                    None => BTreeMap::new(),
                    Some(p) => serde_json::from_value(p.clone()).map_err(|_| Invalid::Resource)?,
                };
                let u = catalog.get(id).ok_or(Invalid::Upstream)?;
                (
                    Origin::Catalog,
                    u.resolved(&params).ok_or(Invalid::Resource)?,
                )
            }
            (None, Some(c)) if m.get("params").is_none() => {
                let mut u: Upstream =
                    serde_json::from_value(c.clone()).map_err(|_| Invalid::Resource)?;
                if u.id != name || !u.placeholders.is_empty() {
                    return Err(Invalid::Resource);
                }
                u.placeholders = Vec::new();
                (Origin::Realm, u)
            }
            _ => return Err(Invalid::Resource),
        };
        let actions = match m.get("actions") {
            Some(Json::Array(a)) => a.iter().map(action).collect::<Result<Vec<_>, _>>()?,
            _ => return Err(Invalid::Resource),
        };
        let r = Self {
            name: String::from(name),
            origin,
            upstream,
            client_id: String::from(text(m, "client_id")?),
            client_secret_ref: String::from(text(m, "client_secret_ref")?),
            scopes: texts(m, "scopes")?,
            actions,
            executors: texts(m, "executors")?,
        };
        r.check()?;
        Ok(r)
    }

    /// Whether it is inside the rules: names, a client and its secret reference, scopes the
    /// upstream knows (any scope for the realm's own), every action's scopes among them, no
    /// action of the `access` or `idp` namespaces, executors as `x5t#S256`.
    ///
    /// # Errors
    /// [`Invalid::Resource`].
    pub fn check(&self) -> Result<(), Invalid> {
        let known = |s: &String| match self.origin {
            Origin::Catalog => self.upstream.knows(s),
            Origin::Realm => s.len() <= 256 && s.bytes().all(|c| c.is_ascii_graphic() && c != b','),
        };
        let mut seen = BTreeSet::new();
        let actions_ok = (1..=MAX_ACTIONS).contains(&self.actions.len())
            && self.actions.iter().all(|a| {
                seen.insert((a.namespace.clone(), a.name.clone(), a.major))
                    && !a.namespace.is_empty()
                    && a.namespace.len() <= 64
                    && !a.name.is_empty()
                    && a.name.len() <= 64
                    && a.namespace != access_kernel::meta::NAMESPACE
                    && a.namespace != access_internal_api::idp::RESOURCE_NAMESPACE
                    && !a.namespace.starts_with("idp.")
                    && a.scopes.is_subset(&self.scopes)
            });
        let ok = name_ok(&self.name)
            && self.upstream.check()
            && self.upstream.placeholders.is_empty()
            && (1..=255).contains(&self.client_id.len())
            && !self.client_id.chars().any(char::is_control)
            && secret_ref_ok(&self.client_secret_ref)
            && self.scopes.len() <= MAX_SCOPES
            && self.scopes.iter().all(known)
            && actions_ok
            && self.executors.len() <= MAX_EXECUTORS
            && self.executors.iter().all(|e| executor_ok(e));
        if ok { Ok(()) } else { Err(Invalid::Resource) }
    }

    /// The mapped action `action`, when the Resource maps it.
    #[must_use]
    pub fn mapped(&self, action: &ActionRef) -> Option<&MappedAction> {
        self.actions.iter().find(|a| a.is(action))
    }

    /// Its stored form: deterministic JSON.
    ///
    /// # Errors
    /// [`Invalid::Resource`] when it does not encode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Invalid> {
        serde_json::to_vec(self).map_err(|_| Invalid::Resource)
    }

    /// Reads its stored form.
    ///
    /// # Errors
    /// [`Invalid::Resource`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Invalid> {
        let r: Self = serde_json::from_slice(bytes).map_err(|_| Invalid::Resource)?;
        r.check()?;
        Ok(r)
    }

    /// What an administrator reads of it: never the secret itself, only its reference.
    #[must_use]
    pub fn view(&self) -> Json {
        serde_json::json!({
            "resource": self.name,
            "origin": self.origin.name(),
            "upstream": self.upstream.id,
            "display_name": self.upstream.display_name,
            "client_id": self.client_id,
            "client_secret_ref": self.client_secret_ref,
            "scopes": self.scopes,
            "actions": self.actions,
            "executors": self.executors,
            "revocation": self.upstream.revocation_endpoint.is_some(),
        })
    }
}

/// An `idp.vault.*` change (OP-154 m.3 (a), (t)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultChange {
    /// `idp.vault.resource_enable` (CT2): a catalog upstream, enabled or changed.
    Enable(Resource),
    /// `idp.vault.resource_register` (reserved, CT3): the realm's own upstream.
    Register(Resource),
    /// `idp.vault.resource_disable` (CT1): no new connection or release under it.
    Disable(String),
    /// `idp.vault.release_mode_open` (CT2, `true`) or `release_mode_close` (CT1, `false`).
    ReleaseMode(bool),
}

impl VaultChange {
    /// The `putVaultResource` change: a catalog upstream is enabled, the realm's own is
    /// registered.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn put(name: &str, body: &Json, catalog: &Catalog) -> Result<Self, Invalid> {
        let r = Resource::from_json(name, body, catalog)?;
        Ok(match r.origin {
            Origin::Catalog => Self::Enable(r),
            Origin::Realm => Self::Register(r),
        })
    }

    /// The `putVaultReleaseMode` change: `{"mode": "open" | "closed"}`.
    ///
    /// # Errors
    /// [`Invalid::Resource`].
    pub fn release_mode(body: &Json) -> Result<Self, Invalid> {
        let m = body.as_object().ok_or(Invalid::Resource)?;
        if m.len() != 1 {
            return Err(Invalid::Resource);
        }
        match m.get("mode").and_then(Json::as_str) {
            Some("open") => Ok(Self::ReleaseMode(true)),
            Some("closed") => Ok(Self::ReleaseMode(false)),
            _ => Err(Invalid::Resource),
        }
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Enable(_) => IdpAction::VaultResourceEnable,
            Self::Register(_) => IdpAction::VaultResourceRegister,
            Self::Disable(_) => IdpAction::VaultResourceDisable,
            Self::ReleaseMode(true) => IdpAction::VaultReleaseModeOpen,
            Self::ReleaseMode(false) => IdpAction::VaultReleaseModeClose,
        }
    }

    /// Whether it is inside the rules.
    ///
    /// # Errors
    /// [`Invalid::Resource`].
    pub fn check(&self) -> Result<(), Invalid> {
        match self {
            Self::Enable(r) | Self::Register(r) => r.check(),
            Self::Disable(n) if name_ok(n) => Ok(()),
            Self::Disable(_) => Err(Invalid::Resource),
            Self::ReleaseMode(_) => Ok(()),
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::Enable(r) | Self::Register(r) => Value::Map(vec![(
                Value::text("resource"),
                Value::Bytes(r.to_bytes().unwrap_or_default()),
            )]),
            Self::Disable(n) => Value::Map(vec![(Value::text("disable"), Value::text(n))]),
            Self::ReleaseMode(open) => Value::Map(vec![(
                Value::text("release_mode"),
                Value::text(if *open { "open" } else { "closed" }),
            )]),
        }
    }

    /// Its resource path below the realm's slug: `vault/<name>`, or `vault` for the mode.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::Enable(r) | Self::Register(r) => vec![String::from("vault"), r.name.clone()],
            Self::Disable(n) => vec![String::from("vault"), n.clone()],
            Self::ReleaseMode(_) => vec![String::from("vault")],
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema() -> String {
        b64url_encode(&[7; 32])
    }

    fn body() -> Json {
        json!({
            "upstream": "github",
            "client_id": "Iv1.abc",
            "client_secret_ref": "secret://vault/github",
            "scopes": ["repo", "read:user"],
            "actions": [{"namespace": "work", "name": "open_issue", "major": 1,
                         "schema": schema(), "scopes": ["repo"]}],
            "executors": [b64url_encode(&[9; 32])],
        })
    }

    // AG-39, E36, OP-154 m.3 (t), Ek B 4413, 4487
    #[test]
    fn a_catalog_upstream_is_enabled_and_its_own_is_registered() {
        let c = Catalog::shipped().unwrap();
        let ch = VaultChange::put("github", &body(), &c).unwrap();
        assert_eq!(ch.action(), IdpAction::VaultResourceEnable);
        let VaultChange::Enable(r) = &ch else {
            panic!()
        };
        assert_eq!(Resource::from_bytes(&r.to_bytes().unwrap()).unwrap(), *r);
        assert!(r.view().get("client_secret").is_none());

        let mut own = body();
        own.as_object_mut().unwrap().remove("upstream");
        own["custom"] = json!({
            "id": "erp",
            "display_name": "ERP",
            "authorization_endpoint": "https://erp.example/authorize",
            "token_endpoint": "https://erp.example/token",
            "refresh": "rotating",
        });
        own["scopes"] = json!(["orders"]);
        own["actions"][0]["scopes"] = json!(["orders"]);
        let ch = VaultChange::put("erp", &own, &c).unwrap();
        assert_eq!(ch.action(), IdpAction::VaultResourceRegister);
        assert!(VaultChange::put("other", &own, &c).is_err());
    }

    // AGI-2, §9.9.6: scope_mapping names only scopes the Resource holds and never a core or idp
    // action; it produces no authority
    #[test]
    fn a_resource_outside_the_rules_is_refused() {
        let c = Catalog::shipped().unwrap();
        let mut cases = Vec::new();
        let mut b = body();
        b["scopes"] = json!(["admin:enterprise"]);
        cases.push(b);
        let mut b = body();
        b["actions"][0]["scopes"] = json!(["read:org"]);
        cases.push(b);
        let mut b = body();
        b["actions"][0]["namespace"] = json!("access");
        cases.push(b);
        let mut b = body();
        b["actions"][0]["namespace"] = json!("idp.vault");
        cases.push(b);
        let mut b = body();
        b["actions"] = json!([]);
        cases.push(b);
        let mut b = body();
        b["client_secret_ref"] = json!("plain-secret");
        cases.push(b);
        let mut b = body();
        b["executors"] = json!(["short"]);
        cases.push(b);
        let mut b = body();
        b["client_secret"] = json!("s3cr3t");
        cases.push(b);
        for b in cases {
            assert!(VaultChange::put("github", &b, &c).is_err(), "{b}");
        }
        let mut b = body();
        b["upstream"] = json!("nowhere");
        assert_eq!(VaultChange::put("x", &b, &c), Err(Invalid::Upstream));
    }

    #[test]
    fn the_release_mode_is_open_or_closed() {
        assert_eq!(
            VaultChange::release_mode(&json!({"mode": "open"}))
                .unwrap()
                .action(),
            IdpAction::VaultReleaseModeOpen
        );
        assert_eq!(
            VaultChange::release_mode(&json!({"mode": "closed"}))
                .unwrap()
                .action(),
            IdpAction::VaultReleaseModeClose
        );
        assert!(VaultChange::release_mode(&json!({"mode": "wide"})).is_err());
    }
}
