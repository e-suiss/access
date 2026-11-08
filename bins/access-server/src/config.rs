//! Process configuration (OP-63 rule 4).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use access_http::SecurityTxt;
use access_identity_oauth::adapters::outbound::DeclaredTarget;
use access_identity_oauth::domain::issuer::{Issuer, RealmBase};
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// Validated process configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Listen address. Defaults to loopback (§14.3 RAUTHY-008): exposing the
    /// server beyond the host is an explicit operator decision.
    pub(crate) listen: SocketAddr,
    /// The management listener: the management API `/admin/v1/*` and the console's `/console/*`,
    /// on its own address (OP-151 m.3 (b), CMP-15.5, §17.9.6). Required; never the public one.
    pub(crate) management_listen: Option<SocketAddr>,
    /// The internal listener: `/livez`, `/readyz`, `/healthz`, `/metrics` (OP-67 m.3, OP-151
    /// m.3 (b)). Required; never the public or management one.
    pub(crate) internal_listen: Option<SocketAddr>,
    /// `tracing` filter directives.
    pub(crate) log: String,
    /// `security.txt` contact URIs (RFC 9116).
    pub(crate) security_contacts: Vec<String>,
    /// `security.txt` policy URI.
    pub(crate) security_policy: Option<String>,
    /// `security.txt` validity in days; RFC 9116 recommends less than a year.
    pub(crate) security_txt_valid_days: u16,
    /// TLS certificate chain and key (CR-12); there is no plain-text listener.
    pub(crate) tls: Option<Tls>,
    /// The issuer the ADP discovery document names (L1-ADP-11), without a trailing slash.
    pub(crate) issuer: Option<String>,
    /// The database (OP-141 m.18 (g)).
    pub(crate) database: Option<Database>,
    /// The PKCS#11 token (OP-94, OP-141 m.18 (h)).
    pub(crate) hsm: Option<Hsm>,
    /// The authority signer's Unix socket (OP-143 m.5, CMP-22a). Required: receipts, lists and
    /// checkpoints are signed there.
    pub(crate) signer: Option<PathBuf>,
    /// The identity plane (TN-10, CMP-22b, OP-138).
    pub(crate) identity: Option<Identity>,
    pub(crate) login: Login,
    /// The console (OP-151 m.2 M3).
    #[serde(default)]
    pub(crate) console: Console,
    /// The account pages (OP-153 m.3 (w)).
    #[serde(default)]
    pub(crate) account: Account,
    /// The Suiss deployment this Access belongs to (OP-149 m.3, E42).
    pub(crate) suiss: Option<Suiss>,
    /// Event delivery targets the operator declares (OP-149 m.23): a push or webhook stream
    /// endpoint with exactly one of these URLs may be on a private address or another port than
    /// 443. Empty by default. In the environment:
    /// `ACCESS_DELIVERY_TARGETS='[{url="https://host:8443/path", ca_file="/ca.pem"}]'`.
    pub(crate) delivery_targets: Vec<DeliveryTarget>,
    /// What the operator declares about its key infrastructure, published with what the code
    /// fixes (SI-13, CR-22, CR-30, OP-150 m.3 (e)); undeclared facts are published as null.
    #[serde(default)]
    pub(crate) provider: access_http::declarations::Stated,
    /// Log format, OTLP export and trace sampling (OP-47, OP-67).
    #[serde(default)]
    pub(crate) telemetry: access_telemetry::Settings,
    /// SL2 risk sources (TN-46, OP-151 m.1 (b), m.3 (o)).
    #[serde(default)]
    pub(crate) risk: Risk,
    /// Social sign-in (IDP-31, OP-153 m.3 (l)).
    #[serde(default)]
    pub(crate) social: Social,
}

/// Social sign-in (IDP-31, OP-153 m.3 (l)): where the realms' client secrets are mounted and the
/// shared development clients, which only a sandbox realm may use.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Social {
    /// The directory a `secret://<path>` reference resolves under; without it every social
    /// sign-in is unavailable (MD-8).
    #[serde(default)]
    pub(crate) secrets_dir: Option<PathBuf>,
    /// Shared development clients by preset id (`social.dev_clients`).
    #[serde(default)]
    pub(crate) dev_clients: BTreeMap<String, DevClient>,
}

/// One shared development client.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DevClient {
    /// The client id at the provider.
    pub(crate) client_id: String,
    /// Its secret's reference, `secret://…`.
    pub(crate) secret_ref: String,
}

/// SL2 risk sources (TN-46, OP-151 m.1 (b), m.3 (o)). Each one is optional; a missing source
/// makes its signals `unavailable`, never "fine" (MD-8), and the management surface says so.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Risk {
    /// A GeoIP/ASN MMDB file (any `MaxMind` DB producer). No data is embedded; it is read again
    /// when it changes.
    #[serde(default)]
    pub(crate) geo_mmdb_path: Option<PathBuf>,
    /// The k-anonymity range API base, `https://…` without a trailing path to `/range` (HIBP
    /// format, e.g. `https://api.pwnedpasswords.com`).
    #[serde(default)]
    pub(crate) breach_range_api: Option<String>,
    /// A local mirror of the range files `<PREFIX>.txt`, used when no range API is set.
    #[serde(default)]
    pub(crate) breach_ranges_dir: Option<PathBuf>,
}

/// One declared event delivery target (OP-149 m.23).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryTarget {
    /// The exact endpoint URL, written as Access writes URLs: `https`, lowercase host, the port
    /// only when not 443, a path, no user info or fragment.
    pub(crate) url: String,
    /// PEM trust anchors its certificate must chain to; only these when given, else the
    /// operator's trust anchors for clients' endpoints.
    #[serde(default)]
    pub(crate) ca_file: Option<PathBuf>,
}

/// What the Suiss discovery document and the tenant snapshot name (OP-149 m.3, m.4).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Suiss {
    /// The deployment's region, e.g. `eu-central`.
    pub(crate) region: String,
    /// Relay's base URL.
    pub(crate) relay: String,
    /// The management API's base URL.
    pub(crate) management_api: String,
    /// Product name to base URL.
    #[serde(default)]
    pub(crate) products: BTreeMap<String, String>,
    /// The platform tenant's realm slug: its governing domain governs the platform-admin
    /// surface (OP-151 m.2 M2, TN-119). Without it the platform surface finds no domain and
    /// refuses every request.
    #[serde(default)]
    pub(crate) platform_realm: Option<String>,
}

impl Suiss {
    fn valid(&self) -> bool {
        let region =
            !self.region.is_empty()
                && self.region.len() <= 63
                && self.region.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && b == b'-')
                });
        let url = |u: &String| Issuer::parse(u).is_ok();
        let product = |n: &String| {
            !n.is_empty() && n.len() <= 32 && n.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        };
        let platform = self
            .platform_realm
            .as_deref()
            .is_none_or(|s| access_identity_oauth::domain::issuer::check_slug(s).is_ok());
        region
            && platform
            && url(&self.relay)
            && url(&self.management_api)
            && self.products.iter().all(|(n, u)| product(n) && url(u))
    }

    /// The deployment's part of the Suiss discovery document; `api_base` is the ADP issuer.
    pub(crate) fn settings(
        &self,
        api_base: &str,
    ) -> access_identity_oauth::domain::suiss::Settings {
        access_identity_oauth::domain::suiss::Settings {
            region: self.region.clone(),
            relay: self.relay.clone(),
            management_api: self.management_api.clone(),
            api_base: api_base.to_owned(),
            products: self.products.clone(),
        }
    }
}

/// The console on the management listener (TN-128, OP-151 m.2 M3).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Console {
    /// The built `web/console/dist`; read once before the lockdown. Without it only the
    /// console's API is served.
    pub(crate) dist_dir: Option<PathBuf>,
}

/// The account pages on the realm's public listener (OP-153 m.3 (w)).
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Account {
    /// The built `web/account/dist`; read once before the lockdown. Without it only the
    /// account's API is served.
    pub(crate) dist_dir: Option<PathBuf>,
}

/// The hosted login (OP-146 m.12, m.14).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Login {
    /// The built `web/login/dist`; read once before the lockdown. Without it only the login
    /// API is served.
    pub(crate) dist_dir: Option<PathBuf>,
    /// Where a completed sign-in goes: a path on the realm's origin.
    pub(crate) redirect_to: String,
    /// Session idle lifetime, seconds (TN-36; OP-146 m.14 (c): 7 days).
    pub(crate) session_idle_s: u64,
    /// Session absolute lifetime, seconds (TN-36; OP-146 m.14 (c): 30 days).
    pub(crate) session_absolute_s: u64,
    /// The calibrated Argon2id time that pads refusals until successes are measured (TN-82,
    /// OP-146 m.4 (f)).
    pub(crate) hash_mean_ms: u64,
}

impl Default for Login {
    fn default() -> Self {
        Self {
            dist_dir: None,
            redirect_to: "/".to_owned(),
            session_idle_s: 7 * 86_400,
            session_absolute_s: 30 * 86_400,
            hash_mean_ms: 0,
        }
    }
}

impl Login {
    /// The session lifetimes, if inside the TN-36 ranges.
    pub(crate) fn lifetimes(
        &self,
    ) -> Option<access_identity_session::domain::session::SessionPolicy> {
        access_identity_session::domain::session::SessionPolicy::new(
            self.session_idle_s.checked_mul(1000)?,
            self.session_absolute_s.checked_mul(1000)?,
        )
        .ok()
    }
}

/// The identity plane's realm runtime.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    /// The origin realm issuers are formed under, `https://<host>[:port]` without a path:
    /// `https://<slug>.<host>` by default (TN-10). Issuers are stored on the realm rows and
    /// never built from a request (§17.9.6).
    pub(crate) realm_base: String,
    /// The identity signer's Unix socket (CMP-22b).
    pub(crate) signer: PathBuf,
    /// PEM trust anchors for clients' own endpoints: `jwks_uri` and back-channel logout
    /// (§10.4.6, §11.3.6). Without it the system bundle is read; without either those
    /// requests fail and the server still starts.
    #[serde(default)]
    pub(crate) outbound_ca_file: Option<PathBuf>,
}

/// TLS files, read once before the lockdown.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the _file suffix marks a path setting (OP-129 m.3)"
)]
pub(crate) struct Tls {
    /// PEM certificate chain, leaf first.
    pub(crate) cert_file: PathBuf,
    /// PEM private key; readable by the server's user only (CR-35).
    pub(crate) key_file: PathBuf,
    /// PEM bundle of the CAs that issue PEP client certificates (OP-141 m.18 (b)).
    pub(crate) client_ca_file: Option<PathBuf>,
}

/// How the deployment declares its durability (OP-24, HL-40).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Durability {
    /// Synchronous standbys.
    Replicated,
    /// The small-provider single-node declaration.
    SingleNode,
}

/// One login role and its pool.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Role {
    /// Login role, a member of the plane role.
    pub(crate) user: String,
    /// Credential file (OP-129 m.3).
    pub(crate) password_file: PathBuf,
    /// Pool size (OP-53).
    pub(crate) pool: u32,
}

/// The database and the two authority roles (OP-130 m.2).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    /// Server host name, checked against its certificate.
    pub(crate) host: String,
    /// Port.
    pub(crate) port: u16,
    /// Database name.
    pub(crate) name: String,
    /// PEM root the server certificate chains to.
    pub(crate) root_cert_file: PathBuf,
    /// Declared durability.
    pub(crate) durability: Durability,
    /// `access_sequencer` login.
    pub(crate) sequencer: Role,
    /// `access_app` login.
    pub(crate) app: Role,
    /// `access_deriver` login (OP-141 m.22 (k)).
    pub(crate) deriver: Role,
    /// `access_router` login: Host → realm resolution (OP-132 m.3).
    pub(crate) router: Role,
    /// `access_archive` login: opens the day partitions of the ephemeral protocol tables
    /// (OP-146 m.5 (f)).
    pub(crate) archive: Role,
    /// `access_outbox_reader` login: the back-channel logout courier (OP-131).
    pub(crate) outbox_reader: Role,
    /// `access_checkpointer` login: integrates and signs the audit chains (OP-38, OP-44).
    pub(crate) checkpointer: Role,
    /// `access_migrator` login: only `access-server migrate` uses it, never the server
    /// (OP-55).
    #[serde(default)]
    pub(crate) migrator: Option<Role>,
    /// A read replica's host for admin search and listing (OP-27, §17.4.6), reached with the
    /// `access_app` login and pool size on the same port and database. No security read is
    /// served from it; without it those reads go to the primary.
    #[serde(default)]
    pub(crate) replica_host: Option<String>,
}

/// The PKCS#11 token holding the domains' keys.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hsm {
    /// The PKCS#11 module, loaded before the lockdown.
    pub(crate) module: PathBuf,
    /// Token label.
    pub(crate) token: String,
    /// User PIN file (OP-129 m.3).
    pub(crate) pin_file: PathBuf,
    /// Directories a file-backed token keeps its objects in, opened read-write.
    #[serde(default)]
    pub(crate) paths: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)),
            management_listen: None,
            internal_listen: None,
            log: "info".to_owned(),
            security_contacts: vec![
                "https://github.com/e-suiss/access/security/advisories/new".to_owned(),
            ],
            security_policy: Some("https://github.com/e-suiss/access/security/policy".to_owned()),
            security_txt_valid_days: 180,
            tls: None,
            issuer: None,
            database: None,
            hsm: None,
            signer: None,
            identity: None,
            login: Login::default(),
            console: Console::default(),
            account: Account::default(),
            suiss: None,
            delivery_targets: Vec::new(),
            provider: access_http::declarations::Stated::default(),
            telemetry: access_telemetry::Settings::default(),
            risk: Risk::default(),
            social: Social::default(),
        }
    }
}

/// Why the configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error(transparent)]
    Parse(#[from] Box<figment::Error>),
    #[error("security_contacts must not be empty (RFC 9116 requires Contact)")]
    NoSecurityContact,
    #[error("security_txt_valid_days must be between 1 and 364")]
    SecurityTxtValidity,
    #[error("tls.cert_file and tls.key_file are required: the server speaks TLS 1.3 only (CR-12)")]
    NoTls,
    #[error("issuer is required and must be an https URL without a trailing slash (L1-ADP-11)")]
    Issuer,
    #[error("the database section is required (OP-141 m.18)")]
    NoDatabase,
    #[error("the hsm section is required (OP-94)")]
    NoHsm,
    #[error("database pools must have at least one connection each")]
    PoolSize,
    #[error("signer is required: the authority signer's Unix socket (OP-143 m.5, CMP-22a)")]
    NoSigner,
    #[error("the identity section is required (TN-10, CMP-22b)")]
    NoIdentity,
    #[error("login session lifetimes are outside the TN-36 ranges")]
    SessionLifetimes,
    #[error("login.redirect_to must be a path on the realm's origin")]
    RedirectTo,
    #[error("identity.realm_base must be an https origin without a path or trailing slash (TN-10)")]
    RealmBase,
    #[error(
        "the suiss section is required: region, https base URLs without a trailing slash for relay, management_api and products (OP-149 m.3), and a realm slug as platform_realm when set (OP-151 m.2 M2)"
    )]
    Suiss,
    #[error(
        "risk.breach_range_api must be an https URL without query or fragment (OP-151 m.3 (o))"
    )]
    BreachRangeApi,
    #[error(
        "delivery_targets must be distinct https URLs with a lowercase host, the port only when not 443, a path and no user info or fragment (OP-149 m.23)"
    )]
    DeliveryTargets,
    #[error(transparent)]
    Telemetry(#[from] access_telemetry::SettingsError),
    #[error(transparent)]
    SecretEnvironment(#[from] access_crypto::secret_file::SecretFileError),
    #[error(
        "management_listen and internal_listen are required: the management API and the health endpoints have listeners of their own (OP-151 m.3 (b), CMP-15.5)"
    )]
    NoListeners,
    #[error(
        "listen, management_listen and internal_listen must be three different addresses; the admin interface is never on the public listener (§17.9.6, OP-148)"
    )]
    SharedListener,
    #[error("management_listen binds a non-loopback address without TLS (§17.9.6, OP-148)")]
    AdminWithoutTls,
}

/// Whether two listen addresses would take the same socket: one port, and one address or the
/// unspecified address on either side. An ephemeral port (0) takes a fresh port each time.
fn overlap(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

/// The admin address check at start-up (OP-148, §17.9.6, Ek B "admin adresi açılış denetimi"):
/// three distinct listeners; the management one never non-loopback without TLS; all three speak
/// TLS (TI-9, OP-152 m.5 (g)).
pub(crate) fn check_listeners(config: &Config) -> Result<(), ConfigError> {
    let (Some(management), Some(internal)) = (config.management_listen, config.internal_listen)
    else {
        return Err(ConfigError::NoListeners);
    };
    if overlap(config.listen, management)
        || overlap(config.listen, internal)
        || overlap(management, internal)
    {
        return Err(ConfigError::SharedListener);
    }
    if config.tls.is_none() && !management.ip().is_loopback() {
        return Err(ConfigError::AdminWithoutTls);
    }
    Ok(())
}

impl Config {
    pub(crate) fn load() -> Result<Self, ConfigError> {
        // OP-129 m.3
        access_crypto::secret_file::refuse_secret_environment(
            std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()),
        )?;
        let file = std::env::var("ACCESS_CONFIG").unwrap_or_else(|_| "access.toml".to_owned());
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(file))
            .merge(Env::prefixed("ACCESS_").ignore(&["CONFIG"]))
            .extract()
            .map_err(Box::new)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.security_contacts.is_empty() {
            return Err(ConfigError::NoSecurityContact);
        }
        if !(1..=364).contains(&self.security_txt_valid_days) {
            return Err(ConfigError::SecurityTxtValidity);
        }
        // OP-148, OP-151 m.3 (b), §17.9.6
        check_listeners(self)?;
        if self.tls.is_none() {
            return Err(ConfigError::NoTls);
        }
        match &self.issuer {
            Some(i) if Issuer::parse(i).is_ok() => {}
            _ => return Err(ConfigError::Issuer),
        }
        let db = self.database.as_ref().ok_or(ConfigError::NoDatabase)?;
        // OP-53
        if [
            &db.sequencer,
            &db.app,
            &db.deriver,
            &db.router,
            &db.archive,
            &db.outbox_reader,
            &db.checkpointer,
        ]
        .into_iter()
        .chain(db.migrator.as_ref())
        .any(|r| r.pool == 0)
        {
            return Err(ConfigError::PoolSize);
        }
        // OP-143 m.5, CMP-22a
        if self.signer.is_none() {
            return Err(ConfigError::NoSigner);
        }
        if self.hsm.is_none() {
            return Err(ConfigError::NoHsm);
        }
        let identity = self.identity.as_ref().ok_or(ConfigError::NoIdentity)?;
        // OP-138, §17.9.6
        RealmBase::parse(&identity.realm_base).map_err(|_| ConfigError::RealmBase)?;
        if self.login.lifetimes().is_none() {
            return Err(ConfigError::SessionLifetimes);
        }
        let to = &self.login.redirect_to;
        if !to.starts_with('/') || to.starts_with("//") || to.contains('\\') {
            return Err(ConfigError::RedirectTo);
        }
        if !self.suiss.as_ref().is_some_and(Suiss::valid) {
            return Err(ConfigError::Suiss);
        }
        // OP-149 m.23
        let mut urls = BTreeSet::new();
        for t in &self.delivery_targets {
            if DeclaredTarget::new(&t.url, None).is_err() || !urls.insert(t.url.as_str()) {
                return Err(ConfigError::DeliveryTargets);
            }
        }
        // OP-67
        self.telemetry.validate()?;
        // OP-151 m.3 (o)
        if let Some(base) = &self.risk.breach_range_api
            && access_identity_risk::adapters::range_api::RangeApi::new(base, ()).is_err()
        {
            return Err(ConfigError::BreachRangeApi);
        }
        Ok(())
    }

    pub(crate) fn security_txt(&self) -> SecurityTxt {
        SecurityTxt {
            contacts: self.security_contacts.clone(),
            expires: OffsetDateTime::now_utc()
                .saturating_add(Duration::days(i64::from(self.security_txt_valid_days))),
            policy: self.security_policy.clone(),
            preferred_languages: Some("en, tr".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RAUTHY-008, §14.3
    #[test]
    fn default_listen_address_is_loopback() {
        assert!(Config::default().listen.ip().is_loopback());
    }

    fn role(user: &str) -> Role {
        Role {
            user: user.to_owned(),
            password_file: "/run/secrets/db".into(),
            pool: 4,
        }
    }

    fn with_tls() -> Config {
        Config {
            management_listen: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9443))),
            internal_listen: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9090))),
            tls: Some(Tls {
                cert_file: "/run/tls/tls.crt".into(),
                key_file: "/run/tls/tls.key".into(),
                client_ca_file: None,
            }),
            issuer: Some("https://access.example".to_owned()),
            database: Some(Database {
                host: "db.internal".to_owned(),
                port: 5432,
                name: "access".to_owned(),
                root_cert_file: "/run/tls/db-root.pem".into(),
                durability: Durability::Replicated,
                sequencer: role("access_sequencer_login"),
                app: role("access_app_login"),
                deriver: role("access_deriver_login"),
                router: role("access_router_login"),
                archive: role("access_archive_login"),
                outbox_reader: role("access_outbox_reader_login"),
                checkpointer: role("access_checkpointer_login"),
                migrator: None,
                replica_host: None,
            }),
            signer: Some("/run/access/signer.sock".into()),
            hsm: Some(Hsm {
                module: "/usr/lib/softhsm/libsofthsm2.so".into(),
                token: "access".to_owned(),
                pin_file: "/run/secrets/pin".into(),
                paths: Vec::new(),
            }),
            identity: Some(Identity {
                realm_base: "https://id.access.example".to_owned(),
                signer: "/run/access/identity-signer.sock".into(),
                outbound_ca_file: None,
            }),
            suiss: Some(Suiss {
                region: "eu-central".to_owned(),
                relay: "https://relay.example".to_owned(),
                management_api: "https://api.access.example".to_owned(),
                products: BTreeMap::from([("work".to_owned(), "https://work.example".to_owned())]),
                platform_realm: Some("platform".to_owned()),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn defaults_with_tls_are_valid() {
        with_tls().validate().unwrap();
    }

    // TN-36, OP-146 m.14 (c)
    #[test]
    fn login_settings_are_checked() {
        let long = Config {
            login: Login {
                session_absolute_s: 10 * 365 * 86_400,
                ..Login::default()
            },
            ..with_tls()
        };
        assert!(matches!(
            long.validate(),
            Err(ConfigError::SessionLifetimes)
        ));
        for to in ["https://evil.example/", "//evil.example", "/\\evil.example"] {
            let away = Config {
                login: Login {
                    redirect_to: to.to_owned(),
                    ..Login::default()
                },
                ..with_tls()
            };
            assert!(
                matches!(away.validate(), Err(ConfigError::RedirectTo)),
                "{to}"
            );
        }
    }

    // CR-12, OP-52
    #[test]
    fn tls_is_required() {
        let config = Config {
            tls: None,
            ..with_tls()
        };
        assert!(matches!(config.validate(), Err(ConfigError::NoTls)));
    }

    fn listeners(management: &str, internal: &str) -> Config {
        Config {
            management_listen: Some(management.parse().unwrap()),
            internal_listen: Some(internal.parse().unwrap()),
            ..with_tls()
        }
    }

    // OP-151 m.3 (b), CMP-15.5, §17.9.6
    #[test]
    fn the_management_and_internal_listeners_are_required() {
        assert!(matches!(
            Config::default().validate(),
            Err(ConfigError::NoListeners)
        ));
        for (m, i) in [
            (None, Some("127.0.0.1:9090")),
            (Some("127.0.0.1:9443"), None),
        ] {
            let config = Config {
                management_listen: m.map(|a| a.parse().unwrap()),
                internal_listen: i.map(|a| a.parse().unwrap()),
                ..with_tls()
            };
            assert!(matches!(config.validate(), Err(ConfigError::NoListeners)));
        }
    }

    // OP-148, §17.9.6
    #[test]
    fn the_admin_address_is_checked_at_start_up() {
        for (m, i) in [
            ("127.0.0.1:8443", "127.0.0.1:9090"),
            ("0.0.0.0:8443", "127.0.0.1:9090"),
            ("127.0.0.1:9443", "127.0.0.1:8443"),
            ("127.0.0.1:9443", "0.0.0.0:9443"),
        ] {
            assert!(
                matches!(listeners(m, i).validate(), Err(ConfigError::SharedListener)),
                "{m} {i}"
            );
        }
        let config = Config {
            tls: None,
            ..listeners("0.0.0.0:9443", "127.0.0.1:9090")
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::AdminWithoutTls)
        ));
        let config = Config {
            tls: None,
            ..listeners("127.0.0.1:9443", "127.0.0.1:9090")
        };
        assert!(matches!(config.validate(), Err(ConfigError::NoTls)));
    }

    // TI-9, OP-152 m.5 (g)
    #[test]
    fn the_internal_listener_has_no_plain_text_switch() {
        for key in ["internal_plain = true", "internal_plain = false"] {
            let result: Result<Config, _> = Figment::from(Serialized::defaults(with_tls()))
                .merge(Toml::string(key))
                .extract();
            assert!(result.is_err(), "{key}");
        }
    }

    #[test]
    fn empty_security_contact_is_rejected() {
        let config = Config {
            security_contacts: Vec::new(),
            ..with_tls()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::NoSecurityContact)
        ));
    }

    // OP-141 m.18 (g), (h), (i)
    #[test]
    fn the_authority_plane_is_not_optional() {
        let no_db = Config {
            database: None,
            ..with_tls()
        };
        assert!(matches!(no_db.validate(), Err(ConfigError::NoDatabase)));
        let no_hsm = Config {
            hsm: None,
            ..with_tls()
        };
        assert!(matches!(no_hsm.validate(), Err(ConfigError::NoHsm)));
        for issuer in [None, Some("http://a.example"), Some("https://a.example/")] {
            let config = Config {
                issuer: issuer.map(str::to_owned),
                ..with_tls()
            };
            assert!(matches!(config.validate(), Err(ConfigError::Issuer)));
        }
    }

    // OP-138, TN-10, §17.9.6, CMP-22b
    #[test]
    fn the_identity_plane_is_not_optional() {
        let none = Config {
            identity: None,
            ..with_tls()
        };
        assert!(matches!(none.validate(), Err(ConfigError::NoIdentity)));
        for base in [
            "http://id.example",
            "https://id.example/",
            "https://id.example/realms",
            "https://ID.example",
            "https://id.example?x",
        ] {
            let config = Config {
                identity: Some(Identity {
                    realm_base: base.to_owned(),
                    signer: "/run/s.sock".into(),
                    outbound_ca_file: None,
                }),
                ..with_tls()
            };
            assert!(
                matches!(config.validate(), Err(ConfigError::RealmBase)),
                "{base}"
            );
        }
    }

    // OP-149 m.3, E42
    #[test]
    fn the_suiss_section_is_checked() {
        let none = Config {
            suiss: None,
            ..with_tls()
        };
        assert!(matches!(none.validate(), Err(ConfigError::Suiss)));
        let bad = |f: fn(&mut Suiss)| {
            let mut c = with_tls();
            if let Some(s) = c.suiss.as_mut() {
                f(s);
            }
            matches!(c.validate(), Err(ConfigError::Suiss))
        };
        assert!(bad(|s| s.region = "EU".to_owned()));
        assert!(bad(|s| s.region = "-eu".to_owned()));
        assert!(bad(|s| s.relay = "http://relay.example".to_owned()));
        assert!(bad(|s| s.management_api = "https://api.example/".to_owned()));
        assert!(bad(|s| {
            s.products
                .insert("Work".to_owned(), "https://w.example".to_owned());
        }));
    }

    // OP-69, OP-149 m.21, OP-55
    #[test]
    fn the_local_deployment_configuration_is_valid() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/access/access.toml"
        );
        let config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file_exact(path))
            .extract()
            .unwrap();
        config.validate().unwrap();
        assert!(config.database.and_then(|d| d.migrator).is_some());
    }

    // OP-149 m.23, TI-9, OP-69
    #[test]
    fn delivery_targets_are_declared_exactly() {
        assert!(with_tls().delivery_targets.is_empty());
        let env: figment::value::Value =
            r#"[{url="https://work-server:8443/v1/inbound/events", ca_file="/var/lib/access/certs/ca.crt"}]"#
                .parse()
                .unwrap();
        let config: Config = Figment::from(Serialized::defaults(with_tls()))
            .merge(Serialized::default("delivery_targets", env))
            .extract()
            .unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.delivery_targets.first().map(|t| t.url.as_str()),
            Some("https://work-server:8443/v1/inbound/events")
        );
        let empty: figment::value::Value = "[]".parse().unwrap();
        let config: Config = Figment::from(Serialized::defaults(with_tls()))
            .merge(Serialized::default("delivery_targets", empty))
            .extract()
            .unwrap();
        assert!(config.delivery_targets.is_empty());
        let target = |url: &str| DeliveryTarget {
            url: url.to_owned(),
            ca_file: None,
        };
        for bad in [
            vec![target("http://work-server:8443/v1/inbound/events")],
            vec![target("https://Work-Server:8443/v1/inbound/events")],
            vec![target("https://work-server:8443")],
            vec![target("https://u@work-server:8443/v1/inbound/events")],
            vec![target("https://work-server:8443/v1/inbound/events#x")],
            vec![
                target("https://work-server:8443/v1/inbound/events"),
                target("https://work-server:8443/v1/inbound/events"),
            ],
        ] {
            let config = Config {
                delivery_targets: bad,
                ..with_tls()
            };
            assert!(matches!(
                config.validate(),
                Err(ConfigError::DeliveryTargets)
            ));
        }
        let result: Result<Config, _> = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string(
                "delivery_targets = [{ url = \"https://a.example/x\", insecure = true }]",
            ))
            .extract();
        assert!(result.is_err());
    }

    // A-9, OP-53
    #[test]
    fn every_pool_has_a_connection() {
        let empty = |f: fn(&mut Database)| {
            let mut c = with_tls();
            if let Some(db) = c.database.as_mut() {
                f(db);
            }
            matches!(c.validate(), Err(ConfigError::PoolSize))
        };
        assert!(empty(|d| d.sequencer.pool = 0));
        assert!(empty(|d| d.app.pool = 0));
        assert!(empty(|d| d.deriver.pool = 0));
        assert!(empty(|d| d.router.pool = 0));
        assert!(empty(|d| d.archive.pool = 0));
        assert!(empty(|d| d.outbox_reader.pool = 0));
        assert!(empty(|d| d.checkpointer.pool = 0));
        assert!(empty(|d| {
            d.migrator = Some(Role {
                user: "access_migrator_login".to_owned(),
                password_file: "/run/secrets/db".into(),
                pool: 0,
            });
        }));
    }

    // A-3, OP-143 m.5, CMP-22a, MD-8
    #[test]
    fn the_authority_signer_is_required() {
        let config = Config {
            signer: None,
            ..with_tls()
        };
        assert!(matches!(config.validate(), Err(ConfigError::NoSigner)));
    }

    // OP-63, TI-9
    #[test]
    fn unknown_configuration_key_is_rejected() {
        let result: Result<Config, _> = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::string("dev_mode = true"))
            .extract();
        assert!(result.is_err());
    }
}
