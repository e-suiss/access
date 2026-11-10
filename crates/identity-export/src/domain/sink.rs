//! Export sinks as administrators declare them (OP-156 m.3 (a), (s)): `idp.export.sink_register`
//! (CT2), `sink_update` (CT2) and `sink_retire` (CT1). A body names the adapter, where the copy
//! goes, the adapter's settings and, write-only, its secret. Every adapter's settings are checked
//! here, before the change is decided. Sans-I/O.

use access_identity_oauth::adapters::outbound::Target;
use access_internal_api::idp::IdpAction;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;
use zeroize::Zeroizing;

use super::Invalid;

/// Where and how the copy goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adapter {
    /// OCSF Parquet objects on S3 or Amazon Security Lake.
    S3Parquet,
    /// OTLP/HTTP log records.
    Otlp,
    /// An HTTP event collector, plain or with a vendor preset.
    Collector,
    /// Syslog over TLS (RFC 5424, RFC 5425).
    Syslog,
}

impl Adapter {
    /// Its name in bodies and in the store.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::S3Parquet => "s3_parquet",
            Self::Otlp => "otlp",
            Self::Collector => "collector",
            Self::Syslog => "syslog",
        }
    }

    /// The adapter named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::S3Parquet, Self::Otlp, Self::Collector, Self::Syslog]
            .into_iter()
            .find(|a| a.name() == s)
    }
}

/// The HTTP collector's data presets (OP-156 m.3 (s)); no licence gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// Splunk HTTP Event Collector.
    Splunk,
    /// Microsoft Sentinel through the Logs Ingestion API.
    Sentinel,
    /// Datadog Logs.
    Datadog,
    /// Elasticsearch `_bulk`.
    Elastic,
}

impl Preset {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Splunk => "splunk",
            Self::Sentinel => "sentinel",
            Self::Datadog => "datadog",
            Self::Elastic => "elastic",
        }
    }

    /// The preset named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Splunk, Self::Sentinel, Self::Datadog, Self::Elastic]
            .into_iter()
            .find(|p| p.name() == s)
    }
}

/// The syslog message format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `ArcSight` Common Event Format.
    Cef,
    /// IBM `QRadar` Log Event Extended Format 2.0.
    Leef,
}

impl Format {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cef => "cef",
            Self::Leef => "leef",
        }
    }

    /// The format named `s`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Cef, Self::Leef].into_iter().find(|f| f.name() == s)
    }
}

/// A sink's secret: an S3 secret access key, a collector token or client secret. Write-only:
/// never shown, logged or echoed (OP-64).
#[derive(Clone, PartialEq, Eq)]
pub struct SinkSecret(Zeroizing<String>);

impl SinkSecret {
    /// The secret's text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A secret from its text.
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self(Zeroizing::new(String::from(s)))
    }
}

impl core::fmt::Debug for SinkSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SinkSecret(..)")
    }
}

/// A sink's declaration without its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkSpec {
    /// The adapter.
    pub adapter: Adapter,
    /// The collector's preset.
    pub preset: Option<Preset>,
    /// The syslog format.
    pub format: Option<Format>,
    /// An `https` URL, or `host:port` for syslog.
    pub endpoint: String,
    /// The adapter's settings.
    pub settings: Map<String, Json>,
}

/// One `idp.export.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportChange {
    /// `registerExportSink`: `idp.export.sink_register`.
    Register {
        /// The sink's name.
        name: String,
        /// Its declaration.
        spec: SinkSpec,
        /// Its secret.
        secret: Option<SinkSecret>,
    },
    /// `putExportSink`: `idp.export.sink_update`; without a secret the current one stays.
    Update {
        /// The sink's name.
        name: String,
        /// Its new declaration.
        spec: SinkSpec,
        /// Its new secret.
        secret: Option<SinkSecret>,
    },
    /// `retireExportSink`: `idp.export.sink_retire`.
    Retire(String),
}

const MAX_SECRET: usize = 4096;

fn name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    (1..=63).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn text<'a>(m: &'a Map<String, Json>, key: &str) -> Option<&'a str> {
    m.get(key).and_then(Json::as_str)
}

fn https(url: &str) -> bool {
    Target::parse(url).is_ok() && !url.contains('#')
}

/// The host and port of a syslog `host:port` endpoint.
#[must_use]
pub fn host_port(endpoint: &str) -> Option<(&str, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.');
    ok.then_some((host, port))
}

fn only(m: &Map<String, Json>, allowed: &[&str]) -> Result<(), Invalid> {
    if m.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Invalid::Settings)
    }
}

fn need(m: &Map<String, Json>, keys: &[&str]) -> Result<(), Invalid> {
    let ok = keys
        .iter()
        .all(|k| text(m, k).is_some_and(|v| !v.is_empty() && v.len() <= 256));
    if ok { Ok(()) } else { Err(Invalid::Settings) }
}

fn short_texts(m: &Map<String, Json>, keys: &[&str]) -> Result<(), Invalid> {
    let ok = keys.iter().all(|k| match m.get(*k) {
        None => true,
        Some(Json::String(v)) => v.len() <= 256 && v.bytes().all(|c| c.is_ascii_graphic()),
        Some(_) => false,
    });
    if ok { Ok(()) } else { Err(Invalid::Settings) }
}

fn s3_settings(m: &Map<String, Json>) -> Result<(), Invalid> {
    only(
        m,
        &[
            "bucket",
            "region",
            "access_key_id",
            "prefix",
            "account_id",
            "path_style",
        ],
    )?;
    need(m, &["bucket", "region", "access_key_id"])?;
    short_texts(
        m,
        &["bucket", "region", "access_key_id", "prefix", "account_id"],
    )?;
    let bucket_ok = text(m, "bucket").is_some_and(|b| {
        (3..=63).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
    });
    let account_ok = text(m, "account_id")
        .is_none_or(|a| a.len() == 12 && a.bytes().all(|c| c.is_ascii_digit()));
    let prefix_ok = text(m, "prefix").is_none_or(|p| {
        p.ends_with('/')
            && !p.starts_with('/')
            && p.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'-' | b'_' | b'.'))
    });
    let style_ok = m.get("path_style").is_none_or(Json::is_boolean);
    if bucket_ok && account_ok && prefix_ok && style_ok {
        Ok(())
    } else {
        Err(Invalid::Settings)
    }
}

impl SinkSpec {
    /// Checks the declaration and whether `secret` is given where the adapter needs one.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, has_secret: bool) -> Result<(), Invalid> {
        let m = &self.settings;
        match (self.adapter, self.preset, self.format) {
            (Adapter::Syslog, None, Some(_)) => {
                host_port(&self.endpoint).ok_or(Invalid::Endpoint)?;
                only(m, &["app_name", "hostname"])?;
                short_texts(m, &["app_name", "hostname"])?;
                if has_secret {
                    return Err(Invalid::Secret);
                }
                return Ok(());
            }
            (Adapter::Syslog, ..) | (_, _, Some(_)) => return Err(Invalid::Settings),
            _ => {}
        }
        if !https(&self.endpoint) {
            return Err(Invalid::Endpoint);
        }
        let secret_needed = match (self.adapter, self.preset) {
            (Adapter::S3Parquet, None) => {
                s3_settings(m)?;
                true
            }
            (Adapter::Otlp | Adapter::Collector, None) => {
                only(m, &["auth_header"])?;
                short_texts(m, &["auth_header"])?;
                let header_ok = text(m, "auth_header").is_none_or(|h| {
                    !h.is_empty() && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                });
                if !header_ok {
                    return Err(Invalid::Settings);
                }
                false
            }
            (Adapter::Collector, Some(Preset::Splunk)) => {
                only(m, &["index", "source", "sourcetype"])?;
                short_texts(m, &["index", "source", "sourcetype"])?;
                true
            }
            (Adapter::Collector, Some(Preset::Sentinel)) => {
                only(
                    m,
                    &[
                        "dcr_immutable_id",
                        "stream",
                        "tenant_id",
                        "client_id",
                        "token_url",
                    ],
                )?;
                need(m, &["dcr_immutable_id", "stream", "tenant_id", "client_id"])?;
                short_texts(m, &["dcr_immutable_id", "stream", "tenant_id", "client_id"])?;
                let token_ok = match m.get("token_url") {
                    None => true,
                    Some(Json::String(u)) => https(u),
                    Some(_) => false,
                };
                if !token_ok {
                    return Err(Invalid::Settings);
                }
                true
            }
            (Adapter::Collector, Some(Preset::Datadog)) => {
                only(m, &["service", "tags"])?;
                short_texts(m, &["service", "tags"])?;
                true
            }
            (Adapter::Collector, Some(Preset::Elastic)) => {
                only(m, &["index"])?;
                need(m, &["index"])?;
                short_texts(m, &["index"])?;
                true
            }
            _ => return Err(Invalid::Settings),
        };
        if secret_needed && !has_secret {
            return Err(Invalid::Secret);
        }
        Ok(())
    }

    /// The settings' JSON text, as stored.
    #[must_use]
    pub fn settings_text(&self) -> String {
        Json::Object(self.settings.clone()).to_string()
    }
}

fn spec_of(m: &Map<String, Json>) -> Result<SinkSpec, Invalid> {
    let adapter = text(m, "adapter")
        .and_then(Adapter::parse)
        .ok_or(Invalid::Settings)?;
    let preset = match m.get("preset") {
        None | Some(Json::Null) => None,
        Some(Json::String(p)) => Some(Preset::parse(p).ok_or(Invalid::Settings)?),
        Some(_) => return Err(Invalid::Settings),
    };
    let format = match m.get("format") {
        None | Some(Json::Null) => None,
        Some(Json::String(f)) => Some(Format::parse(f).ok_or(Invalid::Settings)?),
        Some(_) => return Err(Invalid::Settings),
    };
    let endpoint = text(m, "endpoint")
        .filter(|e| !e.is_empty() && e.len() <= 2048)
        .ok_or(Invalid::Endpoint)?;
    let settings = match m.get("settings") {
        None => Map::new(),
        Some(Json::Object(o)) => o.clone(),
        Some(_) => return Err(Invalid::Settings),
    };
    Ok(SinkSpec {
        adapter,
        preset,
        format,
        endpoint: String::from(endpoint),
        settings,
    })
}

fn secret_of(m: &Map<String, Json>) -> Result<Option<SinkSecret>, Invalid> {
    match m.get("secret") {
        None => Ok(None),
        Some(Json::String(s))
            if !s.is_empty()
                && s.len() <= MAX_SECRET
                && s.bytes().all(|c| c.is_ascii_graphic()) =>
        {
            Ok(Some(SinkSecret::new(s)))
        }
        Some(_) => Err(Invalid::Secret),
    }
}

impl ExportChange {
    /// `registerExportSink`: `{name, adapter, preset?, format?, endpoint, settings?, secret?}`.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn register(body: &Json) -> Result<Self, Invalid> {
        let m = body.as_object().ok_or(Invalid::Settings)?;
        only(
            m,
            &[
                "name", "adapter", "preset", "format", "endpoint", "settings", "secret",
            ],
        )?;
        let name = text(m, "name")
            .filter(|n| name_ok(n))
            .ok_or(Invalid::Name)?;
        let spec = spec_of(m)?;
        let secret = secret_of(m)?;
        spec.check(secret.is_some())?;
        Ok(Self::Register {
            name: String::from(name),
            spec,
            secret,
        })
    }

    /// `putExportSink` of `name`: the declaration as registered, without `name`; without a
    /// `secret` the current one stays.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn update(name: &str, body: &Json) -> Result<Self, Invalid> {
        let m = body.as_object().ok_or(Invalid::Settings)?;
        only(
            m,
            &[
                "adapter", "preset", "format", "endpoint", "settings", "secret",
            ],
        )?;
        if !name_ok(name) {
            return Err(Invalid::Name);
        }
        let spec = spec_of(m)?;
        let secret = secret_of(m)?;
        Ok(Self::Update {
            name: String::from(name),
            spec,
            secret,
        })
    }

    /// `retireExportSink` of `name`: `{}`.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn retire(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !name_ok(name) {
            return Err(Invalid::Name);
        }
        if !body.as_object().is_some_and(Map::is_empty) {
            return Err(Invalid::Settings);
        }
        Ok(Self::Retire(String::from(name)))
    }

    /// The action.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register { .. } => IdpAction::ExportSinkRegister,
            Self::Update { .. } => IdpAction::ExportSinkUpdate,
            Self::Retire(_) => IdpAction::ExportSinkRetire,
        }
    }

    /// The sink's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Register { name, .. } | Self::Update { name, .. } | Self::Retire(name) => name,
        }
    }

    /// Checks the change on its own; an update's secret need is checked against the stored one.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self) -> Result<(), Invalid> {
        if !name_ok(self.name()) {
            return Err(Invalid::Name);
        }
        match self {
            Self::Register { spec, secret, .. } => spec.check(secret.is_some()),
            Self::Update { spec, secret, .. } => spec.check(secret.is_some()).or_else(|e| {
                if e == Invalid::Secret && secret.is_none() {
                    Ok(())
                } else {
                    Err(e)
                }
            }),
            Self::Retire(_) => Ok(()),
        }
    }

    /// The change body the intent digests: the declaration and the secret's digest, never the
    /// secret.
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        let spec_body = |spec: &SinkSpec, secret: Option<&SinkSecret>| {
            let mut e = vec![
                ("adapter", Value::text(spec.adapter.name())),
                ("endpoint", Value::text(&spec.endpoint)),
                ("settings", Value::text(&spec.settings_text())),
            ];
            if let Some(p) = spec.preset {
                e.push(("preset", Value::text(p.name())));
            }
            if let Some(f) = spec.format {
                e.push(("format", Value::text(f.name())));
            }
            if let Some(s) = secret {
                e.push((
                    "secret_digest",
                    Value::Bytes(
                        suiss_crypto::digest::context_digest(
                            "access/export-secret-digest/v1",
                            s.expose().as_bytes(),
                        )
                        .0
                        .to_vec(),
                    ),
                ));
            }
            e
        };
        match self {
            Self::Register { name, spec, secret } | Self::Update { name, spec, secret } => {
                let mut e = vec![("name", Value::text(name))];
                e.extend(spec_body(spec, secret.as_ref()));
                m(e)
            }
            Self::Retire(name) => m(vec![("retire", Value::text(name))]),
        }
    }

    /// The resource path below the realm.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        vec![String::from("export-sink"), String::from(self.name())]
    }
}

#[cfg(test)]
mod tests;
