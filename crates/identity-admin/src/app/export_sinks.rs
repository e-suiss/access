//! `idp.export.*` changes against the realm and under their committed ALLOW (OP-156 m.3 (a),
//! (s)), and the export sinks as administrators read them. A sink's secret is sealed under the
//! realm KEK in the same transaction and never read back here; a retired sink keeps its name and
//! its cursor (OP-73). The list shows each sink's delivery state; what it holds is a copy, not
//! the record (X22).

use access_identity_export::domain::copy;
use access_identity_export::domain::secret::seal;
use access_identity_export::domain::sink::{Adapter, ExportChange, SinkSpec, host_port};
use access_identity_hooks::ports::KeyVault;
use access_identity_oauth::adapters::outbound::{DeclaredTargets, SYSLOG_TLS_PORT};
use access_store::export::{self as store, NewSink, SinkRow};
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use serde_json::{Value as Json, json};

use crate::AdminError;
use crate::domain::Invalid;

fn invalid(_: access_identity_export::domain::Invalid) -> Invalid {
    Invalid::ExportSink
}

/// Whether Access may reach the sink: an `https` endpoint on port 443 or declared, a syslog
/// receiver on port 6514 or at a declared target's host and port (§14.3, OP-149 m.23).
fn reachable(spec: &SinkSpec, declared: &DeclaredTargets) -> bool {
    if spec.adapter == Adapter::Syslog {
        return host_port(&spec.endpoint).is_some_and(|(host, port)| {
            port == SYSLOG_TLS_PORT || declared.declares(&format!("https://{host}:{port}/"))
        });
    }
    let https = |url: &str| {
        let slashed = format!("{}/", url.trim_end_matches('/'));
        declared.accepts(url)
            || declared
                .urls()
                .iter()
                .any(|d| d.ends_with('/') && (url.starts_with(d.as_str()) || slashed == *d))
    };
    let token_ok = spec
        .settings
        .get("token_url")
        .and_then(Json::as_str)
        .is_none_or(https);
    https(&spec.endpoint) && token_ok
}

fn sink_id(name: &str, exercise: &[u8]) -> [u8; 16] {
    let mut input = b"access/export-sink\0".to_vec();
    input.extend_from_slice(name.as_bytes());
    input.push(0);
    input.extend_from_slice(exercise);
    let d = suiss_crypto::digest::sha256(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

/// What must hold now for `change`: a new sink's name was never used; an updated or retired one
/// is live; the sink is one Access may reach, and has the secret its adapter needs.
///
/// # Errors
/// [`Invalid`]; [`AdminError`].
pub(crate) async fn current(
    t: &mut TenantTx,
    change: &ExportChange,
    declared: &DeclaredTargets,
) -> Result<(), AdminError> {
    change.check().map_err(invalid)?;
    let stored = store::sink(t, change.name()).await?;
    match change {
        ExportChange::Register { spec, .. } => {
            if stored.is_some() {
                return Err(Invalid::ExportSinkExists.into());
            }
            if !reachable(spec, declared) {
                return Err(Invalid::ExportSink.into());
            }
        }
        ExportChange::Update { spec, secret, .. } => {
            let s = stored
                .filter(|s| s.state == "live")
                .ok_or(Invalid::NoExportSink)?;
            spec.check(secret.is_some() || s.secret.is_some())
                .map_err(invalid)?;
            if !reachable(spec, declared) {
                return Err(Invalid::ExportSink.into());
            }
        }
        ExportChange::Retire(_) => {
            if !stored.is_some_and(|s| s.state == "live") {
                return Err(Invalid::NoExportSink.into());
            }
        }
    }
    Ok(())
}

/// Writes `change` under `bound`, sealing a new secret with `vault`'s realm KEK.
///
/// # Errors
/// [`AdminError`]; without the realm KEK no secret is stored.
pub(crate) async fn write(
    t: &mut TenantTx,
    bound: &Bound,
    change: &ExportChange,
    vault: Option<&dyn KeyVault>,
) -> Result<bool, AdminError> {
    let tenant = t.tenant();
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let stored = store::sink(t, change.name()).await?;
    let (id, spec, secret, state) = match change {
        ExportChange::Register { name, spec, secret } => (
            sink_id(name, &bound.position().to_be_bytes()),
            spec.clone(),
            secret.as_ref(),
            "live",
        ),
        ExportChange::Update { spec, secret, .. } => {
            let s = stored.as_ref().ok_or(Invalid::NoExportSink)?;
            (s.id, spec.clone(), secret.as_ref(), "live")
        }
        ExportChange::Retire(_) => {
            let s = stored.as_ref().ok_or(Invalid::NoExportSink)?;
            let spec = access_identity_export::app::spec_of(s)
                .map_err(|_| AdminError::Store(access_store::StoreError::Corrupt))?;
            (s.id, spec, None, "retired")
        }
    };
    let sealed = match secret {
        Some(secret) => {
            let kek = vault
                .and_then(|v| v.realm_kek(tenant, realm))
                .ok_or_else(|| AdminError::Unavailable(String::from("kek")))?;
            Some(
                seal(&*kek, (tenant, realm), &id, secret)
                    .map_err(|_| AdminError::Unavailable(String::from("kek")))?,
            )
        }
        None if state == "live" => stored.as_ref().and_then(|s| s.secret.clone()),
        None => None,
    };
    let settings = spec.settings_text();
    store::write(
        t,
        bound,
        &NewSink {
            id,
            name: change.name(),
            state,
            adapter: spec.adapter.name(),
            preset: spec.preset.map(|p| p.name()),
            format: spec.format.map(|f| f.name()),
            endpoint: &spec.endpoint,
            settings: &settings,
            secret: sealed.as_ref(),
        },
    )
    .await?;
    Ok(true)
}

fn rfc3339(ms: Option<u64>) -> Json {
    ms.map_or(Json::Null, |ms| Json::from(super::rest::rfc3339(ms)))
}

fn item(s: &SinkRow, c: Option<&store::CursorRow>) -> Json {
    let settings: Json = serde_json::from_str(&s.settings).unwrap_or_else(|_| json!({}));
    let changed_ms = u64::try_from(s.changed_at)
        .ok()
        .and_then(|v| v.checked_mul(1000));
    json!({
        "name": s.name,
        "adapter": s.adapter,
        "preset": s.preset,
        "format": s.format,
        "endpoint": s.endpoint,
        "settings": settings,
        "has_secret": s.secret.is_some(),
        "status": s.state,
        "version": s.version,
        "changed_at": rfc3339(changed_ms),
        "record": copy::VALUE,
        "delivery": c.map_or(Json::Null, |c| json!({
            "sent": c.sent.to_string(),
            "failures": c.failures,
            "failing_since": rfc3339(c.failed_since_ms),
            "last_error": c.last_error,
            "last_sent_at": rfc3339(c.sent_at_ms),
        })),
    })
}

/// The realm's export sinks, by name, with their delivery state; with `key`, only that one.
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn list(
    t: &mut TenantTx,
    key: Option<&str>,
) -> Result<Vec<(Json, u64)>, AdminError> {
    let mut out = Vec::new();
    for s in store::sinks(t).await? {
        if key.is_some_and(|k| k != s.name) {
            continue;
        }
        let c = store::cursor(t, s.id).await?;
        out.push((item(&s, c.as_ref()), s.decision_pos));
    }
    Ok(out)
}
