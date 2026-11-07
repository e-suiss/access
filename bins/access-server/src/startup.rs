//! The start-up report (OP-148, OP-138, §17.9.6, §17.9.7, MD-8): before the server serves, it
//! checks that its issuer and management origin are in their one form and covered by its TLS
//! certificate, that the admin interface is on its own listener, that the signers answer and
//! every realm's issuer and JWKS load. It writes one structured line, `event =
//! "startup.checks"`, naming every check, and refuses to serve when any failed.

use std::path::Path;

use access_identity_oauth::app::StartupError;
use access_identity_oauth::domain::issuer::{Issuer, RealmBase};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, ServerName};

use crate::config::Config;

/// One check: its name and, when it failed, a reason without secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Check {
    /// The check.
    pub(crate) name: &'static str,
    /// Why it failed; `None` when it passed.
    pub(crate) failure: Option<String>,
}

/// The checks of one start, in the order they ran.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Report(Vec<Check>);

impl Report {
    /// Records the outcome of `name`.
    pub(crate) fn record(&mut self, name: &'static str, outcome: Result<(), String>) {
        self.0.push(Check {
            name,
            failure: outcome.err(),
        });
    }

    /// Whether every check passed.
    pub(crate) fn passed(&self) -> bool {
        self.0.iter().all(|c| c.failure.is_none())
    }

    /// The names of the failed checks.
    pub(crate) fn failed(&self) -> Vec<&'static str> {
        self.0
            .iter()
            .filter(|c| c.failure.is_some())
            .map(|c| c.name)
            .collect()
    }

    /// Writes the one report line (OP-67: no secrets, no tenant labels).
    pub(crate) fn emit(&self) {
        let checks: Vec<&str> = self.0.iter().map(|c| c.name).collect();
        if self.passed() {
            tracing::info!(
                event = "startup.checks",
                outcome = "success",
                passed = true,
                checks = ?checks,
                failed = ?Vec::<&str>::new(),
                "start-up checks passed"
            );
        } else {
            let reasons: Vec<String> = self
                .0
                .iter()
                .filter_map(|c| c.failure.as_ref().map(|f| format!("{}: {f}", c.name)))
                .collect();
            tracing::error!(
                event = "startup.checks",
                outcome = "failure",
                passed = false,
                checks = ?checks,
                failed = ?self.failed(),
                reasons = ?reasons,
                "start-up checks failed; refusing to serve (MD-8)"
            );
        }
    }

    /// `Ok` when every check passed; otherwise the failed checks (MD-8).
    pub(crate) fn into_result(self) -> Result<(), String> {
        if self.passed() {
            Ok(())
        } else {
            Err(format!(
                "start-up checks failed: {}",
                self.failed().join(", ")
            ))
        }
    }
}

fn host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// The hosts the server answers as: the ADP issuer and the management origin, each parsed in
/// its one form (L1-ADP-11, §17.9.6).
///
/// # Errors
/// What does not parse.
pub(crate) fn origins(config: &Config) -> Result<Vec<String>, String> {
    let issuer = config.issuer.as_deref().ok_or("no issuer")?;
    let issuer = Issuer::parse(issuer).map_err(|_| "issuer is not an https origin".to_owned())?;
    let management = config
        .suiss
        .as_ref()
        .map(|s| s.management_api.as_str())
        .ok_or("no management_api")?;
    let management = Issuer::parse(management)
        .map_err(|_| "management_api is not an https origin".to_owned())?;
    if let Some(identity) = &config.identity {
        RealmBase::parse(&identity.realm_base)
            .map_err(|_| "identity.realm_base is not an https origin".to_owned())?;
    }
    let mut hosts = vec![
        host(issuer.authority()).to_owned(),
        host(management.authority()).to_owned(),
    ];
    hosts.dedup();
    Ok(hosts)
}

/// Whether the leaf of the PEM certificate chain `chain_pem` is valid for every one of `hosts`
/// (RFC 6125 through webpki).
///
/// # Errors
/// The first host it does not cover, or a chain that does not parse.
pub(crate) fn covered(chain_pem: &[u8], hosts: &[String]) -> Result<(), String> {
    let leaf = CertificateDer::pem_slice_iter(chain_pem)
        .next()
        .ok_or("no certificate")?
        .map_err(|_| "the certificate chain does not parse".to_owned())?;
    let cert = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|_| "the leaf certificate does not parse".to_owned())?;
    for h in hosts {
        let name = ServerName::try_from(h.as_str()).map_err(|_| format!("{h} is not a name"))?;
        cert.verify_is_valid_for_subject_name(&name)
            .map_err(|_| format!("{h} is not in the certificate's subject names"))?;
    }
    Ok(())
}

/// The TLS check: the configured origins are in their one form and the certificate covers
/// them. The chain is read before the lockdown closes the file system.
///
/// # Errors
/// Why the origins or the certificate do not fit.
pub(crate) fn tls_names(config: &Config, chain_pem: &[u8]) -> Result<(), String> {
    covered(chain_pem, &origins(config)?)
}

/// Whether the authority signer's socket accepts a connection, when one is configured.
///
/// # Errors
/// Why it does not.
pub(crate) async fn authority_signer(socket: Option<&Path>) -> Result<(), String> {
    let Some(path) = socket else {
        return Ok(());
    };
    tokio::net::UnixStream::connect(path)
        .await
        .map(drop)
        .map_err(|e| format!("{}: {}", path.display(), e.kind()))
}

/// The identity plane's checks as report entries (OP-138, §17.9.7, CMP-22b).
pub(crate) fn identity(outcome: &Result<usize, StartupError>, report: &mut Report) {
    let fail = |e: &StartupError| Err(e.to_string());
    let (signer, issuers, jwks) = match outcome {
        Ok(_) => (Ok(()), Ok(()), Ok(())),
        Err(e @ StartupError::Issuer(_)) => (Ok(()), fail(e), Err("not checked".to_owned())),
        Err(e @ StartupError::Jwks(_)) => (Ok(()), Ok(()), fail(e)),
        Err(e) => (
            fail(e),
            Err("not checked".to_owned()),
            Err("not checked".to_owned()),
        ),
    };
    report.record("identity-signer", signer);
    report.record("realm-issuers", issuers);
    report.record("realm-jwks", jwks);
}

#[cfg(test)]
mod tests;
