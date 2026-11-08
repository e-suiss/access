//! The ports over the real world: providers through the SSRF-guarded outbound client (§14.3)
//! and client secrets from files the operator mounts (a Kubernetes `Secret` volume).

use std::path::PathBuf;

use access_crypto::Secret;
use access_identity_oauth::adapters::outbound::Outbound;

use crate::domain::token::MAX_ANSWER;
use crate::ports::{Answer, ProviderHttp, SocialSecrets, Unreachable};

const JSON: &str = "application/json";

/// Providers over [`Outbound`]: `https` on 443, public addresses only, no redirects.
pub struct OutboundProviders(pub Outbound);

impl ProviderHttp for OutboundProviders {
    async fn get_json(&self, url: &str, bearer: Option<&str>) -> Result<Answer, Unreachable> {
        let a = match bearer {
            Some(t) => self.0.get_bearer(url, JSON, t, MAX_ANSWER).await,
            None => self.0.get(url, JSON, MAX_ANSWER).await,
        }
        .map_err(|_| Unreachable)?;
        Ok((a.status, a.body))
    }

    async fn post_form(&self, url: &str, form: &str) -> Result<Answer, Unreachable> {
        let headers = [("Accept", String::from(JSON))];
        let a = self
            .0
            .post_reading(
                url,
                "application/x-www-form-urlencoded",
                &headers,
                form.as_bytes(),
                MAX_ANSWER,
            )
            .await
            .map_err(|_| Unreachable)?;
        Ok((a.status, a.body))
    }
}

/// Secrets as files under one directory: `secret://social/google` is `<dir>/social/google`.
/// No directory configured answers [`Unreachable`] for every reference (MD-8).
pub struct FileSecrets(pub Option<PathBuf>);

fn path_of(reference: &str) -> Option<&str> {
    let rest = reference.strip_prefix("secret://")?;
    let ok = !rest.is_empty()
        && rest.len() <= 246
        && rest.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        });
    ok.then_some(rest)
}

impl SocialSecrets for FileSecrets {
    async fn secret(&self, reference: &str) -> Result<Secret<String>, Unreachable> {
        let (Some(dir), Some(rel)) = (&self.0, path_of(reference)) else {
            return Err(Unreachable);
        };
        let text = tokio::fs::read_to_string(dir.join(rel))
            .await
            .map_err(|_| Unreachable)?;
        let value = text.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            return Err(Unreachable);
        }
        Ok(Secret::new(String::from(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // §14.3, OP-153 m.3 (l)
    #[test]
    fn a_reference_cannot_leave_the_secret_directory() {
        assert_eq!(path_of("secret://social/google"), Some("social/google"));
        assert_eq!(path_of("secret://../etc/passwd"), None);
        assert_eq!(path_of("secret://a//b"), None);
        assert_eq!(path_of("secret:///abs"), None);
        assert_eq!(path_of("file:///x"), None);
    }
}
