//! A platform client's stream status (SSF 1.0 §8.1.2, OP-149 m.19 (f), m.26 (c)) through the
//! platform routes, and its service token for another product (OP-149 m.31 (a)) at the realm's
//! token endpoint, both authenticated by an RFC 7523 client assertion the product's client key
//! signs (OP-149 m.19 (e)).

use serde_json::{Value, json};

use crate::ClientError;
use crate::dpop::Es256Key;
use crate::http::Http;
use crate::login::form;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The platform client.
pub struct PlatformClient<'a> {
    /// The deployment's API base, e.g. `https://access-server:8443`.
    pub api_base: &'a str,
    /// The platform realm's issuer: the assertion's `aud`.
    pub issuer: &'a str,
    /// The `client_id`.
    pub client_id: &'a str,
    /// The client key, from the product's private JWK.
    pub key: &'a Es256Key,
}

/// A status change.
pub struct StatusChange<'a> {
    /// `enabled`, `paused` or `disabled`.
    pub status: &'a str,
    /// Why, free text.
    pub reason: Option<&'a str>,
}

impl PlatformClient<'_> {
    fn authorization(&self) -> Result<String, ClientError> {
        Ok(format!(
            "Bearer {}",
            self.key.assertion(self.client_id, self.issuer)?
        ))
    }

    /// `GET`, or with `change` `POST`, `/access/v1/platform/streams/{stream}/status`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn stream_status(
        &self,
        http: &Http,
        stream: &str,
        change: Option<&StatusChange<'_>>,
    ) -> Result<Value, ClientError> {
        let url = format!(
            "{}/access/v1/platform/streams/{stream}/status",
            self.api_base
        );
        let authorization = self.authorization()?;
        let r = match change {
            None => {
                http.request(
                    "GET",
                    &url,
                    &[("Authorization", authorization.as_str())],
                    None,
                )
                .await?
            }
            Some(c) => {
                let mut body = json!({ "stream_id": stream, "status": c.status });
                if let (Some(reason), Some(m)) = (c.reason, body.as_object_mut()) {
                    m.insert("reason".into(), reason.into());
                }
                let body = body.to_string();
                http.request(
                    "POST",
                    &url,
                    &[("Authorization", authorization.as_str())],
                    Some(("application/json", body.as_bytes())),
                )
                .await?
            }
        };
        if r.status == 200 {
            Ok(r.json())
        } else {
            Err(ClientError::Unexpected {
                step: "platform stream status",
                status: r.status,
                body: r.text(),
            })
        }
    }

    /// `POST {issuer}/token` with `grant_type=client_credentials` and `resource` the other
    /// product's `client_id` (RFC 8707, OP-149 m.31 (a)): the identity-assertion service token,
    /// DPoP-bound to the client key itself, once more with the server's nonce when it asks for
    /// one. The answer carries `dpop_jkt`, the key the token is bound to.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn service_token(&self, http: &Http, resource: &str) -> Result<Value, ClientError> {
        let token_url = format!("{}/token", self.issuer);
        let mut nonce = None;
        for _ in 0..2 {
            let assertion = self.key.assertion(self.client_id, self.issuer)?;
            let body = form(&[
                ("grant_type", "client_credentials"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
                ("resource", resource),
            ]);
            let proof = self.key.proof("POST", &token_url, nonce.as_deref(), None)?;
            let r = http
                .request(
                    "POST",
                    &token_url,
                    &[("DPoP", proof.as_str())],
                    Some(("application/x-www-form-urlencoded", body.as_bytes())),
                )
                .await?;
            if r.status == 200 {
                let mut tokens = r.json();
                if let Some(m) = tokens.as_object_mut() {
                    m.insert("dpop_jkt".into(), self.key.jkt().into());
                }
                return Ok(tokens);
            }
            let fresh = r.header("dpop-nonce").map(String::from);
            let error = r.json();
            if error.get("error").and_then(Value::as_str) == Some("use_dpop_nonce")
                && fresh.is_some()
                && nonce.is_none()
            {
                nonce = fresh;
                continue;
            }
            return Err(ClientError::Unexpected {
                step: "service token",
                status: r.status,
                body: r.text(),
            });
        }
        Err(ClientError::Http(String::from(
            "the token endpoint kept asking for a nonce",
        )))
    }
}
