//! The console's sign-in through the realm's own authorization server (OP-151 m.12 (b), RFC
//! 10017 BFF pattern, TN-128): the BFF is the realm's first-party confidential client whose
//! redirect URI is the management origin's callback and whose `private_key_jwt` key the server
//! holds in its HSM; there is no shared secret. A sign-in is the authorization code flow with
//! PKCE S256 and `prompt=login`; the code is exchanged in process with a client assertion and a
//! DPoP proof; the ID token's `sid` names the grant, and so the subject and the login session.
//! The PKCE verifier and the OIDC nonce are derived from the state under an HSM key, so nothing
//! is kept between the redirect and the callback beyond the state cookie.

use std::fmt::Write as _;
use std::sync::Arc;

use access_crypto::AwsLcBackend;
use access_http::api::ports::Clock as _;
use access_http::console::ports::{SignIn, SignedIn, Unavailable};
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::domain::client::ASSERTION_TYPE;
use access_identity_oauth::domain::jwt::{parse_jwks, realm_key_set};
use access_identity_oauth::domain::metadata::Endpoint;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::domain::tokens::ID_TYP;
use access_identity_oauth::ports::oauth::TokenSigner as _;
use access_identity_oauth::ports::{Directory as _, RealmEntry};
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};
use access_store::Pool;
use access_store::identity::TenantTx;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use suiss_crypto::digest::sha256;
use suiss_crypto::pkcs11::{HsmSigner, KeyStore};
use suiss_crypto::signer::{Signer as _, SoftSigner};
use tower::ServiceExt as _;

use crate::ids::CellIds;
use crate::login::ID_KEY_ROOT;

/// The HSM label of the console client's `private_key_jwt` key (P-256, MD-3).
pub(crate) const CLIENT_KEY_LABEL: &str = "access/console/client-key";

/// The display name of the console client in each realm.
pub(crate) const CLIENT_NAME: &str = "Access console";

const PKCE_CONTEXT: &[u8] = b"access/console-pkce/v1";
const NONCE_CONTEXT: &[u8] = b"access/console-nonce/v1";

/// Largest token endpoint answer read.
const MAX_ANSWER: usize = 64 * 1024;

/// The console client's key in `keys`, made once.
///
/// # Errors
/// The HSM's error text.
pub(crate) fn client_key(keys: &KeyStore) -> Result<HsmSigner, String> {
    match keys.signer(CLIENT_KEY_LABEL) {
        Ok(s) => Ok(s),
        Err(_) => keys
            .generate_p256(CLIENT_KEY_LABEL)
            .map_err(|e| e.to_string()),
    }
}

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

/// RFC 3986 unreserved characters pass; everything else is percent-encoded.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The realm sign-in of the console BFF.
pub(crate) struct RealmSignIn {
    /// The public listener's routes, called in process.
    pub(crate) public: Router,
    pub(crate) directory: PgDirectory,
    pub(crate) app: Pool,
    pub(crate) keys: Arc<KeyStore>,
    pub(crate) ids: Arc<CellIds>,
    pub(crate) signer: SignerKeys,
    /// The management origin (TN-131: from configuration only).
    pub(crate) origin: String,
}

/// What the realm's token endpoint answered with.
struct Answer {
    status: u16,
    nonce: Option<String>,
    body: serde_json::Value,
}

impl RealmSignIn {
    fn derive(&self, context: &[u8], realm: &str, state: &str) -> Result<String, Unavailable> {
        let mut input = context.to_vec();
        input.push(0);
        input.extend_from_slice(realm.as_bytes());
        input.push(0);
        input.extend_from_slice(state.as_bytes());
        let mac = self
            .keys
            .mac(ID_KEY_ROOT)
            .and_then(|m| m.mac(&input))
            .map_err(down)?;
        Ok(b64url_encode(&mac))
    }

    fn key(&self) -> Result<HsmSigner, Unavailable> {
        client_key(&self.keys).map_err(down)
    }

    /// The realm's active console client: the one whose redirect URI is `callback` and whose
    /// one registered key is this server's console key.
    async fn client(
        &self,
        realm: &RealmEntry,
        callback: &str,
    ) -> Result<Option<String>, Unavailable> {
        let public = self.key()?.public_key();
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(down)?;
        let found = registered(&mut t, callback, &public).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(found)
    }

    fn assertion(
        &self,
        client_id: &str,
        audience: &str,
        now_ms: u64,
    ) -> Result<String, Unavailable> {
        let jti = b64url_encode(&access_crypto::random::bytes::<16>().map_err(down)?);
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": jti,
            "iat": now_ms / 1000,
            "exp": (now_ms / 1000).saturating_add(120),
        });
        let mut out = b64url_encode(header.as_bytes());
        out.push('.');
        out.push_str(&b64url_encode(claims.to_string().as_bytes()));
        let sig = self.key()?.sign(out.as_bytes()).map_err(down)?;
        out.push('.');
        out.push_str(&b64url_encode(&sig));
        Ok(out)
    }

    async fn post_token(
        &self,
        realm: &RealmEntry,
        body: String,
        proof: String,
    ) -> Result<Answer, Unavailable> {
        let url = realm.issuer.endpoint(Endpoint::Token.path());
        let path = url
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').and_then(|i| rest.get(i..)))
            .unwrap_or(Endpoint::Token.path());
        let request = Request::post(path)
            .header(header::HOST, realm.issuer.authority())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("dpop", proof)
            .body(Body::from(body))
            .map_err(down)?;
        let response = self.public.clone().oneshot(request).await.map_err(down)?;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, MAX_ANSWER).await.map_err(down)?;
        Ok(Answer {
            status: parts.status.as_u16(),
            nonce: parts
                .headers
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        })
    }

    /// RFC 6749 §4.1.3 with RFC 7523 client authentication and an RFC 9449 proof by a key
    /// used for this exchange only; a `use_dpop_nonce` answer is retried once with the nonce.
    async fn exchange(
        &self,
        realm: &RealmEntry,
        client_id: &str,
        code: &str,
        verifier: &str,
        callback: &str,
        now_ms: u64,
    ) -> Result<Option<serde_json::Value>, Unavailable> {
        let (dpop, _) = SoftSigner::generate_p256().map_err(down)?;
        let url = realm.issuer.endpoint(Endpoint::Token.path());
        let mut nonce: Option<String> = None;
        for _ in 0..2 {
            let assertion = self.assertion(client_id, realm.issuer.as_str(), now_ms)?;
            let body = form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", callback),
                ("code_verifier", verifier),
                ("client_id", client_id),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ]);
            let proof = proof(&dpop, &url, nonce.as_deref(), now_ms)?;
            let answer = self.post_token(realm, body, proof).await?;
            match answer.status {
                200 => return Ok(Some(answer.body)),
                400 if answer.body.get("error").and_then(|e| e.as_str())
                    == Some("use_dpop_nonce")
                    && nonce.is_none() =>
                {
                    nonce = answer.nonce;
                    if nonce.is_none() {
                        return Ok(None);
                    }
                }
                s if s >= 500 => return Err(Unavailable),
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// The ID token's claims, verified with the realm's keys.
    async fn id_claims(
        &self,
        realm: &RealmEntry,
        token: &str,
    ) -> Result<Option<Json>, Unavailable> {
        let jwks = self.signer.jwks(realm.realm).await.map_err(down)?;
        let keys = realm_key_set(jwks.as_bytes()).map_err(down)?;
        let Ok(v) = verify_compact(&AwsLcBackend, token, &keys, ID_TYP, Origin::Native) else {
            return Ok(None);
        };
        Ok(json::parse(&v.payload, MAX_PAYLOAD).ok())
    }

    /// The signed-in subject behind the grant `sid`, with its login session.
    async fn who(
        &self,
        realm: &RealmEntry,
        sid: [u8; 16],
    ) -> Result<Option<SignedIn>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, realm.tenant, realm.realm)
            .await
            .map_err(down)?;
        let Some(grant) = t.grant_by_sid(&sid).await.map_err(down)? else {
            return Ok(None);
        };
        let Some(session) = t.session_by_id(grant.session).await.map_err(down)? else {
            return Ok(None);
        };
        let governing = access_store::idp::governance(&mut t).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let (Some(g), Some(account)) = (governing, self.ids.encode(SUBJECT_PREFIX, grant.subject))
        else {
            return Ok(None);
        };
        Ok(Some(SignedIn {
            realm: realm.slug.clone(),
            domain: access_kernel::digest::Digest(*g.domain.as_bytes()),
            display_name: account.clone(),
            account,
            subject: grant.subject,
            login_session: session.id,
            auth_time_ms: u64::try_from(session.auth_time_ms).unwrap_or(0),
        }))
    }
}

/// The realm's active client with the redirect URI `callback` whose one registered key is
/// `key`: the console's client (OP-151 m.12 (b)).
///
/// # Errors
/// [`access_store::StoreError`].
pub(crate) async fn registered(
    t: &mut TenantTx,
    callback: &str,
    key: &PublicKey,
) -> Result<Option<String>, access_store::StoreError> {
    for id in access_store::idp::clients_with_redirect(t, callback).await? {
        let Some(row) = access_store::idp::client(t, &id).await? else {
            continue;
        };
        let ours = row.active
            && row.auth_method == "private_key_jwt"
            && row.jwks.as_deref().is_some_and(|j| holds(j, key));
        if ours {
            return Ok(Some(row.client_id));
        }
    }
    Ok(None)
}

/// Whether the one-key JWKS `jwks` holds `key`.
fn holds(jwks: &str, key: &PublicKey) -> bool {
    let PublicKey::P256(sec1) = key else {
        return false;
    };
    parse_jwks(jwks.as_bytes()).is_ok_and(|keys| {
        keys.iter()
            .any(|k| matches!(&k.key, access_crypto::oauth::ClientKey::P256(p) if p == sec1))
    })
}

/// A DPoP proof for `POST url` by `key` (RFC 9449 §4.2), with the server's nonce when it gave
/// one.
fn proof(
    key: &SoftSigner,
    url: &str,
    nonce: Option<&str>,
    now_ms: u64,
) -> Result<String, Unavailable> {
    let jwk = access_crypto::jose::confirmation_jwk(&key.public_key()).map_err(down)?;
    let header = format!(
        r#"{{"alg":"ES256","jwk":{},"typ":"dpop+jwt"}}"#,
        access_crypto::jose::output::to_string(&jwk)
    );
    let jti = b64url_encode(&access_crypto::random::bytes::<16>().map_err(down)?);
    let mut claims = serde_json::json!({
        "htm": "POST",
        "htu": url,
        "iat": now_ms / 1000,
        "jti": jti,
    });
    if let (Some(n), Some(m)) = (nonce, claims.as_object_mut()) {
        m.insert(String::from("nonce"), n.into());
    }
    let mut out = b64url_encode(header.as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(claims.to_string().as_bytes()));
    let sig = key.sign(out.as_bytes()).map_err(down)?;
    out.push('.');
    out.push_str(&b64url_encode(&sig));
    Ok(out)
}

fn text(c: &Json, name: &str) -> Option<String> {
    c.get(name).and_then(Json::as_str).map(String::from)
}

impl SignIn for RealmSignIn {
    async fn start(
        &self,
        realm: &str,
        state: &str,
        callback: &str,
    ) -> Result<Option<String>, Unavailable> {
        let Some(entry) = self.directory.by_slug(realm).await.map_err(down)? else {
            return Ok(None);
        };
        let Some(client_id) = self.client(&entry, callback).await? else {
            return Ok(None);
        };
        let verifier = self.derive(PKCE_CONTEXT, realm, state)?;
        let challenge = b64url_encode(&sha256(verifier.as_bytes()));
        let nonce = self.derive(NONCE_CONTEXT, realm, state)?;
        let query = form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", callback),
            ("scope", "openid"),
            ("state", state),
            ("nonce", &nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            // TN-129: every console session starts from a fresh authentication
            ("prompt", "login"),
        ]);
        Ok(Some(format!(
            "{}?{query}",
            entry.issuer.endpoint(Endpoint::Authorize.path())
        )))
    }

    async fn finish(
        &self,
        realm: &str,
        state: &str,
        query: &str,
    ) -> Result<Option<SignedIn>, Unavailable> {
        let Ok(params) = Params::parse(query) else {
            return Ok(None);
        };
        let Some(entry) = self.directory.by_slug(realm).await.map_err(down)? else {
            return Ok(None);
        };
        // RFC 6749 §10.12, RFC 9207
        if params.get("state") != Some(state)
            || params
                .get("iss")
                .is_some_and(|i| i != entry.issuer.as_str())
            || params.get("error").is_some()
        {
            return Ok(None);
        }
        let Some(code) = params.get("code") else {
            return Ok(None);
        };
        let callback = format!(
            "{}{}",
            self.origin,
            access_http::console::app::CALLBACK_PATH
        );
        let Some(client_id) = self.client(&entry, &callback).await? else {
            return Ok(None);
        };
        let verifier = self.derive(PKCE_CONTEXT, realm, state)?;
        let now = crate::admin::WallClock.now_ms()?;
        let Some(tokens) = self
            .exchange(&entry, &client_id, code, &verifier, &callback, now)
            .await?
        else {
            return Ok(None);
        };
        let Some(id_token) = tokens.get("id_token").and_then(|t| t.as_str()) else {
            return Ok(None);
        };
        let Some(claims) = self.id_claims(&entry, id_token).await? else {
            return Ok(None);
        };
        let nonce = self.derive(NONCE_CONTEXT, realm, state)?;
        if text(&claims, "aud").as_deref() != Some(client_id.as_str())
            || text(&claims, "nonce").as_deref() != Some(nonce.as_str())
        {
            return Ok(None);
        }
        let Some(sid) = text(&claims, "sid")
            .and_then(|s| b64url_decode(&s).ok())
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
        else {
            return Ok(None);
        };
        self.who(&entry, sid).await
    }
}
