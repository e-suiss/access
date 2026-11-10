//! CIBA as an invitation on the real server (OP-155 m.3 (l), IDP-14, §10.5.3, §9.14.5 k.2,
//! OP-153 m.3 (gg)): the realm's authorization server with the authority plane's openings, the
//! person's Relay invitation sealed in the identity outbox, the hosted Approval Surface over TLS
//! with the software passkey and device Instance, and the agent's own commit on the same nonce.
//! Only the ping transport is recorded instead of sent: the SSRF guard keeps loopback out.

use std::sync::Mutex;
use std::time::Duration;

use access_identity_admin::domain::{
    AuthMethod, Change, CibaSetting, Client, ClientId, ProfileDelta, RedirectUri,
};
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::{DeclaredTargets, Outbound};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::ports::Unavailable;
use access_identity_oauth::ports::oauth::{CibaInvite, CibaOpening, CibaServices, Held};
use access_kernel::json::b64url_decode;
use access_local_client::login::{Credential, Jar, post_json, sign_in};
use access_local_client::passkey::{Passkey, relying_party};
use access_sdk::auth::dpop::{ProofFor, ProofKey, proof};
use access_sdk::auth::{Random, RandomUnavailable};
use access_store::identity::{RealmId, TenantId};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::{Value as JsonValue, json};
use suiss_crypto::signer::SoftSigner;

use super::*;

/// The pings the realm sent: endpoint, bearer token and `auth_req_id`.
pub(super) type Pings = Arc<Mutex<Vec<(String, String, String)>>>;

/// The server's CIBA services, with the ping recorded.
struct RecordingCiba {
    inner: crate::ciba::ServerCiba<TestPlane>,
    pings: Pings,
}

impl CibaServices for RecordingCiba {
    fn opening(&self, domain: [u8; 32], intent: [u8; 32]) -> Held<'_, Option<CibaOpening>> {
        self.inner.opening(domain, intent)
    }

    fn invite(&self, invite: CibaInvite) -> Held<'_, ()> {
        self.inner.invite(invite)
    }

    fn login_hint(
        &self,
        tenant: TenantId,
        realm: RealmId,
        hint: String,
    ) -> Held<'_, Option<[u8; 16]>> {
        self.inner.login_hint(tenant, realm, hint)
    }

    fn ping(&self, endpoint: String, token: String, auth_req_id: String) -> Held<'_, bool> {
        Box::pin(async move {
            self.pings
                .lock()
                .map_err(|_| Unavailable)?
                .push((endpoint, token, auth_req_id));
            Ok(true)
        })
    }
}

/// The realm authorization server and discovery of the deployment, CIBA wired as in `main`.
pub(super) fn oauth_router(w: &World) -> (axum::Router, Pings) {
    let pings: Pings = Arc::new(Mutex::new(Vec::new()));
    let ids = Arc::new(crate::ids::CellIds::new(w.keys.clone()));
    let ciba = RecordingCiba {
        inner: crate::ciba::ServerCiba {
            plane: w.plane.clone(),
            app: w.db.app.clone(),
            keks: crate::login::RealmKeks::new(Arc::clone(&w.keys)),
            ids: Arc::clone(&ids),
            outbound: Outbound::disabled(Duration::from_secs(5)),
        },
        pings: Arc::clone(&pings),
    };
    let router = access_http::oauth::router(OAuth::new(crate::oauth::ServerEnv {
        saml: std::sync::Arc::new(access_identity_oauth::ports::profile::NoSamlAssertions),
        client_certificates: Arc::new(access_identity_oauth::ports::profile::NoClientCertificates),
        db: PgOAuth::with_reader(w.db.app.clone(), w.db.reader.clone()),
        signer: SignerKeys::new(w.identity_signer.clone()),
        client_keys: HttpClientKeys::new(
            Outbound::disabled(Duration::from_secs(5)),
            CachePolicy::default(),
        ),
        documents: access_identity_oauth::adapters::cimd::HttpClientDocuments::new(
            Outbound::disabled(Duration::from_secs(5)),
        ),
        bundles: Arc::new(access_identity_attest::ports::NoBundles),
        workload_trust: Arc::new(w.plane.clone()),
        standing: Arc::new(w.plane.clone()),
        directory: PgDirectory::new(w.db.router.clone()),
        app: w.db.app.clone(),
        nonces: crate::oauth::HsmNonces::new(w.keys.clone()),
        dpop: DpopProfile::default(),
        projections: w.plane.clone(),
        tenant_ids: ids,
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        management: Arc::new(crate::admin::tokens::PlaneHolders(w.plane.clone(), None)),
        claims: Arc::new(access_identity_oauth::ports::oauth::NoClaims),
        issuers: Arc::new(w.plane.clone()),
        ciba: Arc::new(ciba),
        geo: Arc::new(access_identity_oauth::ports::oauth::NoGeo),
    }));
    let discovery = access_http::realm::router(access_identity_oauth::app::Discovery::new(
        PgDirectory::new(w.db.router.clone()).with_facts(w.db.app.clone()),
        SignerKeys::new(w.identity_signer.clone()),
    ));
    (router.merge(discovery), pings)
}

struct Csprng;

impl Random for Csprng {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in out.chunks_mut(16) {
            let b: [u8; 16] = access_crypto::random::bytes().map_err(|_| RandomUnavailable)?;
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        Ok(())
    }
}

/// A DPoP key of the agent's client.
struct DpopKey {
    key: SoftSigner,
    public: PublicKey,
}

impl ProofKey for DpopKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        suiss_crypto::signer::Signer::sign(&self.key, input).ok()
    }
}

/// A registered confidential client of the realm: its `client_id`, its `private_key_jwt` key, its
/// internal id and its DPoP key.
pub(super) struct CibaClient {
    pub(super) id: String,
    key: EcdsaKeyPair,
    pub(super) uuid: [u8; 16],
    dpop: DpopKey,
    nonce: Mutex<Option<String>>,
}

fn es256(key: &EcdsaKeyPair, typ: &str, claims: &JsonValue) -> String {
    let header = json!({ "alg": "ES256", "typ": typ });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

impl Desk {
    /// The root's `change` of the realm.
    async fn root_change(&self, change: Change) {
        let declared = DeclaredTargets::default();
        let b = Bootstrap {
            app: &self.w.db.app,
            router: &self.w.db.router,
            plane: &self.w.plane,
            realm_keys: &self.w.keyring,
            hsm: &self.w.keys,
            base: &self.w.base,
            declared: &declared,
            console: None,
        };
        let ids = cell_ids(&self.w.db.app, &self.w.keys).await.unwrap();
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        b.change(
            &b.admin(&ids, None),
            (route.tenant, route.realm),
            self.domain,
            &root_key(&self.w.keys).unwrap(),
            change,
        )
        .await
        .unwrap();
    }

    /// `idp.realm.ciba` with the free `login_hint` flag and the clients told by ping.
    pub(super) async fn ciba_on(&self, login_hint: bool, ping: &[(&CibaClient, &str)]) {
        self.root_change(Change::Ciba(CibaSetting {
            enabled: true,
            login_hint,
            ping: ping
                .iter()
                .map(|(c, e)| (ClientId::parse(&c.id).unwrap(), String::from(*e)))
                .collect(),
        }))
        .await;
    }

    /// A confidential client of the realm, under FAPI 2.0 when `fapi`.
    pub(super) async fn ciba_client(&self, name: &str, fapi: bool) -> CibaClient {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let declared = DeclaredTargets::default();
        let b = Bootstrap {
            app: &self.w.db.app,
            router: &self.w.db.router,
            plane: &self.w.plane,
            realm_keys: &self.w.keyring,
            hsm: &self.w.keys,
            base: &self.w.base,
            declared: &declared,
            console: None,
        };
        let ids = cell_ids(&self.w.db.app, &self.w.keys).await.unwrap();
        let id = b.admin(&ids, None).new_client_id().await.unwrap();
        let text = String::from(id.as_str());
        self.root_change(Change::ClientRegister(Client {
            id: id.clone(),
            display_name: String::from(name),
            auth: AuthMethod::PrivateKeyJwtKey {
                key: PublicKey::P256(key.public_key().as_ref().to_vec()),
            },
            redirect_uris: vec![RedirectUri::parse("https://agent.access.test/cb").unwrap()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            platform: None,
            subject: access_identity_admin::domain::Subject::default(),
            third_party: false,
        }))
        .await;
        if fapi {
            self.root_change(Change::ClientProfile {
                client: id,
                delta: ProfileDelta::Fapi2(true),
            })
            .await;
        }
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let uuid = access_store::idp::client(&mut t, &text)
            .await
            .unwrap()
            .unwrap()
            .client_uuid;
        t.commit().await.unwrap();
        let (dpop, _) = SoftSigner::generate_p256().unwrap();
        let public = dpop.public_key();
        CibaClient {
            id: text,
            key,
            uuid,
            dpop: DpopKey { key: dpop, public },
            nonce: Mutex::new(None),
        }
    }

    /// The client's `private_key_jwt` assertion for the realm.
    fn assertion(&self, c: &CibaClient) -> String {
        let now_s = now_ms() / 1000;
        es256(
            &c.key,
            "JWT",
            &json!({
                "iss": c.id, "sub": c.id, "aud": self.user.issuer, "iat": now_s,
                "exp": now_s + 60, "jti": b64url_encode(&nonce()),
            }),
        )
    }

    /// A request object the client signed over `claims` (RFC 9101, CIBA Core §7.1.1).
    pub(super) fn signed_request(&self, c: &CibaClient, claims: &JsonValue) -> String {
        let now_s = now_ms() / 1000;
        let mut all = claims.clone();
        for (k, v) in [
            ("iss", json!(c.id)),
            ("client_id", json!(c.id)),
            ("aud", json!(self.user.issuer)),
            ("iat", json!(now_s)),
            ("nbf", json!(now_s)),
            ("exp", json!(now_s + 300)),
            ("jti", json!(b64url_encode(&nonce()))),
        ] {
            all[k] = v;
        }
        es256(&c.key, "oauth-authz-req+jwt", &all)
    }

    /// P's pairwise `sub` as `c` knows it, and a `login_hint_token` naming it.
    pub(super) async fn hint_token(&self, c: &CibaClient) -> String {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let candidate = b64url_encode(&access_crypto::random::bytes::<32>().unwrap());
        let sub = t.pairwise(self.subject, c.uuid, &candidate).await.unwrap();
        t.commit().await.unwrap();
        let now_s = now_ms() / 1000;
        es256(
            &c.key,
            "JWT",
            &json!({ "iss": c.id, "aud": self.user.issuer, "sub": sub, "iat": now_s, "exp": now_s + 120 }),
        )
    }

    /// The backchannel request parameters for the agent's waiting `ex` of `intent`.
    pub(super) fn ciba_params(
        &self,
        ex: &Exercise,
        intent: &JsonValue,
        hint: (&str, &str),
        binding_message: Option<&str>,
    ) -> Vec<(String, String)> {
        let envelope = access_local_client::intent::parse(intent).unwrap();
        let digest = intent_digest(&envelope).unwrap();
        let details = json!([{
            "type": format!("{}:{}:{}", envelope.action.namespace, envelope.action.name, envelope.action.major),
            "kind": "intent",
            "schema": format!("sha-256:{}", b64url_encode(&envelope.action.schema.0)),
            "intent": format!("sha-256:{}", b64url_encode(&digest.0)),
        }]);
        let mut out = vec![
            (String::from("scope"), String::from("openid")),
            (String::from(hint.0), String::from(hint.1)),
            (String::from("authorization_details"), details.to_string()),
            (
                String::from("access_exercise_ref"),
                json!({ "domain": b64url_encode(&self.domain.0), "nonce": b64url_encode(ex.nonce()) })
                    .to_string(),
            ),
        ];
        if let Some(m) = binding_message {
            out.push((String::from("binding_message"), String::from(m)));
        }
        out
    }

    /// `POST /bc-authorize` by `c` with `pairs`, authenticated by its assertion.
    pub(super) async fn bc_authorize(
        &self,
        c: &CibaClient,
        pairs: &[(String, String)],
    ) -> (u16, JsonValue) {
        let assertion = self.assertion(c);
        let mut all: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        all.push(("client_id", c.id.as_str()));
        all.push((
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ));
        all.push(("client_assertion", assertion.as_str()));
        let body = form(&all);
        let r = self
            .agent_http
            .request(
                "POST",
                &format!("{}/bc-authorize", self.user.issuer),
                &[],
                Some(("application/x-www-form-urlencoded", body.as_bytes())),
            )
            .await
            .unwrap();
        (r.status, r.json())
    }

    /// One poll of `c` for `auth_req_id` at `/token`, with a DPoP proof and the nonce retry.
    pub(super) async fn ciba_poll(&self, c: &CibaClient, auth_req_id: &str) -> (u16, JsonValue) {
        let token_uri = format!("{}/token", self.user.issuer);
        let mut nonce_seen = c.nonce.lock().unwrap().clone();
        for _ in 0..2 {
            let p = proof(
                &c.dpop,
                &ProofFor {
                    method: "POST",
                    uri: &token_uri,
                    access_token: None,
                    nonce: nonce_seen.as_deref(),
                },
                now_ms(),
                &Csprng,
            )
            .unwrap();
            let assertion = self.assertion(c);
            let body = form(&[
                ("grant_type", "urn:openid:params:grant-type:ciba"),
                ("auth_req_id", auth_req_id),
                ("client_id", c.id.as_str()),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ]);
            let r = self
                .agent_http
                .request(
                    "POST",
                    &token_uri,
                    &[("DPoP", p.as_str())],
                    Some(("application/x-www-form-urlencoded", body.as_bytes())),
                )
                .await
                .unwrap();
            let fresh = r.all("dpop-nonce").next().map(String::from);
            if let Some(f) = &fresh {
                *c.nonce.lock().unwrap() = Some(f.clone());
            }
            let json = r.json();
            if json["error"] == "use_dpop_nonce" && fresh.is_some() {
                nonce_seen = fresh;
                continue;
            }
            return (r.status, json);
        }
        panic!("no nonce accepted");
    }

    /// The Approval Surface's handle of the request `auth_req_id` names, as the invitation
    /// links it.
    pub(super) async fn ciba_request(&self, auth_req_id: &str) -> String {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let handle = b64url_decode(auth_req_id).unwrap();
        let row = t
            .ciba_by_handle(&access_identity_oauth::domain::ciba::handle_hash(&handle))
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();
        b64url_encode(&row.id)
    }

    /// P's signed-in browser on the Approval Surface.
    pub(super) async fn person(&self) -> Jar {
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        sign_in(
            &self.http,
            &self.user.issuer,
            &self.user.identifier,
            Credential::Passkey(&passkey),
        )
        .await
        .unwrap()
    }

    /// `POST /v1/ciba/preview` in P's browser.
    pub(super) async fn ciba_preview(&self, jar: &mut Jar, request: &str) -> (u16, JsonValue) {
        self.w.domains.derive().await;
        let r = post_json(
            &self.http,
            &format!("{}/v1/ciba/preview", self.user.issuer),
            jar,
            Some(json!({ "request": request })),
        )
        .await
        .unwrap();
        (r.status, r.json())
    }

    /// `POST /v1/ciba/approval` in P's browser with the CSRF token: declined, or approved by the
    /// hosted approval pushed under `approval`.
    pub(super) async fn ciba_answer(
        &self,
        jar: &Jar,
        request: &str,
        csrf: &str,
        approval: Option<&str>,
    ) -> (u16, JsonValue) {
        let body = match approval {
            Some(a) => json!({ "request": request, "approve": true, "approval": a }),
            None => json!({ "request": request, "approve": false }),
        }
        .to_string();
        let cookies = jar.header();
        let r = self
            .http
            .request(
                "POST",
                &format!("{}/v1/ciba/approval", self.user.issuer),
                &[("Cookie", cookies.as_str()), ("x-csrf-token", csrf)],
                Some(("application/json", body.as_bytes())),
            )
            .await
            .unwrap();
        (r.status, r.json())
    }

    /// P's AAS on the hosted Approval Surface over the request the CIBA preview built for
    /// `intent`: the contribution P's device signed and the `request_uri` it was pushed under.
    pub(super) async fn ciba_aas(&self, request: &JsonValue, intent: &JsonValue) -> JsonValue {
        use access_local_client::approve::{Approve, approve};
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        let done = approve(
            &self.http,
            &Approve {
                issuer: &self.user.issuer,
                api_base: "https://access.test",
                redirect_uri: &self.user.redirect_uri,
                identifier: &self.user.identifier,
                passkey: &passkey,
                device: &device,
                pep_leaf_der: &self.leaf,
                domain: self.domain,
                party: self.person,
                instance: Some(id_of(&self.user.instance)),
                intent,
                basis: holding_of(&self.allowed["basis"]),
                contribution: holding_of(&self.allowed["contribution"]["basis"]),
                reason: "The mail agent asks for your approval.",
                request: Some(request),
                work_gate: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(done["render_digest_verified"], true, "{done}");
        done
    }
}

/// The contribution Exercise of an answer's `access_approval`.
pub(super) fn contribution_of(body: &JsonValue) -> Digest {
    Digest(
        <[u8; 32]>::try_from(
            b64url_decode(body["access_approval"]["contribution"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    )
}

// IDI-9, OP-154 m.13 (f), §9.14.5 k.2, P54, OP-155 m.3 (l), Ek B 4718, 4719, 4720
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ciba_answer_needs_the_persons_aas_and_a_nonce_is_answered_once() {
    let d = Desk::open("p8-ciba-once", false).await;
    let client = d.ciba_client("Mail agent", false).await;
    d.ciba_on(false, &[]).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let hint = d.hint_token(&client).await;
    let (status, first) = d
        .bc_authorize(
            &client,
            &d.ciba_params(&ex, &intent, ("login_hint_token", &hint), None),
        )
        .await;
    assert_eq!(status, 200, "{first}");
    let invites = identity_events_until(
        &d.w.db,
        "relay.message.ciba_invite.v1",
        |q| !q.is_empty(),
        "the invitation",
    )
    .await;
    assert_eq!(invites.len(), 1);
    let id = d.ciba_request(first["auth_req_id"].as_str().unwrap()).await;
    let mut jar = d.person().await;
    let (status, preview) = d.ciba_preview(&mut jar, &id).await;
    assert_eq!(status, 200, "{preview}");
    let csrf = String::from(preview["csrf"].as_str().unwrap());

    // IDI-9
    let (status, body) = d
        .ciba_answer(
            &jar,
            &id,
            &csrf,
            Some("urn:ietf:params:oauth:request_uri:unknown"),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "ciba-not-approved", "{body}");
    let (status, body) = d
        .ciba_poll(&client, first["auth_req_id"].as_str().unwrap())
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "authorization_pending", "{body}");
    assert!(body.get("access_token").is_none());

    let done = d.ciba_aas(&preview["request"], &intent).await;
    let uri = String::from(done["request_uri"].as_str().unwrap());
    let (status, body) = d.ciba_answer(&jar, &id, &csrf, Some(&uri)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["decision"], "approved");

    // OP-154 m.13 (f)
    let (status, second) = d
        .bc_authorize(
            &client,
            &d.ciba_params(&ex, &intent, ("login_hint_token", &hint), None),
        )
        .await;
    assert_eq!(status, 200, "{second}");
    let again_id = d
        .ciba_request(second["auth_req_id"].as_str().unwrap())
        .await;
    let (_, preview2) = d.ciba_preview(&mut jar, &again_id).await;
    let csrf2 = String::from(preview2["csrf"].as_str().unwrap());
    let (status, body) = d.ciba_answer(&jar, &again_id, &csrf2, Some(&uri)).await;
    assert_eq!(status, 409, "{body}");

    tokio::time::sleep(Duration::from_secs(5)).await;
    let (status, token) = d
        .ciba_poll(&client, first["auth_req_id"].as_str().unwrap())
        .await;
    assert_eq!(status, 200, "{token}");
    assert_eq!(
        contribution_of(&token).0.as_slice(),
        b64url_decode(done["contribution"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );
    let (status, body) = d
        .ciba_poll(&client, first["auth_req_id"].as_str().unwrap())
        .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant", "{body}");
    d.close().await;
}

// OP-155 m.3 (l), IDP-14, Ek B 4718
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_request_is_access_denied_for_good_and_the_ping_client_is_told() {
    let d = Desk::open("p8-ciba-deny", false).await;
    let client = d.ciba_client("Mail agent", false).await;
    d.ciba_on(false, &[(&client, "https://agent.access.test/ciba")])
        .await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let hint = d.hint_token(&client).await;
    let mut params = d.ciba_params(&ex, &intent, ("login_hint_token", &hint), None);
    // IDP-14
    let (status, body) = d.bc_authorize(&client, &params).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_request");
    let bearer = b64url_encode(&nonce());
    params.push((String::from("client_notification_token"), bearer.clone()));
    let (status, asked) = d.bc_authorize(&client, &params).await;
    assert_eq!(status, 200, "{asked}");
    let auth_req_id = String::from(asked["auth_req_id"].as_str().unwrap());
    let id = d.ciba_request(&auth_req_id).await;
    let mut jar = d.person().await;
    let (_, preview) = d.ciba_preview(&mut jar, &id).await;
    let csrf = String::from(preview["csrf"].as_str().unwrap());
    let (status, body) = d.ciba_answer(&jar, &id, &csrf, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["decision"], "denied");
    assert_eq!(
        *d.pings.lock().unwrap(),
        vec![(
            String::from("https://agent.access.test/ciba"),
            bearer,
            auth_req_id.clone()
        )]
    );
    for _ in 0..2 {
        let (status, body) = d.ciba_poll(&client, &auth_req_id).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["error"], "access_denied", "{body}");
    }
    let (status, _) = d.ciba_preview(&mut jar, &id).await;
    assert_eq!(status, 404);
    d.close().await;
}

// IDP-14, §10.5.3, §10.2.1, §10.5.1, OP-155 m.3 (l), Ek B 4718, 4721, 5043
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_and_free_hints_are_refused_and_fapi_clients_sign_their_request() {
    let d = Desk::open("p8-ciba-profile", false).await;
    let client = d.ciba_client("Mail agent", false).await;
    let fapi = d.ciba_client("Bank agent", true).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let mut ex = d.exercise(&intent, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    let hint = d.hint_token(&client).await;
    let params = d.ciba_params(&ex, &intent, ("login_hint_token", &hint), Some("Code 4F2Q"));
    // OP-155 m.3 (l)
    let (status, _) = d.bc_authorize(&client, &params).await;
    assert_eq!(status, 404);
    d.ciba_on(false, &[]).await;
    let meta = d
        .agent_http
        .request(
            "GET",
            &format!("{}/.well-known/openid-configuration", d.user.issuer),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(meta.status, 200, "{}", meta.text());
    let meta = meta.json();
    assert_eq!(
        meta["backchannel_authentication_endpoint"],
        format!("{}/bc-authorize", d.user.issuer)
    );
    assert_eq!(
        meta["backchannel_token_delivery_modes_supported"],
        json!(["poll", "ping"])
    );
    assert_eq!(meta["backchannel_user_code_parameter_supported"], false);
    assert!(
        meta["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("urn:openid:params:grant-type:ciba"))
    );

    // IDP-14, Ek B 5043
    let mut push = params.clone();
    push.push((
        String::from("client_notification_endpoint"),
        String::from("https://agent.access.test/push"),
    ));
    let (status, body) = d.bc_authorize(&client, &push).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request"))
    );
    // §10.2.1
    let free = d.ciba_params(&ex, &intent, ("login_hint", &d.user.identifier), None);
    let (status, body) = d.bc_authorize(&client, &free).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("unknown_user_id")),
        "{body}"
    );
    // OP-155 m.3 (l)
    let long = d.ciba_params(
        &ex,
        &intent,
        ("login_hint_token", &hint),
        Some(&"x".repeat(33)),
    );
    let (status, body) = d.bc_authorize(&client, &long).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_binding_message"))
    );
    let (status, body) = d.bc_authorize(&client, &params).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["interval"], 5);
    assert!(body["expires_in"].as_u64().unwrap() <= 600);

    // §10.2.1
    d.ciba_on(true, &[]).await;
    let (status, known) = d.bc_authorize(&client, &free).await;
    assert_eq!(status, 200, "{known}");
    let nobody = d.ciba_params(&ex, &intent, ("login_hint", "nobody@acme.example"), None);
    let (status, unknown) = d.bc_authorize(&client, &nobody).await;
    assert_eq!(status, 200, "{unknown}");
    let shape = |v: &JsonValue| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(shape(&known), shape(&unknown));

    // §10.5.1, Ek B 4721
    let fapi_hint = d.hint_token(&fapi).await;
    let fapi_params = d.ciba_params(&ex, &intent, ("login_hint_token", &fapi_hint), None);
    let (status, body) = d.bc_authorize(&fapi, &fapi_params).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_request")),
        "{body}"
    );
    let mut claims = json!({});
    for (k, v) in &fapi_params {
        claims[k.as_str()] = json!(v);
    }
    let object = d.signed_request(&fapi, &claims);
    let (status, body) = d
        .bc_authorize(&fapi, &[(String::from("request"), object)])
        .await;
    assert_eq!(status, 200, "{body}");
    d.close().await;
}

// §10.3.4, §9.14.5, §13.7.3, OP-155 m.3 (l), Ek B 4895
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aas_over_another_material_value_does_not_answer_the_request() {
    let d = Desk::open("p8-ciba-link", false).await;
    let client = d.ciba_client("Payment agent", false).await;
    d.ciba_on(false, &[]).await;
    let (_, held) = d.agent_grant().await;
    let intent = d.intent_json("main").await;
    let other = d.intent_json("other").await;
    let mut ex = d.exercise(&intent, held);
    let mut changed = d.exercise(&other, held);
    assert!(matches!(d.ask(&mut ex), Step::Wait(_)));
    assert!(matches!(d.ask(&mut changed), Step::Wait(_)));
    let hint = d.hint_token(&client).await;
    let (status, asked) = d
        .bc_authorize(
            &client,
            &d.ciba_params(&ex, &intent, ("login_hint_token", &hint), Some("Pay 4F2Q")),
        )
        .await;
    assert_eq!(status, 200, "{asked}");
    let id = d.ciba_request(asked["auth_req_id"].as_str().unwrap()).await;
    let mut jar = d.person().await;
    let (_, preview) = d.ciba_preview(&mut jar, &id).await;
    assert_eq!(preview["binding_message"], "Pay 4F2Q");
    let csrf = String::from(preview["csrf"].as_str().unwrap());
    // §10.3.4, §13.7.3
    let mut moved = preview["request"].clone();
    let other_digest = intent_digest(&access_local_client::intent::parse(&other).unwrap()).unwrap();
    moved["require_action"]["intent"] = json!(b64url_encode(&other_digest.0));
    moved["require_action"]["nonce"] = json!(b64url_encode(changed.nonce()));
    let done = d.ciba_aas(&moved, &other).await;
    let uri = String::from(done["request_uri"].as_str().unwrap());
    let (status, body) = d.ciba_answer(&jar, &id, &csrf, Some(&uri)).await;
    assert_eq!(status, 409, "{body}");
    let (status, body) = d
        .ciba_poll(&client, asked["auth_req_id"].as_str().unwrap())
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("authorization_pending"))
    );
    d.close().await;
}
