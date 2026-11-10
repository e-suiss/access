//! PEP transport identity by a DPoP-bound `client_credentials` token next to mTLS (OP-155
//! m.3 (q), §9.5.1 m.10, Ek B 5074): a confidential client of the realm asks the realm's real
//! token endpoint for a PEP token for the ADP, and the real ADP router hears the PEP its DPoP
//! key names; a PEP with neither a certificate nor a token is refused.

use std::time::Duration;

use access_identity_admin::domain::{AuthMethod, Change, Client, RedirectUri, Subject};
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_sdk::auth::dpop::{ProofFor, ProofKey, proof};
use access_sdk::auth::{Random, RandomUnavailable};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

use super::*;

const REALM_ISSUER: &str = "https://access.test/realms/authzen";

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

/// The PEP's DPoP key.
struct DpopKey {
    pair: EcdsaKeyPair,
    public: PublicKey,
}

impl DpopKey {
    fn generate() -> Self {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let public = PublicKey::P256(pair.public_key().as_ref().to_vec());
        Self { pair, public }
    }
}

impl ProofKey for DpopKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.pair
            .sign(&SystemRandom::new(), input)
            .ok()
            .map(|s| s.as_ref().to_vec())
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// The realm's confidential client: its id and assertion key.
struct PepClient {
    id: String,
    key: EcdsaKeyPair,
}

impl PepClient {
    /// A fresh `private_key_jwt` assertion for the realm's token endpoint.
    fn assertion(&self) -> String {
        let now_s = now_ms() / 1000;
        let jti = access_crypto::random::bytes::<16>().unwrap();
        let header = json!({ "alg": "ES256", "typ": "JWT" });
        let claims = json!({
            "iss": self.id, "sub": self.id, "aud": REALM_ISSUER, "iat": now_s, "exp": now_s + 60,
            "jti": b64url_encode(&jti),
        });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64url_encode(sig.as_ref()))
    }
}

/// The realm with a confidential client, its token endpoint and the public ADP router that
/// hears PEP tokens, both over one OAuth service as the server wires them.
struct Tokens {
    p: Pdp,
    client: PepClient,
    oauth: axum::Router,
    adp: axum::Router,
}

async fn tokens(label: &str) -> Tokens {
    let p = pdp(label).await;
    let route = route_by_slug(&p.w.db.router, SLUG).await.unwrap().unwrap();
    let declared = DeclaredTargets::default();
    let b = Bootstrap {
        app: &p.w.db.app,
        router: &p.w.db.router,
        plane: &p.w.plane,
        realm_keys: &p.w.keyring,
        hsm: &p.w.keys,
        base: &p.w.base,
        declared: &declared,
        console: None,
    };
    let ids = cell_ids(&p.w.db.app, &p.w.keys).await.unwrap();
    let admin = b.admin(&ids, None);
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let id = admin.new_client_id().await.unwrap();
    let client = PepClient {
        id: String::from(id.as_str()),
        key,
    };
    b.change(
        &admin,
        (route.tenant, route.realm),
        p.domain,
        &p.root,
        Change::ClientRegister(Client {
            id,
            display_name: String::from("Shop PEP"),
            auth: AuthMethod::PrivateKeyJwtKey {
                key: PublicKey::P256(client.key.public_key().as_ref().to_vec()),
            },
            redirect_uris: vec![RedirectUri::parse("https://pep.access.test/cb").unwrap()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            platform: None,
            subject: Subject::default(),
            third_party: false,
        }),
    )
    .await
    .unwrap();
    p.w.domains.release().await;
    crate::jobs::open_now(&p.w.db.app, &p.w.db.archive, label).await;
    let day = u32::try_from(now_ms() / 86_400_000).unwrap();
    for d in [day - 1, day, day + 1] {
        access_store::dpop::open_dpop_replay_day(&p.w.db.archive, d)
            .await
            .unwrap();
    }
    let service = Arc::new(
        OAuth::new(crate::oauth::ServerEnv {
            saml: Arc::new(access_identity_oauth::ports::profile::NoSamlAssertions),
            client_certificates: Arc::new(
                access_identity_oauth::ports::profile::NoClientCertificates,
            ),
            db: PgOAuth::with_reader(p.w.db.app.clone(), p.w.db.reader.clone()),
            signer: SignerKeys::new(p.w.identity_signer.clone()),
            client_keys: HttpClientKeys::new(
                Outbound::disabled(Duration::from_secs(5)),
                CachePolicy::default(),
            ),
            documents: access_identity_oauth::adapters::cimd::HttpClientDocuments::new(
                Outbound::disabled(Duration::from_secs(5)),
            ),
            directory: PgDirectory::new(p.w.db.router.clone()),
            app: p.w.db.app.clone(),
            nonces: crate::oauth::HsmNonces::new(p.w.keys.clone()),
            dpop: DpopProfile::default(),
            projections: p.w.plane.clone(),
            issuers: Arc::new(p.w.plane.clone()),
            bundles: Arc::new(access_identity_attest::ports::NoBundles),
            workload_trust: Arc::new(p.w.plane.clone()),
            standing: Arc::new(p.w.plane.clone()),
            tenant_ids: Arc::new(crate::ids::CellIds::new(p.w.keys.clone())),
            hooks: Arc::new(access_identity_hooks::ports::NoHooks),
            management: Arc::new(crate::admin::tokens::PlaneHolders(p.w.plane.clone(), None)),
            claims: Arc::new(access_identity_oauth::ports::oauth::NoClaims),
            ciba: Arc::new(access_identity_oauth::ports::oauth::NoCiba),
            geo: Arc::new(access_identity_oauth::ports::oauth::NoGeo),
        })
        .with_pep_audience(String::from(ISSUER)),
    );
    let oauth = access_http::oauth::shared_router(service.clone());
    let limits = Limits::default();
    let adp = harden(
        access_http::adp::pep::with_tokens(
            adp_router(
                Service::new(p.w.domains.clone(), limits.max_body_bytes),
                Discovery {
                    issuer: String::from(ISSUER),
                },
            ),
            service,
            String::from(ISSUER),
        ),
        limits,
    );
    Tokens {
        p,
        client,
        oauth,
        adp,
    }
}

/// One request with a DPoP proof by `key`, retried once with the server's nonce.
async fn with_proof(
    router: &axum::Router,
    key: &DpopKey,
    uri: &str,
    token: Option<&str>,
    build: impl Fn(&str) -> HttpRequest<Body>,
) -> Answer {
    let mut nonce: Option<String> = None;
    for _ in 0..2 {
        let p = proof(
            key,
            &ProofFor {
                method: "POST",
                uri,
                access_token: token,
                nonce: nonce.as_deref(),
            },
            now_ms(),
            &Csprng,
        )
        .unwrap();
        let r = router.clone().oneshot(build(&p)).await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
        let fresh = headers
            .get("dpop-nonce")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let wants_nonce = String::from_utf8_lossy(&body).contains("use_dpop_nonce")
            || headers
                .get(header::WWW_AUTHENTICATE)
                .is_some_and(|v| v.to_str().unwrap_or("").contains("use_dpop_nonce"));
        if wants_nonce && fresh.is_some() && nonce.is_none() {
            nonce = fresh;
            continue;
        }
        return Answer {
            status,
            headers,
            body,
        };
    }
    panic!("no nonce accepted");
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}",
                v.bytes()
                    .map(|b| match b {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                            char::from(b).to_string()
                        }
                        _ => format!("%{b:02X}"),
                    })
                    .collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

impl Tokens {
    /// The client's PEP token for the ADP, bound to `key`.
    async fn pep_token(&self, key: &DpopKey, resource: &str) -> Answer {
        with_proof(
            &self.oauth,
            key,
            &format!("{REALM_ISSUER}/token"),
            None,
            |p| {
                let assertion = self.client.assertion();
                let body = form(&[
                    ("grant_type", "client_credentials"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", &assertion),
                    ("client_id", &self.client.id),
                    ("resource", resource),
                ]);
                HttpRequest::post("/realms/authzen/token")
                    .header(header::HOST, "access.test")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("dpop", p)
                    .body(Body::from(body))
                    .unwrap()
            },
        )
        .await
    }

    /// An evaluation with `authorization` and a proof by `key` for `token`.
    async fn evaluate(
        &self,
        key: &DpopKey,
        authorization: &str,
        token: &str,
        body: &Json,
    ) -> Answer {
        let body = body.to_string();
        with_proof(
            &self.adp,
            key,
            &format!("{ISSUER}/access/v1/evaluation"),
            Some(token),
            |p| {
                HttpRequest::post("/access/v1/evaluation")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, authorization)
                    .header("dpop", p)
                    .body(Body::from(body.clone()))
                    .unwrap()
            },
        )
        .await
    }

    /// The root's allowed check, its AIS naming `pep`.
    async fn allowed_for(&self, pep: &str) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let intent = self.p.idp_intent(IdpAction::ClientRegister, "client").await;
        self.p
            .body(Mode::Check, &nonce, &intent, self.p.idp_basis(), pep)
            .await
    }
}

fn jkt_of(token: &str) -> String {
    let payload = token.split('.').nth(1).unwrap();
    let claims: Json =
        serde_json::from_slice(&access_kernel::json::b64url_decode(payload).unwrap()).unwrap();
    String::from(claims["cnf"]["jkt"].as_str().unwrap())
}

// OP-155 m.3 (q), §9.5, §9.5.1 m.10, E17, PI-7, TN-27, Ek B 5074
#[tokio::test]
async fn a_pep_authenticates_with_a_dpop_bound_client_credentials_token() {
    let t = tokens("az-pep-token").await;
    let key = DpopKey::generate();
    let issued = t.pep_token(&key, ISSUER).await;
    let v = issued.json();
    assert_eq!(issued.status, StatusCode::OK, "{v}");
    assert_eq!(v["token_type"], "DPoP");
    assert!(v.get("refresh_token").is_none());
    let token = String::from(v["access_token"].as_str().unwrap());
    let payload = token.split('.').nth(1).unwrap();
    let claims: Json =
        serde_json::from_slice(&access_kernel::json::b64url_decode(payload).unwrap()).unwrap();
    assert_eq!(claims["aud"], ISSUER);
    assert_eq!(claims["client_id"], t.client.id);
    assert!(claims.get("authorization_details").is_none());
    assert!(claims.get("scope").is_none());
    let jkt = jkt_of(&token);

    let heard = t
        .evaluate(
            &key,
            &format!("DPoP {token}"),
            &token,
            &t.allowed_for(&jkt).await,
        )
        .await;
    let v = heard.json();
    assert_eq!(heard.status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true, "{v}");
    assert!(heard.headers.get("dpop-nonce").is_some());

    // §9.5 k.3
    let elsewhere = t
        .evaluate(
            &key,
            &format!("DPoP {token}"),
            &token,
            &t.allowed_for(PEP).await,
        )
        .await;
    assert_eq!(
        elsewhere.status,
        StatusCode::BAD_REQUEST,
        "{}",
        elsewhere.json()
    );

    // TN-27
    let stolen = t
        .evaluate(
            &DpopKey::generate(),
            &format!("DPoP {token}"),
            &token,
            &t.allowed_for(&jkt).await,
        )
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stolen.json()["code"], "pep-unauthenticated");
    let bearer = t
        .evaluate(
            &key,
            &format!("Bearer {token}"),
            &token,
            &t.allowed_for(&jkt).await,
        )
        .await;
    assert_eq!(bearer.status, StatusCode::UNAUTHORIZED);
    let unproven = t
        .adp
        .clone()
        .oneshot(
            HttpRequest::post("/access/v1/evaluation")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("DPoP {token}"))
                .body(Body::from(t.allowed_for(&jkt).await.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unproven.status(), StatusCode::UNAUTHORIZED);
    let mut req = HttpRequest::post("/access/v1/evaluation")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .body(Body::from(t.allowed_for(&jkt).await.to_string()))
        .unwrap();
    req.extensions_mut().insert(Pep(String::from(PEP)));
    let both = t.adp.clone().oneshot(req).await.unwrap();
    assert_eq!(both.status(), StatusCode::BAD_REQUEST);

    // OP-149 m.31 (a)
    let other = t.pep_token(&key, "https://elsewhere.access.test").await;
    assert_ne!(other.status, StatusCode::OK, "{}", other.json());
    t.p.w.domains.release().await;
}

// OP-155 m.3 (q), §9.5.1 m.10, L1-ADP-2, Ek B 5074
#[tokio::test]
async fn a_pep_with_neither_a_certificate_nor_a_token_is_refused() {
    let t = tokens("az-pep-neither").await;
    let body = t.allowed_for(PEP).await.to_string();
    let before = t.p.w.domains.head(t.p.domain).await.unwrap().0;
    for path in [
        "/access/v1/evaluation",
        "/access/v1/evaluations",
        "/access/v1/explain",
        "/access/v1/search/subject",
        "/access/v1/eligibility:check",
    ] {
        let r = t
            .adp
            .clone()
            .oneshot(
                HttpRequest::post(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    assert_eq!(t.p.w.domains.head(t.p.domain).await.unwrap().0, before);
    t.p.w.domains.release().await;
}
