//! The headless login against an in-process Access (OP-149 m.26 (b), (e)): the realm
//! authorization server and the hosted login's JSON surface over TLS from a test CA, a real
//! PostgreSQL and a real identity signer; the client runs the whole flow as it does against a
//! local deployment, with the password and with the software passkey.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../../crates/identity-oauth/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::webauthn::DecoyKey;
use access_http::login::router as login_router;
use access_http::oauth::router as oauth_router;
use access_http::tls::{serve, server_config};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, set_password,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::Message;
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{BreachRanges, RangeUnavailable};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_identity_session::adapters::OsRandom;
use access_identity_session::adapters::passkeys::PgPasskeys;
use access_identity_session::app::{Auth, Passkeys};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::adapters::LogSignals;
use access_identity_ui::app::Hosted;
use access_identity_ui::ports::{Clock, Kits, Messages, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::ceremony::{ClientExtensionResults, RegistrationResponse};
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_kernel::json::b64url_decode;
use access_local_client::http::Http;
use access_local_client::login::{Credential, Login, login};
use access_local_client::passkey::Passkey;
use access_store::identity::TenantTx;
use serde_json::Value;
use suiss_crypto::signer::{Signer as _, SoftSigner};
use support::{Cluster, NATIVE};

const PW: &str = "correct horse battery staple";
const WHO: &str = "alice@acme.example";

struct Live;

impl Clock for Live {
    fn now_ms(&self) -> u64 {
        support::now()
    }
}

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

#[derive(Clone, Default)]
struct Silent;

struct Dropping;

impl Notifier for Dropping {
    fn notify(
        &self,
        _: &mut TenantTx,
        _: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send {
        std::future::ready(Ok(EventId([1; 16])))
    }
}

impl Messages for Silent {
    type For<'a> = Dropping;

    fn notifier<'a>(&'a self, _: &'a Realm<'a>) -> Dropping {
        Dropping
    }
}

struct Dir(RealmEntry);

impl Directory for Dir {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((host == self.0.issuer.authority()).then(|| self.0.clone()))
    }

    async fn by_slug(&self, _: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok(None)
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(vec![self.0.clone()])
    }
}

struct NoKeys;

impl Keys for NoKeys {
    async fn ping(&self) -> Result<(), Unavailable> {
        Ok(())
    }

    async fn jwks(&self, _: access_store::identity::RealmId) -> Result<String, Unavailable> {
        Err(Unavailable)
    }
}

struct Kit(Arc<RealmKit>);

impl Kits for Kit {
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        if entry.realm == self.0.realm {
            Ok(self.0.clone())
        } else {
            Err(Unavailable)
        }
    }
}

fn kit(entry: &RealmEntry) -> RealmKit {
    let wa = WaRealm::from_bytes(*entry.realm.as_bytes());
    RealmKit {
        tenant: entry.tenant,
        realm: entry.realm,
        issuer: String::from(entry.issuer.as_str()),
        name: String::from("Acme"),
        kek: Box::new(SoftKek::new("realm-kek:1", [3; 32])),
        ids: IdKey::new(Secret::new([4; 32])),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([9; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(entry.issuer.authority()).unwrap(),
            name: String::from("Acme"),
            pinned: true,
            related: Vec::new(),
        },
        webauthn: RealmPolicy::default(),
        auth: AuthPolicy::DEFAULT,
        lifetimes: SessionPolicy::DEFAULT,
    }
}

/// A test CA and a leaf for `host`, PEM.
fn tls(host: &str) -> (String, String, String) {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&key, &issuer).unwrap();
    (ca_pem, cert.pem(), key.serialize_pem())
}

/// Registers the software passkey of `key` for `subject` the way the bootstrap does (OP-149
/// m.26 (e)): the realm's own registration ceremony, finished through the hosted path's step.
async fn register_passkey(
    pool: &access_store::Pool,
    kit: &RealmKit,
    subject: [u8; 16],
    key: &SoftSigner,
    issuer: &str,
) {
    let access_kernel::verify::cose::PublicKey::Ed25519(public) = key.public_key() else {
        panic!("not ed25519");
    };
    let authenticator =
        access_identity_webauthn::domain::software::SoftwareAuthenticator::ed25519(public);
    let db = PgAccounts(pool.clone());
    let registry = PgPasskeys {
        pool,
        tenant: kit.tenant,
        kek: &*kit.kek,
        ids: &kit.ids,
    };
    let gate = LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0);
    let hasher = Hasher::new(HasherConfig::sized(Argon2Params::CANONICAL, 4, None));
    let link_base = format!("{issuer}/login/link#");
    let auth = Auth {
        db: &db,
        realm: kit.realm(),
        policy: kit.auth,
        lifetimes: kit.lifetimes,
        clock: &Live,
        random: &OsRandom,
        notifier: &Dropping,
        link_base: &link_base,
        gate: &gate,
        hasher: &hasher,
        passkeys: Passkeys {
            registry: &registry,
            signals: &LogSignals,
            decoys: &kit.decoys,
            rp: &kit.rp,
            policy: &kit.webauthn,
        },
    };
    let start = auth.start_passkey(subject, WHO, WHO).await.unwrap();
    let (rp_id, origin) = access_local_client::passkey::relying_party(issuer).unwrap();
    let reg = authenticator.registration(&rp_id, &origin, &start.state.challenge);
    let outcome = auth
        .register_passkey(
            subject,
            &start.state,
            &RegistrationResponse {
                raw_id: &reg.id,
                client_data_json: &reg.client_data_json,
                attestation_object: &reg.attestation_object,
                transports: &[String::from("internal")],
                extensions: ClientExtensionResults::default(),
            },
            "test",
        )
        .await
        .unwrap();
    assert!(matches!(outcome, RegistrationOutcome::Registered(_)));
}

fn claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap()
}

// OP-149 m.26 (b), RFC 6749 §4.1, RFC 7636, RFC 9449, RFC 9207, TN-27, OP-69: the client signs
// the test user in through the Frontend API's JSON steps, returns to /authorize, exchanges the
// code with PKCE and a DPoP proof (taking the server's nonce once) and gets cnf-bound tokens;
// the realm's own issuer is the one resource it may name without a product; a wrong password
// or an unknown client is reported, not worked around; plain http is refused
#[tokio::test]
async fn the_headless_client_runs_the_code_flow() {
    let c = Cluster::new(&["acme"]).await;
    let f = &c.realms[0];
    let entry = RealmEntry {
        tenant: f.realm.tenant,
        realm: f.realm.realm,
        slug: f.slug.clone(),
        issuer: f.realm.issuer.clone(),
    };
    let kit = Arc::new(kit(&entry));
    let hasher = HasherConfig::sized(Argon2Params::CANONICAL, 4, None);
    let hosted = Arc::new(Hosted {
        kits: Kit(kit.clone()),
        db: c.db.app.clone(),
        clock: Live,
        messages: Silent,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(hasher),
        redirect_to: String::from("/"),
    });
    // the test user, as the bootstrap makes it (OP-149 m.26 (b))
    let accounts = PgAccounts(c.db.app.clone());
    let who = Actor {
        actor: "test",
        correlation: "test",
    };
    let id = Identifier::new(IdentifierKind::Email, WHO).unwrap();
    let subject = create(&accounts, &kit.realm(), &[id], &who).await.unwrap();
    let hasher = Hasher::new(hasher);
    set_password(
        &accounts,
        &kit.realm(),
        &PasswordServices {
            hasher: &hasher,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        },
        subject,
        PW,
        &who,
    )
    .await
    .unwrap();
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(&accounts, &kit.realm(), subject, to, &who)
            .await
            .unwrap();
    }

    let app = oauth_router(OAuth::new(c.env())).merge(login_router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted,
        None,
    ));
    let (ca_pem, cert_pem, key_pem) = tls(&f.host);
    let config = server_config(cert_pem.as_bytes(), key_pem.as_bytes(), None).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(serve(listener, config, app, async {
        let _ = stopped.await;
    }));

    let http = Http::new(ca_pem.as_bytes(), None, Some(addr)).unwrap();
    let issuer = f.issuer.clone();
    let l = Login {
        issuer: &issuer,
        client_id: &f.public,
        redirect_uri: NATIVE,
        identifier: WHO,
        credential: Credential::Password(PW, None),
        resource: None,
        scope: "openid",
    };
    let tokens = login(&http, &l).await.unwrap();
    assert_eq!(tokens["token_type"], "DPoP");
    let at = claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], issuer);
    assert_eq!(at["iss"], issuer);
    assert_eq!(at["client_id"], f.public);
    assert_eq!(at["cnf"]["jkt"], tokens["dpop_jkt"]);
    let id = claims(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["aud"], f.public);
    assert_eq!(id["sub"], at["sub"]);
    assert!(tokens["refresh_token"].is_string());

    // RFC 8707: the realm itself may be named as the resource
    let again = login(
        &http,
        &Login {
            resource: Some(&issuer),
            ..l
        },
    )
    .await
    .unwrap();
    assert_eq!(
        claims(again["access_token"].as_str().unwrap())["aud"],
        issuer
    );
    // anything else is invalid_target, reported from the authorization response
    let wrong = login(
        &http,
        &Login {
            resource: Some("cli_0000000000000000000000000z"),
            ..l
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(wrong.contains("invalid_target"), "{wrong}");

    // CR-40: a wrong password is the neutral refusal, never a token
    let refused = login(
        &http,
        &Login {
            credential: Credential::Password("not the password at all", None),
            ..l
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("password") && refused.contains("401"),
        "{refused}"
    );
    let unknown = login(
        &http,
        &Login {
            client_id: "cli_0000000000000000000000000z",
            ..l
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unknown.contains("authorize") && unknown.contains("400"),
        "{unknown}"
    );
    // TI-9, OP-69: only https, and only the trusted CA
    assert!(
        login(
            &http,
            &Login {
                issuer: "http://acme.id.test",
                ..l
            }
        )
        .await
        .is_err()
    );
    let other = tls(&f.host).0;
    let untrusted = Http::new(other.as_bytes(), None, Some(addr)).unwrap();
    let tls_error = login(&untrusted, &l).await.unwrap_err().to_string();
    assert!(tls_error.starts_with("tls"), "{tls_error}");

    // OP-149 m.26 (e), §10.2.4: the software passkey, registered through the step the hosted
    // registration finishes with, signs the user in identifier-first (AAL2, no userHandle
    // needed); another key under the same relying party is refused, never a token
    let (key, _) = SoftSigner::generate_ed25519().unwrap();
    register_passkey(&c.db.app, &kit, subject, &key, &issuer).await;
    let (rp_id, origin) = access_local_client::passkey::relying_party(&issuer).unwrap();
    let passkey = Passkey {
        key: &key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let with_passkey = login(
        &http,
        &Login {
            credential: Credential::Passkey(&passkey),
            ..l
        },
    )
    .await
    .unwrap();
    assert_eq!(with_passkey["token_type"], "DPoP");
    assert_eq!(
        claims(with_passkey["id_token"].as_str().unwrap())["sub"],
        at["sub"]
    );
    let (stranger, _) = SoftSigner::generate_ed25519().unwrap();
    let forged = Passkey {
        key: &stranger,
        rp_id: &rp_id,
        origin: &origin,
    };
    let refused = login(
        &http,
        &Login {
            credential: Credential::Passkey(&forged),
            ..l
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("passkey") && refused.contains("401"),
        "{refused}"
    );

    let _ = stop.send(());
    let _ = served.await;
}
