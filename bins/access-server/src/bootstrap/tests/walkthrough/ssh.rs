//! The realm SSH certificate authority on the real server (OP-156 m.3 (o), IDP-32, OP-153 m.3
//! (gg)): the CA is turned on and its server group registered by committed `idp.ssh.*`
//! decisions; the test user P signs in with the software passkey through `/authorize` and
//! `/token` (PKCE, DPoP) and asks `POST /realms/acme/ssh/certificate` with the access token for
//! an ephemeral key; the draft comes from P's `ssh.login` Grant, P's device Instance signs it,
//! the real sequencer decides it and the identity signer over `SoftHSM` signs the certificate.
//! `ssh-keygen` reads the certificate and the KRL the realm publishes.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through the certificate authority's rules"
)]

use std::collections::BTreeMap;

use access_identity_oauth::domain::authority::{TokenExercise, encode_exercise};
use access_identity_ssh::domain::cert::{Certificate, Extension};
use access_identity_ssh::domain::change::SshChange;
use access_identity_ssh::domain::key::Ed25519Public;
use access_identity_ssh::domain::krl::Krl;
use access_identity_ssh::domain::schema;
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_decode;
use access_kernel::model::{Bound, EqValue, Structural};
use access_local_client::dpop::Es256Key;
use access_local_client::login::{Credential, Login, login_keyed};
use access_local_client::passkey::{Passkey, relying_party};
use serde_json::{Value as JsonValue, json};
use suiss_crypto::signer::SoftSigner;

use super::*;

const HOUR_MS: u64 = 3_600_000;

/// A signed-in holder: its access token and the DPoP key it is bound to.
struct SignedIn {
    token: String,
    key: Es256Key,
}

fn texts(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

/// `ssh.login` over every server group with `params`, for `life_ms`.
fn login_authority(params: BTreeMap<String, Bound>, now: u64, life_ms: u64) -> CanonicalAuthority {
    let mut a = authority(
        BTreeSet::from([schema::login_ref()]),
        schema::NAMESPACE,
        BTreeSet::new(),
    );
    a.authority.resource = ResourceSelector::Structural(Structural {
        namespace: String::from(schema::NAMESPACE),
        prefix: vec![String::from(schema::HOST_GROUP)],
        kind: None,
        attrs: BTreeMap::new(),
    });
    a.authority.params = params;
    a.constraints.validity = Window {
        from: now - 60_000,
        until: now + life_ms,
    };
    a
}

fn deploy_params() -> BTreeMap<String, Bound> {
    BTreeMap::from([
        (
            String::from(schema::PRINCIPAL),
            Bound::Enum(texts(&["ayse", "deploy"])),
        ),
        (
            String::from(schema::FORCE_COMMAND),
            Bound::Eq(EqValue::Text(String::from("/usr/local/bin/deploy"))),
        ),
        (String::from("permit_pty"), Bound::Flag(true)),
    ])
}

fn ephemeral() -> Ed25519Public {
    let (key, _) = SoftSigner::generate_ed25519().unwrap();
    match key.public_key() {
        PublicKey::Ed25519(k) => Ed25519Public(k),
        other => panic!("{other:?}"),
    }
}

fn keygen(args: &[&str], at: &std::path::Path) -> (bool, String) {
    let out = std::process::Command::new("ssh-keygen")
        .args(args)
        .current_dir(at)
        .output()
        .expect("ssh-keygen runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

impl Desk {
    /// Commits an `idp.ssh.*` change as the realm's root.
    async fn ssh_change(&self, change: SshChange) {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
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
        b.change(
            &b.admin(&ids, None),
            (route.tenant, route.realm),
            self.domain,
            &root_key(&self.w.keys).unwrap(),
            access_identity_admin::domain::Change::Ssh(change),
        )
        .await
        .unwrap();
    }

    /// P signs in with the passkey through the code flow, the session bound to P's device.
    async fn ssh_sign_in(&self) -> SignedIn {
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        let (tokens, key) = login_keyed(
            &self.http,
            &Login {
                issuer: &self.user.issuer,
                client_id: &self.user.client_id,
                redirect_uri: &self.user.redirect_uri,
                identifier: &self.user.identifier,
                credential: Credential::Passkey(&passkey),
                resource: None,
                scope: "openid",
                device: Some(&device),
            },
            Es256Key::generate().unwrap(),
        )
        .await
        .unwrap();
        SignedIn {
            token: String::from(tokens["access_token"].as_str().unwrap()),
            key,
        }
    }

    async fn ssh_get(&self, path: &str) -> (u16, Vec<u8>) {
        let r = self
            .http
            .request("GET", &format!("{}{path}", self.user.issuer), &[], None)
            .await
            .unwrap();
        (r.status, r.body.clone())
    }

    /// One `POST /ssh/certificate` with the access token and a fresh DPoP proof, retried once
    /// with the nonce the realm asks for.
    async fn ssh_post(&self, who: &SignedIn, body: &JsonValue) -> (u16, JsonValue) {
        let url = format!("{}/ssh/certificate", self.user.issuer);
        let mut nonce: Option<String> = None;
        for _ in 0..2 {
            let proof = who
                .key
                .proof("POST", &url, nonce.as_deref(), Some(&who.token))
                .unwrap();
            let authorization = format!("DPoP {}", who.token);
            let bytes = body.to_string().into_bytes();
            let r = self
                .http
                .request(
                    "POST",
                    &url,
                    &[("authorization", &authorization), ("dpop", &proof)],
                    Some(("application/json", &bytes)),
                )
                .await
                .unwrap();
            if r.status == 401
                && let Some(n) = r.header("dpop-nonce")
                && nonce.is_none()
            {
                nonce = Some(String::from(n));
                continue;
            }
            let json = serde_json::from_slice(&r.body).unwrap_or(JsonValue::Null);
            return (r.status, json);
        }
        panic!("no answer after the nonce");
    }

    /// The draft for `ask`, signed by `signer` (an Instance key of the draft's holder) with
    /// `tamper` applied to its bounds first.
    async fn ssh_signed(
        &self,
        who: &SignedIn,
        ask: &JsonValue,
        signer: &dyn Fn(&Statement) -> Vec<u8>,
        tamper: impl FnOnce(&mut CanonicalAuthority),
    ) -> (u16, JsonValue) {
        let (status, drafted) = self.ssh_post(who, ask).await;
        assert_eq!(status, 200, "{drafted}");
        let d = &drafted["draft"];
        let b64 = |k: &str| b64url_decode(d[k].as_str().unwrap()).unwrap();
        let mut payload = Payload::from_bytes(&b64("payload")).unwrap();
        let mut intent = IntentEnvelope::from_bytes(&b64("intent")).unwrap();
        let Payload::ProjectionIssue { bounds, .. } = &mut payload else {
            panic!("{d}");
        };
        let before = bounds.clone();
        tamper(bounds);
        if *bounds != before {
            let validity = intent.validity;
            let holder = Id(<[u8; 16]>::try_from(
                b64url_decode(d["basis"]["holding"]["holder"].as_str().unwrap()).unwrap(),
            )
            .unwrap());
            intent = self_signed_intent(&payload, holder, validity).unwrap();
        }
        let h = &d["basis"]["holding"];
        let id16 = |v: &JsonValue| {
            Id(<[u8; 16]>::try_from(b64url_decode(v.as_str().unwrap()).unwrap()).unwrap())
        };
        let basis = ExerciseBasis::Holding(HoldingRef {
            grant: id16(&h["grant"]),
            holder: id16(&h["holder"]),
            since: h["since"].as_u64().unwrap(),
        });
        let domain = Digest(<[u8; 32]>::try_from(b64("domain")).unwrap());
        let capacity = match &d["capacity"] {
            JsonValue::String(s) if s == "own" => Capacity::Own,
            c => Capacity::For(id16(&c["for"])),
        };
        let nonce = b64("nonce");
        let ais = signer(&Statement {
            domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(d["pep"].as_str().unwrap()),
            capacity,
            basis,
            iat: server_time(&self.w.db.app).await.unwrap(),
            exercise: None,
        });
        let exercise = encode_exercise(&TokenExercise {
            domain,
            nonce,
            intent,
            payload_bytes: payload.to_bytes().unwrap(),
            payload,
            basis,
            capacity,
            ais,
            target: None,
        })
        .unwrap();
        self.ssh_post(who, &json!({ "exercise": exercise })).await
    }
}

fn ca_keys(text: &[u8]) -> Vec<Ed25519Public> {
    String::from_utf8(text.to_vec())
        .unwrap()
        .lines()
        .map(|l| Ed25519Public::of_line(l).unwrap())
        .collect()
}

// IDP-32, OP-156 m.3 (o), G2, Ek B 5134, 5205
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_certificate_is_a_projection_of_the_ssh_login_grant() {
    Box::pin(person_walk()).await;
}

async fn person_walk() {
    let d = Box::pin(Desk::open("q8-ssh-person", false)).await;
    let (status, _) = d.ssh_get("/ssh/ca.pub").await;
    assert_eq!(status, 409);
    d.ssh_change(SshChange::CaEnable).await;
    d.ssh_change(SshChange::HostGroupRegister {
        name: String::from("prod-web"),
        description: String::from("Web servers"),
    })
    .await;
    let (status, body) = d.ssh_get("/ssh/ca.pub").await;
    assert_eq!(status, 200);
    let ca = ca_keys(&body);
    assert_eq!(ca.len(), 1);

    let now = server_time(&d.w.db.app).await.unwrap();
    let held = root_grant(
        &d.w,
        d.domain,
        grant_of(
            &d.domain,
            d.person,
            login_authority(deploy_params(), now, 48 * HOUR_MS),
        ),
    )
    .await;
    // OP-141 m.22 (g)
    assert!(d.w.domains.derive().await.is_empty());
    let p = Box::pin(d.ssh_sign_in()).await;
    let device = d.token.signer(local::TEST_DEVICE_LABEL).unwrap();
    let by_device = |s: &Statement| sign(&device, s).unwrap();
    let key = ephemeral();
    let ask = json!({ "host_group": "prod-web", "public_key": b64url_encode(&key.0) });

    let (status, issued) = d.ssh_signed(&p, &ask, &by_device, |_| {}).await;
    assert_eq!(status, 200, "{issued}");
    let cert = Certificate::of_line(issued["certificate"].as_str().unwrap()).unwrap();
    let (fields, signature, signed) = cert.parse().unwrap();
    suiss_crypto::sig::ed25519(
        &suiss_crypto::sig::PureBackend,
        &ca[0].0,
        cert.0.get(..signed).unwrap(),
        &signature,
    )
    .unwrap();
    assert_eq!(fields.ca, ca[0]);
    assert_eq!(fields.key, key);
    assert_eq!(fields.principals, texts(&["ayse", "deploy"]));
    assert_eq!(
        fields.force_command.as_deref(),
        Some("/usr/local/bin/deploy")
    );
    assert_eq!(fields.extensions, BTreeSet::from([Extension::Pty]));
    assert!(fields.valid_before - fields.valid_after <= (8 * HOUR_MS + 60_000) / 1000);
    assert_ne!(fields.serial, 0);
    assert_eq!(issued["holder"], "person");

    let at = std::env::temp_dir().join(format!("access-q8-ssh-{}", std::process::id()));
    std::fs::create_dir_all(&at).unwrap();
    std::fs::write(at.join("id-cert.pub"), cert.line("p@acme")).unwrap();
    let (ok, out) = keygen(&["-L", "-f", "id-cert.pub"], &at);
    assert!(
        ok && out.contains("force-command /usr/local/bin/deploy"),
        "{out}"
    );

    // IDP-32, G2
    let only_root = json!({ "host_group": "prod-web", "public_key": b64url_encode(&key.0),
                            "principals": ["root"] });
    let (status, refused) = d.ssh_post(&p, &only_root).await;
    assert_eq!(status, 403, "{refused}");
    let (status, refused) = d
        .ssh_signed(&p, &ask, &by_device, |b| {
            b.authority.params.insert(
                String::from(schema::PRINCIPAL),
                Bound::Enum(texts(&["ayse", "root"])),
            );
        })
        .await;
    assert_eq!(status, 403, "{refused}");
    let (status, refused) = d
        .ssh_signed(&p, &ask, &by_device, |b| {
            b.authority.params.remove(schema::FORCE_COMMAND);
        })
        .await;
    assert_eq!(status, 403, "{refused}");
    // OP-156 m.3 (o)
    let long = json!({ "host_group": "prod-web", "public_key": b64url_encode(&key.0),
                       "lifetime_s": 13 * 3600 });
    let (status, refused) = d.ssh_post(&p, &long).await;
    assert_eq!(status, 400, "{refused}");
    let (status, refused) = d
        .ssh_post(
            &p,
            &json!({ "host_group": "staging", "public_key": b64url_encode(&key.0) }),
        )
        .await;
    assert_eq!(status, 403, "{refused}");

    let (status, krl) = d.ssh_get("/ssh/krl").await;
    assert_eq!(status, 200);
    assert!(!Krl::decode(&krl).unwrap().revokes(&ca[0], fields.serial));
    // INV-5, OP-156 m.3 (o)
    root_revoke(&d.w, d.domain, held.grant, d.person).await;
    let (status, krl) = d.ssh_get("/ssh/krl").await;
    assert_eq!(status, 200);
    let list = Krl::decode(&krl).unwrap();
    assert!(list.revokes(&ca[0], fields.serial));
    std::fs::write(at.join("krl"), &krl).unwrap();
    let (ok, out) = keygen(&["-Q", "-f", "krl", "id-cert.pub"], &at);
    assert!(!ok && out.contains("REVOKED"), "{out}");
    let (status, refused) = d.ssh_post(&p, &ask).await;
    assert_eq!(status, 403, "{refused}");

    d.ssh_change(SshChange::CaRotate).await;
    let (_, body) = d.ssh_get("/ssh/ca.pub").await;
    assert_eq!(ca_keys(&body).len(), 2);
    d.ssh_change(SshChange::CaDisable).await;
    let (status, _) = d.ssh_get("/ssh/ca.pub").await;
    assert_eq!(status, 409);
    let (_, krl) = d.ssh_get("/ssh/krl").await;
    let list = Krl::decode(&krl).unwrap();
    assert!(list.keys.contains(&ca[0]));
    assert_eq!(list.keys.len(), 2);
    d.close().await;
}

// IDP-32, OP-156 m.3 (o), AG-24, Ek B 5217
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_certificate_is_narrower_and_lives_at_most_one_hour() {
    Box::pin(agent_walk()).await;
}

async fn agent_walk() {
    let d = Box::pin(Desk::open("q8-ssh-agent", true)).await;
    d.ssh_change(SshChange::CaEnable).await;
    d.ssh_change(SshChange::HostGroupRegister {
        name: String::from("prod-web"),
        description: String::new(),
    })
    .await;
    let now = server_time(&d.w.db.app).await.unwrap();
    let mut person_params = deploy_params();
    person_params.remove("permit_pty");
    let mut to_person = grant_of(
        &d.domain,
        d.person,
        login_authority(person_params, now, 48 * HOUR_MS),
    );
    to_person.authority.delegation = DelegationTerms {
        depth: 1,
        downstream_holder_class: Some(SubjectSelector::Party(AGENT)),
    };
    let parent = root_grant(&d.w, d.domain, to_person).await;
    let mut onward = login_authority(
        BTreeMap::from([
            (
                String::from(schema::PRINCIPAL),
                Bound::Enum(texts(&["deploy"])),
            ),
            (
                String::from(schema::FORCE_COMMAND),
                Bound::Eq(EqValue::Text(String::from("/usr/local/bin/deploy"))),
            ),
        ]),
        now,
        24 * HOUR_MS,
    );
    onward.delegation = DelegationTerms {
        depth: 0,
        downstream_holder_class: Some(SubjectSelector::Party(AGENT)),
    };
    let device = d.token.signer(local::TEST_DEVICE_LABEL).unwrap();
    issue(
        &d.w,
        d.domain,
        &device,
        Some(parent),
        AGENT,
        onward,
        (BTreeSet::from([Capacity::For(d.person)]), Capacity::Own),
    )
    .await;
    // OP-141 m.22 (g)
    assert!(d.w.domains.derive().await.is_empty());
    let p = Box::pin(d.ssh_sign_in()).await;
    let by_agent = |s: &Statement| super::super::agent::ais_by(&d.runtime.0, s).unwrap();
    let key = ephemeral();
    let ask = json!({ "host_group": "prod-web", "public_key": b64url_encode(&key.0),
                      "agent": b64url_encode(&AGENT.0) });
    let (status, issued) = d.ssh_signed(&p, &ask, &by_agent, |_| {}).await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["holder"], "agent");
    let cert = Certificate::of_line(issued["certificate"].as_str().unwrap()).unwrap();
    let (fields, _, _) = cert.parse().unwrap();
    assert_eq!(fields.principals, texts(&["deploy"]));
    assert!(fields.extensions.is_empty());
    assert!(fields.valid_before - fields.valid_after <= (15 * 60_000 + 60_000) / 1000);

    // OP-156 m.3 (o)
    let long = json!({ "host_group": "prod-web", "public_key": b64url_encode(&key.0),
                       "agent": b64url_encode(&AGENT.0), "lifetime_s": 7200 });
    let (status, refused) = d.ssh_post(&p, &long).await;
    assert_eq!(status, 400, "{refused}");
    let (status, refused) = d
        .ssh_signed(&p, &ask, &by_agent, |b| {
            b.constraints.validity.until = now + 2 * HOUR_MS;
        })
        .await;
    assert_eq!(status, 400, "{refused}");
    // G2, AG-24
    let (status, refused) = d
        .ssh_signed(&p, &ask, &by_agent, |b| {
            b.authority.params.insert(
                String::from(schema::PRINCIPAL),
                Bound::Enum(texts(&["ayse", "deploy"])),
            );
        })
        .await;
    assert_eq!(status, 403, "{refused}");
    let (status, refused) = d
        .ssh_signed(&p, &ask, &by_agent, |b| {
            b.authority
                .params
                .insert(String::from("permit_pty"), Bound::Flag(true));
        })
        .await;
    assert_eq!(status, 403, "{refused}");
    d.close().await;
}
