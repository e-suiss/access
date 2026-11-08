//! The account shell's session (OP-153 m.3 (w)): what the realm's `/account` pages read from
//! the hosted login session they reuse. The cookie carries the Account section's own,
//! authority-free screens; the Authority hub needs the session's device Instance, whose key
//! lives in the browser, and only its public half is read here (OP-151 m.3 (e)).

use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::domain::device::{Assurance, assurance, instance_key};
use access_identity_session::domain::session::{SESSION_COOKIE, clear_cookie};
use access_identity_session::ports::Clock;
use access_internal_api::instances::{Registrant, Registration, SelfSigned, self_signed_intent};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::{Id, Window};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::TenantTx;
use access_store::{idp, issuer};
use serde_json::Value;

use super::me::{governing, unavailable};
use super::{Body, Browser, Devices, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::domain::frontend::{rfc3339, unix_ms};
use crate::ports::{Kits, Messages};

/// Largest `COSE_Key` the shell accepts.
const MAX_KEY: usize = 256;

/// The session's device Instance: its id and the public half of the browser's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellInstance {
    /// The Instance.
    pub instance: [u8; 16],
    /// RFC 7638 thumbprint of the key, the AIS `kid`.
    pub kid: [u8; 32],
    /// The public key.
    pub key: PublicKey,
}

/// A live hosted login session as the account shell sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shell {
    /// The realm's slug.
    pub slug: String,
    /// The realm's origin, `https://host[:port]`, from its stored issuer (never from `Host`).
    pub origin: String,
    /// The realm's governing domain.
    pub domain: Digest,
    /// The account's external id.
    pub account: String,
    /// The login session's internal id.
    pub session: [u8; 16],
    /// When the session ends, Unix ms.
    pub expires_ms: u64,
    /// The Party the account is bound to, once bound.
    pub party: Option<[u8; 16]>,
    /// The session's device Instance, once registered or bound (INV-13).
    pub instance: Option<ShellInstance>,
    /// Whether the session may set up a device now: AAL2, authenticated or stepped up within
    /// the window (OP-149 m.6).
    pub fresh: bool,
}

fn ended(status: &SessionStatus) -> Reply {
    let mut r = Reply::problem(SESSION_REQUIRED);
    if matches!(status, SessionStatus::Invalid(_)) {
        r.cookies.push(clear_cookie(SESSION_COOKIE));
    }
    r
}

fn public_key(row: &issuer::DeviceKeyRow) -> Option<PublicKey> {
    match row.key_type.as_str() {
        "OKP" => <[u8; 32]>::try_from(row.public_key.as_slice())
            .ok()
            .map(PublicKey::Ed25519),
        "EC2" => Some(PublicKey::P256(row.public_key.clone())),
        _ => None,
    }
}

fn envelope(payload: &access_kernel::meta::Payload, party: Id, validity: Window) -> Option<String> {
    let intent = self_signed_intent(payload, party, validity)?;
    intent.to_bytes().ok().map(|b| b64url_encode(&b))
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// The live session behind the browser's cookie, with its Party and device Instance.
    ///
    /// # Errors
    /// The reply to send instead: `401` without a live session (G57), `503` when a store does
    /// not answer.
    pub async fn shell(&self, entry: &RealmEntry, b: &Browser<'_>) -> Result<Shell, Reply> {
        let kit = self.kit(entry).await?;
        signin!(self, kit, auth);
        let cookie = b.session.ok_or_else(|| Reply::problem(SESSION_REQUIRED))?;
        let v = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => v,
            Ok(other) => return Err(ended(&other)),
            Err(e) => return Err(failed(&e)),
        };
        let fresh = matches!(
            assurance(v.assurance.aal, v.auth_time_ms, self.clock.now_ms()),
            Assurance::Fresh
        );
        let domain = governing(&self.db, &kit).await?;
        let mut t = TenantTx::begin(&self.db, kit.tenant, kit.realm)
            .await
            .map_err(|_| unavailable())?;
        let party = idp::subject_party(&mut t, &v.subject)
            .await
            .map_err(|_| unavailable())?;
        let bound = issuer::session_instance(&mut t, &v.id)
            .await
            .map_err(|_| unavailable())?;
        let keys = match bound {
            Some(_) => issuer::subject_device_keys(&mut t, &v.subject)
                .await
                .map_err(|_| unavailable())?,
            None => Vec::new(),
        };
        t.commit().await.map_err(|_| unavailable())?;
        let instance = bound.and_then(|i| {
            let row = keys.iter().find(|k| k.instance == i)?;
            let key = public_key(row)?;
            Some(ShellInstance {
                instance: i,
                kid: thumbprint(&key),
                key,
            })
        });
        let issuer = entry.issuer.as_str();
        let origin = issuer
            .get(..issuer.len().saturating_sub(entry.issuer.path().len()))
            .unwrap_or(issuer)
            .to_owned();
        Ok(Shell {
            slug: entry.slug.clone(),
            origin,
            domain,
            account: kit.realm().external(v.subject).map_err(|_| unavailable())?,
            session: v.id,
            expires_ms: v.expires_ms,
            party,
            instance,
            fresh,
        })
    }

    /// The device challenge of the account shell (OP-149 m.6, OP-151 m.3 (e), X11): the
    /// Frontend API's challenge for the browser's `COSE_Key`, with the canonical
    /// `instance_create` (and, for an account without a Party, `party_register`) intent
    /// envelopes the browser's Kernel decodes and shows before it signs, and the validity they
    /// carry. The registration itself is the Frontend API's own `register_instance`.
    pub async fn shell_challenge<A, I, P, Q>(
        &self,
        devices: &Devices<A, I, P, Q>,
        entry: &RealmEntry,
        b: &Browser<'_>,
        cose: &str,
    ) -> Reply {
        let invalid = || {
            Reply::problem(access_identity_account::domain::login::Problem {
                status: 400,
                code: "key-invalid",
                title: "The device key could not be verified",
                retry_after_s: None,
            })
        };
        let Some(key) = b64url_decode(cose)
            .ok()
            .filter(|k| (1..=MAX_KEY).contains(&k.len()))
            .and_then(|k| instance_key(&k).ok())
        else {
            return invalid();
        };
        let mut reply = self.instance_challenge(devices, entry, b).await;
        let Body::Json(Value::Object(out)) = &mut reply.body else {
            return reply;
        };
        let text = |name: &str| out.get(name).and_then(Value::as_str).map(String::from);
        let (Some(domain), Some(expires)) = (
            text("domain").and_then(|d| b64url_decode(&d).ok()),
            text("expires_at").and_then(|e| unix_ms(&e)),
        ) else {
            return unavailable();
        };
        let Ok(domain) = <[u8; 32]>::try_from(domain.as_slice()).map(Digest) else {
            return unavailable();
        };
        let bound = text("party")
            .and_then(|p| b64url_decode(&p).ok())
            .and_then(|p| <[u8; 16]>::try_from(p.as_slice()).ok());
        let party = match bound {
            Some(p) => p,
            None => match access_crypto::random::bytes::<16>() {
                Ok(p) => p,
                Err(_) => return unavailable(),
            },
        };
        let validity = Window {
            from: self.clock.now_ms(),
            until: expires,
        };
        let preview = Registration {
            tenant: *entry.tenant.as_bytes(),
            domain,
            registrant: Registrant::Device {
                realm: *entry.realm.as_bytes(),
                subject: [0; 16],
            },
            party: Id(party),
            key,
            register: None,
            create: SelfSigned {
                nonce: Vec::new(),
                validity,
                ais: Vec::new(),
            },
            pep: devices.pep.clone(),
            context: None,
        };
        let Some(create) = envelope(&preview.create_payload(), Id(party), validity) else {
            return unavailable();
        };
        out.insert("party".into(), b64url_encode(&party).into());
        out.insert("valid_from".into(), rfc3339(validity.from).into());
        out.insert("valid_until".into(), rfc3339(validity.until).into());
        out.insert("create".into(), create.into());
        if bound.is_none() {
            let Some(register) = envelope(&preview.register_payload(), Id(party), validity) else {
                return unavailable();
            };
            out.insert("register".into(), register.into());
        }
        reply
    }
}
