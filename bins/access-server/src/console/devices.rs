//! The console session's device Instance (OP-149 m.6, m.16 (a), OP-151 m.3 (e), m.12 (d)): the
//! browser's non-extractable key opens its own Instance through the same self-signed
//! `instance_create` (and, for a user without a Party, `party_register`) Exercises the Frontend
//! API uses. The challenge is the BFF's, kept on the session row and taken once; the session
//! must have authenticated within [`FRESH_MS`] (the console signs in with `prompt=login`). The
//! key is recorded as the subject's device key with its Claims, bound to the login session the
//! console signed in with (§10.1.3, OP-150 L2). One Instance per session (INV-13).

use access_http::console::ports::{
    ConsoleSession, DeviceAnswer, Devices, SessionInstance, Unavailable,
};
use access_identity_account::adapters::pg::PgTx;
use access_identity_session::domain::device::instance_key;
use access_identity_ui::app::devices::{DeviceKey, bind_party, record_device_key};
use access_identity_ui::domain::frontend::{IDENTITY_PEP, InstanceRegistration, rfc3339, unix_ms};
use access_identity_ui::ports::DeviceInstances;
use access_internal_api::context::RateContext;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, register_nonce,
    self_signed_intent,
};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{Id, Window};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use access_store::Pool;
use access_store::console::{self, ConsoleSessionRow, Pending};
use access_store::identity::TenantTx;
use axum::body::Bytes;
use serde_json::json;
use suiss_crypto::dcbor::{self, Limits};

/// How long after its authentication a console session may register its device (PD).
pub(crate) const FRESH_MS: u64 = 15 * 60_000;

/// How long a registration challenge and its intents are valid (PD).
pub(crate) const CHALLENGE_MS: u64 = 10 * 60_000;

/// Largest `COSE_Key` accepted.
const MAX_KEY: usize = 256;

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

fn answer(status: u16, body: serde_json::Value) -> DeviceAnswer {
    DeviceAnswer {
        status,
        body,
        instance: None,
    }
}

fn problem(status: u16, code: &str, title: &str) -> DeviceAnswer {
    answer(
        status,
        json!({
            "type": format!("urn:suiss:access:problem:{code}"),
            "title": title,
            "status": status,
        }),
    )
}

/// The answer to a registration the authority plane refused.
fn refusal(code: &str) -> DeviceAnswer {
    tracing::info!(
        event = "console.device.refused",
        outcome = "refused",
        %code,
        "device not registered"
    );
    if code.starts_with("ais-") {
        problem(
            400,
            "key-pop-invalid",
            "The device key could not be verified",
        )
    } else {
        problem(
            409,
            "instance-not-registered",
            "The device could not be registered",
        )
    }
}

fn invalid() -> DeviceAnswer {
    problem(400, "invalid-request", "The request is not valid")
}

fn bytes(text: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    b64url_decode(text)
        .ok()
        .filter(|b| (min..=max).contains(&b.len()))
}

/// The console's device Instances over the application pool and the authority plane.
pub(crate) struct ConsoleDevices<I> {
    pub(crate) app: Pool,
    pub(crate) instances: I,
    /// The cell's address pseudonyms, for the bootstrap rate context (OP-152 m.5 (b)).
    pub(crate) ips: std::sync::Arc<dyn access_identity_risk::ports::IpPseudonyms>,
}

impl<I: DeviceInstances> ConsoleDevices<I> {
    async fn live_row(
        &self,
        session: &ConsoleSession,
    ) -> Result<Option<ConsoleSessionRow>, Unavailable> {
        let row = console::by_id(&self.app, &session.id).await.map_err(down)?;
        Ok(row.filter(|r| r.ended_ms.is_none() && r.instance.is_none()))
    }

    async fn row_party(&self, row: &ConsoleSessionRow) -> Result<Option<[u8; 16]>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, row.tenant, row.realm)
            .await
            .map_err(down)?;
        let p = access_store::idp::subject_party(&mut t, &row.subject)
            .await
            .map_err(down)?;
        t.commit().await.map_err(down)?;
        Ok(p)
    }

    fn registration(
        row: &ConsoleSessionRow,
        party: [u8; 16],
        key: PublicKey,
        create: SelfSigned,
        register: Option<SelfSigned>,
    ) -> Registration {
        Registration {
            tenant: *row.tenant.as_bytes(),
            domain: Digest(row.domain),
            registrant: Registrant::Device {
                realm: *row.realm.as_bytes(),
                subject: row.subject,
            },
            party: Id(party),
            key,
            register,
            create,
            pep: String::from(IDENTITY_PEP),
            context: None,
        }
    }

    /// The bootstrap rate context of a console session (OP-152 m.5 (b)): the pseudonym of the
    /// address prefix its network binding names, or its autonomous system as a class.
    fn context(&self, row: &ConsoleSessionRow, session: &ConsoleSession) -> Option<RateContext> {
        use access_identity_session::domain::console::Binding;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let ip = match session.facts.binding {
            Binding::Asn(asn) => return RateContext::attestation(&format!("asn.{asn}")),
            Binding::V4Prefix([a, b, c]) => IpAddr::V4(Ipv4Addr::new(a, b, c, 0)),
            Binding::V6Prefix(p) => {
                let mut o = [0; 16];
                o[..6].copy_from_slice(&p);
                IpAddr::V6(Ipv6Addr::from(o))
            }
            Binding::Address(ip) => ip,
        };
        self.ips
            .prefix(row.tenant.as_bytes(), row.realm.as_bytes(), ip)
            .map(|p| RateContext::address(&p))
    }

    async fn recorded(
        &self,
        row: &ConsoleSessionRow,
        party: Option<([u8; 16], &[u8])>,
        key: &PublicKey,
        instance: [u8; 16],
    ) -> Result<(), Unavailable> {
        let mut tx = PgTx::new(
            TenantTx::begin(&self.app, row.tenant, row.realm)
                .await
                .map_err(down)?,
        );
        if let Some((party, proof)) = party
            && !bind_party(&mut tx, &row.subject, &party, proof)
                .await
                .map_err(down)?
        {
            tracing::warn!(
                event = "console.device.party_bound",
                outcome = "skipped",
                "device party already bound"
            );
        }
        record_device_key(
            &mut tx,
            &DeviceKey {
                subject: row.subject,
                key: key.clone(),
                instance,
                session: Some(row.login_session),
            },
        )
        .await
        .map_err(down)?;
        tx.0.commit().await.map_err(down)
    }
}

/// A registration body in bytes.
struct Parsed {
    challenge: [u8; 32],
    party: [u8; 16],
    cose: Vec<u8>,
    ais: Vec<u8>,
    validity: Window,
    register_ais: Option<Vec<u8>>,
}

fn parsed(body: &[u8]) -> Option<Parsed> {
    let r = serde_json::from_slice::<InstanceRegistration>(body).ok()?;
    let register_ais = match r.register_ais.as_deref() {
        None => None,
        Some(a) => Some(bytes(a, 1, 8192)?),
    };
    let (from, until) = (unix_ms(&r.valid_from)?, unix_ms(&r.valid_until)?);
    (from <= until).then_some(())?;
    Some(Parsed {
        challenge: <[u8; 32]>::try_from(bytes(&r.challenge, 32, 32)?).ok()?,
        party: <[u8; 16]>::try_from(bytes(&r.party, 16, 16)?).ok()?,
        cose: bytes(&r.key, 1, MAX_KEY)?,
        ais: bytes(&r.ais, 1, 8192)?,
        validity: Window { from, until },
        register_ais,
    })
}

fn envelope(
    payload: &access_kernel::meta::Payload,
    party: [u8; 16],
    validity: Window,
) -> Result<String, Unavailable> {
    let intent = self_signed_intent(payload, Id(party), validity).ok_or(Unavailable)?;
    let bytes = dcbor::encode(&intent.to_value(), Limits::CEILING).map_err(down)?;
    Ok(b64url_encode(&bytes))
}

impl<I: DeviceInstances> Devices for ConsoleDevices<I> {
    async fn challenge(
        &self,
        session: &ConsoleSession,
        body: Bytes,
    ) -> Result<DeviceAnswer, Unavailable> {
        let Some(cose) = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("key")
                    .and_then(|k| k.as_str())
                    .and_then(|k| bytes(k, 1, MAX_KEY))
            })
        else {
            return Ok(invalid());
        };
        let Ok(key) = instance_key(&cose) else {
            return Ok(problem(
                400,
                "key-invalid",
                "The device key could not be verified",
            ));
        };
        let Some(row) = self.live_row(session).await? else {
            return Ok(problem(
                409,
                "instance-exists",
                "This sign-in already has a device",
            ));
        };
        let now = crate::admin::now_ms()?;
        if row.auth_time_ms.saturating_add(FRESH_MS) < now {
            return Ok(problem(403, "step-up-required", "Sign in again first"));
        }
        let bound = self.row_party(&row).await?;
        let party = match bound {
            Some(p) => p,
            None => access_crypto::random::bytes::<16>().map_err(down)?,
        };
        let challenge = access_crypto::random::bytes::<32>().map_err(down)?;
        let validity = Window {
            from: now,
            until: now.saturating_add(CHALLENGE_MS),
        };
        let preview = Self::registration(
            &row,
            party,
            key,
            SelfSigned {
                nonce: challenge.to_vec(),
                validity,
                ais: Vec::new(),
            },
            None,
        );
        let ExerciseBasis::Public(grant) = bootstrap_basis(&preview.domain) else {
            return Err(Unavailable);
        };
        let mut out = json!({
            "challenge": b64url_encode(&challenge),
            "domain": b64url_encode(&row.domain),
            "basis": b64url_encode(&grant.0),
            "pep": IDENTITY_PEP,
            "party": b64url_encode(&party),
            "valid_from": rfc3339(validity.from),
            "valid_until": rfc3339(validity.until),
            "expires_at": rfc3339(validity.until),
            "create": envelope(&preview.create_payload(), party, validity)?,
        });
        if bound.is_none()
            && let Some(m) = out.as_object_mut()
        {
            m.insert(
                String::from("register"),
                envelope(&preview.register_payload(), party, validity)?.into(),
            );
        }
        let pending = Pending {
            challenge,
            key: cose,
            party,
            from_ms: validity.from,
            until_ms: validity.until,
        };
        if !console::set_pending(&self.app, &session.id, &pending)
            .await
            .map_err(down)?
        {
            return Ok(problem(
                409,
                "instance-exists",
                "This sign-in already has a device",
            ));
        }
        Ok(answer(201, out))
    }

    async fn register(
        &self,
        session: &ConsoleSession,
        body: Bytes,
    ) -> Result<DeviceAnswer, Unavailable> {
        let Some(Parsed {
            challenge,
            party,
            cose,
            ais,
            validity,
            register_ais,
        }) = parsed(&body)
        else {
            return Ok(invalid());
        };
        let Some(row) = self.live_row(session).await? else {
            return Ok(problem(
                409,
                "instance-exists",
                "This sign-in already has a device",
            ));
        };
        let now = crate::admin::now_ms()?;
        let Some(pending) = console::take_pending(&self.app, &session.id, &challenge, now)
            .await
            .map_err(down)?
        else {
            return Ok(problem(400, "invalid-challenge", "Ask for a new challenge"));
        };
        if pending.key != cose
            || pending.party != party
            || pending.from_ms != validity.from
            || pending.until_ms != validity.until
        {
            return Ok(problem(400, "invalid-challenge", "Ask for a new challenge"));
        }
        let Ok(key) = instance_key(&cose) else {
            return Ok(problem(
                400,
                "key-invalid",
                "The device key could not be verified",
            ));
        };
        let bound = self.row_party(&row).await?;
        let fits = match (bound, &register_ais) {
            (Some(p), None) => p == party,
            (None, Some(_)) => true,
            _ => false,
        };
        if !fits {
            return Ok(problem(
                400,
                "invalid-party",
                "The Party is not this user's",
            ));
        }
        let mut registration = Self::registration(
            &row,
            party,
            key.clone(),
            SelfSigned {
                nonce: challenge.to_vec(),
                validity,
                ais,
            },
            register_ais.as_ref().map(|a| SelfSigned {
                nonce: register_nonce(&challenge),
                validity,
                ais: a.clone(),
            }),
        );
        registration.context = self.context(&row, session);
        let verdict = self.instances.register(registration).await.map_err(down)?;
        let registered = match verdict {
            RegistrationVerdict::Registered(r) => r,
            RegistrationVerdict::Refused { code } => return Ok(refusal(&code)),
        };
        let proof = register_ais.as_deref().map(|p| (party, p));
        self.recorded(
            &row,
            bound.is_none().then_some(proof).flatten(),
            &key,
            registered.instance.0,
        )
        .await?;
        tracing::info!(
            event = "console.device.registered",
            outcome = "ok",
            "console device registered"
        );
        Ok(DeviceAnswer {
            status: 201,
            body: json!({
                "instance": b64url_encode(&registered.instance.0),
                "kid": b64url_encode(&registered.kid),
                "party": b64url_encode(&registered.party.0),
            }),
            instance: Some(SessionInstance {
                kid: thumbprint(&key),
                key,
            }),
        })
    }

    async fn party(&self, session: &ConsoleSession) -> Result<Option<[u8; 16]>, Unavailable> {
        let row = console::by_id(&self.app, &session.id).await.map_err(down)?;
        match row.filter(|r| r.ended_ms.is_none()) {
            Some(r) => self.row_party(&r).await,
            None => Ok(None),
        }
    }
}
