//! A workload opens its own Instance (OP-154 m.3 (d), §11.21.1 carleton note, U20): the key it
//! presented at the token endpoint signs its own `instance_create` under the bootstrap basis,
//! and the authority plane accepts it only on the realm issuer's live
//! `identity_binding_workload` Claim about that key and the agent. No session, no cookie: the
//! signature is the proof of possession. The Instance acts only through a Grant.

use access_identity_account::domain::login::Problem;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::domain::device::instance_key;
use access_internal_api::instances::{RegistrationVerdict, SelfSigned};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::{Id, Window};
use serde::Deserialize;
use serde_json::json;

use super::me::{governing, unavailable};
use super::{Hosted, Reply};
use crate::domain::frontend::{IDENTITY_PEP, unix_ms};
use crate::ports::{Clock, Kits, Messages, PartyKeys, WorkloadInstances, WorkloadOpen};
use access_identity_attest::domain::runtime::RuntimeClass;

/// `POST /v1/workloads/instances`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadInstanceBody {
    /// The agent's `PartyID`, base64url of its 16 bytes.
    pub party: String,
    /// The workload's key as a `COSE_Key`, base64url: the key its DPoP proofs use.
    pub key: String,
    /// The Exercise nonce, base64url: 16 to 64 random bytes.
    pub nonce: String,
    /// The intent's validity start, RFC 3339.
    pub valid_from: String,
    /// The intent's validity end, RFC 3339.
    pub valid_until: String,
    /// The AIS (`COSE_Sign1`) of `instance_create` by the key, base64url.
    pub ais: String,
}

fn problem(status: u16, code: &'static str, title: &'static str) -> Reply {
    Reply::problem(Problem {
        status,
        code,
        title,
        retry_after_s: None,
    })
}

fn invalid() -> Reply {
    problem(400, "invalid-request", "The request is not valid")
}

fn bytes(text: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    b64url_decode(text)
        .ok()
        .filter(|b| (min..=max).contains(&b.len()))
}

fn parsed(body: &WorkloadInstanceBody) -> Option<(Id, Vec<u8>, SelfSigned)> {
    let (from, until) = (unix_ms(&body.valid_from)?, unix_ms(&body.valid_until)?);
    (from <= until).then_some(())?;
    Some((
        Id(<[u8; 16]>::try_from(bytes(&body.party, 16, 16)?).ok()?),
        bytes(&body.key, 1, 256)?,
        SelfSigned {
            nonce: bytes(&body.nonce, 16, 64)?,
            validity: Window { from, until },
            ais: bytes(&body.ais, 1, 8192)?,
        },
    ))
}

impl<K: Kits, C: Clock + Sync, M: Messages> Hosted<K, C, M> {
    /// `POST /v1/workloads/instances` (OP-154 m.3 (d)): the Instance the key opened, or the
    /// refusal; a key without the realm issuer's live Claim gets `403 workload-not-bound`.
    pub async fn open_workload_instance<W: WorkloadInstances>(
        &self,
        entry: &RealmEntry,
        body: &WorkloadInstanceBody,
        workloads: &W,
    ) -> Reply {
        let Some((party, key, create)) = parsed(body) else {
            return invalid();
        };
        let Ok(key) = instance_key(&key) else {
            return problem(400, "invalid-key", "The workload key could not be read");
        };
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let verdict = workloads
            .open_workload(WorkloadOpen {
                domain,
                party,
                key,
                create,
                pep: String::from(IDENTITY_PEP),
            })
            .await;
        match verdict {
            Ok(RegistrationVerdict::Registered(r)) => Reply::json(
                201,
                json!({
                    "instance": b64url_encode(&r.instance.0),
                    "kid": b64url_encode(&r.kid),
                    "party": b64url_encode(&r.party.0),
                }),
            ),
            Ok(RegistrationVerdict::Refused { code }) => {
                tracing::info!(%code, "workload instance not opened");
                problem(
                    403,
                    "workload-not-bound",
                    "This key has no live workload binding for that agent",
                )
            }
            Err(_) => unavailable(),
        }
    }
}

/// The attestation roots a realm's surface verifies against (OP-154 m.3 (s), AG-31 model 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestRoots {
    /// Android hardware key attestation roots.
    pub android: Vec<Vec<u8>>,
    /// TPM 2.0 manufacturer roots.
    pub tpm: Vec<Vec<u8>>,
}

impl AttestRoots {
    /// The roots `crates/identity-attest` embeds.
    #[must_use]
    pub fn embedded() -> Self {
        use access_identity_attest::domain::roots;
        Self {
            android: roots::ANDROID.iter().map(|r| r.to_vec()).collect(),
            tpm: roots::TPM.iter().map(|r| r.to_vec()).collect(),
        }
    }
}

/// `POST /v1/workloads/attestations`: hardware evidence that an Instance's own key lives in
/// hardware, for the challenge of `instance` at `at`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBody {
    /// The attested Instance, base64url of its 16 bytes.
    pub instance: String,
    /// The challenge's time, RFC 3339; within five minutes of the trusted time.
    pub at: String,
    /// `android-key`, `tpm` or `apple-app-attest`.
    pub format: String,
    /// Android: the attestation certificate chain, leaf first; TPM: the attestation key's
    /// certificate and its chain. DER, base64url.
    #[serde(default)]
    pub x5c: Vec<String>,
    /// TPM: `certInfo`, base64url.
    #[serde(default)]
    pub cert_info: Option<String>,
    /// TPM: the attestation key's signature over `certInfo`, base64url.
    #[serde(default)]
    pub sig: Option<String>,
    /// TPM: `ES256` or `RS256`.
    #[serde(default)]
    pub alg: Option<String>,
    /// TPM: the certified key's `pubArea`, base64url.
    #[serde(default)]
    pub pub_area: Option<String>,
}

/// Most certificates a chain carries.
const MAX_CHAIN: usize = 8;

fn chain(x5c: &[String]) -> Option<Vec<Vec<u8>>> {
    if x5c.is_empty() || x5c.len() > MAX_CHAIN {
        return None;
    }
    x5c.iter().map(|c| bytes(c, 1, 8192)).collect()
}

fn optional(v: Option<&String>, max: usize) -> Option<Vec<u8>> {
    v.and_then(|t| bytes(t, 1, max))
}

/// What a verified piece of evidence says: the attested key (SEC1 uncompressed) and the class.
fn verified(
    body: &AttestationBody,
    roots: &AttestRoots,
    challenge: &[u8; 32],
    now_s: u64,
) -> Result<(Vec<u8>, RuntimeClass), Reply> {
    use access_identity_attest::domain::{android, tpm};
    let refused = |e: access_identity_attest::AttestError| {
        tracing::info!(code = e.code(), "attestation refused");
        problem(
            400,
            "attestation-refused",
            "The attestation does not verify",
        )
    };
    match body.format.as_str() {
        // OP-154 m.3 (s), L21
        "android-key" => {
            let certs = chain(&body.x5c).ok_or_else(invalid)?;
            let anchors: Vec<&[u8]> = roots.android.iter().map(Vec::as_slice).collect();
            let a = android::verify(
                &certs,
                &anchors,
                &android::Policy {
                    challenge,
                    strongbox: false,
                    verified_boot: true,
                    locked: true,
                },
                now_s,
            )
            .map_err(refused)?;
            let class = RuntimeClass::android(&a);
            Ok((a.public_key, class))
        }
        "tpm" => {
            let certs = chain(&body.x5c).ok_or_else(invalid)?;
            let cert_info = optional(body.cert_info.as_ref(), 4096).ok_or_else(invalid)?;
            let sig = optional(body.sig.as_ref(), 1024).ok_or_else(invalid)?;
            let pub_area = optional(body.pub_area.as_ref(), 4096).ok_or_else(invalid)?;
            let alg = match body.alg.as_deref() {
                Some("ES256") => tpm::SigAlg::Es256,
                Some("RS256") => tpm::SigAlg::Rs256,
                _ => return Err(invalid()),
            };
            let anchors: Vec<&[u8]> = roots.tpm.iter().map(Vec::as_slice).collect();
            tpm::verify(
                &tpm::Evidence {
                    cert_info: &cert_info,
                    sig: &sig,
                    alg,
                    pub_area: &pub_area,
                    x5c: &certs,
                },
                &anchors,
                challenge,
                now_s,
            )
            .map_err(refused)?;
            let point = tpm::ecc_p256_point(&pub_area).ok_or_else(|| {
                problem(
                    400,
                    "attestation-other-key",
                    "The attested key is not this Instance's key",
                )
            })?;
            Ok((point, RuntimeClass::Tpm))
        }
        // L21
        "apple-app-attest" => Err(problem(
            400,
            "attestation-format-unsupported",
            "An App Attest key is never an Instance's own key",
        )),
        _ => Err(invalid()),
    }
}

impl<K: Kits, C: Clock + Sync, M: Messages> Hosted<K, C, M> {
    /// `POST /v1/workloads/attestations` (§5.9, §10.1.2, §12.2.1, L21, AG-31, OP-154 m.3 (s)):
    /// verifies the evidence against the embedded roots, for the challenge of the Instance at
    /// `at`; the attested key must be the Instance's own current key. The realm issuer's
    /// `attestation_runtime` Claim about the Instance's Party, bound to the Instance, is queued
    /// for the courier; it narrows or meets requirements and grants nothing.
    pub async fn attest_workload<P: PartyKeys>(
        &self,
        entry: &RealmEntry,
        body: &AttestationBody,
        (keys, roots): (&P, &AttestRoots),
    ) -> Reply {
        use access_identity_attest::domain::runtime::{CHALLENGE_SKEW_MS, challenge};
        let Some(instance) =
            bytes(&body.instance, 16, 16).and_then(|b| <[u8; 16]>::try_from(b).ok())
        else {
            return invalid();
        };
        let Some(at) = unix_ms(&body.at) else {
            return invalid();
        };
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let Ok(t) = access_store::identity::TenantTx::begin(&self.db, kit.tenant, kit.realm).await
        else {
            return unavailable();
        };
        let mut tx = access_identity_account::adapters::pg::PgTx::new(t);
        let Ok(now) = tx.0.server_time().await else {
            return unavailable();
        };
        if now.abs_diff(at) > CHALLENGE_SKEW_MS {
            return problem(400, "attestation-stale", "Ask for the attestation again");
        }
        let domain = match governing(&self.db, &kit).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let (party, key) = match keys.instance_key(domain, instance).await {
            Ok(Some(k)) => k,
            Ok(None) => return problem(404, "instance-unknown", "No such live Instance"),
            Err(_) => return unavailable(),
        };
        let c = challenge(kit.issuer.as_str(), &instance, at);
        let (attested, class) = match verified(body, roots, &c, now / 1000) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let access_kernel::verify::cose::PublicKey::P256(own) = &key else {
            return problem(
                400,
                "attestation-other-key",
                "The attested key is not this Instance's key",
            );
        };
        if own.as_slice() != attested.as_slice() {
            return problem(
                400,
                "attestation-other-key",
                "The attested key is not this Instance's key",
            );
        }
        let order = access_identity_account::domain::claims::runtime_attestation(
            party.0,
            instance,
            class.digest(),
            now,
        );
        if access_identity_account::app::claims::emit(&mut tx, &order)
            .await
            .is_err()
            || tx.0.commit().await.is_err()
        {
            return unavailable();
        }
        Reply::json(
            202,
            json!({
                "instance": b64url_encode(&instance),
                "runtime": class.name(),
            }),
        )
    }
}
