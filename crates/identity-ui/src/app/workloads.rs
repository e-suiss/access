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
use crate::ports::{Clock, Kits, Messages, WorkloadInstances, WorkloadOpen};

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
