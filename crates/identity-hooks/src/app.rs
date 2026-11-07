//! The hook caller (TN-135): finds the realm's live hook, signs the request, posts it with
//! the deadline and reads the answer into an outcome. Every failure is a refusal (MD-8).

use std::time::Duration;

use access_kernel::json::b64url_encode;
use access_store::identity::{RealmId, TenantId};

use crate::domain::{
    Call, Outcome, Refusal, Reply, TIMEOUT_MS, decide, request_body, request_headers,
};
use crate::ports::{CallFuture, HookCaller, HookClock, HookRegistry, HookTransport};

/// Calls hooks over a registry, a transport and a clock.
pub struct Hooks<R, T, C> {
    registry: R,
    transport: T,
    clock: C,
}

impl<R, T, C> Hooks<R, T, C>
where
    R: HookRegistry,
    T: HookTransport,
    C: HookClock,
{
    /// A caller over its ports.
    pub const fn new(registry: R, transport: T, clock: C) -> Self {
        Self {
            registry,
            transport,
            clock,
        }
    }

    /// One call at `call`'s point.
    pub async fn run(&self, tenant: TenantId, realm: RealmId, call: Call) -> Outcome {
        let point = call.point();
        let live = match self.registry.live(tenant, realm, point).await {
            Ok(Some(l)) => l,
            Ok(None) => return Outcome::proceed(),
            Err(_) => {
                tracing::warn!(point = point.name(), "hook registry unavailable; refused");
                return Outcome::Refused(Refusal::Unavailable);
            }
        };
        let reg = &live.registration;
        let reply = match (self.clock.now_ms(), access_crypto::random::bytes::<16>()) {
            (Some(now), Ok(raw)) => {
                let call_id = b64url_encode(&raw);
                match request_body(
                    reg,
                    &call,
                    &call_id,
                    realm.as_bytes(),
                    now,
                    live.realm_allows_disclosure,
                ) {
                    Ok(body) => {
                        let ts = now / 1000;
                        let signature = live.key.sign(&call_id, ts, &body);
                        let headers = request_headers(&call_id, ts, signature, &reg.id);
                        let deadline = Duration::from_millis(TIMEOUT_MS);
                        tokio::time::timeout(
                            deadline,
                            self.transport.post(&reg.url, &headers, &body, deadline),
                        )
                        .await
                        .unwrap_or(Reply::NoAnswer)
                    }
                    Err(_) => Reply::NoAnswer,
                }
            }
            _ => Reply::NoAnswer,
        };
        let outcome = decide(point, reg.on_no_answer, &reply);
        if let Outcome::Refused(r) = &outcome {
            tracing::info!(
                event = "hook.refused",
                point = point.name(),
                reason = r.code(),
                "hook refused"
            );
        }
        outcome
    }
}

/// What a written hook registration shows once.
pub enum Written {
    /// Registered; the receiver verifies with this.
    Registered(ShownKey),
    /// Retired.
    Retired,
}

/// The key material a registration shows once: an Ed25519 public key (`whpk_…`), or an HMAC
/// secret (`whsec_…`) that is never shown again. It never appears in `Debug`.
pub struct ShownKey(zeroize::Zeroizing<String>);

impl ShownKey {
    /// The written key.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ShownKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShownKey(<redacted>)")
    }
}

/// Why a hook change was not written.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The change is not valid.
    #[error(transparent)]
    Invalid(#[from] crate::domain::Invalid),
    /// No such live hook, or the call point already has one.
    #[error("conflict")]
    Conflict,
    /// Keys, randomness or storage failed; nothing was written.
    #[error("unavailable")]
    Unavailable,
}

impl From<access_store::StoreError> for WriteError {
    fn from(_: access_store::StoreError) -> Self {
        Self::Unavailable
    }
}

/// A fresh key of `signing`, sealed for `id`, with what is shown of it once.
///
/// # Errors
/// [`WriteError::Unavailable`].
pub fn new_key<V: crate::ports::KeyVault + ?Sized>(
    vault: &V,
    tenant: TenantId,
    realm: RealmId,
    id: &[u8; 16],
    signing: crate::domain::Signing,
) -> Result<(access_store::events::SealedKey, Option<[u8; 32]>, ShownKey), WriteError> {
    use access_crypto::webhook::{WebhookSecret, WebhookSigningKey};
    fn down<E>(_: E) -> WriteError {
        WriteError::Unavailable
    }
    match signing {
        crate::domain::Signing::Ed25519 => {
            let k = WebhookSigningKey::generate().map_err(down)?;
            let sealed = vault
                .seal(tenant, realm, id, k.expose_seed())
                .map_err(down)?;
            let pk = k.public_key();
            Ok((
                sealed,
                Some(*pk.as_bytes()),
                ShownKey(zeroize::Zeroizing::new(pk.text())),
            ))
        }
        crate::domain::Signing::Hmac => {
            let k = WebhookSecret::generate().map_err(down)?;
            let sealed = vault
                .seal(tenant, realm, id, k.expose_bytes())
                .map_err(down)?;
            Ok((sealed, None, ShownKey(k.expose_text())))
        }
    }
}

/// Writes a hook change against the decision `bound` in this transaction (EI-25, MD-14): a
/// registration gets a fresh key, sealed; its public key or HMAC secret is shown once.
///
/// # Errors
/// [`WriteError`]; the caller rolls its transaction back.
pub async fn write<V: crate::ports::KeyVault + ?Sized>(
    t: &mut access_store::identity::TenantTx,
    bound: &access_store::idp::Bound,
    change: &crate::domain::HookChange,
    vault: &V,
    allow_private: bool,
) -> Result<Written, WriteError> {
    use crate::domain::HookChange;
    let realm = t.realm().ok_or(WriteError::Unavailable)?;
    match change {
        HookChange::Register { id, spec } => {
            spec.check(allow_private)?;
            if access_store::extensions::live_hook(t, spec.point.name())
                .await?
                .is_some()
            {
                return Err(WriteError::Conflict);
            }
            let (key, public_key, shown) = new_key(vault, t.tenant(), realm, id, spec.signing)?;
            let row = access_store::extensions::HookRow {
                id: *id,
                point: String::from(spec.point.name()),
                url: spec.url.clone(),
                on_no_answer: String::from(spec.on_no_answer.name()),
                disclose: spec
                    .disclose
                    .iter()
                    .map(|d| String::from(d.name()))
                    .collect(),
                signing: String::from(spec.signing.name()),
                key,
                public_key,
                active: true,
            };
            access_store::extensions::insert_hook(t, bound, &row).await?;
            Ok(Written::Registered(shown))
        }
        HookChange::Retire { id } => {
            if access_store::extensions::retire_hook(t, bound, id).await? {
                Ok(Written::Retired)
            } else {
                Err(WriteError::Conflict)
            }
        }
    }
}

impl<R, T, C> HookCaller for Hooks<R, T, C>
where
    R: HookRegistry,
    T: HookTransport,
    C: HookClock,
{
    fn call(&self, tenant: TenantId, realm: RealmId, call: Call) -> CallFuture<'_> {
        Box::pin(self.run(tenant, realm, call))
    }
}
