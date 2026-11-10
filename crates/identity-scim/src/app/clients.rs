//! The writes of `idp.scim.*` decisions (OP-155 m.3 (a), (g), MD-14, IDI-1): a client is
//! registered with an opaque bearer secret shown once and kept as its SHA-256, its secret is
//! replaced, or it is retired; a target is registered with its secret sealed under the realm KEK
//! or retired. Each runs in the transaction that bound the decision. A name, once used, is never
//! registered again, so neither a client's issuer Party nor its resources pass to another
//! (INV-32).

use access_kernel::json::b64url_encode;
use access_store::events::SealedKey;
use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::scim::TargetWrite;

/// Digest context of a client's issuer Party.
pub const ISSUER_CONTEXT: &str = "access/scim-issuer/v1";

/// Why an `idp.scim.*` write was refused.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The name is not a client or target name.
    #[error("invalid name")]
    Name,
    /// The name was used before.
    #[error("name taken")]
    Taken,
    /// No live client or target has the name.
    #[error("not live")]
    NotLive,
    /// The tolerance profile is not one the server ships.
    #[error("unknown tolerance profile")]
    Profile,
    /// The target URL is not an `https` URL.
    #[error("invalid target url")]
    Url,
    /// The random source failed.
    #[error("no randomness")]
    Random,
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] access_store::StoreError),
}

/// Whether `name` is a client or target name.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A bearer secret, shown once. It never appears in `Debug`.
#[derive(PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The text to hand to the client's operator once.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Its SHA-256, the only form kept.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        suiss_crypto::digest::sha256(self.0.as_bytes())
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A fresh bearer secret: 256 random bits as base64url.
///
/// # Errors
/// [`ClientError::Random`].
pub fn new_secret() -> Result<Secret, ClientError> {
    let raw = access_crypto::random::bytes::<32>().map_err(|_| ClientError::Random)?;
    Ok(Secret(b64url_encode(&raw)))
}

/// The issuer Party of client `name` of the transaction's realm: the same for every version of
/// it, different for every realm and name.
///
/// # Errors
/// [`ClientError::Store`] outside a realm.
pub fn issuer_party(t: &TenantTx, name: &str) -> Result<[u8; 16], ClientError> {
    let realm = t.realm().ok_or(access_store::StoreError::Range)?;
    let mut input = t.tenant().as_bytes().to_vec();
    input.extend_from_slice(realm.as_bytes());
    input.extend_from_slice(name.as_bytes());
    let d = suiss_crypto::digest::context_digest(ISSUER_CONTEXT, &input).0;
    let mut id = [0; 16];
    id.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    Ok(id)
}

/// Checks a client registration before the decision is drawn.
///
/// # Errors
/// [`ClientError`].
pub fn check_register(name: &str, profile: Option<&str>) -> Result<(), ClientError> {
    if !valid_name(name) {
        return Err(ClientError::Name);
    }
    if profile.is_some_and(|p| crate::domain::tolerance::shipped(p).is_none()) {
        return Err(ClientError::Profile);
    }
    Ok(())
}

/// Whether client `name` may be registered now: never used before.
///
/// # Errors
/// [`ClientError`].
pub async fn registrable(t: &mut TenantTx, name: &str) -> Result<(), ClientError> {
    if access_store::scim::client(t, name).await?.is_some() {
        return Err(ClientError::Taken);
    }
    Ok(())
}

/// Whether client `name` is live.
///
/// # Errors
/// [`ClientError::NotLive`]; [`ClientError::Store`].
pub async fn live(t: &mut TenantTx, name: &str) -> Result<(), ClientError> {
    match access_store::scim::client(t, name).await? {
        Some(c) if c.live => Ok(()),
        _ => Err(ClientError::NotLive),
    }
}

/// `idp.scim.client_register`: the new client and its secret, shown once.
///
/// # Errors
/// [`ClientError`].
pub async fn register(
    t: &mut TenantTx,
    bound: &Bound,
    name: &str,
    profile: Option<&str>,
) -> Result<Secret, ClientError> {
    check_register(name, profile)?;
    registrable(t, name).await?;
    let secret = new_secret()?;
    let issuer = issuer_party(t, name)?;
    access_store::scim::put_client(t, bound, name, &secret.digest(), profile, &issuer, true)
        .await?;
    Ok(secret)
}

/// `idp.scim.token_rotate`: a new secret, shown once; the old one stops working at once.
///
/// # Errors
/// [`ClientError`].
pub async fn rotate(t: &mut TenantTx, bound: &Bound, name: &str) -> Result<Secret, ClientError> {
    let c = access_store::scim::client(t, name)
        .await?
        .filter(|c| c.live)
        .ok_or(ClientError::NotLive)?;
    let secret = new_secret()?;
    access_store::scim::put_client(
        t,
        bound,
        name,
        &secret.digest(),
        c.profile.as_deref(),
        &c.issuer,
        true,
    )
    .await?;
    Ok(secret)
}

/// `idp.scim.client_retire`: the client's secret stops working and its queued Claims are no
/// longer issued; its resources stay as they are.
///
/// # Errors
/// [`ClientError`].
pub async fn retire(t: &mut TenantTx, bound: &Bound, name: &str) -> Result<(), ClientError> {
    let c = access_store::scim::client(t, name)
        .await?
        .filter(|c| c.live)
        .ok_or(ClientError::NotLive)?;
    access_store::scim::put_client(
        t,
        bound,
        name,
        &c.secret_sha256,
        c.profile.as_deref(),
        &c.issuer,
        false,
    )
    .await?;
    Ok(())
}

/// Checks a target registration before the decision is drawn.
///
/// # Errors
/// [`ClientError`].
pub fn check_target(name: &str, base_url: &str) -> Result<(), ClientError> {
    if !valid_name(name) {
        return Err(ClientError::Name);
    }
    let ok = base_url.len() <= 2048
        && base_url
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.contains(['#', '?', ' ', '@']));
    if ok { Ok(()) } else { Err(ClientError::Url) }
}

/// The id a target's secret is sealed for.
#[must_use]
pub fn target_id(name: &str) -> [u8; 16] {
    let d = suiss_crypto::digest::context_digest("access/scim-target/v1", name.as_bytes()).0;
    let mut id = [0; 16];
    id.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    id
}

/// `idp.scim.outbound_register`: the target with its sealed secret (IDP-29).
///
/// # Errors
/// [`ClientError`].
pub async fn register_target(
    t: &mut TenantTx,
    bound: &Bound,
    name: &str,
    base_url: &str,
    secret: &SealedKey,
) -> Result<(), ClientError> {
    check_target(name, base_url)?;
    if access_store::scim::targets(t)
        .await?
        .iter()
        .any(|x| x.name == name)
    {
        return Err(ClientError::Taken);
    }
    access_store::scim::put_target(
        t,
        bound,
        &TargetWrite {
            name,
            base_url,
            secret,
            live: true,
        },
    )
    .await?;
    Ok(())
}

/// `idp.scim.outbound_retire`: nothing more is pushed to the target.
///
/// # Errors
/// [`ClientError`].
pub async fn retire_target(t: &mut TenantTx, bound: &Bound, name: &str) -> Result<(), ClientError> {
    let x = access_store::scim::targets(t)
        .await?
        .into_iter()
        .find(|x| x.name == name && x.live)
        .ok_or(ClientError::NotLive)?;
    access_store::scim::put_target(
        t,
        bound,
        &TargetWrite {
            name,
            base_url: &x.base_url,
            secret: &x.secret,
            live: false,
        },
    )
    .await?;
    Ok(())
}
