//! Domain types and rules, free of I/O (OP-63): the typed `idp.*` changes, their validation and
//! the intent each one is authorized by (MD-14, EI-25).

use std::collections::{BTreeMap, BTreeSet};

use access_identity_account::domain::password::Argon2Params;
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_internal_api::idp::{IdpAction, RESOURCE_NAMESPACE};
use access_internal_api::instances::PlatformProduct;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::model::{ResourceRef, Window};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;
use suiss_crypto::rotation::Policy;

pub mod provision;
pub mod realm;

pub use realm::{
    Binding, Group, Members, MembershipIssuer, Name, SessionPolicy, SigninMethod, SigninPolicy,
    Upstream,
};

/// Context label of a change digest.
pub const CHANGE_CONTEXT: &str = "access/idp-change/v1";

/// The intent's opaque parameter that carries the change digest (EI-25).
pub const CHANGE_PARAM: &str = "change";

/// Type prefix of a `client_id` (OP-137).
pub const CLIENT_PREFIX: &str = "cli";

/// Most redirect URIs of one client.
pub const MAX_REDIRECT_URIS: usize = 32;

/// Longest redirect URI, in bytes.
pub const MAX_URI: usize = 2048;

/// Most CIMD domains of a realm.
pub const MAX_CIMD_DOMAINS: usize = 64;

/// Claims a tenant cannot define (must-never #18, §9.9.4 k.1, P55) with the OIDC protocol claims
/// the tokens already carry.
pub const RESERVED_CLAIMS: [&str; 21] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "nbf",
    "act",
    "may_act",
    "cnf",
    "scope",
    "client_id",
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "azp",
    "sid",
    "at_hash",
    "c_hash",
    "authorization_details",
];

/// Claims only an authority projection carries (§5.3, §5.17, INV-33, S-1, P55): a role is a
/// Grant's projection by `projection.issue`, group membership is an identity Claim that never
/// stands as authority, and the rest name the token's own contract. A mapper cannot define them.
pub const AUTHORITY_CLAIMS: [&str; 10] = [
    "roles",
    "role",
    "groups",
    "entitlements",
    "permissions",
    "access_contract",
    "family",
    "rev",
    "status",
    "events",
];

/// The profile attributes a mapper may take a claim from: the OpenID Connect standard claims
/// of the subject's own profile (OIDC Core §5.1), nothing that names authority (§9.9.6, P55,
/// PI-8). A tenant chooses among them; it cannot define a source.
pub const PROFILE_ATTRIBUTES: [&str; 18] = [
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "updated_at",
];

/// Most CSP origins a realm's branding names (TN-106, PD).
pub const MAX_CSP_ORIGINS: usize = 16;

/// Longest branding display name, in characters.
pub const MAX_BRAND_NAME: usize = 64;

/// How far before a known compromise time the issuer cutoff falls (§13.7.7, PD).
pub const CUTOFF_MARGIN_MS: u64 = 24 * 3_600_000;

/// How far before the declaration the issuer cutoff falls when the compromise time is unknown
/// (§13.7.7, PD).
pub const CUTOFF_UNKNOWN_MS: u64 = 7 * 24 * 3_600_000;

/// The issuer cutoff of a compromised realm key (§13.7.7, SEC9): `t_c − 24 h`, or `t_d − 7 d`
/// when the compromise time `t_c` is unknown or later than the declaration `t_d`. Claims and
/// tokens of the realm issued at or after it are not relied on.
#[must_use]
pub const fn issuer_cutoff(compromised_at: Option<u64>, declared_at: u64) -> u64 {
    match compromised_at {
        Some(t) if t <= declared_at => t.saturating_sub(CUTOFF_MARGIN_MS),
        _ => declared_at.saturating_sub(CUTOFF_UNKNOWN_MS),
    }
}

/// Why a change is not valid; a stable code for RFC 9457 problems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// A `client_id` that is not `cli_` and 26 base32 characters.
    #[error("malformed client_id")]
    ClientId,
    /// An empty, too long or control-character display name.
    #[error("bad display name")]
    DisplayName,
    /// A redirect URI that is not an exact, absolute, allowed URI (IDP-7, RFC 9700).
    #[error("bad redirect URI")]
    RedirectUri,
    /// Too many or repeated redirect URIs.
    #[error("bad redirect URI list")]
    RedirectUris,
    /// A JWKS URI that is not `https`.
    #[error("bad jwks_uri")]
    JwksUri,
    /// A host name that is not a lower-case DNS name.
    #[error("bad host name")]
    Host,
    /// A claim name outside the grammar or reserved (must-never #18).
    #[error("reserved or malformed claim")]
    Claim,
    /// A profile attribute name outside the grammar.
    #[error("bad attribute")]
    Attribute,
    /// Argon2 parameters below the canonical or current ones (OP-33).
    #[error("Argon2 parameters may only be raised")]
    Argon2,
    /// An RP ID that is not the issuer's host or a parent domain of it (WebAuthn §5.1.4).
    #[error("RP ID does not cover the issuer")]
    RpId,
    /// The client does not exist or is retired.
    #[error("no such client")]
    NoClient,
    /// The client exists already.
    #[error("client exists")]
    ClientExists,
    /// A platform product client outside the platform tenant (OP-149 m.4).
    #[error("platform clients belong to the platform tenant")]
    PlatformTenant,
    /// A platform product client that does not use `private_key_jwt` (OP-149 m.4).
    #[error("platform clients use private_key_jwt")]
    PlatformAuth,
    /// A public key that is not Ed25519 or P-256 (OP-149 m.14 (a)).
    #[error("bad public key")]
    PublicKey,
    /// A `private_key_jwt` client key that is not P-256: client assertions are ES256 and `EdDSA`
    /// is never accepted in JOSE (MD-3, OP-149 m.20).
    #[error("client keys are P-256")]
    ClientKey,
    /// A `suiss_event_receiver` that is not an absolute `https` URL Access may push to
    /// (OP-149 m.4, m.23).
    #[error("bad suiss_event_receiver")]
    EventReceiver,
    /// Branding outside its fields' shapes, or a logo outside its CSP origins (TN-106).
    #[error("bad branding")]
    Branding,
    /// A key rotation policy the realm may not take (CR-26, TN-118).
    #[error("bad key policy")]
    KeyPolicy,
    /// A rotation or drop of a key the realm does not publish.
    #[error("no such key")]
    NoKey,
    /// A group or upstream name outside `^[a-z][a-z0-9_-]{0,63}$`.
    #[error("bad name")]
    Name,
    /// A membership issuer that is not `admin` or `upstream:<name>` (TN-117).
    #[error("bad membership issuer")]
    MembershipIssuer,
    /// No members, or too many in one change.
    #[error("bad member list")]
    Members,
    /// An upstream registration outside its fields' shapes (OP-150 m.11 (j)).
    #[error("bad upstream registration")]
    Upstream,
    /// Sign-in requirements outside their shapes (TN-132).
    #[error("bad sign-in policy")]
    SigninPolicy,
    /// A console session policy beyond 12 h / 15 min or without a binding (TN-129).
    #[error("bad session policy")]
    SessionPolicy,
    /// The group does not exist or is retired.
    #[error("no such group")]
    NoGroup,
    /// The group exists already.
    #[error("group exists")]
    GroupExists,
    /// The group's members are issued by an upstream provider, not the administration (TN-117).
    #[error("membership issued upstream")]
    UpstreamMembership,
    /// The account does not exist.
    #[error("no such account")]
    NoAccount,
    /// The account is not in a state the change leaves (§12.3.1, TN-49).
    #[error("account state")]
    AccountState,
    /// The upstream provider does not exist or is retired.
    #[error("no such upstream")]
    NoUpstream,
    /// The upstream provider exists already.
    #[error("upstream exists")]
    UpstreamExists,
    /// The client does not authenticate with a secret.
    #[error("client has no secret")]
    NoSecret,
    /// An RP ID change without acknowledging the realm's registered passkeys (IDI-4).
    #[error("passkeys would be lost")]
    PasskeyLoss,
    /// A request body that is not the operation's JSON object.
    #[error("bad body")]
    Body,
    /// An intent validity missing, malformed, inverted or longer than 15 minutes.
    #[error("bad validity")]
    Validity,
}

impl Invalid {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClientId => "invalid-client-id",
            Self::DisplayName => "invalid-display-name",
            Self::RedirectUri | Self::RedirectUris => "invalid-redirect-uri",
            Self::JwksUri => "invalid-jwks-uri",
            Self::Host => "invalid-host",
            Self::Claim => "reserved-claim",
            Self::Attribute => "invalid-attribute",
            Self::Argon2 => "argon2-lowered",
            Self::RpId => "invalid-rp-id",
            Self::NoClient => "no-such-client",
            Self::ClientExists => "client-exists",
            Self::PlatformTenant => "platform-tenant-only",
            Self::PlatformAuth => "platform-requires-private-key-jwt",
            Self::PublicKey => "invalid-public-key",
            Self::ClientKey => "client-key-not-p256",
            Self::EventReceiver => "invalid-event-receiver",
            Self::Branding => "invalid-branding",
            Self::KeyPolicy => "invalid-key-policy",
            Self::NoKey => "no-such-key",
            Self::Name => "invalid-name",
            Self::MembershipIssuer => "invalid-membership-issuer",
            Self::Members => "invalid-members",
            Self::Upstream => "invalid-upstream",
            Self::SigninPolicy => "invalid-signin-policy",
            Self::SessionPolicy => "invalid-session-policy",
            Self::NoGroup => "no-such-group",
            Self::GroupExists => "group-exists",
            Self::UpstreamMembership => "membership-issued-upstream",
            Self::NoAccount => "no-such-account",
            Self::AccountState => "account-state-conflict",
            Self::NoUpstream => "no-such-upstream",
            Self::UpstreamExists => "upstream-exists",
            Self::NoSecret => "client-has-no-secret",
            Self::PasskeyLoss => "passkey-loss-not-acknowledged",
            Self::Body => "invalid-body",
            Self::Validity => "invalid-validity",
        }
    }
}

fn base32(c: u8) -> bool {
    c.is_ascii_digit() || (c.is_ascii_lowercase() && !matches!(c, b'i' | b'l' | b'o' | b'u'))
}

/// An opaque, server-generated `client_id` (OP-137, TN-15); global and never reused (TN-20).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(String);

impl ClientId {
    /// Checks the text form.
    ///
    /// # Errors
    /// [`Invalid::ClientId`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        let ok = s
            .strip_prefix("cli_")
            .is_some_and(|rest| rest.len() == 26 && rest.bytes().all(base32));
        if ok {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::ClientId)
        }
    }

    /// The text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn host(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            (1..=63).contains(&b.len())
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b.first().is_some_and(|c| *c != b'-')
                && b.last().is_some_and(|c| *c != b'-')
        })
}

/// A redirect URI, kept as the exact string the client registered (IDP-7, RFC 9700 §4.1.3).
/// `https` URIs, loopback `http` URIs (RFC 8252 §7.3) and private-use schemes in reverse
/// domain form (RFC 8252 §7.1); no fragment, no wildcard, no user info.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Checks a redirect URI.
    ///
    /// # Errors
    /// [`Invalid::RedirectUri`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        let bad = s.is_empty()
            || s.len() > MAX_URI
            || s.bytes()
                .any(|c| c <= b' ' || c == 0x7f || matches!(c, b'#' | b'*' | b'\\'));
        let (scheme, rest) = s.split_once(':').ok_or(Invalid::RedirectUri)?;
        if bad {
            return Err(Invalid::RedirectUri);
        }
        let ok = match scheme {
            "https" => authority(rest)
                .is_some_and(|a| !a.contains('@') && host(a.split_once(':').map_or(a, |(h, _)| h))),
            "http" => authority(rest).is_some_and(|a| {
                matches!(
                    a.rsplit_once(':').map_or(a, |(h, _)| h),
                    "127.0.0.1" | "[::1]"
                ) || a == "[::1]"
            }),
            _ => {
                let b = scheme.as_bytes();
                scheme.contains('.')
                    && b.first().is_some_and(u8::is_ascii_lowercase)
                    && b.iter().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-')
                    })
                    && !rest.is_empty()
            }
        };
        if ok {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::RedirectUri)
        }
    }

    /// The exact string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn authority(rest: &str) -> Option<&str> {
    let after = rest.strip_prefix("//")?;
    let end = after.find(['/', '?']).unwrap_or(after.len());
    let a = after.get(..end)?;
    (!a.is_empty()).then_some(a)
}

fn https(s: &str) -> bool {
    s.len() <= MAX_URI
        && !s.bytes().any(|c| c <= b' ' || c == 0x7f || c == b'#')
        && s.strip_prefix("https://")
            .and_then(|r| r.split(['/', '?']).next())
            .is_some_and(|a| !a.contains('@') && host(a.split_once(':').map_or(a, |(h, _)| h)))
}

/// An Instance or client key: Ed25519 or P-256 (OP-149 m.14 (a)).
fn usable(key: &PublicKey) -> bool {
    matches!(key, PublicKey::Ed25519(_) | PublicKey::P256(_)) && key.check().is_ok()
}

/// The key as a public JWK whose `kid` is its RFC 7638 thumbprint (CR-24).
#[must_use]
pub fn jwk(key: &PublicKey) -> String {
    let kid = b64url_encode(&thumbprint(key));
    match key {
        PublicKey::Ed25519(x) => format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{kid}","use":"sig"}}"#,
            b64url_encode(x)
        ),
        PublicKey::P256(sec1) => {
            let (x, y) = sec1
                .get(1..)
                .and_then(|xy| xy.split_at_checked(32))
                .unwrap_or_default();
            format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"{kid}","use":"sig"}}"#,
                b64url_encode(x),
                b64url_encode(y)
            )
        }
        PublicKey::MlDsa(..) => String::from("{}"),
    }
}

/// The key as a deterministic `COSE_Key` (RFC 9052 §7), without `alg`.
#[must_use]
pub fn cose_key(key: &PublicKey) -> Vec<u8> {
    let v = match key {
        PublicKey::Ed25519(x) => Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::int(-1), Value::Unsigned(6)),
            (Value::int(-2), Value::Bytes(x.to_vec())),
        ]),
        PublicKey::P256(sec1) => {
            let (x, y) = sec1
                .get(1..)
                .and_then(|xy| xy.split_at_checked(32))
                .unwrap_or_default();
            Value::Map(vec![
                (Value::Unsigned(1), Value::Unsigned(2)),
                (Value::int(-1), Value::Unsigned(1)),
                (Value::int(-2), Value::Bytes(x.to_vec())),
                (Value::int(-3), Value::Bytes(y.to_vec())),
            ])
        }
        PublicKey::MlDsa(..) => Value::Map(Vec::new()),
    };
    dcbor::encode(&v, Limits::CEILING).unwrap_or_default()
}

/// The key of a stored [`cose_key`]; `None` for anything but a usable Ed25519 or P-256 key.
#[must_use]
pub fn from_cose_key(bytes: &[u8]) -> Option<PublicKey> {
    let Ok(Value::Map(m)) = dcbor::decode(bytes, Limits::CEILING) else {
        return None;
    };
    let get = |k: &Value| m.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let Some(Value::Bytes(x)) = get(&Value::int(-2)) else {
        return None;
    };
    let key = match (get(&Value::Unsigned(1)), get(&Value::int(-1))) {
        (Some(Value::Unsigned(1)), Some(Value::Unsigned(6))) => {
            PublicKey::Ed25519(x.clone().try_into().ok()?)
        }
        (Some(Value::Unsigned(2)), Some(Value::Unsigned(1))) => {
            let Some(Value::Bytes(y)) = get(&Value::int(-3)) else {
                return None;
            };
            let mut sec1 = vec![4];
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            PublicKey::P256(sec1)
        }
        _ => return None,
    };
    usable(&key).then_some(key)
}

/// A platform product's pairing (OP-149 m.4): the product, and the public key of the service
/// Instance it holds in each tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    /// The product.
    pub product: PlatformProduct,
    /// The service Instance key; its private key stays in the product's PKCS#11 token.
    pub service_key: PublicKey,
    /// `suiss_event_receiver`: the absolute `https` URL where the product receives Access
    /// events. Pairing opens one SSF push stream (RFC 8935) to it for the client.
    pub event_receiver: Option<String>,
}

impl Platform {
    /// Whether the event receiver, when given, is an `https` URL the SSRF-guarded client can
    /// post to: one the operator declared (OP-149 m.23), whose host may be a single label on
    /// the local network, or one with a public DNS name on port 443.
    #[must_use]
    pub fn receiver_ok(&self, declared: &DeclaredTargets) -> bool {
        self.event_receiver
            .as_deref()
            .is_none_or(|u| declared.declares(u) || (https(u) && declared.accepts(u)))
    }
}

/// How the client authenticates at the token endpoint (§11.4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// A public client (PKCE only).
    None,
    /// `private_key_jwt` against the client's JWKS (RFC 7523).
    PrivateKeyJwt {
        /// The client's JWKS.
        jwks_uri: String,
    },
    /// `private_key_jwt` against one registered public key (RFC 7523, OP-149 m.4).
    PrivateKeyJwtKey {
        /// P-256 (MD-3, OP-149 m.20).
        key: PublicKey,
    },
    /// A shared secret, for pre-registered confidential clients only.
    ClientSecretBasic,
}

impl AuthMethod {
    /// The `token_endpoint_auth_method` name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PrivateKeyJwt { .. } | Self::PrivateKeyJwtKey { .. } => "private_key_jwt",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }

    /// The JWKS URI, for `private_key_jwt`.
    #[must_use]
    pub fn jwks_uri(&self) -> Option<&str> {
        match self {
            Self::PrivateKeyJwt { jwks_uri } => Some(jwks_uri),
            _ => None,
        }
    }

    /// The one-key JWKS of a `private_key_jwt` client registered with a single key.
    #[must_use]
    pub fn jwks(&self) -> Option<String> {
        match self {
            Self::PrivateKeyJwtKey { key } => Some(format!(r#"{{"keys":[{}]}}"#, jwk(key))),
            _ => None,
        }
    }

    /// From the stored name and JWKS URI.
    ///
    /// # Errors
    /// [`Invalid::JwksUri`].
    pub fn from_parts(name: &str, jwks_uri: Option<&str>) -> Result<Self, Invalid> {
        match (name, jwks_uri) {
            ("none", None) => Ok(Self::None),
            ("client_secret_basic", None) => Ok(Self::ClientSecretBasic),
            ("private_key_jwt", Some(u)) if https(u) => Ok(Self::PrivateKeyJwt {
                jwks_uri: String::from(u),
            }),
            _ => Err(Invalid::JwksUri),
        }
    }
}

/// A client registration (TN-15, IDP-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    /// The server-generated id.
    pub id: ClientId,
    /// The display name, apart from the id (§17.2.1).
    pub display_name: String,
    /// Token endpoint authentication.
    pub auth: AuthMethod,
    /// Redirect URIs, compared as exact strings.
    pub redirect_uris: Vec<RedirectUri>,
    /// Post-logout redirect URIs, compared as exact strings (§10.4.6).
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The back-channel logout endpoint, `https` (§10.4.6).
    pub backchannel_logout_uri: Option<String>,
    /// Whether its authorization requests are accepted only by `request_uri` from `/par`
    /// (RFC 9126 §6, §10.4.3).
    pub require_par: bool,
    /// The platform product it pairs (OP-149 m.4); set only in the platform tenant.
    pub platform: Option<Platform>,
}

impl Client {
    /// Checks the parts that are not checked by their types; `declared` are the operator's
    /// declared delivery targets (OP-149 m.23).
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, declared: &DeclaredTargets) -> Result<(), Invalid> {
        let n = self.display_name.chars().count();
        if n == 0 || n > 128 || self.display_name.chars().any(char::is_control) {
            return Err(Invalid::DisplayName);
        }
        for list in [&self.redirect_uris, &self.post_logout_redirect_uris] {
            let distinct: BTreeSet<&RedirectUri> = list.iter().collect();
            if list.len() > MAX_REDIRECT_URIS || distinct.len() != list.len() {
                return Err(Invalid::RedirectUris);
            }
        }
        if self
            .backchannel_logout_uri
            .as_deref()
            .is_some_and(|u| !https(u))
        {
            return Err(Invalid::RedirectUri);
        }
        if let AuthMethod::PrivateKeyJwt { jwks_uri } = &self.auth
            && !https(jwks_uri)
        {
            return Err(Invalid::JwksUri);
        }
        if let AuthMethod::PrivateKeyJwtKey { key } = &self.auth {
            if !usable(key) {
                return Err(Invalid::PublicKey);
            }
            if !matches!(key, PublicKey::P256(_)) {
                return Err(Invalid::ClientKey);
            }
        }
        if let Some(p) = &self.platform {
            if !matches!(
                self.auth,
                AuthMethod::PrivateKeyJwt { .. } | AuthMethod::PrivateKeyJwtKey { .. }
            ) {
                return Err(Invalid::PlatformAuth);
            }
            if !usable(&p.service_key) {
                return Err(Invalid::PublicKey);
            }
            if !p.receiver_ok(declared) {
                return Err(Invalid::EventReceiver);
            }
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("client_id"), Value::text(self.id.as_str())),
            (Value::text("display_name"), Value::text(&self.display_name)),
            (Value::text("auth_method"), Value::text(self.auth.name())),
            (
                Value::text("redirect_uris"),
                Value::Array(
                    self.redirect_uris
                        .iter()
                        .map(|u| Value::text(u.as_str()))
                        .collect(),
                ),
            ),
        ];
        if let Some(u) = self.auth.jwks_uri() {
            m.push((Value::text("jwks_uri"), Value::text(u)));
        }
        if let AuthMethod::PrivateKeyJwtKey { key } = &self.auth {
            m.push((Value::text("public_key"), Value::Bytes(cose_key(key))));
        }
        if let Some(p) = &self.platform {
            m.push((
                Value::text("platform_product"),
                Value::text(p.product.name()),
            ));
            m.push((
                Value::text("service_key"),
                Value::Bytes(cose_key(&p.service_key)),
            ));
            if let Some(u) = &p.event_receiver {
                m.push((Value::text("suiss_event_receiver"), Value::text(u)));
            }
        }
        if !self.post_logout_redirect_uris.is_empty() {
            m.push((
                Value::text("post_logout_redirect_uris"),
                Value::Array(
                    self.post_logout_redirect_uris
                        .iter()
                        .map(|u| Value::text(u.as_str()))
                        .collect(),
                ),
            ));
        }
        if let Some(u) = &self.backchannel_logout_uri {
            m.push((Value::text("backchannel_logout_uri"), Value::text(u)));
        }
        if self.require_par {
            m.push((
                Value::text("require_pushed_authorization_requests"),
                Value::Bool(true),
            ));
        }
        Value::Map(m)
    }
}

/// A claim name a tenant may define: not a reserved protocol claim (must-never #18) and not a
/// claim only an authority projection carries ([`AUTHORITY_CLAIMS`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimName(String);

fn ident(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl ClaimName {
    /// Checks a claim name.
    ///
    /// # Errors
    /// [`Invalid::Claim`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        if ident(s) && !RESERVED_CLAIMS.contains(&s) && !AUTHORITY_CLAIMS.contains(&s) {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::Claim)
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A profile attribute a claim is taken from: one of [`PROFILE_ATTRIBUTES`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute(String);

impl Attribute {
    /// Checks an attribute name.
    ///
    /// # Errors
    /// [`Invalid::Attribute`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        if PROFILE_ATTRIBUTES.contains(&s) {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::Attribute)
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The realm's JOSE signing algorithm (OP-146 m.8 (d), (e)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoseAlg {
    /// ECDSA P-256, the default.
    Es256,
    /// `EdDSA` over Ed25519.
    Ed25519,
}

impl JoseAlg {
    /// The JOSE name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ed25519 => "Ed25519",
        }
    }

    /// From the JOSE name.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::Es256),
            "Ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// A WebAuthn RP ID (IDP-5): a lower-case DNS name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpId(String);

impl RpId {
    /// Checks an RP ID.
    ///
    /// # Errors
    /// [`Invalid::Host`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        if host(s) {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::Host)
        }
    }

    /// Whether it may serve a realm whose issuer host is `issuer_host`: that host or a parent
    /// domain of it (WebAuthn §5.1.4).
    #[must_use]
    pub fn covers(&self, issuer_host: &str) -> bool {
        issuer_host == self.0
            || issuer_host
                .strip_suffix(self.0.as_str())
                .is_some_and(|head| head.ends_with('.'))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The realm's client and CIMD acceptance policy (§11.3, AG-4): off by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CimdPolicy {
    /// Whether CIMD clients are accepted.
    pub enabled: bool,
    /// The domains whose CIMD clients are accepted.
    pub domains: BTreeSet<String>,
}

impl CimdPolicy {
    /// Checks the domains.
    ///
    /// # Errors
    /// [`Invalid::Host`].
    pub fn check(&self) -> Result<(), Invalid> {
        if self.domains.len() > MAX_CIMD_DOMAINS || !self.domains.iter().all(|d| host(d)) {
            return Err(Invalid::Host);
        }
        Ok(())
    }
}

/// A `#rrggbb` colour, lower case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Color(String);

impl Color {
    /// Checks a colour.
    ///
    /// # Errors
    /// [`Invalid::Branding`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        let ok = s.len() == 7
            && s.strip_prefix('#').is_some_and(|h| {
                h.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            });
        if ok {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::Branding)
        }
    }

    /// The text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The origin of an `https` URL: `https://host[:port]`.
fn origin(u: &str) -> Option<&str> {
    let rest = u.strip_prefix("https://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    u.get(..end.checked_add(8)?)
}

/// A realm's login branding (TN-106, §12.4.2): data only. There is no template, script or
/// style sheet a tenant writes; the hosted page draws these values itself, and the only
/// outside content it loads comes from the CSP origins listed here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Branding {
    /// The name the login page shows.
    pub display_name: Option<String>,
    /// The logo, an `https` URL from one of [`Branding::csp_origins`].
    pub logo_uri: Option<String>,
    /// The primary colour.
    pub primary_color: Option<Color>,
    /// The background colour.
    pub background_color: Option<Color>,
    /// The `https` origins the hosted page's CSP allows images from; widening it is an
    /// expansion of what the page loads.
    pub csp_origins: BTreeSet<String>,
}

impl Branding {
    /// Checks the fields.
    ///
    /// # Errors
    /// [`Invalid::Branding`].
    pub fn check(&self) -> Result<(), Invalid> {
        let name_ok = self.display_name.as_deref().is_none_or(|n| {
            let len = n.chars().count();
            (1..=MAX_BRAND_NAME).contains(&len) && !n.chars().any(char::is_control)
        });
        let origins_ok = self.csp_origins.len() <= MAX_CSP_ORIGINS
            && self
                .csp_origins
                .iter()
                .all(|o| https(o) && origin(o) == Some(o.as_str()));
        let logo_ok = self
            .logo_uri
            .as_deref()
            .is_none_or(|u| https(u) && origin(u).is_some_and(|o| self.csp_origins.contains(o)));
        if name_ok && origins_ok && logo_ok {
            Ok(())
        } else {
            Err(Invalid::Branding)
        }
    }

    /// The branding as the change and its stored form carry it: deterministic CBOR.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = Vec::new();
        if let Some(n) = &self.display_name {
            m.push((Value::text("display_name"), Value::text(n)));
        }
        if let Some(u) = &self.logo_uri {
            m.push((Value::text("logo_uri"), Value::text(u)));
        }
        if let Some(c) = &self.primary_color {
            m.push((Value::text("primary_color"), Value::text(c.as_str())));
        }
        if let Some(c) = &self.background_color {
            m.push((Value::text("background_color"), Value::text(c.as_str())));
        }
        m.push((
            Value::text("csp_origins"),
            Value::Array(self.csp_origins.iter().map(|o| Value::text(o)).collect()),
        ));
        Value::Map(m)
    }
}

/// A rotation policy as the change and its digest carry it.
#[must_use]
pub fn policy_value(p: &Policy) -> Value {
    Value::Map(vec![
        (Value::text("lifetime_ms"), Value::Unsigned(p.lifetime_ms)),
        (Value::text("window_ms"), Value::Unsigned(p.window_ms)),
        (
            Value::text("publish_lead_ms"),
            Value::Unsigned(p.publish_lead_ms),
        ),
        (Value::text("retain_ms"), Value::Unsigned(p.retain_ms)),
        (
            Value::text("max_signatures"),
            Value::Unsigned(p.max_signatures),
        ),
        (
            Value::text("jitter_permille"),
            Value::Unsigned(u64::from(p.jitter_permille)),
        ),
    ])
}

/// One `idp.*` configuration change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// `idp.client.register`.
    ClientRegister(Client),
    /// `idp.client.update`.
    ClientUpdate(Client),
    /// `idp.client.retire`.
    ClientRetire(ClientId),
    /// `idp.client.cimd_policy`.
    CimdPolicy(CimdPolicy),
    /// `idp.mapper.set`; `None` removes the mapper.
    MapperSet {
        /// The claim.
        claim: ClaimName,
        /// Its source, `None` to remove.
        source: Option<Attribute>,
    },
    /// `idp.realm.jose_alg`.
    JoseAlg(JoseAlg),
    /// `idp.realm.argon2`.
    Argon2(Argon2Params),
    /// `idp.realm.rp_id`.
    RpId(RpId),
    /// `idp.realm.branding`.
    Branding(Branding),
    /// `idp.realm.key_policy`.
    KeyPolicy(Policy),
    /// `idp.realm.key_rotate`: rotates out the active key `retire`.
    KeyRotate {
        /// The active key's `kid`.
        retire: [u8; 32],
    },
    /// `idp.realm.key_drop`: drops `kid` at once.
    KeyDrop {
        /// The key's `kid`.
        kid: [u8; 32],
        /// When it was compromised, if known.
        compromised_at: Option<u64>,
    },
    /// `idp.client.secret_rotate`.
    ClientSecretRotate(ClientId),
    /// `idp.group.create`.
    GroupCreate(Group),
    /// `idp.group.update`.
    GroupUpdate(Group),
    /// `idp.group.retire`.
    GroupRetire(Name),
    /// `idp.group.members_add`.
    GroupMembersAdd(Members),
    /// `idp.group.members_remove`.
    GroupMembersRemove(Members),
    /// `idp.account.suspend`: the subject's internal id.
    AccountSuspend([u8; 16]),
    /// `idp.account.reactivate`.
    AccountReactivate([u8; 16]),
    /// `idp.upstream.register`.
    UpstreamRegister(Upstream),
    /// `idp.upstream.update`.
    UpstreamUpdate(Upstream),
    /// `idp.upstream.retire`.
    UpstreamRetire(Name),
    /// `idp.realm.signin_policy`.
    SigninPolicy(SigninPolicy),
    /// `idp.realm.session_policy`.
    SessionPolicy(SessionPolicy),
}

fn uint(v: u32) -> Value {
    Value::Unsigned(u64::from(v))
}

impl Change {
    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::ClientRegister(_) => IdpAction::ClientRegister,
            Self::ClientUpdate(_) => IdpAction::ClientUpdate,
            Self::ClientRetire(_) => IdpAction::ClientRetire,
            Self::CimdPolicy(_) => IdpAction::CimdPolicy,
            Self::MapperSet { .. } => IdpAction::MapperSet,
            Self::JoseAlg(_) => IdpAction::RealmJoseAlg,
            Self::Argon2(_) => IdpAction::RealmArgon2,
            Self::RpId(_) => IdpAction::RealmRpId,
            Self::Branding(_) => IdpAction::RealmBranding,
            Self::KeyPolicy(_) => IdpAction::RealmKeyPolicy,
            Self::KeyRotate { .. } => IdpAction::RealmKeyRotate,
            Self::KeyDrop { .. } => IdpAction::RealmKeyDrop,
            Self::ClientSecretRotate(_) => IdpAction::ClientSecretRotate,
            Self::GroupCreate(_) => IdpAction::GroupCreate,
            Self::GroupUpdate(_) => IdpAction::GroupUpdate,
            Self::GroupRetire(_) => IdpAction::GroupRetire,
            Self::GroupMembersAdd(_) => IdpAction::GroupMembersAdd,
            Self::GroupMembersRemove(_) => IdpAction::GroupMembersRemove,
            Self::AccountSuspend(_) => IdpAction::AccountSuspend,
            Self::AccountReactivate(_) => IdpAction::AccountReactivate,
            Self::UpstreamRegister(_) => IdpAction::UpstreamRegister,
            Self::UpstreamUpdate(_) => IdpAction::UpstreamUpdate,
            Self::UpstreamRetire(_) => IdpAction::UpstreamRetire,
            Self::SigninPolicy(_) => IdpAction::RealmSigninPolicy,
            Self::SessionPolicy(_) => IdpAction::RealmSessionPolicy,
        }
    }

    /// Checks the change on its own, against the operator's declared delivery targets
    /// (OP-149 m.23).
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn check(&self, declared: &DeclaredTargets) -> Result<(), Invalid> {
        match self {
            Self::ClientRegister(c) | Self::ClientUpdate(c) => c.check(declared),
            Self::CimdPolicy(p) => p.check(),
            Self::Argon2(p) => Argon2Params::for_realm(p.m_kib, p.t, p.p)
                .map(drop)
                .map_err(|_| Invalid::Argon2),
            Self::Branding(b) => b.check(),
            Self::KeyPolicy(p) => {
                access_identity_signer::domain::check(p).map_err(|_| Invalid::KeyPolicy)
            }
            Self::GroupCreate(g) | Self::GroupUpdate(g) => g.check(),
            Self::GroupMembersAdd(m) | Self::GroupMembersRemove(m) => m.check(),
            Self::UpstreamRegister(u) | Self::UpstreamUpdate(u) => u.check(),
            Self::SigninPolicy(p) => p.check(),
            Self::SessionPolicy(p) => p.check(),
            Self::ClientRetire(_)
            | Self::MapperSet { .. }
            | Self::JoseAlg(_)
            | Self::RpId(_)
            | Self::KeyRotate { .. }
            | Self::KeyDrop { .. }
            | Self::ClientSecretRotate(_)
            | Self::GroupRetire(_)
            | Self::AccountSuspend(_)
            | Self::AccountReactivate(_)
            | Self::UpstreamRetire(_) => Ok(()),
        }
    }

    fn body(&self) -> Value {
        match self {
            Self::ClientRegister(c) | Self::ClientUpdate(c) => c.to_value(),
            Self::ClientRetire(id) | Self::ClientSecretRotate(id) => {
                Value::Map(vec![(Value::text("client_id"), Value::text(id.as_str()))])
            }
            Self::CimdPolicy(p) => Value::Map(vec![
                (Value::text("enabled"), Value::Bool(p.enabled)),
                (
                    Value::text("domains"),
                    Value::Array(p.domains.iter().map(|d| Value::text(d)).collect()),
                ),
            ]),
            Self::MapperSet { claim, source } => {
                let mut m = vec![(Value::text("claim"), Value::text(claim.as_str()))];
                if let Some(s) = source {
                    m.push((Value::text("source"), Value::text(s.as_str())));
                }
                Value::Map(m)
            }
            Self::JoseAlg(a) => Value::Map(vec![(Value::text("alg"), Value::text(a.name()))]),
            Self::Argon2(p) => Value::Map(vec![
                (Value::text("m_kib"), uint(p.m_kib)),
                (Value::text("t"), uint(p.t)),
                (Value::text("p"), uint(p.p)),
            ]),
            Self::RpId(r) => Value::Map(vec![(Value::text("rp_id"), Value::text(r.as_str()))]),
            Self::Branding(b) => b.to_value(),
            Self::KeyPolicy(p) => policy_value(p),
            Self::KeyRotate { retire } => {
                Value::Map(vec![(Value::text("retire"), Value::Bytes(retire.to_vec()))])
            }
            Self::KeyDrop {
                kid,
                compromised_at,
            } => {
                let mut m = vec![(Value::text("kid"), Value::Bytes(kid.to_vec()))];
                if let Some(t) = compromised_at {
                    m.push((Value::text("compromised_at"), Value::Unsigned(*t)));
                }
                Value::Map(m)
            }
            Self::GroupCreate(g) | Self::GroupUpdate(g) => g.to_value(),
            Self::GroupRetire(n) | Self::UpstreamRetire(n) => {
                Value::Map(vec![(Value::text("name"), Value::text(n.as_str()))])
            }
            Self::GroupMembersAdd(m) | Self::GroupMembersRemove(m) => m.to_value(),
            Self::AccountSuspend(s) | Self::AccountReactivate(s) => {
                Value::Map(vec![(Value::text("subject"), Value::Bytes(s.to_vec()))])
            }
            Self::UpstreamRegister(u) | Self::UpstreamUpdate(u) => u.to_value(),
            Self::SigninPolicy(p) => p.to_value(),
            Self::SessionPolicy(p) => p.to_value(),
        }
    }

    /// `SHA-256("access/idp-change/v1" ‖ 0x00 ‖ dCBOR({action, body}))`: what the intent binds.
    ///
    /// # Errors
    /// [`dcbor::EncodeError`] past the encoding limits.
    pub fn digest(&self) -> Result<Digest, dcbor::EncodeError> {
        let v = Value::Map(vec![
            (Value::text("action"), Value::text(&self.action().label())),
            (Value::text("body"), self.body()),
        ]);
        let bytes = dcbor::encode(&v, Limits::CEILING)?;
        Ok(Digest(context_digest(CHANGE_CONTEXT, &bytes).0))
    }

    /// The resource it changes: `idp:[slug, kind, …]`.
    #[must_use]
    pub fn resource(&self, slug: &str) -> ResourceRef {
        let mut path = vec![String::from(slug)];
        match self {
            Self::ClientRegister(c) | Self::ClientUpdate(c) => {
                path.extend([String::from("client"), String::from(c.id.as_str())]);
            }
            Self::ClientRetire(id) | Self::ClientSecretRotate(id) => {
                path.extend([String::from("client"), String::from(id.as_str())]);
            }
            Self::GroupCreate(Group { name, .. })
            | Self::GroupUpdate(Group { name, .. })
            | Self::GroupRetire(name)
            | Self::GroupMembersAdd(Members { group: name, .. })
            | Self::GroupMembersRemove(Members { group: name, .. }) => {
                path.extend([String::from("group"), String::from(name.as_str())]);
            }
            Self::AccountSuspend(s) | Self::AccountReactivate(s) => {
                path.extend([String::from("account"), b64url_encode(s)]);
            }
            Self::UpstreamRegister(Upstream { name, .. })
            | Self::UpstreamUpdate(Upstream { name, .. })
            | Self::UpstreamRetire(name) => {
                path.extend([String::from("upstream"), String::from(name.as_str())]);
            }
            Self::MapperSet { claim, .. } => {
                path.extend([String::from("mapper"), String::from(claim.as_str())]);
            }
            Self::CimdPolicy(_)
            | Self::JoseAlg(_)
            | Self::Argon2(_)
            | Self::RpId(_)
            | Self::Branding(_)
            | Self::SigninPolicy(_)
            | Self::SessionPolicy(_) => {
                path.push(String::from("realm"));
            }
            Self::KeyPolicy(_) | Self::KeyRotate { .. } | Self::KeyDrop { .. } => {
                path.push(String::from("keys"));
            }
        }
        ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path,
            incarnation: 0,
        }
    }

    /// The intent that authorizes it in the realm `slug`, valid over `validity` (EI-25: its
    /// `opaque["change"]` is [`Change::digest`]).
    ///
    /// # Errors
    /// [`dcbor::EncodeError`].
    pub fn intent(
        &self,
        slug: &str,
        validity: Window,
    ) -> Result<IntentEnvelope, dcbor::EncodeError> {
        Ok(IntentEnvelope {
            action: self.action().action_ref(),
            resources: vec![self.resource(slug)],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from(CHANGE_PARAM), self.digest()?)]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity,
        })
    }
}

/// OP-33: new Argon2 parameters are at least the current ones and differ from them.
#[must_use]
pub const fn raises(new: &Argon2Params, current: &Argon2Params) -> bool {
    !new.weaker_than(current)
        && (new.m_kib != current.m_kib || new.t != current.t || new.p != current.p)
}

#[cfg(test)]
mod tests;
