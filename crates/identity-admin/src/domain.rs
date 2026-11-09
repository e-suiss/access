//! Domain types and rules, free of I/O (OP-63): the typed `idp.*` changes, their validation and
//! the intent each one is authorized by (MD-14, EI-25).

use std::collections::{BTreeMap, BTreeSet};

use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::recovery_policy::{self, RecoveryPolicy};
pub use access_identity_events::domain::webhook::{WebhookChange, WebhookSpec};
use access_identity_hooks::domain::uuid;
pub use access_identity_hooks::domain::{
    Disclosure, ExtensionPolicy, HookChange, HookPoint, HookSpec, OnNoAnswer, Signing,
};
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

pub mod dns;
pub mod org;
pub mod provision;
pub use access_identity_risk::domain::mode::ProtectionMode;

pub mod realm;

pub use realm::{
    Binding, Group, Members, MembershipIssuer, Name, SessionPolicy, SigninMethod, SigninPolicy,
    Social, SocialClient, Upstream, UpstreamLink,
};

/// Context label of a change digest.
pub const CHANGE_CONTEXT: &str = "access/idp-change/v1";

/// The intent's opaque parameter that carries the change digest (EI-25).
pub const CHANGE_PARAM: &str = "change";

/// Type prefix of a `client_id` (OP-137).
pub const CLIENT_PREFIX: &str = "cli";

/// Type prefix of an inline hook's external id (OP-65, OP-137).
pub const HOOK_PREFIX: &str = "hok";

/// Type prefix of a webhook's external id (OP-65, OP-137).
pub const WEBHOOK_PREFIX: &str = "whk";

/// The realm-admin error of an extension point registration that M6's contract refuses.
#[must_use]
pub fn extension_invalid(e: access_identity_hooks::domain::Invalid) -> Invalid {
    match e.0 {
        "url" => Invalid::ExtensionTarget,
        "events" => Invalid::WebhookEvents,
        "extension_policy" => Invalid::ExtensionPolicy,
        _ => Invalid::Hook,
    }
}

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
    /// A public `sub` without the explicit opt-in, or a subject type that is neither
    /// `pairwise` nor `public` (MD-10).
    #[error("public sub needs the opt-in")]
    PublicSub,
    /// A sector identifier URI that is not `https`, or whose document is not a JSON array of
    /// `https` URIs listing every redirect URI (OIDC Core §8.1).
    #[error("bad sector_identifier_uri")]
    SectorIdentifier,
    /// A management operation the catalogue declares and reserves: never applied
    /// (OP-150 m.11 (b)).
    #[error("reserved operation")]
    Reserved,
    /// A JOSE algorithm the realm cannot take: `ES256` or `Ed25519` (MD-3, CR-5).
    #[error("bad JOSE algorithm")]
    JoseAlg,
    /// A protection mode outside its model; brute-force protection is always enforced
    /// (OP-151 m.3 (o), TI-9).
    #[error("bad protection mode")]
    ProtectionMode,
    /// A hook or webhook URL that is not `https` on a DNS name, or a private target the realm
    /// does not allow or the operator did not declare (OP-151 m.10 (e), OP-149 m.23).
    #[error("bad extension target")]
    ExtensionTarget,
    /// A hook registration outside its call point's contract (TN-135).
    #[error("bad hook")]
    Hook,
    /// A hook asking for personal data the realm's extension policy does not permit
    /// (OP-151 m.10 (e)).
    #[error("disclosure not permitted")]
    Disclosure,
    /// Webhook events outside the identity event catalogue (TN-136).
    #[error("bad webhook events")]
    WebhookEvents,
    /// An extension policy outside its shape.
    #[error("bad extension policy")]
    ExtensionPolicy,
    /// The call point has a live hook already (OP-151 m.10 (d)).
    #[error("hook point taken")]
    HookPointTaken,
    /// The hook does not exist or is retired.
    #[error("no such hook")]
    NoHook,
    /// The webhook does not exist or is retired.
    #[error("no such webhook")]
    NoWebhook,
    /// An upstream subject that is empty, too long or has control characters.
    #[error("bad upstream subject")]
    UpstreamSubject,
    /// The upstream subject is linked to another account already.
    #[error("upstream subject linked")]
    UpstreamSubjectLinked,
    /// The realm's governing domain does not accept the catalog that declares the action yet
    /// (OP-153 m.3 (a)).
    #[error("catalog upgrade required")]
    CatalogUpgradeRequired,
    /// The actor's account is in the grace period after a recovery, which refuses this change
    /// (TN-56, OP-153 m.3 (e)).
    #[error("recovery grace")]
    RecoveryGrace,
    /// The organization does not exist or ended.
    #[error("no such organization")]
    NoOrg,
    /// An organization is bound to this Party already (TN-5).
    #[error("organization exists")]
    OrgExists,
    /// The account is not an active member of the organization.
    #[error("no such member")]
    NoMember,
    /// The change would leave the organization without an active owner (TN-91).
    #[error("last owner")]
    LastOwner,
    /// A recovery policy outside its ranges or below the floor of OP-153 m.3 (e) (TN-55).
    #[error("bad recovery policy")]
    RecoveryPolicy,
    /// The realm or the account has turned this recovery option off: temporary access passes
    /// exist only when the realm opts in (TN-62); an account without assisted recovery takes no
    /// reset intent or pass (TN-60).
    #[error("recovery option off")]
    RecoveryOption,
    /// Nobody issues a recovery pass or intent for their own account (TN-62).
    #[error("self issue")]
    SelfIssue,
    /// The Party is not a live organization Party of the domain (OP-153 m.3 (b), m.10 (e)).
    #[error("not an organization")]
    NotOrganization,
    /// The founder created as many organizations today as allowed (OP-153 m.3 (o)).
    #[error("organization limit")]
    OrgLimit,
    /// The organization sent as many invitations this hour or day as allowed (OP-153 m.3 (o)).
    #[error("invitation limit")]
    InviteLimit,
    /// An invitee address, inviter name, role or lifetime outside the rules (TN-89).
    #[error("invalid invitation")]
    Invitation,
    /// The invitation does not exist, was accepted or revoked, or expired.
    #[error("no such invitation")]
    NoInvitation,
    /// Home realm discovery needs a verified domain no other organization claims (§10.2.6,
    /// TN-98).
    #[error("home realm discovery needs a verified domain")]
    HrdUnverified,
    /// An unknown preset or a malformed client (IDP-31).
    #[error("bad social provider")]
    Social,
    /// The realm has not enabled the preset, or disabled it.
    #[error("no such social provider")]
    NoSocial,
    /// The realm offers the preset already.
    #[error("social provider exists")]
    SocialExists,
    /// The shared development client named in a realm that is not a sandbox (IDP-31 (4)).
    #[error("shared social key in production")]
    SharedSocialKey,
    /// A domain that is not a lower-case DNS name, or a verification method Access does not
    /// know (TN-90).
    #[error("invalid domain claim")]
    DomainClaim,
    /// The organization claims the domain already, or the claim does not exist or was released.
    #[error("no such domain claim")]
    NoDomain,
    /// Autojoin is refused on a consumer, free mail, ISP or university domain (TN-90,
    /// OP-153 m.1 (d)).
    #[error("consumer domain")]
    ConsumerDomain,
    /// Another organization claims the domain too: no autojoin for any of them (TN-90).
    #[error("domain contested")]
    DomainContested,
    /// The claim is not verified now (TN-90).
    #[error("domain not verified")]
    DomainUnverified,
    /// An enterprise connection draft whose issuer is not an https URL or whose client id is
    /// empty or too long (TN-120).
    #[error("invalid connection draft")]
    SsoDraft,
    /// The organization's invitations are mostly ignored: invitations wait (TN-89 (11)).
    #[error("invitation reputation")]
    InviteReputation,
    /// N5: a Related Origins list that is not `https` origins, names more than five
    /// registrable labels with the RP ID, or an origin outside the realm's verified domains
    /// (TN-18, OP-153 m.3 (u)).
    #[error("bad related origins")]
    RelatedOrigins,
    /// N5: message overrides naming a protected or unknown key, or text that is not plain
    /// (X35, XI-25, OP-153 m.3 (s)).
    #[error("bad locale overrides")]
    LocaleOverrides,
}

impl Invalid {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClientId => "invalid-client-id",
            Self::NoOrg => "no-such-organization",
            Self::OrgExists => "organization-exists",
            Self::NoMember => "no-such-member",
            Self::LastOwner => "last-owner",
            Self::NotOrganization => "not-an-organization",
            Self::OrgLimit => "organization-limit",
            Self::InviteLimit => "invitation-limit",
            Self::Invitation => "invalid-invitation",
            Self::NoInvitation => "no-such-invitation",
            Self::HrdUnverified => "hrd-needs-verified-domain",
            Self::Social => "invalid-social-provider",
            Self::NoSocial => "no-such-social-provider",
            Self::SocialExists => "social-provider-exists",
            Self::SharedSocialKey => "shared-social-key-in-production",
            Self::DomainClaim => "invalid-domain-claim",
            Self::NoDomain => "no-such-domain-claim",
            Self::ConsumerDomain => "consumer-domain",
            Self::DomainContested => "domain-contested",
            Self::DomainUnverified => "domain-not-verified",
            Self::SsoDraft => "invalid-connection-draft",
            Self::InviteReputation => "invitation-reputation",
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
            Self::RelatedOrigins => "invalid-related-origins",
            Self::LocaleOverrides => "invalid-locale-overrides",
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
            Self::PublicSub => "public-sub-not-opted-in",
            Self::SectorIdentifier => "invalid-sector-identifier-uri",
            Self::Reserved => "reserved-operation",
            Self::ProtectionMode => "invalid-protection-mode",
            Self::JoseAlg => "invalid-jose-alg",
            Self::ExtensionTarget => "invalid-extension-target",
            Self::Hook => "invalid-hook",
            Self::Disclosure => "disclosure-not-permitted",
            Self::WebhookEvents => "invalid-webhook-events",
            Self::ExtensionPolicy => "invalid-extension-policy",
            Self::HookPointTaken => "hook-point-taken",
            Self::NoHook => "no-such-hook",
            Self::NoWebhook => "no-such-webhook",
            Self::UpstreamSubject => "invalid-upstream-subject",
            Self::UpstreamSubjectLinked => "upstream-subject-linked",
            Self::CatalogUpgradeRequired => access_internal_api::idp::CATALOG_UPGRADE_REQUIRED,
            Self::RecoveryPolicy => "invalid-recovery-policy",
            Self::RecoveryOption => "recovery-option-off",
            Self::SelfIssue => "self-issue-refused",
            Self::RecoveryGrace => "recovery-grace",
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

/// Which `sub` a client reads (MD-10): pairwise by default; the realm's public `sub` only by
/// explicit opt-in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subject {
    /// Whether the client opted in to the realm's public `sub`.
    pub public: bool,
    /// The sector identifier URI the client registered, `https` (OIDC Core §8.1). Its document
    /// is checked when the registration is drafted and committed; the pairwise sector stays the
    /// client.
    pub sector_identifier_uri: Option<String>,
}

impl Subject {
    /// The `subject_type` value.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        if self.public { "public" } else { "pairwise" }
    }
}

/// Most entries of a sector identifier document.
pub const MAX_SECTOR_URIS: usize = 256;

/// Whether `document`, a sector identifier URI's body, is a JSON array of `https` URIs that
/// lists every one of `redirect_uris` (OIDC Core §8.1, MD-10).
///
/// # Errors
/// [`Invalid::SectorIdentifier`].
pub fn sector_covers(document: &[u8], redirect_uris: &[RedirectUri]) -> Result<(), Invalid> {
    let listed: Vec<String> =
        serde_json::from_slice(document).map_err(|_| Invalid::SectorIdentifier)?;
    let ok = listed.len() <= MAX_SECTOR_URIS
        && listed
            .iter()
            .all(|u| u.starts_with("https://") && u.len() <= MAX_URI)
        && redirect_uris
            .iter()
            .all(|r| listed.iter().any(|l| l == r.as_str()));
    if ok {
        Ok(())
    } else {
        Err(Invalid::SectorIdentifier)
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
    /// The `sub` it reads (MD-10).
    pub subject: Subject,
    /// Whether it is a third party, asked about before it receives identity claims
    /// (OP-153 m.3 (z)).
    pub third_party: bool,
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
        if self
            .subject
            .sector_identifier_uri
            .as_deref()
            .is_some_and(|u| !https(u))
        {
            return Err(Invalid::SectorIdentifier);
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
        // MD-10
        if self.subject.public {
            m.push((Value::text("subject_type"), Value::text("public")));
        }
        if let Some(u) = &self.subject.sector_identifier_uri {
            m.push((Value::text("sector_identifier_uri"), Value::text(u)));
        }
        // OP-153 m.3 (z)
        if self.third_party {
            m.push((Value::text("third_party"), Value::Bool(true)));
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

/// N5: most registrable labels a Related Origins list names, the RP ID's included (TN-18,
/// IDP-5); browsers cut a longer list.
pub const MAX_RELATED_LABELS: usize = 5;

/// N5: most related origins.
const MAX_RELATED_ORIGINS: usize = 16;

/// N5: the registrable label of a host, the first label of its registrable domain by the
/// embedded Public Suffix List (OP-153 m.3 (u), m.25 (f)): `shop.acme.example` and
/// `www.acme.co.uk` are `acme`; a public suffix itself has none.
#[must_use]
pub fn registrable_label(host: &str) -> Option<&str> {
    access_identity_webauthn::domain::psl::Psl::label(host)
}

/// N5: a realm's Related Origins (`idp.realm.related_origins`, TN-18, IDP-5, OP-153 m.3 (u)):
/// `https` origins of the tenant's own brands, at most [`MAX_RELATED_LABELS`] registrable
/// labels with the RP ID's; each must sit under one of the realm's verified domains, which the
/// commit path checks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelatedOrigins {
    /// `https://host` origins, no path, no port.
    pub origins: BTreeSet<String>,
}

impl RelatedOrigins {
    /// The hosts of the origins.
    #[must_use]
    pub fn hosts(&self) -> Vec<&str> {
        self.origins
            .iter()
            .filter_map(|o| o.strip_prefix("https://"))
            .collect()
    }

    /// The distinct registrable labels of the origins and of `rp_id`.
    #[must_use]
    pub fn labels<'a>(&'a self, rp_id: Option<&'a str>) -> BTreeSet<&'a str> {
        rp_id
            .into_iter()
            .chain(self.hosts())
            .filter_map(registrable_label)
            .collect()
    }

    /// Checks the shape and the label count.
    ///
    /// # Errors
    /// [`Invalid::RelatedOrigins`].
    pub fn check(&self) -> Result<(), Invalid> {
        let shaped = self.origins.len() <= MAX_RELATED_ORIGINS
            && self
                .origins
                .iter()
                .all(|o| o.strip_prefix("https://").is_some_and(host));
        if shaped && self.labels(None).len() <= MAX_RELATED_LABELS {
            Ok(())
        } else {
            Err(Invalid::RelatedOrigins)
        }
    }

    /// The list as the change carries it.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Array(self.origins.iter().map(|o| Value::text(o)).collect())
    }
}

/// N5: the protected message keys (X35, XI-25): no realm override replaces them.
const PROTECTED_MESSAGES: &str =
    include_str!("../../../conformance/catalog/protected-messages.toml");

/// N5: the English catalogs, whose keys are every key a realm may override.
const EN_CATALOGS: [&str; 4] = [
    include_str!("../../../locales/en/login.ftl"),
    include_str!("../../../locales/en/account.ftl"),
    include_str!("../../../locales/en/hub.ftl"),
    include_str!("../../../locales/en/mail.ftl"),
];

/// N5: most override texts.
const MAX_OVERRIDES: usize = 512;

/// N5: longest override text.
const MAX_OVERRIDE_TEXT: usize = 1024;

fn protected_message(key: &str) -> bool {
    PROTECTED_MESSAGES
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split_once('"').map(|(k, _)| k))
        .any(|k| k == key)
}

fn known_message(key: &str) -> bool {
    EN_CATALOGS.iter().any(|c| {
        c.lines()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k))
            .any(|k| k == key)
    })
}

fn locale_tag(tag: &str) -> bool {
    (2..=35).contains(&tag.len())
        && tag.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        && tag.bytes().next().is_some_and(|c| c.is_ascii_alphabetic())
}

/// N5: a realm's message overrides (`idp.realm.locale_overrides`, OP-153 m.3 (s), X35, XI-25):
/// texts by locale and Fluent key, plain text only. A protected key, an unknown key, a
/// placeholder or markup is refused.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocaleOverrides {
    /// Locale → key → text.
    pub texts: BTreeMap<String, BTreeMap<String, String>>,
}

impl LocaleOverrides {
    /// Checks every entry.
    ///
    /// # Errors
    /// [`Invalid::LocaleOverrides`].
    pub fn check(&self) -> Result<(), Invalid> {
        let count: usize = self.texts.values().map(BTreeMap::len).sum();
        let ok = count <= MAX_OVERRIDES
            && self.texts.iter().all(|(locale, texts)| {
                locale_tag(locale)
                    && texts.iter().all(|(k, v)| {
                        known_message(k)
                            && !protected_message(k)
                            && (1..=MAX_OVERRIDE_TEXT).contains(&v.chars().count())
                            && !v
                                .chars()
                                .any(|c| c.is_control() || matches!(c, '{' | '}' | '<' | '>'))
                    })
            });
        if ok {
            Ok(())
        } else {
            Err(Invalid::LocaleOverrides)
        }
    }

    /// The overrides as the change and their stored form carry them: deterministic CBOR.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(
            self.texts
                .iter()
                .map(|(locale, texts)| {
                    (
                        Value::text(locale),
                        Value::Map(
                            texts
                                .iter()
                                .map(|(k, v)| (Value::text(k), Value::text(v)))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
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
    /// N5: `idp.realm.related_origins` (TN-18, OP-153 m.3 (u)).
    RelatedOrigins(RelatedOrigins),
    /// N5: `idp.realm.locale_overrides` (OP-153 m.3 (s), X35).
    LocaleOverrides(LocaleOverrides),
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
    /// `idp.realm.protection_mode` when it only tightens, `idp.realm.protection_mode_loosen`
    /// when anything loosens (OP-151 m.14 (f)); `loosens` is resolved against the realm's
    /// current mode before the intent is drawn.
    ProtectionMode {
        /// The new mode.
        mode: ProtectionMode,
        /// Whether it loosens anything the current mode enforces.
        loosens: bool,
    },
    /// `idp.account.canary`: the subject's internal id (§4.4).
    AccountCanary([u8; 16]),
    /// `idp.account.delete`: the subject's internal id; reserved, CT3 (OP-153 m.3 (bb)).
    AccountDelete([u8; 16]),
    /// `idp.account.reset_intent`: a one-time credential setup token sent to the account's own
    /// registered address, never a credential (TN-61, MD-14); CT2.
    AccountResetIntent {
        /// The subject's internal id.
        subject: [u8; 16],
        /// Its lifetime: one hour by default, at most 24.
        ttl_ms: u64,
    },
    /// `idp.account.tap_issue`: a temporary access pass (TN-62); CT2, only in a realm that opts in.
    AccountTapIssue(TapIssue),
    /// `idp.account.recovery_policy` when it only tightens, `idp.account.recovery_policy_loosen`
    /// when anything loosens (TN-55, OP-153 m.3 (a)); `loosens` is resolved against the realm's
    /// current policy before the intent is drawn.
    RecoveryPolicy {
        /// The new policy.
        policy: RecoveryPolicy,
        /// Whether it loosens anything the current policy enforces.
        loosens: bool,
    },
    /// `idp.realm.extension_policy`.
    ExtensionPolicy(ExtensionPolicy),
    /// `idp.hook.register` or `idp.hook.retire` (TN-135).
    Hook(HookChange),
    /// `idp.webhook.register`, `idp.webhook.update` or `idp.webhook.retire` (TN-136).
    Webhook(WebhookChange),
    /// `idp.upstream.link` (OP-152 m.7 (d) E6).
    UpstreamLink(UpstreamLink),
    /// `idp.org.create` (TN-5, OP-153 m.3 (b)).
    OrgCreate(OrgCreate),
    /// `idp.org.member_remove` (OP-153 m.3 (p)).
    OrgMemberRemove(OrgMember),
    /// `idp.org.invite` (TN-89, OP-153 m.3 (o)).
    OrgInvite(OrgInvite),
    /// `idp.org.update`: the organization's name or home realm discovery (TN-98).
    OrgUpdate(OrgUpdate),
    /// `idp.org.invite_revoke` (OP-153 m.3 (o)).
    OrgInviteRevoke {
        /// The organization's Party.
        org: [u8; 16],
        /// The invitation.
        invitation: [u8; 16],
    },
    /// `idp.social.enable` (OP-153 m.3 (l)).
    SocialEnable(Social),
    /// `idp.social.update`.
    SocialUpdate(Social),
    /// `idp.social.disable`.
    SocialDisable(Name),
    /// `idp.org.domain_claim` (TN-90, OP-153 m.3 (o)).
    OrgDomainClaim(crate::domain::org::DomainClaim),
    /// `idp.org.domain_release` (TN-90).
    OrgDomainRelease {
        /// The organization's Party.
        org: [u8; 16],
        /// The claim.
        claim: [u8; 16],
    },
    /// `idp.org.sso_draft` (TN-120, OP-153 m.3 (p)).
    OrgSsoDraft(crate::domain::org::SsoDraft),
}

/// A change to an organization's profile (TN-98): its name, and whether home realm discovery
/// routes to it, off by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgUpdate {
    /// The organization's Party.
    pub org: [u8; 16],
    /// A new display name, attacker-controlled text (OP-153 m.3 (o)).
    pub display_name: Option<String>,
    /// Home realm discovery on or off.
    pub hrd: Option<bool>,
    /// A verified domain's autojoin rule on or off, off by default (TN-90).
    pub autojoin: Option<(String, bool)>,
}

impl OrgUpdate {
    fn check(&self) -> Result<(), Invalid> {
        if self.display_name.is_none() && self.hrd.is_none() && self.autojoin.is_none() {
            return Err(Invalid::Body);
        }
        if let Some((d, _)) = &self.autojoin
            && !crate::domain::org::domain_ok(d)
        {
            return Err(Invalid::DomainClaim);
        }
        if let Some(n) = &self.display_name {
            OrgCreate {
                party: self.org,
                display_name: n.clone(),
            }
            .check()?;
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![(Value::text("org"), Value::Bytes(self.org.to_vec()))];
        if let Some(n) = &self.display_name {
            m.push((Value::text("display_name"), Value::text(n)));
        }
        if let Some(h) = self.hrd {
            m.push((Value::text("hrd"), Value::Bool(h)));
        }
        if let Some((d, on)) = &self.autojoin {
            m.push((
                Value::text("autojoin"),
                Value::Map(vec![
                    (Value::text("domain"), Value::text(d)),
                    (Value::text("on"), Value::Bool(*on)),
                ]),
            ));
        }
        Value::Map(m)
    }
}

/// Days an invitation lives by default (OP-153 m.3 (o), PD).
pub const INVITATION_DEFAULT_DAYS: u32 = 7;

/// An invitation into an organization (TN-89, OP-153 m.3 (o)). The invitee's address is folded
/// (NFKC, lower case) and never enters the intent or the ledger: the change names it by its
/// SHA-256 only, and the identity plane keeps the realm's blind index of it. The inviter's name
/// and the organization's name are attacker input, sent as text.
#[derive(Clone, PartialEq, Eq)]
pub struct OrgInvite {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The invitee's folded e-mail address.
    pub email: String,
    /// The inviter's name as the mail shows it.
    pub inviter_name: String,
    /// The role: a Named `AuthoritySet` and its version (§5.17).
    pub role: (Name, u64),
    /// Days it lives, at most [`crate::domain::org::INVITATION_MAX_DAYS`].
    pub days: u32,
}

impl core::fmt::Debug for OrgInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OrgInvite")
            .field("org", &self.org)
            .field("email", &"[redacted]")
            .field("role", &self.role)
            .field("days", &self.days)
            .finish_non_exhaustive()
    }
}

impl OrgInvite {
    /// The domain part of the invitee's address.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.email.rsplit_once('@').map_or("", |(_, d)| d)
    }

    fn check(&self) -> Result<(), Invalid> {
        let Some((local, domain)) = self.email.rsplit_once('@') else {
            return Err(Invalid::Invitation);
        };
        let domain_ok = (1..=253).contains(&domain.len())
            && domain.contains('.')
            && domain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        let n = self.inviter_name.chars().count();
        if local.is_empty()
            || self.email.len() > 254
            || self
                .email
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || !domain_ok
            || n == 0
            || n > 200
            || self.inviter_name.chars().any(char::is_control)
            || self.role.1 == 0
            || self.days == 0
            || self.days > crate::domain::org::INVITATION_MAX_DAYS
        {
            return Err(Invalid::Invitation);
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("org"), Value::Bytes(self.org.to_vec())),
            (
                Value::text("invitee"),
                Value::Bytes(suiss_crypto::digest::sha256(self.email.as_bytes()).to_vec()),
            ),
            (Value::text("role"), Value::text(self.role.0.as_str())),
            (Value::text("role_version"), Value::Unsigned(self.role.1)),
            (Value::text("days"), uint(self.days)),
        ])
    }
}

/// An organization bound to the Party its founder's client registered (TN-5, OP-153 m.3 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgCreate {
    /// The organization's Party in the realm's governing domain.
    pub party: [u8; 16],
    /// Its display name, attacker-controlled text (OP-153 m.3 (o)).
    pub display_name: String,
}

impl OrgCreate {
    fn check(&self) -> Result<(), Invalid> {
        let n = self.display_name.chars().count();
        if n == 0 || n > 128 || self.display_name.chars().any(char::is_control) {
            return Err(Invalid::DisplayName);
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("party"), Value::Bytes(self.party.to_vec())),
            (Value::text("display_name"), Value::text(&self.display_name)),
        ])
    }
}

/// One member of an organization, by the organization's Party and the member's subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrgMember {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The member's subject.
    pub subject: [u8; 16],
}

impl OrgMember {
    fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::text("org"), Value::Bytes(self.org.to_vec())),
            (Value::text("subject"), Value::Bytes(self.subject.to_vec())),
        ])
    }
}

/// A temporary access pass to issue (TN-62): one live pass per user, nobody issues one for
/// themselves, and its session binds an authenticator only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapIssue {
    /// The subject's internal id.
    pub subject: [u8; 16],
    /// Its lifetime: one hour by default, between 10 minutes and 30 days.
    pub ttl_ms: u64,
    /// Its length: 16 by default, between 8 and 48 characters.
    pub length: u8,
    /// Used once (the default), or until it expires.
    pub one_time: bool,
}

impl TapIssue {
    /// TN-62's ranges.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn check(&self) -> Result<(), Invalid> {
        let len = usize::from(self.length);
        if (recovery_policy::TAP_TTL_MIN_MS..=recovery_policy::TAP_TTL_MAX_MS)
            .contains(&self.ttl_ms)
            && (recovery_policy::TAP_LENGTH_MIN..=recovery_policy::TAP_LENGTH_MAX).contains(&len)
        {
            Ok(())
        } else {
            Err(Invalid::Body)
        }
    }

    fn to_value(self) -> Value {
        Value::Map(vec![
            (Value::text("subject"), Value::Bytes(self.subject.to_vec())),
            (Value::text("ttl_ms"), Value::Unsigned(self.ttl_ms)),
            (
                Value::text("length"),
                Value::Unsigned(u64::from(self.length)),
            ),
            (Value::text("one_time"), Value::Bool(self.one_time)),
        ])
    }
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
            Self::RelatedOrigins(_) => IdpAction::RealmRelatedOrigins,
            Self::LocaleOverrides(_) => IdpAction::RealmLocaleOverrides,
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
            Self::ProtectionMode { loosens: false, .. } => IdpAction::RealmProtectionMode,
            Self::ProtectionMode { loosens: true, .. } => IdpAction::RealmProtectionModeLoosen,
            Self::AccountCanary(_) => IdpAction::AccountCanary,
            Self::AccountDelete(_) => IdpAction::AccountDelete,
            Self::AccountResetIntent { .. } => IdpAction::AccountResetIntent,
            Self::AccountTapIssue(_) => IdpAction::AccountTapIssue,
            Self::RecoveryPolicy { loosens: false, .. } => IdpAction::AccountRecoveryPolicy,
            Self::RecoveryPolicy { loosens: true, .. } => IdpAction::AccountRecoveryPolicyLoosen,
            Self::ExtensionPolicy(_) => IdpAction::RealmExtensionPolicy,
            Self::Hook(h) => h.action().idp(),
            Self::Webhook(w) => w.action().idp(),
            Self::UpstreamLink(_) => IdpAction::UpstreamLink,
            Self::OrgCreate(_) => IdpAction::OrgCreate,
            Self::OrgMemberRemove(_) => IdpAction::OrgMemberRemove,
            Self::OrgInvite(_) => IdpAction::OrgInvite,
            Self::OrgUpdate(_) => IdpAction::OrgUpdate,
            Self::OrgInviteRevoke { .. } => IdpAction::OrgInviteRevoke,
            Self::SocialEnable(_) => IdpAction::SocialEnable,
            Self::SocialUpdate(_) => IdpAction::SocialUpdate,
            Self::SocialDisable(_) => IdpAction::SocialDisable,
            Self::OrgDomainClaim(_) => IdpAction::OrgDomainClaim,
            Self::OrgDomainRelease { .. } => IdpAction::OrgDomainRelease,
            Self::OrgSsoDraft(_) => IdpAction::OrgSsoDraft,
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
            Self::RelatedOrigins(r) => r.check(),
            Self::LocaleOverrides(o) => o.check(),
            Self::KeyPolicy(p) => {
                access_identity_signer::domain::check(p).map_err(|_| Invalid::KeyPolicy)
            }
            Self::GroupCreate(g) | Self::GroupUpdate(g) => g.check(),
            Self::GroupMembersAdd(m) | Self::GroupMembersRemove(m) => m.check(),
            Self::UpstreamRegister(u) | Self::UpstreamUpdate(u) => u.check(),
            Self::SigninPolicy(p) => p.check(),
            Self::SessionPolicy(p) => p.check(),
            Self::ExtensionPolicy(p) => p.check().map_err(|_| Invalid::ExtensionPolicy),
            Self::UpstreamLink(l) => l.check(),
            // TN-61
            Self::AccountResetIntent { ttl_ms, .. } => {
                if (1..=recovery_policy::INTENT_TTL_MAX_MS).contains(ttl_ms) {
                    Ok(())
                } else {
                    Err(Invalid::Body)
                }
            }
            // TN-62
            Self::AccountTapIssue(t) => t.check(),
            // TN-55
            Self::RecoveryPolicy { policy, .. } => {
                policy.validate().map_err(|_| Invalid::RecoveryPolicy)
            }
            Self::OrgCreate(o) => o.check(),
            Self::SocialEnable(c) | Self::SocialUpdate(c) => c.check(),
            Self::OrgInvite(i) => i.check(),
            Self::OrgUpdate(u) => u.check(),
            Self::OrgDomainClaim(d) => d.check(),
            Self::OrgSsoDraft(d) => d.check(),
            Self::OrgInviteRevoke { .. }
            | Self::SocialDisable(_)
            | Self::OrgDomainRelease { .. }
            | Self::OrgMemberRemove(_)
            | Self::Hook(_)
            | Self::Webhook(_)
            | Self::ClientRetire(_)
            | Self::MapperSet { .. }
            | Self::JoseAlg(_)
            | Self::RpId(_)
            | Self::KeyRotate { .. }
            | Self::KeyDrop { .. }
            | Self::ClientSecretRotate(_)
            | Self::GroupRetire(_)
            | Self::AccountSuspend(_)
            | Self::AccountReactivate(_)
            | Self::UpstreamRetire(_)
            | Self::ProtectionMode { .. }
            | Self::AccountCanary(_)
            | Self::AccountDelete(_) => Ok(()),
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
            Self::RelatedOrigins(r) => r.to_value(),
            Self::LocaleOverrides(o) => o.to_value(),
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
            Self::AccountSuspend(s)
            | Self::AccountReactivate(s)
            | Self::AccountCanary(s)
            | Self::AccountDelete(s) => {
                Value::Map(vec![(Value::text("subject"), Value::Bytes(s.to_vec()))])
            }
            Self::ProtectionMode { mode, .. } => Value::Map(vec![(
                Value::text("mode"),
                Value::text(&access_identity_risk::app::settings::canonical(mode)),
            )]),
            Self::UpstreamRegister(u) | Self::UpstreamUpdate(u) => u.to_value(),
            Self::SigninPolicy(p) => p.to_value(),
            Self::SessionPolicy(p) => p.to_value(),
            Self::ExtensionPolicy(p) => p.to_value(),
            Self::Hook(h) => h.body(),
            Self::Webhook(w) => w.body(),
            Self::UpstreamLink(l) => l.to_value(),
            Self::OrgCreate(o) => o.to_value(),
            Self::OrgMemberRemove(m) => m.to_value(),
            Self::AccountResetIntent { subject, ttl_ms } => Value::Map(vec![
                (Value::text("subject"), Value::Bytes(subject.to_vec())),
                (Value::text("ttl_ms"), Value::Unsigned(*ttl_ms)),
            ]),
            Self::AccountTapIssue(t) => t.to_value(),
            Self::RecoveryPolicy { policy, .. } => Value::Map(vec![(
                Value::text("policy"),
                Value::Bytes(policy.to_bytes().unwrap_or_default()),
            )]),
            Self::OrgInvite(i) => i.to_value(),
            Self::OrgUpdate(u) => u.to_value(),
            Self::OrgInviteRevoke { org, invitation } => Value::Map(vec![
                (Value::text("org"), Value::Bytes(org.to_vec())),
                (Value::text("invitation"), Value::Bytes(invitation.to_vec())),
            ]),
            Self::SocialEnable(c) | Self::SocialUpdate(c) => c.to_value(),
            Self::SocialDisable(n) => {
                Value::Map(vec![(Value::text("preset"), Value::text(n.as_str()))])
            }
            Self::OrgDomainClaim(d) => d.to_value(),
            Self::OrgDomainRelease { org, claim } => Value::Map(vec![
                (Value::text("org"), Value::Bytes(org.to_vec())),
                (Value::text("claim"), Value::Bytes(claim.to_vec())),
            ]),
            Self::OrgSsoDraft(d) => d.to_value(),
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
            Self::AccountSuspend(s)
            | Self::AccountReactivate(s)
            | Self::AccountCanary(s)
            | Self::AccountDelete(s)
            | Self::AccountResetIntent { subject: s, .. }
            | Self::AccountTapIssue(TapIssue { subject: s, .. }) => {
                path.extend([String::from("account"), b64url_encode(s)]);
            }
            Self::UpstreamRegister(Upstream { name, .. })
            | Self::UpstreamUpdate(Upstream { name, .. })
            | Self::UpstreamRetire(name)
            | Self::UpstreamLink(UpstreamLink { upstream: name, .. }) => {
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
            | Self::RelatedOrigins(_)
            | Self::LocaleOverrides(_)
            | Self::SigninPolicy(_)
            | Self::SessionPolicy(_)
            | Self::ProtectionMode { .. }
            | Self::RecoveryPolicy { .. }
            | Self::ExtensionPolicy(_) => {
                path.push(String::from("realm"));
            }
            Self::Hook(HookChange::Register { id, .. } | HookChange::Retire { id }) => {
                path.extend([String::from("hook"), uuid(id)]);
            }
            Self::Webhook(w) => {
                path.extend([String::from("webhook"), uuid(w.id())]);
            }
            Self::KeyPolicy(_) | Self::KeyRotate { .. } | Self::KeyDrop { .. } => {
                path.push(String::from("keys"));
            }
            Self::OrgCreate(OrgCreate { party: org, .. })
            | Self::OrgMemberRemove(OrgMember { org, .. })
            | Self::OrgInvite(OrgInvite { org, .. })
            | Self::OrgUpdate(OrgUpdate { org, .. })
            | Self::OrgInviteRevoke { org, .. }
            | Self::OrgDomainRelease { org, .. }
            | Self::OrgDomainClaim(crate::domain::org::DomainClaim { org, .. })
            | Self::OrgSsoDraft(crate::domain::org::SsoDraft { org, .. }) => {
                path.extend([String::from("org"), b64url_encode(org)]);
            }
            Self::SocialEnable(Social { preset, .. })
            | Self::SocialUpdate(Social { preset, .. })
            | Self::SocialDisable(preset) => {
                path.extend([String::from("social"), String::from(preset.as_str())]);
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
