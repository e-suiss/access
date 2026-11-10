//! The assurance vector (§10.1.6, F15, F17) and its framework mappings (§10.3): NIST SP 800-63-4
//! AAL and FAL, the `eIDAS` level of assurance, and the CT ceiling the identity plane can contribute (IDP-8). The
//! decision reads the vector; a single level is only a derived view.

use serde::{Deserialize, Serialize};

/// A method class (§10.2). The method names the technology; the class is what the vector reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodClass {
    /// Memorized secret.
    Password,
    /// WebAuthn credential.
    Passkey,
    /// RFC 6238 authenticator app.
    Totp,
    /// Single-use recovery code (§10.2.2).
    RecoveryCode,
    /// Code sent by e-mail.
    EmailOtp,
    /// Link sent by e-mail.
    MagicLink,
    /// Push approval with number matching; reserved, delivered from Stage 11 (OP-146 m.4 (c)).
    Push,
    /// App PIN plus an app-bound key pair (MD-11, IDP-9); reserved.
    AppControlled,
    /// A social or upstream provider's checked assertion (IDP-31, OP-153 m.3 (l)): AAL1, no CT.
    Federated,
    /// A client certificate whose issuer policy the realm mapped as hardware-bound PIV, CAC or
    /// smart card, presented on the mTLS listener (OP-155 m.3 (m)).
    SmartCard,
    /// Any other client certificate presented on the mTLS listener: a software key (OP-155
    /// m.3 (m)).
    Certificate,
    /// A restricted SMS one-time code (OP-156 m.3 (f), IDP-4): AAL2 second factor at best, no CT.
    Sms,
}

impl MethodClass {
    /// The `amr` value (RFC 8176).
    #[must_use]
    pub const fn amr(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Passkey => "hwk",
            Self::Totp => "otp",
            Self::RecoveryCode => "kba",
            Self::EmailOtp | Self::MagicLink => "mail",
            Self::Push => "mca",
            Self::AppControlled => "pin",
            Self::Federated => "fed",
            Self::SmartCard => "sc",
            Self::Certificate => "swk",
            Self::Sms => "sms",
        }
    }
}

/// NIST SP 800-63B-4 authenticator assurance level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Aal {
    /// Single factor.
    Aal1,
    /// Two factors with replay resistance, or a UV synced passkey.
    Aal2,
    /// Phishing-resistant, non-exportable key with UV.
    Aal3,
}

/// eIDAS level of assurance (§10.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LoaEidas {
    /// Low.
    Low,
    /// Substantial.
    Substantial,
    /// High.
    High,
}

/// NIST SP 800-63C-4 federation assurance level of an issued assertion (§10.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fal {
    /// Bearer assertion; not a default.
    Fal1,
    /// Holder-bound (DPoP or mTLS).
    Fal2,
    /// Holder-bound under the FAPI 2.0 profile with PAR.
    Fal3,
}

/// How a token or assertion is bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presentation {
    /// DPoP or mTLS binding.
    pub holder_bound: bool,
    /// FAPI 2.0 with PAR.
    pub fapi: bool,
}

/// §10.3.1: FAL1 bearer, FAL2 holder-bound, FAL3 FAPI 2.0 + PAR + holder-bound.
#[must_use]
pub const fn fal(p: Presentation) -> Fal {
    match (p.holder_bound, p.fapi) {
        (false, _) => Fal::Fal1,
        (true, false) => Fal::Fal2,
        (true, true) => Fal::Fal3,
    }
}

/// How phishing resistance was proven (§10.3.1). Only these two paths set the flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhishingProof {
    /// Channel binding: mTLS, TLS-bound.
    ChannelBinding,
    /// Verifier name binding: the WebAuthn origin and RP ID.
    VerifierNameBinding,
}

/// Key binding strength (§10.2, IDP-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStrength {
    /// No key: a shared secret or a delivered code.
    None,
    /// A key the provider may sync (BE = 1).
    Synced,
    /// A key that cannot leave the authenticator (BE = 0).
    DeviceBound,
}

/// The NIST factor category a proof belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorKind {
    /// Something you know.
    Knowledge,
    /// Something you have.
    Possession,
}

/// One completed authentication step: what the method proved.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact a step proves (§10.1.6)"
)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Factor {
    /// Method class.
    pub method: MethodClass,
    /// Categories the step proved; a UV passkey proves two.
    pub kinds: Vec<FactorKind>,
    /// Phishing resistance, when proven.
    pub phishing: Option<PhishingProof>,
    /// Key binding.
    pub binding: BindingStrength,
    /// UV that counts as a factor (MD-11: platform biometrics alone never does).
    pub uv: bool,
    /// Human presence (WebAuthn UP).
    pub human_presence: bool,
    /// Replay resistant (§10.3.1 AAL2).
    pub replay_resistant: bool,
    /// The authenticator cannot satisfy any CT (RS256 passkeys; §10.2.4).
    pub session_login_only: bool,
    /// MD-11 app-controlled factor.
    pub app_controlled: bool,
    /// The credential used, when there is one.
    pub credential: Option<[u8; 16]>,
    /// When the step completed, Unix milliseconds.
    pub at_ms: u64,
    /// What a passkey's assertion showed, for its `authentication` Claim (§10.1.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<PasskeyDetail>,
    /// A client certificate's SHA-256 thumbprint, for its `authentication` Claim (OP-155
    /// m.3 (m)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<[u8; 32]>,
    /// What an enterprise upstream declared, for its `authentication` Claim (OP-155 m.3 (h)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamStep>,
}

/// An enterprise upstream's checked sign-in (§10.1.2 OIDC and SAML rows, OP-155 m.3 (h)): its
/// declarations as evidence, and the assurance its connection's map gave them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamStep {
    /// The connection.
    pub connection: String,
    /// SAML rather than OIDC.
    pub saml: bool,
    /// The verified issuer (RFC 9207) or identity provider entity ID.
    pub iss: String,
    /// `acr` or `AuthnContextClassRef`, as declared.
    pub acr: Option<String>,
    /// `amr`, as declared.
    pub amr: Vec<String>,
    /// The digest of the raw assertion.
    pub evidence: [u8; 32],
    /// The AAL the assurance map gave, 1 when it gave none (IDP-27).
    pub aal: u8,
    /// The eIDAS level the assurance map gave, 1 to 3.
    pub loa_eidas: Option<u8>,
}

/// What a passkey assertion showed (§10.1.2 WebAuthn row): the AAGUID hint, the counter, the
/// flags and the digest of the assertion as received. Never the credential id or a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyDetail {
    /// AAGUID.
    pub aaguid: [u8; 16],
    /// Signature counter.
    pub sign_count: u32,
    /// UV.
    pub uv: bool,
    /// BE.
    pub be: bool,
    /// BS.
    pub bs: bool,
    /// Digest of authenticator data, client data and signature.
    pub evidence: [u8; 32],
}

impl Factor {
    fn base(method: MethodClass, kinds: Vec<FactorKind>, at_ms: u64) -> Self {
        Self {
            method,
            kinds,
            phishing: None,
            binding: BindingStrength::None,
            uv: false,
            human_presence: false,
            replay_resistant: false,
            session_login_only: false,
            app_controlled: false,
            credential: None,
            at_ms,
            webauthn: None,
            certificate: None,
            upstream: None,
        }
    }

    /// A password (§10.2.1): knowledge, AAL1, no CT.
    #[must_use]
    pub fn password(at_ms: u64) -> Self {
        Self::base(MethodClass::Password, vec![FactorKind::Knowledge], at_ms)
    }

    /// A TOTP code (§10.2.2): possession, replay resistant through the used-step rule.
    #[must_use]
    pub fn totp(credential: [u8; 16], at_ms: u64) -> Self {
        Self {
            credential: Some(credential),
            replay_resistant: true,
            ..Self::base(MethodClass::Totp, vec![FactorKind::Possession], at_ms)
        }
    }

    /// A recovery code: a single-use secret held by the user (§10.2.2).
    #[must_use]
    pub fn recovery_code(credential: [u8; 16], at_ms: u64) -> Self {
        Self {
            credential: Some(credential),
            replay_resistant: true,
            ..Self::base(
                MethodClass::RecoveryCode,
                vec![FactorKind::Possession],
                at_ms,
            )
        }
    }

    /// A provider's assertion checked in the back end (IDP-31): AAL1, no CT; the provider's own
    /// factors are not ours to count.
    #[must_use]
    pub fn federated(at_ms: u64) -> Self {
        Self::base(MethodClass::Federated, vec![FactorKind::Possession], at_ms)
    }

    /// An enterprise upstream's checked sign-in (OP-155 m.3 (h)): a federated step whose AAL and
    /// eIDAS level are only what the connection's assurance map gave; it is never phishing
    /// resistant on our side and so satisfies no CT (IDP-8, IDP-27).
    #[must_use]
    pub fn upstream(step: UpstreamStep, at_ms: u64) -> Self {
        Self {
            upstream: Some(step),
            ..Self::base(MethodClass::Federated, vec![FactorKind::Possession], at_ms)
        }
    }

    /// A client certificate on the mTLS listener (§10.2.5, OP-155 m.3 (m)): channel binding, so
    /// phishing resistant. A certificate whose issuer policy the realm mapped as hardware-bound
    /// PIV is a device-bound key activated by the card's PIN (AAL3, CT3); any other is a software
    /// key of one category, which never reaches CT3.
    #[must_use]
    pub fn certificate(thumbprint: [u8; 32], hardware_bound: bool, at_ms: u64) -> Self {
        let (method, kinds, binding) = if hardware_bound {
            (
                MethodClass::SmartCard,
                vec![FactorKind::Possession, FactorKind::Knowledge],
                BindingStrength::DeviceBound,
            )
        } else {
            (
                MethodClass::Certificate,
                vec![FactorKind::Possession],
                BindingStrength::None,
            )
        };
        Self {
            phishing: Some(PhishingProof::ChannelBinding),
            binding,
            uv: hardware_bound,
            replay_resistant: true,
            certificate: Some(thumbprint),
            ..Self::base(method, kinds, at_ms)
        }
    }

    /// An SMS code (§10.2.2, IDP-4, OP-156 m.3 (f)): possession of the line, replay resistant
    /// through its single use, never phishing resistant and never a CT.
    #[must_use]
    pub fn sms(at_ms: u64) -> Self {
        Self {
            replay_resistant: true,
            session_login_only: true,
            ..Self::base(MethodClass::Sms, vec![FactorKind::Possession], at_ms)
        }
    }

    /// The app-controlled factor (MD-11, IDP-9, OP-156 m.3 (e)): an approver key attested in
    /// hardware that signed only after the app checked its own PIN. Possession and knowledge,
    /// replay resistant, never phishing resistant; it adds no key binding to the vector, so it
    /// never lends a synced key a hardware property, and alone it meets no CT.
    #[must_use]
    pub fn app_controlled(approver: [u8; 16], at_ms: u64) -> Self {
        Self {
            replay_resistant: true,
            app_controlled: true,
            credential: Some(approver),
            ..Self::base(
                MethodClass::AppControlled,
                vec![FactorKind::Possession, FactorKind::Knowledge],
                at_ms,
            )
        }
    }

    /// An e-mail code or link (§10.2.2): AAL1, no CT.
    #[must_use]
    pub fn email(method: MethodClass, at_ms: u64) -> Self {
        Self::base(method, vec![FactorKind::Possession], at_ms)
    }

    /// A WebAuthn assertion (§10.2.4, OP-146 m.9 (c)): verifier name binding, so phishing
    /// resistant; UV that counts adds a second category.
    #[must_use]
    pub fn passkey(
        credential: [u8; 16],
        synced: bool,
        uv: bool,
        session_login_only: bool,
        at_ms: u64,
    ) -> Self {
        let kinds = if uv {
            vec![FactorKind::Possession, FactorKind::Knowledge]
        } else {
            vec![FactorKind::Possession]
        };
        Self {
            credential: Some(credential),
            phishing: Some(PhishingProof::VerifierNameBinding),
            binding: if synced {
                BindingStrength::Synced
            } else {
                BindingStrength::DeviceBound
            },
            uv,
            human_presence: true,
            replay_resistant: true,
            session_login_only,
            ..Self::base(MethodClass::Passkey, kinds, at_ms)
        }
    }
}

/// The assurance vector of §10.1.6.
#[expect(
    clippy::struct_excessive_bools,
    reason = "§10.1.6 defines the vector as independent flags"
)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceVector {
    /// NIST AAL.
    pub aal: Aal,
    /// `eIDAS` level of assurance; only from an upstream notified eID or EUDI presentation, never from
    /// Access's own methods (§10.3.2).
    pub loa_eidas: Option<LoaEidas>,
    /// Set only with channel binding or verifier name binding (§10.3.1).
    pub phishing_resistant: bool,
    /// A device-bound key took part.
    pub hardware_bound: bool,
    /// The key is held by the user, not a custodian.
    pub non_custodial: bool,
    /// UV counted as a factor.
    pub uv: bool,
    /// Human presence.
    pub human_presence: bool,
    /// MD-11 app-controlled factor.
    pub app_controlled_factor: bool,
    /// A synced (BS = 1 / BE = 1) key took part.
    pub synced: bool,
    /// Authentication time, Unix milliseconds.
    pub auth_time_ms: u64,
}

/// The highest CT the authentication can contribute to (IDP-8, §13.7.3). Password, OTP, TOTP
/// and push never satisfy any CT, CT0 included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CtCeiling {
    /// None.
    None,
    /// CT1: phishing-resistant proof.
    Ct1,
    /// CT2: plus UV.
    Ct2,
    /// CT3: plus device-bound and non-custodial.
    Ct3,
}

fn has_two_categories(factors: &[Factor]) -> bool {
    let mut knowledge = false;
    let mut possession = false;
    for k in factors.iter().flat_map(|f| f.kinds.iter()) {
        match k {
            FactorKind::Knowledge => knowledge = true,
            FactorKind::Possession => possession = true,
        }
    }
    knowledge && possession
}

/// The vector of a set of completed steps (§10.1.6, §10.3.1).
///
/// AAL3 needs one step that is phishing resistant, device-bound and UV; AAL2 needs two
/// categories with a replay-resistant step, or a UV synced passkey; else AAL1. Synced passkeys
/// never reach AAL3 (OP-146 m.9 (c)). An upstream step adds only what its connection's
/// assurance map gave. The vector carries the latest step's time.
#[must_use]
pub fn vector(factors: &[Factor]) -> AssuranceVector {
    let aal3 = factors
        .iter()
        .any(|f| f.phishing.is_some() && f.binding == BindingStrength::DeviceBound && f.uv);
    let multi = has_two_categories(factors) && factors.iter().any(|f| f.replay_resistant);
    let own = if aal3 {
        Aal::Aal3
    } else if multi {
        Aal::Aal2
    } else {
        Aal::Aal1
    };
    // IDP-27, OP-155 m.3 (h)
    let mapped = factors
        .iter()
        .filter_map(|f| f.upstream.as_ref())
        .map(|u| match u.aal {
            3 => Aal::Aal3,
            2 => Aal::Aal2,
            _ => Aal::Aal1,
        })
        .max()
        .unwrap_or(Aal::Aal1);
    let loa_eidas = factors
        .iter()
        .filter_map(|f| f.upstream.as_ref().and_then(|u| u.loa_eidas))
        .max()
        .map(|l| match l {
            3 => LoaEidas::High,
            2 => LoaEidas::Substantial,
            _ => LoaEidas::Low,
        });
    AssuranceVector {
        aal: own.max(mapped),
        loa_eidas,
        phishing_resistant: factors.iter().any(|f| f.phishing.is_some()),
        hardware_bound: factors
            .iter()
            .any(|f| f.binding == BindingStrength::DeviceBound),
        non_custodial: factors
            .iter()
            .any(|f| f.binding == BindingStrength::DeviceBound),
        uv: factors.iter().any(|f| f.uv),
        human_presence: factors.iter().any(|f| f.human_presence),
        app_controlled_factor: factors.iter().any(|f| f.app_controlled),
        synced: factors.iter().any(|f| f.binding == BindingStrength::Synced),
        auth_time_ms: factors.iter().map(|f| f.at_ms).max().unwrap_or(0),
    }
}

/// IDP-8: the CT ceiling of the steps. Only a phishing-resistant step counts; an app-controlled
/// factor alone never does (MD-11); RS256 passkeys satisfy no CT.
#[must_use]
pub fn ct_ceiling(factors: &[Factor]) -> CtCeiling {
    factors
        .iter()
        .filter(|f| f.phishing.is_some() && !f.session_login_only)
        .map(|f| match (f.uv, f.binding) {
            (true, BindingStrength::DeviceBound) => CtCeiling::Ct3,
            (true, _) => CtCeiling::Ct2,
            (false, _) => CtCeiling::Ct1,
        })
        .max()
        .unwrap_or(CtCeiling::None)
}

/// IDP-8 under a realm's assurance profile (MD-11, SA-54, OP-156 m.3 (e)): the TR payment
/// profile asks CT2 and CT3 for a phishing-resistant step **and** an app-controlled factor, so
/// without one the ceiling stays at CT1. Nothing here raises [`ct_ceiling`].
#[must_use]
pub fn ct_ceiling_in(factors: &[Factor], profile: AssuranceProfile) -> CtCeiling {
    let ceiling = ct_ceiling(factors);
    match profile {
        AssuranceProfile::Standard => ceiling,
        AssuranceProfile::TrPayment if factors.iter().any(|f| f.app_controlled) => ceiling,
        AssuranceProfile::TrPayment => ceiling.min(CtCeiling::Ct1),
    }
}

/// A realm's assurance profile (MD-11, SA-54): realm settings and requirement narrowing only,
/// never a widening.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceProfile {
    /// No profile.
    #[default]
    Standard,
    /// Turkish payment and e-money institutions (BDDK/TCMB, `tr-payment`, OP-156 m.3 (e), (f)).
    TrPayment,
}

impl AssuranceProfile {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::TrPayment => "tr-payment",
        }
    }

    /// From the stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Standard, Self::TrPayment]
            .into_iter()
            .find(|p| p.name() == s)
    }

    /// Whether the platform's own user verification counts as a factor (MD-11): never under the
    /// TR payment profile, where biometrics alone authenticate nothing.
    #[must_use]
    pub const fn platform_uv_is_factor(self) -> bool {
        matches!(self, Self::Standard)
    }

    /// Whether an SMS code may be a sign-in step (OP-156 m.3 (f)): under the TR payment profile
    /// only enrolment and activation take one.
    #[must_use]
    pub const fn sms_signs_in(self) -> bool {
        matches!(self, Self::Standard)
    }
}

/// §10.3.2: the eIDAS equivalent of an upstream-asserted AAL. "High" is never derived from
/// Access's own methods; this maps only upstream evidence (Stage 10 Acceptance).
#[must_use]
pub const fn eidas_from_upstream(aal: Aal, upstream_high: bool) -> LoaEidas {
    match (aal, upstream_high) {
        (Aal::Aal3, true) => LoaEidas::High,
        (Aal::Aal2 | Aal::Aal3, _) => LoaEidas::Substantial,
        (Aal::Aal1, _) => LoaEidas::Low,
    }
}

/// The single typed value between authentication and token issuance (TN-103): method,
/// assurance, authenticators and realm. Token issuance never sees the path that produced it;
/// `tenant` is routing context only, never an authority input (TN-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationResult {
    /// Tenant, as routing context.
    pub tenant: [u8; 16],
    /// Realm.
    pub realm: [u8; 16],
    /// The authenticated subject.
    pub subject: [u8; 16],
    /// Methods used, in completion order.
    pub methods: Vec<MethodClass>,
    /// Credentials used.
    pub authenticators: Vec<[u8; 16]>,
    /// The assurance vector.
    pub assurance: AssuranceVector,
    /// The CT ceiling (IDP-8).
    pub ct: CtCeiling,
}

impl AuthenticationResult {
    /// The result of a completed list of steps.
    #[must_use]
    pub fn of(tenant: [u8; 16], realm: [u8; 16], subject: [u8; 16], factors: &[Factor]) -> Self {
        Self {
            tenant,
            realm,
            subject,
            methods: factors.iter().map(|f| f.method).collect(),
            authenticators: factors.iter().filter_map(|f| f.credential).collect(),
            assurance: vector(factors),
            ct: ct_ceiling(factors),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_000;

    // OP-155 m.3 (m), §10.3.1, IDP-8, Ek B 4671
    #[test]
    fn a_software_certificate_never_reaches_ct3() {
        let soft = [Factor::certificate([7; 32], false, T)];
        let v = vector(&soft);
        assert_eq!(v.aal, Aal::Aal1);
        assert!(v.phishing_resistant);
        assert!(!v.hardware_bound);
        assert_eq!(ct_ceiling(&soft), CtCeiling::Ct1);
        assert_eq!(soft[0].method.amr(), "swk");
        let with_password = [Factor::password(T), soft[0].clone()];
        assert_eq!(vector(&with_password).aal, Aal::Aal2);
        assert_eq!(ct_ceiling(&with_password), CtCeiling::Ct1);
        let piv = [Factor::certificate([7; 32], true, T)];
        let v = vector(&piv);
        assert_eq!(v.aal, Aal::Aal3);
        assert!(v.hardware_bound && v.uv && v.phishing_resistant);
        assert_eq!(ct_ceiling(&piv), CtCeiling::Ct3);
        assert_eq!(piv[0].method.amr(), "sc");
        assert_eq!(piv[0].certificate, Some([7; 32]));
    }

    // §10.1.6, §10.2, §10.3.1, IDP-8
    #[test]
    fn password_alone_is_aal1_and_no_ct() {
        let f = [Factor::password(T)];
        let v = vector(&f);
        assert_eq!(v.aal, Aal::Aal1);
        assert!(!v.phishing_resistant);
        assert_eq!(ct_ceiling(&f), CtCeiling::None);
        assert_eq!(v.loa_eidas, None);
    }

    // §10.3.1
    #[test]
    fn password_and_totp_is_aal2_without_ct() {
        let f = [Factor::password(T), Factor::totp([2; 16], T + 5)];
        let v = vector(&f);
        assert_eq!(v.aal, Aal::Aal2);
        assert!(!v.phishing_resistant);
        assert_eq!(v.auth_time_ms, T + 5);
        assert_eq!(ct_ceiling(&f), CtCeiling::None);
    }

    // §10.3.1, OP-146 m.9 (c), IDP-8
    #[test]
    fn passkeys_map_to_aal_and_ct_by_binding_and_uv() {
        let device = [Factor::passkey([1; 16], false, true, false, T)];
        assert_eq!(vector(&device).aal, Aal::Aal3);
        assert!(vector(&device).hardware_bound && vector(&device).non_custodial);
        assert_eq!(ct_ceiling(&device), CtCeiling::Ct3);
        let synced = [Factor::passkey([1; 16], true, true, false, T)];
        assert_eq!(vector(&synced).aal, Aal::Aal2);
        assert!(vector(&synced).synced);
        assert_eq!(ct_ceiling(&synced), CtCeiling::Ct2);
        let no_uv = [Factor::passkey([1; 16], false, false, false, T)];
        assert_eq!(vector(&no_uv).aal, Aal::Aal1);
        assert_eq!(ct_ceiling(&no_uv), CtCeiling::Ct1);
        let rs256 = [Factor::passkey([1; 16], false, true, true, T)];
        assert_eq!(ct_ceiling(&rs256), CtCeiling::None);
        assert!(vector(&rs256).phishing_resistant);
    }

    // §10.3.1
    #[test]
    fn phishing_resistance_needs_a_binding_proof() {
        let mut f = Factor::passkey([1; 16], false, true, false, T);
        f.phishing = None;
        assert!(!vector(&[f.clone()]).phishing_resistant);
        assert_eq!(ct_ceiling(&[f]), CtCeiling::None);
        for m in [
            Factor::password(T),
            Factor::totp([1; 16], T),
            Factor::recovery_code([1; 16], T),
            Factor::email(MethodClass::EmailOtp, T),
            Factor::email(MethodClass::MagicLink, T),
        ] {
            assert!(!vector(&[m]).phishing_resistant);
        }
    }

    // MD-11, IDP-9, §10.3.3
    #[test]
    fn platform_biometrics_and_app_factor_are_not_strong_alone() {
        let biometric_only = Factor::passkey([1; 16], false, false, false, T);
        assert!(!vector(&[biometric_only]).uv);
        let mut app = Factor::base(MethodClass::AppControlled, vec![FactorKind::Knowledge], T);
        app.app_controlled = true;
        let v = vector(&[app.clone()]);
        assert!(v.app_controlled_factor);
        assert!(!v.phishing_resistant);
        assert_eq!(ct_ceiling(&[app]), CtCeiling::None);
    }

    // MD-11, IDP-9, OP-156 m.3 (e), Ek B 5395
    #[test]
    fn the_app_controlled_factor_alone_meets_no_ct2_and_meets_it_with_a_passkey() {
        let app = Factor::app_controlled([4; 16], T);
        let alone = [app.clone()];
        let v = vector(&alone);
        assert!(v.app_controlled_factor && !v.phishing_resistant && !v.hardware_bound);
        assert_eq!(v.aal, Aal::Aal2);
        assert_eq!(app.method.amr(), "pin");
        for p in [AssuranceProfile::Standard, AssuranceProfile::TrPayment] {
            assert_eq!(ct_ceiling_in(&alone, p), CtCeiling::None);
        }
        let passkey = Factor::passkey([1; 16], true, true, false, T);
        assert_eq!(
            ct_ceiling_in(&[passkey.clone()], AssuranceProfile::TrPayment),
            CtCeiling::Ct1
        );
        assert_eq!(
            ct_ceiling_in(&[passkey.clone()], AssuranceProfile::Standard),
            CtCeiling::Ct2
        );
        let both = [passkey, app];
        assert_eq!(
            ct_ceiling_in(&both, AssuranceProfile::TrPayment),
            CtCeiling::Ct2
        );
        assert!(!vector(&both).hardware_bound);
    }

    // OP-156 m.3 (f), IDP-4, IDP-8
    #[test]
    fn an_sms_code_is_an_aal2_second_factor_and_meets_no_ct() {
        let sms = Factor::sms(T);
        assert_eq!(sms.method.amr(), "sms");
        assert_eq!(vector(&[sms.clone()]).aal, Aal::Aal1);
        let steps = [Factor::password(T), sms];
        assert_eq!(vector(&steps).aal, Aal::Aal2);
        assert!(!vector(&steps).phishing_resistant);
        assert_eq!(ct_ceiling(&steps), CtCeiling::None);
    }

    // MD-11, OP-156 m.3 (e), (f)
    #[test]
    fn the_tr_payment_profile_counts_no_biometrics_and_no_sms_sign_in() {
        assert_eq!(
            AssuranceProfile::parse("tr-payment"),
            Some(AssuranceProfile::TrPayment)
        );
        assert_eq!(AssuranceProfile::parse("TR-payment"), None);
        assert!(!AssuranceProfile::TrPayment.platform_uv_is_factor());
        assert!(!AssuranceProfile::TrPayment.sms_signs_in());
        assert!(AssuranceProfile::Standard.platform_uv_is_factor());
        assert!(AssuranceProfile::Standard.sms_signs_in());
    }

    // §10.3.2
    #[test]
    fn eidas_high_only_from_upstream() {
        let v = vector(&[Factor::passkey([1; 16], false, true, false, T)]);
        assert_eq!(v.loa_eidas, None);
        assert_eq!(eidas_from_upstream(Aal::Aal3, false), LoaEidas::Substantial);
        assert_eq!(eidas_from_upstream(Aal::Aal3, true), LoaEidas::High);
        assert_eq!(eidas_from_upstream(Aal::Aal2, true), LoaEidas::Substantial);
        assert_eq!(eidas_from_upstream(Aal::Aal1, true), LoaEidas::Low);
    }

    fn step(aal: u8, loa_eidas: Option<u8>) -> UpstreamStep {
        UpstreamStep {
            connection: String::from("corp"),
            saml: false,
            iss: String::from("https://idp.example"),
            acr: Some(String::from("urn:x:gold")),
            amr: vec![String::from("mfa")],
            evidence: [9; 32],
            aal,
            loa_eidas,
        }
    }

    // IDP-27, IDP-8, §10.1.2 rule 2, OP-155 m.3 (h)
    #[test]
    fn an_upstream_step_carries_only_what_its_map_gave_and_no_ct() {
        let lowest = [Factor::upstream(step(1, None), T)];
        let v = vector(&lowest);
        assert_eq!(v.aal, Aal::Aal1);
        assert_eq!(v.loa_eidas, None);
        assert!(!v.phishing_resistant);
        assert_eq!(ct_ceiling(&lowest), CtCeiling::None);
        assert_eq!(lowest[0].method.amr(), "fed");
        let mapped = [Factor::upstream(step(3, Some(3)), T)];
        let v = vector(&mapped);
        assert_eq!(v.aal, Aal::Aal3);
        assert_eq!(v.loa_eidas, Some(LoaEidas::High));
        assert!(!v.hardware_bound && !v.phishing_resistant);
        assert_eq!(ct_ceiling(&mapped), CtCeiling::None);
    }

    // §10.3.1 FAL
    #[test]
    fn fal_follows_binding() {
        let p = |holder_bound, fapi| Presentation { holder_bound, fapi };
        assert_eq!(fal(p(false, true)), Fal::Fal1);
        assert_eq!(fal(p(true, false)), Fal::Fal2);
        assert_eq!(fal(p(true, true)), Fal::Fal3);
    }
}
