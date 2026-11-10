//! Texts with stable ids. Clients translate or restyle by id; the English text is the default.

use serde::{Deserialize, Serialize};

/// Every text the contract can carry. The set is closed: there is no free-text message, so a
/// login screen cannot be made to say something the contract does not (X29, X34).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TextId {
    /// One neutral refusal for every failed first factor (CR-40, X34).
    #[serde(rename = "login.failed")]
    LoginFailed,
    /// Too many attempts; the same for every identifier.
    #[serde(rename = "login.throttled")]
    TooManyAttempts,
    /// Capacity shedding (OP-36).
    #[serde(rename = "login.unavailable")]
    Unavailable,
    /// The flow ran out or was already used.
    #[serde(rename = "flow.expired")]
    FlowExpired,
    /// A second-factor code did not verify. Only after the first factor (X34).
    #[serde(rename = "second_factor.failed")]
    SecondFactorFailed,
    /// A passkey is not registered for the signed-in account. Only after the first factor (X34).
    #[serde(rename = "passkey.not_registered")]
    PasskeyNotRegistered,
    /// Identifier field.
    #[serde(rename = "label.identifier")]
    IdentifierLabel,
    /// Password field.
    #[serde(rename = "label.password")]
    PasswordLabel,
    /// TOTP field.
    #[serde(rename = "label.totp_code")]
    TotpLabel,
    /// Recovery code field.
    #[serde(rename = "label.recovery_code")]
    RecoveryCodeLabel,
    /// Continue after the identifier.
    #[serde(rename = "action.continue")]
    Continue,
    /// Sign in with the password.
    #[serde(rename = "action.sign_in")]
    SignIn,
    /// The explicit passkey button (TN-99).
    #[serde(rename = "action.passkey")]
    PasskeySignIn,
    /// Create a passkey.
    #[serde(rename = "action.passkey_create")]
    PasskeyCreate,
    /// Verify a second-factor code.
    #[serde(rename = "action.verify")]
    Verify,
    /// Use a recovery code instead.
    #[serde(rename = "action.recovery_code")]
    UseRecoveryCode,
    /// Decline an optional step.
    #[serde(rename = "action.skip")]
    Skip,
    /// Start again with another identifier.
    #[serde(rename = "action.restart")]
    Restart,
    /// E-mail code field.
    #[serde(rename = "label.email_code")]
    EmailCodeLabel,
    /// Ask for a code by e-mail.
    #[serde(rename = "action.email_code")]
    SendEmailCode,
    /// Ask for a sign-in link by e-mail.
    #[serde(rename = "action.magic_link")]
    SendMagicLink,
    /// An e-mail step is waiting; the same words whether or not anything was sent (TN-102).
    #[serde(rename = "email.sent")]
    EmailSent,
    /// Text `registration.title` (OP-153 m.3 (g)).
    #[serde(rename = "registration.title")]
    RegistrationTitle,
    /// Field label `label.email` (TN-106).
    #[serde(rename = "label.email")]
    EmailLabel,
    /// Field label `label.new_password` (TN-106).
    #[serde(rename = "label.new_password")]
    NewPasswordLabel,
    /// Field label `label.display_name` (TN-106).
    #[serde(rename = "label.display_name")]
    DisplayNameLabel,
    /// Button caption `action.create_account` (TN-106).
    #[serde(rename = "action.create_account")]
    CreateAccount,
    /// Text `registration.code_sent` (OP-153 m.3 (g)).
    #[serde(rename = "registration.code_sent")]
    RegistrationCodeSent,
    /// Text `registration.failed` (OP-153 m.3 (g)).
    #[serde(rename = "registration.failed")]
    RegistrationFailed,
    /// Button caption `action.have_account` (TN-106).
    #[serde(rename = "action.have_account")]
    HaveAccount,
    /// Text `registration.complete` (OP-153 m.3 (g)).
    #[serde(rename = "registration.complete")]
    RegistrationComplete,
    /// Text `recovery.title` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.title")]
    RecoveryTitle,
    /// Button caption `action.recovery_start` (TN-106).
    #[serde(rename = "action.recovery_start")]
    RecoveryStart,
    /// Text `recovery.requested` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.requested")]
    RecoveryRequested,
    /// Text `recovery.cooling` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.cooling")]
    RecoveryCooling,
    /// Text `recovery.denied` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.denied")]
    RecoveryDenied,
    /// Text `recovery.complete` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.complete")]
    RecoveryComplete,
    /// Text `recovery.locked` (OP-153 m.3 (d), (e)).
    #[serde(rename = "recovery.locked")]
    RecoveryLocked,
    /// Text `recovery_codes.title` (OP-153 m.3 (d)).
    #[serde(rename = "recovery_codes.title")]
    RecoveryCodesTitle,
    /// Text `recovery_codes.save` (OP-153 m.3 (d)).
    #[serde(rename = "recovery_codes.save")]
    RecoveryCodesSave,
    /// Button caption `action.codes_saved` (TN-106).
    #[serde(rename = "action.codes_saved")]
    CodesSaved,
    /// Field label `label.link_code` (TN-106).
    #[serde(rename = "label.link_code")]
    LinkCodeLabel,
    /// Text `settings.title` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.title")]
    SettingsTitle,
    /// Text `settings.sign_in_methods` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.sign_in_methods")]
    SignInMethods,
    /// Text `settings.sign_ins` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.sign_ins")]
    SignIns,
    /// Text `settings.tied_to_device` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.tied_to_device")]
    TiedToDevice,
    /// Button caption `action.end_sign_in` (TN-106).
    #[serde(rename = "action.end_sign_in")]
    EndSignIn,
    /// Button caption `action.sign_out` (TN-106).
    #[serde(rename = "action.sign_out")]
    SignOut,
    /// Text `settings.connected_apps` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.connected_apps")]
    ConnectedApps,
    /// Button caption `action.stop_sharing` (TN-106).
    #[serde(rename = "action.stop_sharing")]
    StopSharing,
    /// Text `settings.linked_sign_ins` (S11, OP-153 m.3 (y)).
    #[serde(rename = "settings.linked_sign_ins")]
    LinkedSignIns,
    /// Text `notice.email_changed` (§8.15.2, OP-153 m.3 (i)).
    #[serde(rename = "notice.email_changed")]
    EmailChangedNotice,
    /// Text `notice.new_method` (§8.15.2, OP-153 m.3 (i)).
    #[serde(rename = "notice.new_method")]
    NewMethodNotice,
    /// Button caption `action.secure_account` (TN-106).
    #[serde(rename = "action.secure_account")]
    SecureAccount,
    /// Text `signed_out.password_changed` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.password_changed")]
    SignedOutPasswordChanged,
    /// Text `signed_out.device_mismatch` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.device_mismatch")]
    SignedOutDeviceMismatch,
    /// Text `signed_out.admin_ended` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.admin_ended")]
    SignedOutAdminEnded,
    /// Text `signed_out.recovery` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.recovery")]
    SignedOutRecovery,
    /// Text `signed_out.expired` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.expired")]
    SignedOutExpired,
    /// Text `signed_out.delegations_remain` (OP-153 m.3 (y)).
    #[serde(rename = "signed_out.delegations_remain")]
    SignedOutDelegationsRemain,
    /// Text `account.sign_in_turned_off` (OP-153 m.3 (bb), (cc)).
    #[serde(rename = "account.sign_in_turned_off")]
    SignInTurnedOff,
    /// Text `account.deletion_scheduled` (OP-153 m.3 (bb), (cc)).
    #[serde(rename = "account.deletion_scheduled")]
    DeletionScheduled,
    /// Text `account.deleted` (OP-153 m.3 (bb), (cc)).
    #[serde(rename = "account.deleted")]
    AccountDeleted,
    /// Text `account.export_ready` (OP-153 m.3 (bb), (cc)).
    #[serde(rename = "account.export_ready")]
    ExportReady,
    /// Text `account.email_confirmed` (OP-153 m.3 (bb), (cc)).
    #[serde(rename = "account.email_confirmed")]
    ConfirmedEmail,
    /// Text `consent.title` (OP-153 m.3 (z)).
    #[serde(rename = "consent.title")]
    ConsentTitle,
    /// Text `consent.claims` (OP-153 m.3 (z)).
    #[serde(rename = "consent.claims")]
    ConsentClaims,
    /// Button caption `action.share` (TN-106).
    #[serde(rename = "action.share")]
    Share,
    /// Button caption `action.dont_share` (TN-106).
    #[serde(rename = "action.dont_share")]
    DontShare,
    /// Text `delegation.check_note` (X8, §8.8).
    #[serde(rename = "delegation.check_note")]
    DelegationCheckNote,
    /// Text `delegation.created` (X8, §8.8).
    #[serde(rename = "delegation.created")]
    DelegationCreated,
    /// Text `invitation.title` (OP-153 m.3 (o)).
    #[serde(rename = "invitation.title")]
    InvitationTitle,
    /// Button caption `action.accept_invitation` (TN-106).
    #[serde(rename = "action.accept_invitation")]
    AcceptInvitation,
    /// Text `invitation.expired` (OP-153 m.3 (o)).
    #[serde(rename = "invitation.expired")]
    InvitationExpired,
    /// Field label `label.invitation_code` (TN-106).
    #[serde(rename = "label.invitation_code")]
    InvitationCodeLabel,
    /// Text `link.title` (OP-153 m.3 (m)).
    #[serde(rename = "link.title")]
    LinkTitle,
    /// Text `link.combine_warning` (OP-153 m.3 (m)).
    #[serde(rename = "link.combine_warning")]
    CombineWarning,
    /// Text `error.reference` (X41, OP-153 m.3 (jj)).
    #[serde(rename = "error.reference")]
    ErrorReference,
    /// Text `error.app_owner` (X41, OP-153 m.3 (jj)).
    #[serde(rename = "error.app_owner")]
    ErrorAppOwner,
    /// Text `error.upstream_owner` (X41, OP-153 m.3 (jj)).
    #[serde(rename = "error.upstream_owner")]
    ErrorUpstreamOwner,
    /// Text `error.access_owner` (X41, OP-153 m.3 (jj)).
    #[serde(rename = "error.access_owner")]
    ErrorAccessOwner,
    /// Text `step_up.required` (X29, §8.15.2).
    #[serde(rename = "step_up.required")]
    StepUpRequired,
    /// Text `claim.issuer_says` (§13.8, INV-14).
    #[serde(rename = "claim.issuer_says")]
    IssuerSays,
    /// N5: the "Keep me signed in on this device" option (TN-36, X33).
    #[serde(rename = "label.keep_signed_in")]
    KeepSignedInLabel,
    /// N5: the 30-day second-step option (X33, X-L2).
    #[serde(rename = "label.remember_device")]
    RememberDeviceLabel,
    /// N5: a sign-in provider's button (OP-153 m.3 (l)); `{ $provider }` is its name.
    #[serde(rename = "action.continue_with")]
    ContinueWith,
    /// L1: the MCP/CIMD consent screen's title (OP-154 m.3 (k)); `{ $client }` is the client's claimed name.
    #[serde(rename = "consent.agent_title")]
    ConsentAgentTitle,
    /// L1: the client's name and logo are its own claim (OP-154 m.3 (k)).
    #[serde(rename = "consent.client_says")]
    ConsentClientSays,
    /// L1: the protected resource the Grant covers (OP-154 m.3 (k)).
    #[serde(rename = "consent.resource")]
    ConsentResource,
    /// L1: the redirect hostname, always shown (OP-154 m.3 (k)).
    #[serde(rename = "consent.redirect_host")]
    ConsentRedirectHost,
    /// L1: the extra warning for a client whose only redirects are loopback (AG-6, OP-154 m.3 (k)).
    #[serde(rename = "consent.loopback")]
    ConsentLoopback,
    /// L1: a client first seen less than 7 days ago (OP-154 m.3 (i)).
    #[serde(rename = "consent.new_app")]
    ConsentNewApp,
    /// L1: approving the consent on the Approval Surface (EI-18).
    #[serde(rename = "action.approve_access")]
    ApproveAccess,
    /// L1: declining the consent.
    #[serde(rename = "action.decline_access")]
    DeclineAccess,
    /// L2: the device-code page's title (RFC 8628, OP-154 m.3 (p)).
    #[serde(rename = "device_code.title")]
    DeviceTitle,
    /// L2: the user code field (OP-154 m.3 (p)).
    #[serde(rename = "label.device_code")]
    DeviceCodeLabel,
    /// L2: a user code that did not match; the same for every wrong code.
    #[serde(rename = "device_code.invalid")]
    DeviceCodeInvalid,
    /// L2: what the device asks for and where the request came from (OP-154 m.3 (p)).
    #[serde(rename = "device_code.request")]
    DeviceRequest,
    /// L2: the device was connected.
    #[serde(rename = "device_code.approved")]
    DeviceApproved,
    /// L2: the device was not connected.
    #[serde(rename = "device_code.denied")]
    DeviceDenied,
    /// L1b: the client's name or logo changed since it was first seen (AG-5, OP-154 m.3 (k)).
    #[serde(rename = "consent.visual_changed")]
    ConsentVisualChanged,
    /// P8: the CIBA approval page's title (OP-155 m.3 (l)); `{ $client }` is the requesting client.
    #[serde(rename = "ciba.title")]
    CibaTitle,
    /// P8: the binding message, at most 32 characters, to compare with the client's screen (OP-155 m.3 (l)).
    #[serde(rename = "ciba.binding_message")]
    CibaBindingMessage,
    /// P8: the CIBA request was approved.
    #[serde(rename = "ciba.approved")]
    CibaApproved,
    /// P8: the CIBA request was not approved; nothing was done.
    #[serde(rename = "ciba.denied")]
    CibaDenied,
    /// P8: the CIBA request expired before an answer.
    #[serde(rename = "ciba.expired")]
    CibaExpired,
    /// P8: the device request when no country is known; no placeholder stands in for it (OP-155 m.3 (l)).
    #[serde(rename = "device_code.request_prefix")]
    DeviceRequestNoCountry,
    /// P4: the upstream identity provider cannot be reached (OP-155 m.3 (h)); nothing falls back.
    #[serde(rename = "upstream.unreachable")]
    UpstreamUnreachable,
    /// P4: the upstream's subject changed; only an explicit link after a re-authentication resolves it (OP-155 m.3 (h)).
    #[serde(rename = "upstream.subject_conflict")]
    UpstreamSubjectConflict,
    /// P4: home realm discovery's interstitial title (OP-155 m.3 (h)).
    #[serde(rename = "hrd.title")]
    HrdTitle,
    /// P4: why the organization's own sign-in page follows.
    #[serde(rename = "hrd.confirm")]
    HrdConfirm,
    /// P4: going on to the organization's sign-in.
    #[serde(rename = "action.continue_to_organization")]
    HrdContinue,
    /// P4: staying on the realm's own sign-in.
    #[serde(rename = "action.use_another_way")]
    HrdOtherWay,
    /// P9: certificate, PIV and CAC sign-in (OP-155 m.3 (m)).
    #[serde(rename = "certificate.title")]
    CertificateTitle,
    /// P9: what the browser will ask.
    #[serde(rename = "certificate.prompt")]
    CertificatePrompt,
    /// P9: the certificate cannot sign in here; the same text for every reason.
    #[serde(rename = "certificate.refused")]
    CertificateRefused,
    /// P9: revocation status unknown, unreachable or stale; refused (MD-8).
    #[serde(rename = "certificate.status_unknown")]
    CertificateStatusUnknown,
    /// P9: choosing certificate sign-in.
    #[serde(rename = "action.use_certificate")]
    UseCertificate,
    /// P5: the self-service setup portal's title (OP-155 m.3 (i)).
    #[serde(rename = "sso_setup.title")]
    SsoSetupTitle,
    /// P5: wizard step 1, the identity provider.
    #[serde(rename = "sso_setup.choose_provider")]
    SsoSetupChoose,
    /// P5: wizard step 2, exchanging metadata.
    #[serde(rename = "sso_setup.configure")]
    SsoSetupConfigure,
    /// P5: wizard step 3, a test sign-in.
    #[serde(rename = "sso_setup.test")]
    SsoSetupTest,
    /// P5: the connection works; enacting it is the organization owner's.
    #[serde(rename = "sso_setup.done")]
    SsoSetupDone,
    /// P5: the one-use, 72-hour setup link is spent or expired.
    #[serde(rename = "sso_setup.link_expired")]
    SsoSetupExpired,
    /// P5: what enforcing SSO ends, service accounts included (OP-155 m.3 (i)).
    #[serde(rename = "sso_setup.enforce_preview")]
    SsoEnforcePreview,
    /// P5: the pending invitations' fate is chosen; there is no default.
    #[serde(rename = "sso_setup.enforce_invites")]
    SsoEnforceInvites,
    /// P12: a wallet presentation on the sign-in page (OP-155 m.3 (p)).
    #[serde(rename = "vc.present_title")]
    VcPresentTitle,
    /// P12: what the presentation asks for.
    #[serde(rename = "vc.present_request")]
    VcPresentRequest,
    /// P12: opening the wallet.
    #[serde(rename = "action.open_wallet")]
    OpenWallet,
    /// P12: the wallet's answer could not be used; the same text for every reason.
    #[serde(rename = "vc.present_failed")]
    VcPresentFailed,
    /// P6: a federation trust mark badge; extra information only, it approves nothing (OP-155 m.3 (j)).
    #[serde(rename = "consent.trust_mark")]
    ConsentTrustMark,
    /// P4: an enterprise upstream connection's button; never "Trusted provider" (TN-95, Ek B 4678).
    #[serde(rename = "action.sign_in_with")]
    SignInWith,
    /// P5: the setup portal's domain step: publish the TXT record (TN-134).
    #[serde(rename = "sso_setup.domains")]
    SsoSetupDomains,
    /// P5: the setup portal's provisioning step; the secret comes from an owner (TN-134, TN-95).
    #[serde(rename = "sso_setup.scim")]
    SsoSetupScim,
    /// P5: saves the connection draft; an owner still has to turn it on (TN-134).
    #[serde(rename = "sso_setup.save")]
    SsoSetupSave,
    /// P5: ends the setup and spends the link (TN-134).
    #[serde(rename = "sso_setup.finish")]
    SsoSetupFinish,
    /// P2: a push verification is on its way to the approver (OP-156 m.3 (d)).
    #[serde(rename = "push.title")]
    PushTitle,
    /// P2: the number to type into the approver; the push itself never carries it (OP-156 m.3 (d)).
    #[serde(rename = "push.number")]
    PushNumber,
    /// P2: waiting for the approver's answer, at most 120 seconds.
    #[serde(rename = "push.waiting")]
    PushWaiting,
    /// P2: the push was refused; nothing was done.
    #[serde(rename = "push.denied")]
    PushDenied,
    /// P2: the push expired unanswered.
    #[serde(rename = "push.expired")]
    PushExpired,
    /// P2: push is held after a refusal or unanswered requests; another way is offered (OP-156 m.3 (d)).
    #[serde(rename = "push.held")]
    PushHeld,
    /// P2: the person answered "This wasn't me"; a risk signal and a security notice follow (OP-156 m.3 (d)).
    #[serde(rename = "push.not_me")]
    PushNotMe,
    /// P2: sends a push to the approver.
    #[serde(rename = "action.send_push")]
    SendPush,
    /// P2: the SMS one-time code field (OP-156 m.3 (f)).
    #[serde(rename = "label.sms_code")]
    SmsLabel,
    /// P2: sends an SMS one-time code (OP-156 m.3 (f)).
    #[serde(rename = "action.send_sms")]
    SendSms,
    /// P2: an SMS code was sent to the number ending in the digits shown.
    #[serde(rename = "sms.sent")]
    SmsSent,
    /// P2: an SMS method cannot be used now, the same text for a recent SIM change, a missing signal or a template (OP-156 m.3 (f)).
    #[serde(rename = "sms.refused")]
    SmsRefused,
    /// P8: Secure Payment Confirmation (OP-156 m.3 (g)).
    #[serde(rename = "spc.title")]
    SpcTitle,
    /// P8: the payment shown did not match the request byte for byte; nothing was approved.
    #[serde(rename = "spc.mismatch")]
    SpcMismatch,
    /// P2: the app-controlled factor: the app's key together with its PIN (OP-156 m.3 (e)).
    #[serde(rename = "app_factor.title")]
    AppFactorTitle,
    /// P2: the PIN is checked on the device only and never sent.
    #[serde(rename = "app_factor.pin")]
    AppFactorPin,
    /// P1: the forward-auth interstitial before an application (OP-156 m.3 (l)).
    #[serde(rename = "proxy.title")]
    ProxyTitle,
    /// P1: the application refused the request; the same text for every reason.
    #[serde(rename = "proxy.refused")]
    ProxyRefused,
    /// P1: Access could not be reached; the request is refused (OP-156 m.3 (l)).
    #[serde(rename = "proxy.unavailable")]
    ProxyUnavailable,
    /// P8: approving an SSH certificate for the terminal (OP-156 m.3 (o)).
    #[serde(rename = "ssh.title")]
    SshTitle,
    /// P8: approve only if the person started it from the terminal; the code matches the terminal's.
    #[serde(rename = "ssh.request")]
    SshRequest,
    /// P8: done; back to the terminal.
    #[serde(rename = "ssh.approved")]
    SshApproved,
    /// P1: the Linux console sign-in waits on a device code or an approver (OP-156 m.3 (p)).
    #[serde(rename = "linux.signin_pending")]
    LinuxPending,
    /// P8: a sudo step-up asks for a phishing-resistant authenticator (OP-156 m.3 (p)).
    #[serde(rename = "linux.step_up")]
    LinuxStepUp,
    /// P1: Access cannot be reached and the host's saved sign-in has run out; refused (MD-8).
    #[serde(rename = "linux.unavailable")]
    LinuxUnavailable,
}

impl TextId {
    /// All ids, in declaration order.
    pub const ALL: [Self; 161] = [
        Self::LoginFailed,
        Self::TooManyAttempts,
        Self::Unavailable,
        Self::FlowExpired,
        Self::SecondFactorFailed,
        Self::PasskeyNotRegistered,
        Self::IdentifierLabel,
        Self::PasswordLabel,
        Self::TotpLabel,
        Self::RecoveryCodeLabel,
        Self::Continue,
        Self::SignIn,
        Self::PasskeySignIn,
        Self::PasskeyCreate,
        Self::Verify,
        Self::UseRecoveryCode,
        Self::Skip,
        Self::Restart,
        Self::EmailCodeLabel,
        Self::SendEmailCode,
        Self::SendMagicLink,
        Self::EmailSent,
        Self::RegistrationTitle,
        Self::EmailLabel,
        Self::NewPasswordLabel,
        Self::DisplayNameLabel,
        Self::CreateAccount,
        Self::RegistrationCodeSent,
        Self::RegistrationFailed,
        Self::HaveAccount,
        Self::RegistrationComplete,
        Self::RecoveryTitle,
        Self::RecoveryStart,
        Self::RecoveryRequested,
        Self::RecoveryCooling,
        Self::RecoveryDenied,
        Self::RecoveryComplete,
        Self::RecoveryLocked,
        Self::RecoveryCodesTitle,
        Self::RecoveryCodesSave,
        Self::CodesSaved,
        Self::LinkCodeLabel,
        Self::SettingsTitle,
        Self::SignInMethods,
        Self::SignIns,
        Self::TiedToDevice,
        Self::EndSignIn,
        Self::SignOut,
        Self::ConnectedApps,
        Self::StopSharing,
        Self::LinkedSignIns,
        Self::EmailChangedNotice,
        Self::NewMethodNotice,
        Self::SecureAccount,
        Self::SignedOutPasswordChanged,
        Self::SignedOutDeviceMismatch,
        Self::SignedOutAdminEnded,
        Self::SignedOutRecovery,
        Self::SignedOutExpired,
        Self::SignedOutDelegationsRemain,
        Self::SignInTurnedOff,
        Self::DeletionScheduled,
        Self::AccountDeleted,
        Self::ExportReady,
        Self::ConfirmedEmail,
        Self::ConsentTitle,
        Self::ConsentClaims,
        Self::Share,
        Self::DontShare,
        Self::DelegationCheckNote,
        Self::DelegationCreated,
        Self::InvitationTitle,
        Self::AcceptInvitation,
        Self::InvitationExpired,
        Self::InvitationCodeLabel,
        Self::LinkTitle,
        Self::CombineWarning,
        Self::ErrorReference,
        Self::ErrorAppOwner,
        Self::ErrorUpstreamOwner,
        Self::ErrorAccessOwner,
        Self::StepUpRequired,
        Self::IssuerSays,
        Self::KeepSignedInLabel,
        Self::RememberDeviceLabel,
        Self::ContinueWith,
        Self::ConsentAgentTitle,
        Self::ConsentClientSays,
        Self::ConsentResource,
        Self::ConsentRedirectHost,
        Self::ConsentLoopback,
        Self::ConsentNewApp,
        Self::ApproveAccess,
        Self::DeclineAccess,
        Self::DeviceTitle,
        Self::DeviceCodeLabel,
        Self::DeviceCodeInvalid,
        Self::DeviceRequest,
        Self::DeviceApproved,
        Self::DeviceDenied,
        Self::ConsentVisualChanged,
        Self::CibaTitle,
        Self::CibaBindingMessage,
        Self::CibaApproved,
        Self::CibaDenied,
        Self::CibaExpired,
        Self::DeviceRequestNoCountry,
        Self::UpstreamUnreachable,
        Self::UpstreamSubjectConflict,
        Self::HrdTitle,
        Self::HrdConfirm,
        Self::HrdContinue,
        Self::HrdOtherWay,
        Self::CertificateTitle,
        Self::CertificatePrompt,
        Self::CertificateRefused,
        Self::CertificateStatusUnknown,
        Self::UseCertificate,
        Self::SsoSetupTitle,
        Self::SsoSetupChoose,
        Self::SsoSetupConfigure,
        Self::SsoSetupTest,
        Self::SsoSetupDone,
        Self::SsoSetupExpired,
        Self::SsoEnforcePreview,
        Self::SsoEnforceInvites,
        Self::VcPresentTitle,
        Self::VcPresentRequest,
        Self::OpenWallet,
        Self::VcPresentFailed,
        Self::ConsentTrustMark,
        Self::SignInWith,
        Self::SsoSetupDomains,
        Self::SsoSetupScim,
        Self::SsoSetupSave,
        Self::SsoSetupFinish,
        Self::PushTitle,
        Self::PushNumber,
        Self::PushWaiting,
        Self::PushDenied,
        Self::PushExpired,
        Self::PushHeld,
        Self::PushNotMe,
        Self::SendPush,
        Self::SmsLabel,
        Self::SendSms,
        Self::SmsSent,
        Self::SmsRefused,
        Self::SpcTitle,
        Self::SpcMismatch,
        Self::AppFactorTitle,
        Self::AppFactorPin,
        Self::ProxyTitle,
        Self::ProxyRefused,
        Self::ProxyUnavailable,
        Self::SshTitle,
        Self::SshRequest,
        Self::SshApproved,
        Self::LinuxPending,
        Self::LinuxStepUp,
        Self::LinuxUnavailable,
    ];

    /// The stable id on the wire.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one id per text, read top to bottom")]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginFailed => "login.failed",
            Self::TooManyAttempts => "login.throttled",
            Self::Unavailable => "login.unavailable",
            Self::FlowExpired => "flow.expired",
            Self::SecondFactorFailed => "second_factor.failed",
            Self::PasskeyNotRegistered => "passkey.not_registered",
            Self::IdentifierLabel => "label.identifier",
            Self::PasswordLabel => "label.password",
            Self::TotpLabel => "label.totp_code",
            Self::RecoveryCodeLabel => "label.recovery_code",
            Self::Continue => "action.continue",
            Self::SignIn => "action.sign_in",
            Self::PasskeySignIn => "action.passkey",
            Self::PasskeyCreate => "action.passkey_create",
            Self::Verify => "action.verify",
            Self::UseRecoveryCode => "action.recovery_code",
            Self::Skip => "action.skip",
            Self::Restart => "action.restart",
            Self::EmailCodeLabel => "label.email_code",
            Self::SendEmailCode => "action.email_code",
            Self::SendMagicLink => "action.magic_link",
            Self::EmailSent => "email.sent",
            Self::RegistrationTitle => "registration.title",
            Self::EmailLabel => "label.email",
            Self::NewPasswordLabel => "label.new_password",
            Self::DisplayNameLabel => "label.display_name",
            Self::CreateAccount => "action.create_account",
            Self::RegistrationCodeSent => "registration.code_sent",
            Self::RegistrationFailed => "registration.failed",
            Self::HaveAccount => "action.have_account",
            Self::RegistrationComplete => "registration.complete",
            Self::RecoveryTitle => "recovery.title",
            Self::RecoveryStart => "action.recovery_start",
            Self::RecoveryRequested => "recovery.requested",
            Self::RecoveryCooling => "recovery.cooling",
            Self::RecoveryDenied => "recovery.denied",
            Self::RecoveryComplete => "recovery.complete",
            Self::RecoveryLocked => "recovery.locked",
            Self::RecoveryCodesTitle => "recovery_codes.title",
            Self::RecoveryCodesSave => "recovery_codes.save",
            Self::CodesSaved => "action.codes_saved",
            Self::LinkCodeLabel => "label.link_code",
            Self::SettingsTitle => "settings.title",
            Self::SignInMethods => "settings.sign_in_methods",
            Self::SignIns => "settings.sign_ins",
            Self::TiedToDevice => "settings.tied_to_device",
            Self::EndSignIn => "action.end_sign_in",
            Self::SignOut => "action.sign_out",
            Self::ConnectedApps => "settings.connected_apps",
            Self::StopSharing => "action.stop_sharing",
            Self::LinkedSignIns => "settings.linked_sign_ins",
            Self::EmailChangedNotice => "notice.email_changed",
            Self::NewMethodNotice => "notice.new_method",
            Self::SecureAccount => "action.secure_account",
            Self::SignedOutPasswordChanged => "signed_out.password_changed",
            Self::SignedOutDeviceMismatch => "signed_out.device_mismatch",
            Self::SignedOutAdminEnded => "signed_out.admin_ended",
            Self::SignedOutRecovery => "signed_out.recovery",
            Self::SignedOutExpired => "signed_out.expired",
            Self::SignedOutDelegationsRemain => "signed_out.delegations_remain",
            Self::SignInTurnedOff => "account.sign_in_turned_off",
            Self::DeletionScheduled => "account.deletion_scheduled",
            Self::AccountDeleted => "account.deleted",
            Self::ExportReady => "account.export_ready",
            Self::ConfirmedEmail => "account.email_confirmed",
            Self::ConsentTitle => "consent.title",
            Self::ConsentClaims => "consent.claims",
            Self::Share => "action.share",
            Self::DontShare => "action.dont_share",
            Self::DelegationCheckNote => "delegation.check_note",
            Self::DelegationCreated => "delegation.created",
            Self::InvitationTitle => "invitation.title",
            Self::AcceptInvitation => "action.accept_invitation",
            Self::InvitationExpired => "invitation.expired",
            Self::InvitationCodeLabel => "label.invitation_code",
            Self::LinkTitle => "link.title",
            Self::CombineWarning => "link.combine_warning",
            Self::ErrorReference => "error.reference",
            Self::ErrorAppOwner => "error.app_owner",
            Self::ErrorUpstreamOwner => "error.upstream_owner",
            Self::ErrorAccessOwner => "error.access_owner",
            Self::StepUpRequired => "step_up.required",
            Self::IssuerSays => "claim.issuer_says",
            Self::KeepSignedInLabel => "label.keep_signed_in",
            Self::RememberDeviceLabel => "label.remember_device",
            Self::ContinueWith => "action.continue_with",
            Self::ConsentAgentTitle => "consent.agent_title",
            Self::ConsentClientSays => "consent.client_says",
            Self::ConsentResource => "consent.resource",
            Self::ConsentRedirectHost => "consent.redirect_host",
            Self::ConsentLoopback => "consent.loopback",
            Self::ConsentNewApp => "consent.new_app",
            Self::ApproveAccess => "action.approve_access",
            Self::DeclineAccess => "action.decline_access",
            Self::DeviceTitle => "device_code.title",
            Self::DeviceCodeLabel => "label.device_code",
            Self::DeviceCodeInvalid => "device_code.invalid",
            Self::DeviceRequest => "device_code.request",
            Self::DeviceApproved => "device_code.approved",
            Self::DeviceDenied => "device_code.denied",
            Self::ConsentVisualChanged => "consent.visual_changed",
            Self::CibaTitle => "ciba.title",
            Self::CibaBindingMessage => "ciba.binding_message",
            Self::CibaApproved => "ciba.approved",
            Self::CibaDenied => "ciba.denied",
            Self::CibaExpired => "ciba.expired",
            Self::DeviceRequestNoCountry => "device_code.request_prefix",
            Self::UpstreamUnreachable => "upstream.unreachable",
            Self::UpstreamSubjectConflict => "upstream.subject_conflict",
            Self::HrdTitle => "hrd.title",
            Self::HrdConfirm => "hrd.confirm",
            Self::HrdContinue => "action.continue_to_organization",
            Self::HrdOtherWay => "action.use_another_way",
            Self::CertificateTitle => "certificate.title",
            Self::CertificatePrompt => "certificate.prompt",
            Self::CertificateRefused => "certificate.refused",
            Self::CertificateStatusUnknown => "certificate.status_unknown",
            Self::UseCertificate => "action.use_certificate",
            Self::SsoSetupTitle => "sso_setup.title",
            Self::SsoSetupChoose => "sso_setup.choose_provider",
            Self::SsoSetupConfigure => "sso_setup.configure",
            Self::SsoSetupTest => "sso_setup.test",
            Self::SsoSetupDone => "sso_setup.done",
            Self::SsoSetupExpired => "sso_setup.link_expired",
            Self::SsoEnforcePreview => "sso_setup.enforce_preview",
            Self::SsoEnforceInvites => "sso_setup.enforce_invites",
            Self::VcPresentTitle => "vc.present_title",
            Self::VcPresentRequest => "vc.present_request",
            Self::OpenWallet => "action.open_wallet",
            Self::VcPresentFailed => "vc.present_failed",
            Self::ConsentTrustMark => "consent.trust_mark",
            Self::SignInWith => "action.sign_in_with",
            Self::SsoSetupDomains => "sso_setup.domains",
            Self::SsoSetupScim => "sso_setup.scim",
            Self::SsoSetupSave => "sso_setup.save",
            Self::SsoSetupFinish => "sso_setup.finish",
            Self::PushTitle => "push.title",
            Self::PushNumber => "push.number",
            Self::PushWaiting => "push.waiting",
            Self::PushDenied => "push.denied",
            Self::PushExpired => "push.expired",
            Self::PushHeld => "push.held",
            Self::PushNotMe => "push.not_me",
            Self::SendPush => "action.send_push",
            Self::SmsLabel => "label.sms_code",
            Self::SendSms => "action.send_sms",
            Self::SmsSent => "sms.sent",
            Self::SmsRefused => "sms.refused",
            Self::SpcTitle => "spc.title",
            Self::SpcMismatch => "spc.mismatch",
            Self::AppFactorTitle => "app_factor.title",
            Self::AppFactorPin => "app_factor.pin",
            Self::ProxyTitle => "proxy.title",
            Self::ProxyRefused => "proxy.refused",
            Self::ProxyUnavailable => "proxy.unavailable",
            Self::SshTitle => "ssh.title",
            Self::SshRequest => "ssh.request",
            Self::SshApproved => "ssh.approved",
            Self::LinuxPending => "linux.signin_pending",
            Self::LinuxStepUp => "linux.step_up",
            Self::LinuxUnavailable => "linux.unavailable",
        }
    }

    /// The default English text.
    #[must_use]
    #[expect(clippy::too_many_lines, reason = "one text per id, read top to bottom")]
    pub const fn default_text(self) -> &'static str {
        match self {
            // X-L1
            Self::LoginFailed => "We couldn't sign you in with these details.",
            Self::TooManyAttempts => "Too many attempts. Try again in a moment.",
            Self::Unavailable => "Sign-in is briefly unavailable. Try again shortly.",
            Self::FlowExpired => "This sign-in page has expired. Start again.",
            Self::SecondFactorFailed => "That code didn't work. Check it and try again.",
            Self::PasskeyNotRegistered => "That passkey isn't registered for this account.",
            Self::IdentifierLabel => "Email or username",
            Self::PasswordLabel => "Password",
            Self::TotpLabel => "Code from your authenticator app",
            Self::RecoveryCodeLabel => "Recovery code",
            Self::Continue => "Continue",
            Self::SignIn => "Sign in",
            Self::PasskeySignIn => "Sign in with a passkey",
            Self::PasskeyCreate => "Create a passkey",
            Self::Verify => "Verify",
            Self::UseRecoveryCode => "Use a recovery code",
            Self::Skip => "Not now",
            Self::Restart => "Use a different account",
            Self::EmailCodeLabel => "Code from your email",
            Self::SendEmailCode => "Email me a code",
            Self::SendMagicLink => "Email me a sign-in link",
            Self::EmailSent => "If these details match an account, we've sent an email.",
            Self::RegistrationTitle => "Create your account",
            Self::EmailLabel => "Email",
            Self::NewPasswordLabel => "New password",
            Self::DisplayNameLabel => "Your name",
            Self::CreateAccount => "Create account",
            Self::RegistrationCodeSent => "If this address can be used, we've sent a code to it.",
            Self::RegistrationFailed => "We couldn't create an account with these details.",
            Self::HaveAccount => "Sign in instead",
            Self::RegistrationComplete => "Your account is ready.",
            Self::RecoveryTitle => "Get back into your account",
            Self::RecoveryStart => "Start recovery",
            Self::RecoveryRequested => {
                "If an account exists for these details, we've sent instructions."
            }
            Self::RecoveryCooling => {
                "For your safety, recovery finishes after a waiting period. We'll email you when it can finish."
            }
            Self::RecoveryDenied => {
                "Recovery stopped because someone signed in to this account normally."
            }
            Self::RecoveryComplete => {
                "You're signed in. Your delegations remain. Some sensitive actions are available again after a waiting period. Your devices need to sign in again."
            }
            Self::RecoveryLocked => "Too many tries for this recovery. Start a new one later.",
            Self::RecoveryCodesTitle => "Recovery codes",
            Self::RecoveryCodesSave => "Save these codes somewhere safe. Each code works once.",
            Self::CodesSaved => "I saved them",
            Self::LinkCodeLabel => "Code shown on your other device",
            Self::SettingsTitle => "Account",
            Self::SignInMethods => "Sign-in methods",
            Self::SignIns => "Where you're signed in",
            Self::TiedToDevice => "This sign-in is tied to this device",
            Self::EndSignIn => "End this sign-in",
            Self::SignOut => "Sign out",
            Self::ConnectedApps => "Connected apps",
            Self::StopSharing => "Stop sharing",
            Self::LinkedSignIns => "Linked sign-ins",
            Self::EmailChangedNotice => {
                "Your email address was changed. If this wasn't you: Secure your account."
            }
            Self::NewMethodNotice => {
                "A new sign-in method was added. If this wasn't you: Secure your account."
            }
            Self::SecureAccount => "Secure your account",
            Self::SignedOutPasswordChanged => "Signed out because your password changed.",
            Self::SignedOutDeviceMismatch => {
                "Signed out because this device didn't match the sign-in."
            }
            Self::SignedOutAdminEnded => "Signed out because an administrator ended this sign-in.",
            Self::SignedOutRecovery => "Signed out because the account was recovered.",
            Self::SignedOutExpired => "Signed out because the sign-in expired.",
            Self::SignedOutDelegationsRemain => {
                "Apps and agents you connected keep their access until you revoke it."
            }
            Self::SignInTurnedOff => "Your account's sign-in is turned off by this organization.",
            Self::DeletionScheduled => {
                "Your account will be deleted on the date shown. You can cancel until then."
            }
            Self::AccountDeleted => {
                "Your account is deleted. Some records are kept until the date shown for legal reasons; history entries are redacted, not removed."
            }
            Self::ExportReady => "Your data export is ready. The download link works for 24 hours.",
            Self::ConfirmedEmail => "Confirmed you can receive email at this address.",
            Self::ConsentTitle => "Share with this app",
            Self::ConsentClaims => "This app will receive:",
            Self::Share => "Share",
            Self::DontShare => "Don't share",
            Self::DelegationCheckNote => "Access will still check the request.",
            Self::DelegationCreated => "Delegation created",
            Self::InvitationTitle => "You're invited to join an organization",
            Self::AcceptInvitation => "Join",
            Self::InvitationExpired => "This invitation has expired or was already used.",
            Self::InvitationCodeLabel => "Invitation code",
            Self::LinkTitle => "Link another sign-in",
            Self::CombineWarning => {
                "Combining accounts can't be reversed. Delegations must be given again afterwards."
            }
            Self::ErrorReference => "Reference",
            Self::ErrorAppOwner => {
                "This app isn't set up correctly for sign-in. The app's developer can fix this."
            }
            Self::ErrorUpstreamOwner => {
                "The sign-in provider couldn't complete this request. Try again later."
            }
            Self::ErrorAccessOwner => "Access couldn't complete this request. Try again shortly.",
            Self::StepUpRequired => "Confirm it's you to continue with this action.",
            Self::IssuerSays => "Issuer says (signed)",
            Self::KeepSignedInLabel => "Keep me signed in on this device",
            Self::RememberDeviceLabel => "Don't ask for a second step on this device for 30 days",
            Self::ContinueWith => "Continue with { $provider }",
            Self::ConsentAgentTitle => "{ $client } asks for access",
            Self::ConsentClientSays => {
                "The app calls itself { $name }. Access hasn't checked this name."
            }
            Self::ConsentResource => "It will use { $resource } for you.",
            Self::ConsentRedirectHost => "After you answer, you go to { $host }.",
            Self::ConsentLoopback => {
                "This app sends you back to a program on this device. Approve only if you started it."
            }
            Self::ConsentNewApp => "This app is new: Access first saw it less than 7 days ago.",
            Self::ApproveAccess => "Approve",
            Self::DeclineAccess => "Don't approve",
            Self::DeviceTitle => "Connect a device",
            Self::DeviceCodeLabel => "Code shown on the device",
            Self::DeviceCodeInvalid => "This code didn't work. Check it and try again.",
            Self::DeviceRequest => {
                "{ $client } asks for { $scope }. The request came from { $prefix } in { $country }."
            }
            Self::DeviceApproved => "The device is connected. You can close this page.",
            Self::DeviceDenied => "The device wasn't connected.",
            Self::ConsentVisualChanged => {
                "This app changed its name or logo since Access first saw it. Check that it is the app you expect."
            }
            Self::CibaTitle => "{ $client } asks you to approve a request",
            Self::CibaBindingMessage => "Approve only if { $client } shows this code: { $code }",
            Self::CibaApproved => "Approved. You can go back to { $client }.",
            Self::CibaDenied => "Not approved. Nothing was done.",
            Self::CibaExpired => "This request has expired.",
            Self::DeviceRequestNoCountry => {
                "{ $client } asks for { $scope }. The request came from { $prefix }."
            }
            Self::UpstreamUnreachable => {
                "{ $provider } isn't responding. Try another sign-in method if you've set one up."
            }
            Self::UpstreamSubjectConflict => {
                "Your account at { $provider } has changed. Sign in another way, then link it again from your account."
            }
            Self::HrdTitle => "Continue to { $organization }?",
            Self::HrdConfirm => {
                "Your email address belongs to { $organization }. You'll sign in on its own page."
            }
            Self::HrdContinue => "Continue to { $organization }",
            Self::HrdOtherWay => "Use another way",
            Self::CertificateTitle => "Sign in with a certificate",
            Self::CertificatePrompt => {
                "Pick your certificate or smart card when your browser asks."
            }
            Self::CertificateRefused => "This certificate can't be used to sign in here.",
            Self::CertificateStatusUnknown => {
                "We couldn't check this certificate right now. Try again later."
            }
            Self::UseCertificate => "Use a certificate",
            Self::SsoSetupTitle => "Set up sign-in for { $organization }",
            Self::SsoSetupChoose => "Choose your identity provider",
            Self::SsoSetupConfigure => {
                "Copy these values into { $provider }, then paste its details here."
            }
            Self::SsoSetupTest => "Sign in once to test the connection.",
            Self::SsoSetupDone => {
                "The connection works. An owner of { $organization } can now turn it on."
            }
            Self::SsoSetupExpired => {
                "This setup link has expired or was already used. Ask for a new one."
            }
            Self::SsoEnforcePreview => {
                "Turning this on signs out { $members } members and ends their passwords and API keys. { $service_accounts } service accounts are affected too."
            }
            Self::SsoEnforceInvites => {
                "{ $invites } invitations are pending. Choose whether to cancel them or send them to the new sign-in."
            }
            Self::VcPresentTitle => "Share from your wallet",
            Self::VcPresentRequest => "This asks for: { $claims }",
            Self::OpenWallet => "Open wallet",
            Self::VcPresentFailed => "Your wallet's answer couldn't be used. Try again.",
            Self::ConsentTrustMark => {
                "{ $mark } says this about the app. Access shows it as extra information; it doesn't replace your answer."
            }
            Self::SignInWith => "Sign in with { $provider }",
            Self::SsoSetupDomains => {
                "Prove you own these domains: publish each TXT record shown here."
            }
            Self::SsoSetupScim => {
                "To keep members in step, point your provider's provisioning at this address. An owner of the organization gives you its secret."
            }
            Self::SsoSetupSave => "Save the connection",
            Self::SsoSetupFinish => "Finish setup",
            Self::PushTitle => "Approve on { $approver }",
            Self::PushNumber => "Open { $approver } and enter this number: { $number }",
            Self::PushWaiting => "Waiting for your answer…",
            Self::PushDenied => "Not approved. Nothing was done.",
            Self::PushExpired => "This request expired. Send a new one or use another way.",
            Self::PushHeld => "Requests to your approver are on hold for a while. Use another way to sign in.",
            Self::PushNotMe => "We stopped this sign-in. If it wasn't you, secure your account.",
            Self::SendPush => "Send a request to my approver",
            Self::SmsLabel => "Code from the text message",
            Self::SendSms => "Text me a code",
            Self::SmsSent => "We sent a code to the number ending in { $last_digits }.",
            Self::SmsRefused => "Text message codes can't be used for this number right now. Use another way.",
            Self::SpcTitle => "Confirm this payment",
            Self::SpcMismatch => "The payment details didn't match. Nothing was approved.",
            Self::AppFactorTitle => "Confirm in { $app }",
            Self::AppFactorPin => "Enter your app PIN on your phone to approve.",
            Self::ProxyTitle => "Sign in to continue to { $application }",
            Self::ProxyRefused => "You can't open { $application } with this account.",
            Self::ProxyUnavailable => "{ $application } can't be opened right now. Try again shortly.",
            Self::SshTitle => "Approve SSH access",
            Self::SshRequest => "Your terminal asks for SSH access to { $host_group }. Approve only if you started this and the terminal shows { $code }.",
            Self::SshApproved => "Done. Go back to your terminal.",
            Self::LinuxPending => "To sign in, open { $uri } and enter { $code }.",
            Self::LinuxStepUp => "Confirm it's you with your security key to run this command.",
            Self::LinuxUnavailable => "Access can't be reached and this computer's saved sign-in has run out. Try again when it's online.",
        }
    }

    /// Whether the text may be shown before the first factor succeeds: it must say nothing
    /// about whether an account exists or what state it is in (X34, XI-24).
    #[must_use]
    pub const fn pre_auth(self) -> bool {
        !matches!(
            self,
            Self::SecondFactorFailed
                | Self::PasskeyNotRegistered
                | Self::RegistrationComplete
                | Self::RecoveryCooling
                | Self::RecoveryDenied
                | Self::RecoveryComplete
                | Self::RecoveryLocked
                | Self::RecoveryCodesTitle
                | Self::RecoveryCodesSave
                | Self::CodesSaved
                | Self::SettingsTitle
                | Self::SignInMethods
                | Self::SignIns
                | Self::TiedToDevice
                | Self::EndSignIn
                | Self::SignOut
                | Self::ConnectedApps
                | Self::StopSharing
                | Self::LinkedSignIns
                | Self::EmailChangedNotice
                | Self::NewMethodNotice
                | Self::SecureAccount
                | Self::SignedOutPasswordChanged
                | Self::SignedOutDeviceMismatch
                | Self::SignedOutAdminEnded
                | Self::SignedOutRecovery
                | Self::SignedOutExpired
                | Self::SignedOutDelegationsRemain
                | Self::SignInTurnedOff
                | Self::DeletionScheduled
                | Self::AccountDeleted
                | Self::ExportReady
                | Self::ConfirmedEmail
                | Self::ConsentTitle
                | Self::ConsentClaims
                | Self::Share
                | Self::DontShare
                | Self::DelegationCheckNote
                | Self::DelegationCreated
                | Self::InvitationTitle
                | Self::AcceptInvitation
                | Self::LinkTitle
                | Self::CombineWarning
                | Self::StepUpRequired
                | Self::IssuerSays
                | Self::ConsentAgentTitle
                | Self::ConsentClientSays
                | Self::ConsentResource
                | Self::ConsentRedirectHost
                | Self::ConsentLoopback
                | Self::ConsentNewApp
                | Self::ApproveAccess
                | Self::DeclineAccess
                | Self::DeviceRequest
                | Self::DeviceApproved
                | Self::DeviceDenied
                | Self::ConsentVisualChanged
                | Self::CibaTitle
                | Self::CibaBindingMessage
                | Self::CibaApproved
                | Self::CibaDenied
                | Self::CibaExpired
                | Self::DeviceRequestNoCountry
                | Self::SsoSetupTitle
                | Self::SsoSetupChoose
                | Self::SsoSetupConfigure
                | Self::SsoSetupTest
                | Self::SsoSetupDone
                | Self::SsoEnforcePreview
                | Self::SsoEnforceInvites
                | Self::ConsentTrustMark
                | Self::PushTitle
                | Self::PushNumber
                | Self::PushWaiting
                | Self::PushDenied
                | Self::PushExpired
                | Self::PushHeld
                | Self::PushNotMe
                | Self::SendPush
                | Self::SmsLabel
                | Self::SendSms
                | Self::SmsSent
                | Self::SmsRefused
                | Self::SpcTitle
                | Self::SpcMismatch
                | Self::AppFactorTitle
                | Self::AppFactorPin
                | Self::ProxyRefused
                | Self::SshTitle
                | Self::SshRequest
                | Self::SshApproved
                | Self::LinuxStepUp
        )
    }
}

/// A label or button caption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    /// Stable id.
    pub id: TextId,
    /// Default English text.
    pub text: String,
}

impl From<TextId> for Text {
    fn from(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
        }
    }
}

/// How a message is presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Neutral information.
    Info,
    /// The last submission did not succeed.
    Error,
}

/// A message about the step as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Stable id.
    pub id: TextId,
    /// Default English text.
    pub text: String,
    /// Presentation.
    pub severity: Severity,
    /// Seconds to wait before retrying, for [`TextId::TooManyAttempts`] and
    /// [`TextId::Unavailable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
}

impl Message {
    /// An error message with its default text.
    #[must_use]
    pub fn error(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
            severity: Severity::Error,
            retry_after_s: None,
        }
    }

    /// An information message with its default text.
    #[must_use]
    pub fn info(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
            severity: Severity::Info,
            retry_after_s: None,
        }
    }

    /// With a retry hint.
    #[must_use]
    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_s = Some(seconds);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-40, X34, X-L1, XI-24
    #[test]
    fn the_neutral_refusal_claims_nothing_about_the_account() {
        let text = TextId::LoginFailed.default_text();
        assert_eq!(text, "We couldn't sign you in with these details.");
        for id in TextId::ALL.into_iter().filter(|t| t.pre_auth()) {
            let t = id.default_text().to_lowercase();
            for banned in [
                "wrong password",
                "no account",
                "locked",
                "disabled",
                "doesn't exist",
                "not found",
                "isn't registered",
            ] {
                assert!(!t.contains(banned), "{id:?}: {t}");
            }
        }
    }

    // TN-106
    #[test]
    fn wire_ids_match_serde() {
        for id in TextId::ALL {
            let wire = serde_json::to_value(id).unwrap();
            assert_eq!(wire, id.as_str());
            let back: TextId = serde_json::from_value(wire).unwrap();
            assert_eq!(back, id);
        }
    }
}
