//! `access-cli realm check` on the real path (OP-159 m.3 (ii), §10.3.4, Ek B 6262): the realm's
//! settings are written through the admin REST surface and read back from the settings view the
//! command reads; the profile check reports PCI DSS 4.0 Req 8 and OMB M-22-09 against them and
//! leaves every setting as it was.

use access_identity_admin::domain::profile_check::{Outcome, Profile, check};

use super::*;

fn failed(settings: &serde_json::Value, profile: Profile) -> Vec<&'static str> {
    check(profile, settings)
        .checks
        .into_iter()
        .filter(|c| c.result == Outcome::Fail)
        .map(|c| c.check)
        .collect()
}

impl Console {
    async fn sign_in_policy(&self, methods: &[&str], mfa: bool) {
        let (_, settings, _) = self.rest_read("/admin/v1/realms/acme/settings").await;
        let mut policy = settings["signin_policy"].clone();
        policy["methods"] = serde_json::json!(methods);
        policy["mfa_required"] = serde_json::Value::Bool(mfa);
        let w = self
            .put_setting("signin-policy", "putSigninPolicy", policy)
            .await;
        assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    }

    async fn factor(&self, section: &str, operation: &str, enabled: bool) {
        let w = self
            .put_setting(
                section,
                operation,
                serde_json::json!({ "enabled": enabled }),
            )
            .await;
        assert_eq!(w.status, StatusCode::OK, "{section}: {}", w.body);
    }
}

// OP-159 m.3 (ii), §10.3.4, Ek B 6262
#[tokio::test]
async fn a_realm_check_fails_a_weak_realm_passes_a_hardened_one_and_changes_nothing() {
    let c = console("j9-profile", false).await;
    c.sign_in_policy(&["email", "passkey"], false).await;
    c.factor("push", "putPush", true).await;
    c.factor("sms-otp", "putSmsOtp", true).await;

    let (status, weak, etag) = c.rest_read("/admin/v1/realms/acme/settings").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(weak["push"]["enabled"], true);
    assert_eq!(weak["sms_otp"]["enabled"], true);
    assert_eq!(
        failed(&weak, Profile::PciDss4),
        [
            "mfa-every-access",
            "password-length-12",
            "lockout-10-attempts"
        ]
    );
    assert_eq!(
        failed(&weak, Profile::M2209),
        [
            "mfa-every-access",
            "phishing-resistant-only",
            "no-sms-or-voice"
        ]
    );
    let (_, again, etag_again) = c.rest_read("/admin/v1/realms/acme/settings").await;
    assert_eq!(again, weak, "a check reads only");
    assert_eq!(etag_again, etag);

    c.sign_in_policy(&["passkey"], true).await;
    c.factor("push", "putPush", false).await;
    c.factor("sms-otp", "putSmsOtp", false).await;
    let (_, hard, etag) = c.rest_read("/admin/v1/realms/acme/settings").await;
    for p in Profile::ALL {
        let r = check(p, &hard);
        assert!(r.passed, "{}: {r:?}", p.name());
    }
    let (_, again, etag_again) = c.rest_read("/admin/v1/realms/acme/settings").await;
    assert_eq!(again, hard, "a check reads only");
    assert_eq!(etag_again, etag);
}
