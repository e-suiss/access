//! The social sign-in rules that do not need a provider: shared development clients only in a
//! sandbox realm (IDP-31 (4)), client id reuse and the Apple transfer window (TN-87), the App
//! Store warning (IDP-31 (5)), and the freshness of linking and combining accounts (TN-65,
//! TN-67, OP-153 m.3 (m)).

/// How long Apple's transfer identifiers stay usable after a client id change (TN-87).
pub const APPLE_TRANSFER_MS: u64 = 60 * 24 * 3_600_000;

/// How fresh each account's last authentication must be to combine them (OP-153 m.3 (m)).
pub const COMBINE_FRESHNESS_MS: u64 = 5 * 60_000;

/// How fresh the session's last authentication must be to link another sign-in (TN-65 (3)).
pub const LINK_FRESHNESS_MS: u64 = 5 * 60_000;

/// How long a social attempt waits for the provider's redirect.
pub const ATTEMPT_TTL_MS: u64 = 10 * 60_000;

/// The preset of Sign in with Apple.
pub const APPLE: &str = "apple";

/// A refusal of a social client, as a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRefusal {
    /// A shared development client named in a realm that is not a sandbox (IDP-31 (4)).
    SharedKeyInProduction,
    /// A shared development client named for a preset the operator configured none for.
    NoSharedKey,
}

impl ClientRefusal {
    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SharedKeyInProduction => "shared-social-key-in-production",
            Self::NoSharedKey => "no-shared-social-key",
        }
    }
}

/// Whether a realm may use a social client: a shared development client only in a sandbox
/// realm, at `enable` and at every sign-in (OP-153 m.3 (l)).
///
/// # Errors
/// [`ClientRefusal`].
pub const fn client_allowed(
    shared: bool,
    sandbox: bool,
    configured: bool,
) -> Result<(), ClientRefusal> {
    match (shared, sandbox, configured) {
        (false, _, _) | (true, true, true) => Ok(()),
        (true, false, _) => Err(ClientRefusal::SharedKeyInProduction),
        (true, true, false) => Err(ClientRefusal::NoSharedKey),
    }
}

/// A warning an `idp.social.*` change answers with; never a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// The client id differs from the one before: the provider names every user by a new
    /// subject, so earlier sign-ins no longer match (TN-87).
    ClientIdChanged,
    /// Apple's transfer identifiers move users over until this time; after it they cannot
    /// (TN-87).
    AppleTransferUntil(u64),
    /// Another social provider is offered to a native app without Sign in with Apple
    /// (IDP-31 (5)).
    AppleRecommended,
}

impl Warning {
    /// The stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClientIdChanged => "social-client-id-changed",
            Self::AppleTransferUntil(_) => "apple-transfer-window",
            Self::AppleRecommended => "apple-sign-in-recommended",
        }
    }
}

/// The warnings of moving `preset` from client id `old` to `new` at `now_ms` (TN-87).
#[must_use]
pub fn client_change(preset: &str, old: Option<&str>, new: &str, now_ms: u64) -> Vec<Warning> {
    match old {
        Some(o) if o != new => {
            let mut w = vec![Warning::ClientIdChanged];
            if preset == APPLE {
                w.push(Warning::AppleTransferUntil(
                    now_ms.saturating_add(APPLE_TRANSFER_MS),
                ));
            }
            w
        }
        _ => Vec::new(),
    }
}

/// IDP-31 (5): a realm with a native app client that offers a social provider other than Apple
/// and not Apple is warned.
#[must_use]
pub fn apple_recommended<'a>(
    native_client: bool,
    enabled: impl IntoIterator<Item = &'a str>,
) -> bool {
    let (mut other, mut apple) = (false, false);
    for p in enabled {
        if p == APPLE {
            apple = true;
        } else {
            other = true;
        }
    }
    native_client && other && !apple
}

/// Whether two accounts may be combined at `now_ms` (OP-153 m.3 (m)): two different accounts
/// of one realm, each authenticated within [`COMBINE_FRESHNESS_MS`].
#[must_use]
pub fn combine_allowed(
    survivor: [u8; 16],
    survivor_auth_ms: u64,
    absorbed: [u8; 16],
    absorbed_auth_ms: u64,
    now_ms: u64,
) -> bool {
    let fresh = |at: u64| now_ms.saturating_sub(at) <= COMBINE_FRESHNESS_MS;
    survivor != absorbed && fresh(survivor_auth_ms) && fresh(absorbed_auth_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-31 (4), OP-153 m.3 (l)
    #[test]
    fn a_shared_development_client_is_refused_outside_a_sandbox() {
        assert_eq!(
            client_allowed(true, false, true),
            Err(ClientRefusal::SharedKeyInProduction)
        );
        assert_eq!(
            client_allowed(true, false, false),
            Err(ClientRefusal::SharedKeyInProduction)
        );
        assert_eq!(
            client_allowed(true, true, false),
            Err(ClientRefusal::NoSharedKey)
        );
        assert_eq!(client_allowed(true, true, true), Ok(()));
        assert_eq!(client_allowed(false, false, false), Ok(()));
    }

    // TN-87
    #[test]
    fn a_changed_client_id_warns_and_apple_counts_sixty_days() {
        assert_eq!(client_change("google", Some("a"), "a", 0), []);
        assert_eq!(client_change("google", None, "a", 0), []);
        assert_eq!(
            client_change("google", Some("a"), "b", 0),
            [Warning::ClientIdChanged]
        );
        assert_eq!(
            client_change(APPLE, Some("a"), "b", 1_000),
            [
                Warning::ClientIdChanged,
                Warning::AppleTransferUntil(1_000 + 5_184_000_000)
            ]
        );
    }

    // IDP-31 (5)
    #[test]
    fn apple_is_recommended_beside_another_provider_for_a_native_app() {
        assert!(apple_recommended(true, ["google"]));
        assert!(!apple_recommended(true, ["google", APPLE]));
        assert!(!apple_recommended(false, ["google"]));
        assert!(!apple_recommended(true, [APPLE]));
    }

    // OP-153 m.3 (m), TN-67
    #[test]
    fn combining_needs_two_accounts_both_fresh() {
        let (a, b) = ([1; 16], [2; 16]);
        assert!(combine_allowed(a, 1_000, b, 2_000, 300_000));
        assert!(!combine_allowed(a, 1_000, a, 2_000, 300_000));
        assert!(!combine_allowed(a, 0, b, 2_000, 300_001));
        assert!(!combine_allowed(a, 300_000, b, 0, 300_001));
    }
}
