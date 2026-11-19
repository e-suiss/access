//! TN-163: an app's request outlives the sign-in page it opens, so a sign-in that started again
//! after its page expired still returns to the app.

use access_identity_oauth::domain::tokens::INTERACTIVE_TTL_MS;
use access_identity_session::domain::flow::FLOW_TTL_MS;

// TN-163
#[test]
fn an_apps_request_outlives_several_sign_in_pages() {
    assert!(INTERACTIVE_TTL_MS >= FLOW_TTL_MS.saturating_mul(4));
}
