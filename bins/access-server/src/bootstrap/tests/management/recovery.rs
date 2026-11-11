//! The realm's recovery view on the real server path (§8.17.9.7, §13.6, RR-5, OP-158 m.3 (m)):
//! `getRecovery` reads the governing domain's recovery entry and its handover and recovery
//! history from the authority record; a domain without an entry says "Recovery not available".

use super::*;

// §13.6, RR-5, N-14, OP-158 m.3 (m), Ek B 5748, 6032
#[tokio::test]
async fn a_domain_without_a_recovery_entry_reads_as_not_available() {
    let c = console("recovery-view", false).await;
    let (status, view, _) = c.rest_read("/admin/v1/realms/acme/recovery").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["realm"], "acme");
    assert_eq!(view["recovery"], "not_available");
    assert_eq!(
        view["recovery_reason"],
        access_identity_admin::app::recovery_view::NO_ENTRY
    );
    assert_eq!(view["history"].as_array().map(Vec::len), Some(0));
}
