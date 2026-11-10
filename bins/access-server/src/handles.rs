//! The hosts of handles people own (E56 (2), OP-156 m.4 Q20), reached as Access reaches any
//! outside document: `GET https://<handle>/.well-known/access-handle` through the outbound
//! client, which refuses private addresses and bounds the answer.

use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_ui::domain::handle::{MAX_ANSWER, WELL_KNOWN};
use access_identity_ui::ports::HandleHosts;

/// The outbound client as the handle check uses it.
#[derive(Clone)]
pub(crate) struct OutboundHandles(pub(crate) Outbound);

impl HandleHosts for OutboundHandles {
    async fn well_known(&self, handle: &str) -> Option<Vec<u8>> {
        let url = format!("https://{handle}{WELL_KNOWN}");
        match self
            .0
            .get_as(&url, "text/plain", "access-handle-check/1", MAX_ANSWER)
            .await
        {
            Ok(a) if a.status == 200 => Some(a.body),
            _ => None,
        }
    }
}
