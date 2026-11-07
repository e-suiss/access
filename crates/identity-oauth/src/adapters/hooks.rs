//! The inline hook transport (TN-135): the tenant's HTTPS endpoint through the identity plane's
//! SSRF-guarded outbound client (§14.3), within the hook's deadline. Anything but an answer is
//! [`Reply::NoAnswer`], which the caller turns into a refusal (MD-8).

use std::time::Duration;

use access_identity_hooks::domain::{MAX_ANSWER, Reply};
use access_identity_hooks::ports::HookTransport;

use crate::adapters::outbound::Outbound;

/// Posts hook calls through `Outbound`.
#[derive(Clone)]
pub struct OutboundHooks(pub Outbound);

impl HookTransport for OutboundHooks {
    async fn post(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        deadline: Duration,
    ) -> Reply {
        let headers: Vec<(&str, String)> = headers.iter().map(|(k, v)| (*k, v.clone())).collect();
        let sent = self.0.post_reading(
            url,
            "application/json",
            &headers,
            body,
            MAX_ANSWER.saturating_add(1),
        );
        match tokio::time::timeout(deadline, sent).await {
            Ok(Ok(a)) => Reply::Answered {
                status: a.status,
                body: a.body,
            },
            Ok(Err(_)) | Err(_) => Reply::NoAnswer,
        }
    }
}
