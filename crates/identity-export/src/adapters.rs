//! The export transports over the guarded outbound client (§14.3, OP-149 m.23, OP-156 m.3 (s)):
//! HTTPS to public addresses on port 443 or to declared targets, and syslog over TLS on port
//! 6514 or to a declared target's host and port.

pub mod cold_file;
pub mod publish;

use std::time::Duration;

use access_identity_oauth::adapters::outbound::{Outbound, OutboundError};
use tokio::io::AsyncWriteExt as _;

use crate::domain::collector::Request;
use crate::ports::{Down, Wire};

/// How long one syslog write may take.
const SYSLOG_WRITE: Duration = Duration::from_secs(30);

fn down(e: OutboundError) -> Down {
    Down(String::from(match e {
        OutboundError::Url => "url",
        OutboundError::Blocked => "blocked",
        OutboundError::Unreachable => "unreachable",
        OutboundError::Malformed => "malformed",
    }))
}

/// The guarded outbound client as the sinks' transport.
#[derive(Clone)]
pub struct OutboundWire(pub Outbound);

impl Wire for OutboundWire {
    async fn http(&self, r: &Request, max_body: usize) -> Result<(u16, Vec<u8>), Down> {
        let headers: Vec<(&str, String)> = r
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.clone()))
            .collect();
        let a = self
            .0
            .deliver(
                r.method,
                &r.url,
                (r.content_type, &headers),
                &r.body,
                max_body,
            )
            .await
            .map_err(down)?;
        Ok((a.status, a.body))
    }

    async fn syslog(&self, (host, port): (&str, u16), frames: &[u8]) -> Result<(), Down> {
        let mut s = self.0.tls_stream(host, port).await.map_err(down)?;
        tokio::time::timeout(SYSLOG_WRITE, async {
            s.write_all(frames).await?;
            s.flush().await?;
            s.shutdown().await
        })
        .await
        .map_err(|_| Down(String::from("unreachable")))?
        .map_err(|_| Down(String::from("unreachable")))
    }
}
