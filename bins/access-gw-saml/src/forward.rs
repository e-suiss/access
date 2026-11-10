//! One forward from access-server (OP-155 m.3 (c), (d), IDI-7, IDI-8): the raw binding values are
//! read and verified by the parser worker; the service provider's pinned certificates come from
//! access-server (`session_attest`, `sp`); the verified facts and the handle go back in
//! `session_attest` (`issue`), where access-server decides. A message the worker refuses, or a
//! handle the channel refuses, ends here with a stable code; nothing is signed or stored.

use std::future::Future;

use access_edge_core::ipc::{Op, Reply};
use access_edge_core::saml::{Context, Facts, Redirect, Signed};
use access_identity_saml::binding;
use access_identity_saml::sp::b64;
use access_identity_saml::wire::{Attest, Binding, Done, Forward, SpAnswer};

/// What the gateway needs from outside: the parser worker and the edge channel.
pub(crate) trait Ports: Sync {
    /// Has the parser worker run `op` on `input`.
    fn parse(&self, op: Op, input: Vec<u8>) -> impl Future<Output = Result<Reply, String>> + Send;

    /// Makes the `session_attest` call with `body`; a refusal is its stable code.
    fn attest(&self, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, String>> + Send;

    /// The gateway's realm.
    fn realm(&self) -> &str;
}

fn refused(code: &str) -> Done {
    Done::Refused(String::from(code))
}

async fn worker<P: Ports>(p: &P, op: Op, input: Vec<u8>) -> Result<Vec<u8>, Done> {
    match p.parse(op, input).await {
        Ok(Reply::Ok { output, .. }) => Ok(output),
        Ok(Reply::Refused(code)) => Err(Done::Refused(code)),
        Ok(Reply::WorkerFailed) => Err(refused("worker-failed")),
        Err(_) => Err(refused("parser-unavailable")),
    }
}

/// The message of a forward as bytes, and whether it is still deflated.
fn message(f: &Forward) -> Result<(Vec<u8>, bool), Done> {
    let raw = f
        .message
        .as_deref()
        .ok_or_else(|| refused("saml-message"))?;
    match f.binding {
        Binding::Redirect => {
            let b = binding::form_decode(raw).ok_or_else(|| refused("saml-request-malformed"))?;
            Ok((
                b64::decode(&b).ok_or_else(|| refused("saml-request-malformed"))?,
                true,
            ))
        }
        Binding::Post => Ok((
            b64::decode(raw).ok_or_else(|| refused("saml-request-malformed"))?,
            false,
        )),
        Binding::Soap => Ok((raw.as_bytes().to_vec(), false)),
        Binding::Unsolicited | Binding::Wsfed => Err(refused("saml-message")),
    }
}

async fn read<P: Ports>(
    p: &P,
    xml: &[u8],
    inflate: bool,
    certs: Vec<Vec<u8>>,
    require: bool,
) -> Result<Facts, Done> {
    let ctx = Context {
        inflate,
        certs,
        require_signature: require,
    };
    let input = ctx
        .encode(xml)
        .map_err(|_| refused("saml-request-too-large"))?;
    let out = worker(p, Op::SamlRequest, input).await?;
    Facts::decode(&out).map_err(|_| refused("worker-failed"))
}

async fn redirect_signature<P: Ports>(p: &P, f: &Forward, certs: &[Vec<u8>]) -> Result<bool, Done> {
    let (Some(alg), Some(sig)) = (&f.sig_alg, &f.signature) else {
        return Ok(false);
    };
    let message = f.message.as_deref().unwrap_or_default();
    let signed = binding::signed_octets("SAMLRequest", message, f.relay_state.as_deref(), alg);
    let r = Redirect {
        certs: certs.to_vec(),
        sig_alg: binding::form_decode(alg).ok_or_else(|| refused("saml-request-malformed"))?,
        signed,
        signature: binding::form_decode(sig)
            .and_then(|s| b64::decode(&s))
            .ok_or_else(|| refused("saml-request-malformed"))?,
    };
    let input = r.encode().map_err(|_| refused("saml-request-too-large"))?;
    worker(p, Op::SamlRedirect, input).await?;
    Ok(true)
}

async fn facts_of<P: Ports>(p: &P, f: &Forward) -> Result<(Facts, bool), Done> {
    let (xml, inflate) = message(f)?;
    let first = read(p, &xml, inflate, Vec::new(), false).await?;
    let sp = p
        .attest(
            Attest::Sp {
                realm: String::from(p.realm()),
                entity: first.issuer.clone(),
            }
            .encode(),
        )
        .await
        .map_err(Done::Refused)?;
    let sp = SpAnswer::decode(&sp).map_err(|_| refused("edge-malformed"))?;
    if !sp.found {
        return Err(refused("saml-unknown-sp"));
    }
    let redirect_signed = if f.binding == Binding::Redirect {
        redirect_signature(p, f, &sp.certs).await?
    } else {
        false
    };
    if sp.certs.is_empty() {
        let facts = Facts {
            signed: Signed::Absent,
            ..first
        };
        return Ok((facts, redirect_signed));
    }
    let require = sp.requests_signed && f.binding != Binding::Redirect;
    let verified = read(p, &xml, inflate, sp.certs, require).await?;
    Ok((verified, redirect_signed))
}

/// Handles one forward.
pub(crate) async fn handle<P: Ports>(p: &P, f: &Forward) -> Done {
    if f.realm != p.realm() {
        return refused("edge-realm");
    }
    let (facts, redirect_signed) = match f.binding {
        Binding::Unsolicited | Binding::Wsfed => (None, false),
        Binding::Redirect | Binding::Post | Binding::Soap => match facts_of(p, f).await {
            Ok((facts, signed)) => match facts.encode() {
                Ok(b) => (Some(b), signed),
                Err(_) => return refused("worker-failed"),
            },
            Err(done) => return done,
        },
    };
    let issue = Attest::Issue {
        realm: String::from(p.realm()),
        handle: f.handle,
        facts,
        redirect_signed,
    };
    match p.attest(issue.encode()).await {
        Ok(body) if access_identity_saml::wire::decode_decided(&body).is_ok() => Done::Done,
        Ok(_) => refused("edge-malformed"),
        Err(code) => Done::Refused(code),
    }
}

#[cfg(test)]
mod tests;
