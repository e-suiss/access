//! Enveloped XML signatures over the canonical elements Access writes (§10.6.1 rule 6, OP-155
//! m.3 (d)): one `Reference` to the element's own identifier, the enveloped-signature and
//! exclusive c14n transforms, a SHA-2 digest. The signature value comes from an [`XmlSigner`]: the
//! realm's `saml` key in the identity signer, never a key in this process (Golden SAML, HL-35).

use std::future::Future;

use crate::alg::SigAlg;
use crate::sp::b64;
use crate::uri;
use crate::xml::El;

/// A signature from the realm's SAML key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signature value (PKCS#1 v1.5, or raw `r || s` for ECDSA).
    pub value: Vec<u8>,
    /// The signing key's certificate, DER, for `KeyInfo` (a hint, never a trust anchor).
    pub certificate: Vec<u8>,
}

/// Why nothing was signed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("signer: {0}")]
pub struct SignError(pub String);

/// Signs canonical `SignedInfo` octets with the realm's SAML key (§10.6.1 `XmlSigner`).
pub trait XmlSigner: Sync {
    /// The signature of `signed_info` with `alg`.
    fn sign(
        &self,
        signed_info: Vec<u8>,
        alg: SigAlg,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send;
}

fn ds(local: &'static str) -> El {
    El::new("ds", uri::DS, local)
}

/// The `SignedInfo` over `digest` of `#id`.
#[must_use]
pub fn signed_info(id: &str, digest: &[u8], alg: SigAlg) -> El {
    ds("SignedInfo")
        .child(ds("CanonicalizationMethod").attr("Algorithm", uri::EXC_C14N))
        .child(ds("SignatureMethod").attr("Algorithm", alg.uri()))
        .child(
            ds("Reference")
                .attr("URI", format!("#{id}"))
                .child(
                    ds("Transforms")
                        .child(ds("Transform").attr("Algorithm", uri::ENVELOPED))
                        .child(ds("Transform").attr("Algorithm", uri::EXC_C14N)),
                )
                .child(ds("DigestMethod").attr("Algorithm", alg.digest().uri()))
                .child(ds("DigestValue").text(b64::encode(digest))),
        )
}

/// Signs `el` (whose identifier attribute is `id_attr`) and inserts the signature as its child
/// at `at`: after `Issuer` for SAML 2.0 (1), last for SAML 1.1.
///
/// # Errors
/// [`SignError`].
pub async fn sign<S: XmlSigner>(
    signer: &S,
    el: &mut El,
    id_attr: &str,
    at: Option<usize>,
    alg: SigAlg,
    key_info: bool,
) -> Result<(), SignError> {
    let id = el
        .get(id_attr)
        .ok_or_else(|| SignError(String::from("no identifier")))?
        .to_owned();
    let digest = alg.digest().digest(el.canonical().as_bytes());
    let si = signed_info(&id, &digest, alg);
    let s = signer.sign(si.canonical().into_bytes(), alg).await?;
    let mut signature = ds("Signature")
        .child(si)
        .child(ds("SignatureValue").text(b64::encode(&s.value)));
    if key_info {
        signature =
            signature.child(ds("KeyInfo").child(
                ds("X509Data").child(ds("X509Certificate").text(b64::encode(&s.certificate))),
            ));
    }
    let at = at.unwrap_or(el.children.len());
    el.insert(at, signature);
    Ok(())
}
