//! SAML 2.0 Responses and Assertions (§10.6.1, the 10 normative rules; OP-155 m.3 (e)): schema
//! order, `Destination`/`InResponseTo`/`Issuer`, audience = the registration's audience, one
//! bearer `SubjectConfirmation` without `NotBefore`, an `AuthnStatement` whose `SessionIndex` is
//! the assertion ID and whose class comes from the assurance vector, enveloped exclusive-c14n
//! signatures (Assertion first, then Response), sign-then-encrypt, `_` + 160-bit hex IDs, UTC
//! times. A signed Response is only ever made from a completed authentication (IDI-7): this
//! module is called by access-server with the attested session's facts, never by a gateway.

use crate::alg::SigAlg;
use crate::dsig::{SignError, XmlSigner, sign};
use crate::sp::{Aal3Class, NameIdFormat, Sp};
use crate::time;
use crate::uri;
use crate::xml::El;

/// Random bytes from the process's random source (a port: clock and RNG are ports, OP-63).
pub trait Random: Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`SignError`] when no randomness is available.
    fn fill(&self, out: &mut [u8]) -> Result<(), SignError>;
}

/// A SAML identifier: `_` and 160 random bits in hex (rule 9).
///
/// # Errors
/// [`SignError`] when no randomness is available.
pub fn new_id<R: Random + ?Sized>(r: &R) -> Result<String, SignError> {
    let mut b = [0_u8; 20];
    r.fill(&mut b)?;
    let mut s = String::from("_");
    for x in b {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
    }
    Ok(s)
}

/// A `NameID` value Access makes for one assertion: 32 random bytes, base64url (transient).
///
/// # Errors
/// [`SignError`] when no randomness is available.
pub fn new_value<R: Random + ?Sized>(r: &R) -> Result<String, SignError> {
    let mut b = [0_u8; 32];
    r.fill(&mut b)?;
    Ok(b64url(&b))
}

fn b64url(data: &[u8]) -> String {
    crate::sp::b64::encode(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// The `AuthnContextClassRef` of an authentication at NIST `aal` (OP-155 m.3 (e)).
#[must_use]
pub const fn class_ref(aal: u8, aal3: Aal3Class) -> &'static str {
    match aal {
        3.. => match aal3 {
            Aal3Class::X509 => uri::AC_X509,
            Aal3Class::RefedsMfa => uri::AC_REFEDS_MFA,
        },
        2 => uri::AC_MOBILE_2F,
        _ => uri::AC_PPT,
    }
}

/// One released attribute with its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Released {
    /// `Name`.
    pub name: String,
    /// `NameFormat` URI.
    pub name_format: &'static str,
    /// `FriendlyName`, written only.
    pub friendly_name: Option<String>,
    /// Values; an attribute without values is not written.
    pub values: Vec<String>,
}

/// The facts of one assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The identity provider's entity ID.
    pub idp: String,
    /// The exact ACS URL (`Destination`, `Recipient`).
    pub acs: String,
    /// `InResponseTo`; `None` for IdP-initiated.
    pub in_response_to: Option<String>,
    /// Issue time, ms.
    pub now: u64,
    /// The attested authentication time, ms.
    pub auth_time: u64,
    /// The attested NIST AAL.
    pub aal: u8,
    /// The `NameID` value.
    pub name_id: String,
    /// Its format.
    pub format: NameIdFormat,
    /// `SPNameQualifier` of a persistent `NameID` (the affiliation, or the entity ID).
    pub sp_name_qualifier: Option<String>,
    /// Released attributes.
    pub attributes: Vec<Released>,
    /// IdP-initiated: a 2-minute life and no `InResponseTo`.
    pub idp_initiated: bool,
}

fn saml(local: &'static str) -> El {
    El::new("saml", uri::SAML, local)
}

fn samlp(local: &'static str) -> El {
    El::new("samlp", uri::SAMLP, local)
}

/// The unsigned Assertion (rules 1 to 5, 9).
#[must_use]
pub fn assertion(sp: &Sp, i: &Issue, id: &str) -> El {
    let life = if i.idp_initiated {
        time::IDP_INITIATED_MS
    } else {
        time::NOT_ON_OR_AFTER_MS
    };
    let not_after = time::format(i.now.saturating_add(life));
    let name_id = saml("NameID")
        .attr("Format", i.format.uri())
        .attr_opt("SPNameQualifier", i.sp_name_qualifier.clone())
        .text(i.name_id.clone());
    let confirmation = saml("SubjectConfirmation")
        .attr("Method", uri::CM_BEARER)
        .child(
            saml("SubjectConfirmationData")
                .attr_opt("InResponseTo", i.in_response_to.clone())
                .attr("NotOnOrAfter", not_after.clone())
                .attr("Recipient", i.acs.clone()),
        );
    let mut a = saml("Assertion")
        .attr("ID", id)
        .attr("IssueInstant", time::format(i.now))
        .attr("Version", "2.0")
        .child(saml("Issuer").text(i.idp.clone()))
        .child(saml("Subject").child(name_id).child(confirmation))
        .child(
            saml("Conditions")
                .attr(
                    "NotBefore",
                    time::format(i.now.saturating_sub(time::NOT_BEFORE_MS)),
                )
                .attr("NotOnOrAfter", not_after)
                .child(saml("AudienceRestriction").child(saml("Audience").text(sp.audience()))),
        )
        .child(
            saml("AuthnStatement")
                .attr("AuthnInstant", time::format(i.auth_time))
                .attr("SessionIndex", id)
                .attr(
                    "SessionNotOnOrAfter",
                    time::format(i.auth_time.saturating_add(time::SESSION_MS)),
                )
                .child(
                    saml("AuthnContext")
                        .child(saml("AuthnContextClassRef").text(class_ref(i.aal, sp.aal3_class))),
                ),
        );
    let released: Vec<El> = i
        .attributes
        .iter()
        .filter(|r| !r.values.is_empty())
        .map(|r| {
            saml("Attribute")
                .attr("Name", r.name.clone())
                .attr("NameFormat", r.name_format)
                .attr_opt("FriendlyName", r.friendly_name.clone())
                .children(
                    r.values
                        .iter()
                        .map(|v| saml("AttributeValue").text(v.clone())),
                )
        })
        .collect();
    if !released.is_empty() {
        a = a.child(saml("AttributeStatement").children(released));
    }
    a
}

/// A Response around `content` (an Assertion or an `EncryptedAssertion`), or a status.
#[must_use]
pub fn response(
    i: &Issue,
    id: &str,
    status: (&'static str, Option<&'static str>),
    content: Option<El>,
) -> El {
    let mut code = samlp("StatusCode").attr("Value", status.0);
    if let Some(second) = status.1 {
        code = code.child(samlp("StatusCode").attr("Value", second));
    }
    let mut r = samlp("Response")
        .attr("Destination", i.acs.clone())
        .attr("ID", id)
        .attr_opt("InResponseTo", i.in_response_to.clone())
        .attr("IssueInstant", time::format(i.now))
        .attr("Version", "2.0")
        .child(saml("Issuer").text(i.idp.clone()))
        .child(samlp("Status").child(code));
    if let Some(c) = content {
        r = r.child(c);
    }
    r
}

/// Encrypts a signed assertion for the registration's encryption certificate.
pub trait Encrypter: Sync {
    /// The `saml:EncryptedAssertion` of `assertion`.
    ///
    /// # Errors
    /// [`SignError`].
    fn encrypt(&self, assertion: &El, cert: &[u8]) -> Result<El, SignError>;
}

/// The finished, canonical Response of a completed authentication: the Assertion signed when the
/// registration says so, then encrypted when it says so, then the Response signed when it says
/// so (rules 6, 7). At least one signature is always made.
///
/// # Errors
/// [`SignError`].
pub async fn issue<S: XmlSigner, R: Random + ?Sized, E: Encrypter>(
    sp: &Sp,
    i: &Issue,
    signer: &S,
    random: &R,
    encrypter: &E,
) -> Result<String, SignError> {
    let alg: SigAlg = sp.alg();
    let assertion_id = new_id(random)?;
    let response_id = new_id(random)?;
    let mut a = assertion(sp, i, &assertion_id);
    if sp.sign_assertion {
        sign(signer, &mut a, "ID", Some(1), alg, sp.key_info_certificate).await?;
    }
    let content = match (sp.encrypt_assertion, sp.encryption_cert()) {
        (true, Some(cert)) => encrypter.encrypt(&a, &cert)?,
        (true, None) => return Err(SignError(String::from("no encryption certificate"))),
        (false, _) => a,
    };
    let mut r = response(i, &response_id, (uri::STATUS_SUCCESS, None), Some(content));
    if sp.sign_response || !sp.sign_assertion {
        sign(signer, &mut r, "ID", Some(1), alg, sp.key_info_certificate).await?;
    }
    Ok(r.canonical())
}

/// An unsigned status Response to the validated ACS (no assertion, IDI-7).
///
/// # Errors
/// [`SignError`] when no randomness is available.
pub fn status<R: Random + ?Sized>(
    i: &Issue,
    random: &R,
    codes: (&'static str, &'static str),
) -> Result<String, SignError> {
    let id = new_id(random)?;
    Ok(response(i, &id, (codes.0, Some(codes.1)), None).canonical())
}

/// A `LogoutResponse` to a service provider's `LogoutRequest` (best effort, §10.6.1 SLO): local
/// sign-out always succeeds; logout is not propagated, so `PartialLogout` is said.
#[must_use]
pub fn logout_response(
    idp: &str,
    destination: &str,
    in_response_to: &str,
    id: &str,
    now: u64,
) -> El {
    samlp("LogoutResponse")
        .attr("Destination", destination)
        .attr("ID", id)
        .attr("InResponseTo", in_response_to)
        .attr("IssueInstant", time::format(now))
        .attr("Version", "2.0")
        .child(saml("Issuer").text(idp))
        .child(
            samlp("Status").child(
                samlp("StatusCode")
                    .attr("Value", uri::STATUS_SUCCESS)
                    .child(samlp("StatusCode").attr("Value", uri::STATUS_PARTIAL_LOGOUT)),
            ),
        )
}

/// The SOAP envelope of an ECP Response (SAML ECP profile §4.2.4).
#[must_use]
pub fn ecp_envelope(response_xml: &str, acs: &str) -> String {
    let mut out = String::from(
        "<soap11:Envelope xmlns:soap11=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap11:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" AssertionConsumerServiceURL=\"",
    );
    crate::xml::attr_value(&mut out, acs);
    out.push_str("\" soap11:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap11:mustUnderstand=\"1\"></ecp:Response></soap11:Header><soap11:Body>");
    out.push_str(response_xml);
    out.push_str("</soap11:Body></soap11:Envelope>");
    out
}

#[cfg(test)]
mod tests;
