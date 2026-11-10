//! WS-Federation passive requestor (§10.6.5, OP-155 m.3 (f), IDP-18): `wsignin1.0` answers with a
//! `RequestSecurityTokenResponse` carrying a signed SAML 1.1 or 2.0 token for the relying party,
//! under the same XML and signature rules as SAML (canonical output, enveloped exclusive-c14n
//! signature from the realm's SAML key, signed output only from a completed authentication);
//! `wsignout1.0` signs the user out locally. The request is query parameters only: nothing is
//! parsed as XML.

use crate::assertion::{Issue, Random, assertion, new_id};
use crate::dsig::{SignError, XmlSigner, sign};
use crate::request::Refusal;
use crate::sp::{Protocol, Sp};
use crate::time;
use crate::uri;
use crate::xml::El;

/// Longest `wctx` kept.
pub const MAX_WCTX: usize = 2048;

/// WS-Security utility namespace.
const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// The SAML 1.1 password authentication method.
const AM_PASSWORD: &str = "urn:oasis:names:tc:SAML:1.0:am:password";

/// A passive requestor message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// `wsignin1.0`.
    SignIn,
    /// `wsignout1.0` (or `wsignoutcleanup1.0`).
    SignOut,
}

/// The parameters of one passive requestor request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// `wa`.
    pub action: Action,
    /// `wtrealm`: the relying party's registered entity ID.
    pub realm: Option<String>,
    /// `wreply`: one of its registered reply URLs, exactly.
    pub reply: Option<String>,
    /// `wctx`, returned unchanged.
    pub context: Option<String>,
}

impl Request {
    /// Reads the parameters; `None` when `wa` is not a passive requestor action or a value is
    /// out of bounds.
    #[must_use]
    pub fn of(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let action = match get("wa")?.as_str() {
            uri::WA_SIGNIN => Action::SignIn,
            uri::WA_SIGNOUT | "wsignoutcleanup1.0" => Action::SignOut,
            _ => return None,
        };
        let bounded = |s: String, max: usize| {
            (s.len() <= max && !s.chars().any(char::is_control)).then_some(s)
        };
        let realm = get("wtrealm")
            .map(|s| bounded(s, 1024))
            .map_or(Some(None), |v| v.map(Some))?;
        let reply = get("wreply")
            .map(|s| bounded(s, 2048))
            .map_or(Some(None), |v| v.map(Some))?;
        let context = get("wctx")
            .map(|s| bounded(s, MAX_WCTX))
            .map_or(Some(None), |v| v.map(Some))?;
        if action == Action::SignIn && realm.is_none() {
            return None;
        }
        Some(Self {
            action,
            realm,
            reply,
            context,
        })
    }
}

/// The reply URL of a sign-in: `wreply` when registered exactly, else the default one.
///
/// # Errors
/// [`Refusal`].
pub fn reply<'a>(sp: &'a Sp, r: &Request) -> Result<&'a str, Refusal> {
    if !sp.protocol.wsfed() {
        return Err(Refusal::Protocol);
    }
    match &r.reply {
        Some(u) => sp
            .acs
            .iter()
            .find(|a| &a.url == u)
            .map(|a| a.url.as_str())
            .ok_or(Refusal::Acs),
        None => sp.default_acs().map(|a| a.url.as_str()).ok_or(Refusal::Acs),
    }
}

fn saml1(local: &'static str) -> El {
    El::new("saml", uri::SAML1, local)
}

fn subject(i: &Issue) -> El {
    saml1("Subject")
        .child(
            saml1("NameIdentifier")
                .attr("Format", i.format.uri())
                .text(i.name_id.clone()),
        )
        .child(
            saml1("SubjectConfirmation").child(saml1("ConfirmationMethod").text(uri::CM1_BEARER)),
        )
}

/// The unsigned SAML 1.1 assertion of a sign-in.
#[must_use]
pub fn assertion11(sp: &Sp, i: &Issue, id: &str) -> El {
    let not_after = time::format(i.now.saturating_add(time::NOT_ON_OR_AFTER_MS));
    let mut a = saml1("Assertion")
        .attr("AssertionID", id)
        .attr("IssueInstant", time::format(i.now))
        .attr("Issuer", i.idp.clone())
        .attr("MajorVersion", "1")
        .attr("MinorVersion", "1")
        .child(
            saml1("Conditions")
                .attr(
                    "NotBefore",
                    time::format(i.now.saturating_sub(time::NOT_BEFORE_MS)),
                )
                .attr("NotOnOrAfter", not_after)
                .child(
                    saml1("AudienceRestrictionCondition")
                        .child(saml1("Audience").text(sp.audience())),
                ),
        );
    let released: Vec<El> = i
        .attributes
        .iter()
        .filter(|r| !r.values.is_empty())
        .map(|r| {
            let (ns, name) = r
                .name
                .rsplit_once('/')
                .map_or((String::from(uri::ATTR_URI), r.name.clone()), |(n, l)| {
                    (String::from(n), String::from(l))
                });
            saml1("Attribute")
                .attr("AttributeName", name)
                .attr("AttributeNamespace", ns)
                .children(
                    r.values
                        .iter()
                        .map(|v| saml1("AttributeValue").text(v.clone())),
                )
        })
        .collect();
    if !released.is_empty() {
        a = a.child(
            saml1("AttributeStatement")
                .child(subject(i))
                .children(released),
        );
    }
    a.child(
        saml1("AuthenticationStatement")
            .attr("AuthenticationInstant", time::format(i.auth_time))
            .attr("AuthenticationMethod", AM_PASSWORD)
            .child(subject(i)),
    )
}

/// The `wresult` of a sign-in: a `RequestSecurityTokenResponse` with the signed token.
///
/// # Errors
/// [`SignError`].
pub async fn wresult<S: XmlSigner, R: Random + ?Sized>(
    sp: &Sp,
    i: &Issue,
    signer: &S,
    random: &R,
) -> Result<String, SignError> {
    let id = new_id(random)?;
    let (token, token_type) = if sp.protocol == Protocol::WsfedSaml11 {
        let mut a = assertion11(sp, i, &id);
        sign(
            signer,
            &mut a,
            "AssertionID",
            None,
            sp.alg(),
            sp.key_info_certificate,
        )
        .await?;
        (a, uri::TOKEN_SAML11)
    } else {
        let mut a = assertion(sp, i, &id);
        sign(
            signer,
            &mut a,
            "ID",
            Some(1),
            sp.alg(),
            sp.key_info_certificate,
        )
        .await?;
        (a, uri::TOKEN_SAML20)
    };
    let wst = |l: &'static str| El::new("t", uri::WST, l);
    let rstr = wst("RequestSecurityTokenResponse")
        .child(
            wst("Lifetime")
                .child(El::new("wsu", WSU, "Created").text(time::format(i.now)))
                .child(
                    El::new("wsu", WSU, "Expires")
                        .text(time::format(i.now.saturating_add(time::NOT_ON_OR_AFTER_MS))),
                ),
        )
        .child(
            El::new("wsp", uri::WSP, "AppliesTo").child(
                El::new("wsa", uri::WSA, "EndpointReference")
                    .child(El::new("wsa", uri::WSA, "Address").text(sp.entity_id.clone())),
            ),
        )
        .child(wst("RequestedSecurityToken").child(token))
        .child(wst("TokenType").text(token_type))
        .child(wst("RequestType").text("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"))
        .child(wst("KeyType").text("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey"));
    Ok(rstr.canonical())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-155 m.3 (f): only the passive requestor actions, a bounded wctx, a realm for sign-in.
    #[test]
    fn passive_requests_are_bounded() {
        let q = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| String::from(*v))
            }
        };
        let r = Request::of(q(&[
            ("wa", "wsignin1.0"),
            ("wtrealm", "urn:rp"),
            ("wctx", "c"),
        ]))
        .unwrap();
        assert_eq!(r.action, Action::SignIn);
        assert!(Request::of(q(&[("wa", "wsignin1.0")])).is_none());
        assert!(Request::of(q(&[("wa", "wattr1.0"), ("wtrealm", "urn:rp")])).is_none());
        assert_eq!(
            Request::of(q(&[("wa", "wsignout1.0")])).unwrap().action,
            Action::SignOut
        );
    }
}
