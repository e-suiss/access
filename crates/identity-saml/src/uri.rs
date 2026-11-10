//! The names SAML 2.0, SAML 1.1, XML Signature, XML Encryption and WS-Federation give to
//! namespaces, bindings, formats and statuses (§10.6.1).

/// SAML 2.0 assertion namespace.
pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SAML 2.0 protocol namespace.
pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML 2.0 metadata namespace.
pub const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// SAML 1.1 assertion namespace (WS-Federation tokens).
pub const SAML1: &str = "urn:oasis:names:tc:SAML:1.0:assertion";
/// XML Signature namespace.
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XML Encryption namespace.
pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
/// XML Encryption 1.1 namespace.
pub const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
/// SOAP 1.1 envelope namespace.
pub const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// The ECP profile namespace.
pub const ECP: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
/// WS-Trust 2005/02 namespace (WS-Federation passive requestor).
pub const WST: &str = "http://schemas.xmlsoap.org/ws/2005/02/trust";
/// WS-Policy namespace.
pub const WSP: &str = "http://schemas.xmlsoap.org/ws/2004/09/policy";
/// WS-Addressing namespace.
pub const WSA: &str = "http://www.w3.org/2005/08/addressing";
/// WS-Federation namespace.
pub const FED: &str = "http://docs.oasis-open.org/wsfed/federation/200706";

/// Exclusive canonicalization without comments.
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped-signature transform.
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// HTTP-Redirect binding.
pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/// HTTP-POST binding.
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// PAOS binding (ECP).
pub const BINDING_PAOS: &str = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
/// SOAP binding.
pub const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

/// `NameID` format: persistent (SAML 2.0).
pub const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
/// `NameID` format: transient (SAML 2.0).
pub const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
/// `NameID` format: e-mail address (SAML 1.1 name, §10.6.1 prefix trap).
pub const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
/// `NameID` format: unspecified (SAML 1.1 name).
pub const NAMEID_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

/// Attribute name format: URI.
pub const ATTR_URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
/// Attribute name format: basic.
pub const ATTR_BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
/// Attribute name format: unspecified.
pub const ATTR_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// Subject confirmation method: bearer.
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
/// SAML 1.1 confirmation method: bearer.
pub const CM1_BEARER: &str = "urn:oasis:names:tc:SAML:1.0:cm:bearer";

/// Authentication context: X.509 (AAL3).
pub const AC_X509: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
/// Authentication context: REFEDS MFA (AAL3 for SPs whose template names it).
pub const AC_REFEDS_MFA: &str = "https://refeds.org/profile/mfa";
/// Authentication context: mobile two-factor (AAL2).
pub const AC_MOBILE_2F: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
/// Authentication context: password over a protected transport (AAL1).
pub const AC_PPT: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

/// Status: success.
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// Status: the requester erred.
pub const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
/// Status: the responder erred.
pub const STATUS_RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
/// Second-level status: passive authentication is not possible.
pub const STATUS_NO_PASSIVE: &str = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
/// Second-level status: the requested `NameID` policy cannot be met.
pub const STATUS_INVALID_NAMEID_POLICY: &str =
    "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
/// Second-level status: logout did not reach every session participant.
pub const STATUS_PARTIAL_LOGOUT: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
/// Second-level status: the request is denied.
pub const STATUS_REQUEST_DENIED: &str = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
/// Second-level status: the authentication failed or is unavailable.
pub const STATUS_AUTHN_FAILED: &str = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

/// WS-Federation sign-in action.
pub const WA_SIGNIN: &str = "wsignin1.0";
/// WS-Federation sign-out action.
pub const WA_SIGNOUT: &str = "wsignout1.0";
/// WS-Trust token type: SAML 1.1.
pub const TOKEN_SAML11: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
/// WS-Trust token type: SAML 2.0.
pub const TOKEN_SAML20: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
