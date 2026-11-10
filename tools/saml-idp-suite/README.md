# saml-idp-suite

A neutral test suite for any SAML 2.0 identity provider. It knows no particular IdP and has no
dependencies, so any IdP project can run it in its own CI.

| Part | What it checks |
|---|---|
| `response` | Standards checks on a `samlp:Response`: version, IDs, issue instant, `Destination`, `InResponseTo`, issuer, status, one assertion, bearer subject confirmation (recipient, lifetime, no `NotBefore`), conditions window, audience, authentication statement, and where the signature sits, what it references, its transforms, canonicalization and algorithms (no SHA-1), and no comments inside signed elements |
| `metadata` | An `IDPSSODescriptor` for SAML 2.0 with a signing key, SSO endpoints on standard bindings, and a well-placed signature when signed |
| `request` | The `AuthnRequest` corpus: five XML signature wrapping (XSW) shapes, comment and CDATA injection inside the signed `Issuer`, tampering, a missing signature, DOCTYPE, external entities, entity expansion, an oversized message and replay |
| `profiles` | What Salesforce, AWS, AWS IAM Identity Center, Google Workspace, Slack, Zoom, Atlassian, ServiceNow, Workday, Microsoft Entra ID, Shibboleth SP and SimpleSAMLphp additionally require |

The rule behind every request case: the IdP acts only on what the service provider signed. A case
passes when the IdP refuses the request, or answers exactly the signed request ID, issuer and ACS
URL. Cryptographic verification of the IdP's own signatures is left to a real XML signature
implementation (`xmlsec1`, a service provider); the suite checks what verifiers commonly get wrong
to accept.

## As a library

Implement two traits and call `request::run`:

```rust
use saml_idp_suite::request::{self, Options, Outcome, Seen, Signer, Target, Template};

struct MyIdp;
impl Target for MyIdp {
    fn submit(&mut self, xml: &str) -> Outcome {
        // send `xml` through your binding, then report what the IdP did
        Outcome::Refused(String::from("not wired"))
    }
}

struct MySp;
impl Signer for MySp {
    fn sign(&mut self, t: &Template) -> Result<String, String> {
        // an AuthnRequest for `t`, enveloped signature, exclusive canonicalization
        Err(String::from("not wired"))
    }
}

let results = request::run(&mut MyIdp, &mut MySp, &Options {
    issuer: "https://sp.example.org/metadata".into(),
    acs: "https://sp.example.org/acs".into(),
    destination: "https://idp.example.net/sso".into(),
    signature_required: true,
    replay: true,
    size_limit: Some(256 * 1024),
});
```

Each attack is built from a request signed for that case alone, so replay protection never hides
a result. `response::check_response`, `response::check_metadata` and `profiles::check_profile`
take the XML your IdP produced.

## As a command

```
saml-idp-suite response response.xml --idp https://idp.example.net/metadata \
    --sp https://sp.example.org/metadata --acs https://sp.example.org/acs \
    --request-id _abc --profile salesforce
saml-idp-suite metadata metadata.xml --idp https://idp.example.net/metadata
saml-idp-suite corpus signed-request.xml out/ --unsigned-refused --size-limit 262144
saml-idp-suite profiles
```

`response` takes the XML or its base64 `SAMLResponse` form. `corpus` writes every attack built
around one signed request for IdPs driven from outside Rust. Exit status 1 means a check failed.

## License

Apache-2.0.
