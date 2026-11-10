# SAML service provider requests

Unsigned `AuthnRequest` documents in the shape each service provider sends, reconstructed from the
vendor's published SAML setup guide with placeholder tenant names, identifiers and instants. They
carry no signature and no key. The interop lab reads each through the parser worker and checks
that it takes the issuer, ACS URL, binding, `NameIDPolicy` and flags an independent XML reader
sees. Captures from real vendor tenants replace them as those tenants become available; a capture
is scrubbed of signatures and keys before it is committed.
