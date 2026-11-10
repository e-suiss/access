# access-gw-saml

The SAML gateway of Access. access-server binds the browser endpoints (`/saml/*`, `/wsfed`),
keeps the cookies, and forwards each request here with a one-use attestation handle. The gateway
has the parser worker read and verify the message, asks access-server for the service
provider's pinned certificates, and redeems the handle over the edge channel. access-server then
decides, signs through the identity signer and shows the browser its outcome.

The gateway holds only its edge channel identity (a client certificate whose SAN URI is
`urn:suiss:access:gw:saml:<name>`). It has no store, no signing key and no session; untrusted XML
never parses in this process.

```
ACCESS_GW_LISTEN=127.0.0.1:7400 \
ACCESS_GW_SERVER=access.internal:8443 ACCESS_GW_SERVER_NAME=access.internal \
ACCESS_GW_ROOTS=/etc/access/server-roots.pem \
ACCESS_GW_CERT=/etc/access/gw.pem ACCESS_GW_KEY=/etc/access/gw.key \
ACCESS_PARSER_SOCKET=/run/access/parser.sock ACCESS_PARSER_UID=990 \
access-gw-saml
```

access-server finds the gateway through `identity.saml_gateway` (`host:port`). The gateway is
registered in its realm with `registerGateway` (`idp.gateway.register`).

## One forward

1. Read the message without keys (`saml.request`) to learn its issuer.
2. `session_attest` `sp`: the registration's pinned certificates and whether it signs requests.
3. Verify a detached HTTP-Redirect signature (`saml.redirect`) and read the message again with
   the pinned certificates (`saml.request`), so its facts come from the element whose signature
   verified.
4. `session_attest` `issue` with the handle and those facts. A refused message or handle ends the
   forward with its stable code.

On any operating system other than Linux, and where the lockdown cannot be applied, the gateway
refuses to start.

## License

[Apache License 2.0](../../LICENSE).
