# access-identity-oauth

The OAuth 2.1 authorization server and OpenID Provider of an Access realm: `/authorize`, `/par`,
`/token`, `/userinfo`, `/revoke`, `/introspect`, RP-initiated and back-channel logout, and the
discovery documents.

## One client resolver

Every `client_id` goes through one resolver:

- an opaque `cli_…` id is a client the realm registered;
- a URL is never looked up in the realm's own registry. A federation request (`trust_chain`) is
  refused, and anything else is resolved through its Client ID Metadata Document (CIMD,
  `draft-ietf-oauth-client-id-metadata-document-02`) when the realm accepts CIMD clients from
  that domain.

Where a client comes from (`registered` or `cimd`) is a policy input. It is never authority.

## CIMD clients

A CIMD document is fetched outside any database transaction, through the same SSRF-guarded
outbound client as every other client URL:

- `https` on port 443 only, and every address the host resolves to must be public. The same
  check applies to every URL the document names (`jwks_uri`, `logo_uri`, `policy_uri`, …).
- No redirects are followed and only `200` is a document.
- The read stops at 5 KB. The whole fetch has 5 s and the connection 2 s.
- At most 10 fetches per URL and 100 per realm per minute, with the `User-Agent`
  `Suiss-Access-CIMD/1`.

The document must name its own URL as `client_id` and carry `client_name` and `redirect_uris`.
Shared secrets and private key material are refused. `application_type` is read from the
document. The checked document is kept as the client's snapshot for its `max-age`, clamped to
5 minutes to 24 hours. A refused fetch or document cancels the request and is never cached.

When the snapshot changes:

- a change to `redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks` or
  `jwks_uri` ends the client's consent records, and the person is asked again;
- a change to `client_name` or `logo_uri` is only shown as a warning;
- a domain the realm's CIMD policy no longer admits retires its clients, ending their consent
  records and identity grants. The same URL seen again later is a new client.

The metadata declares `client_id_metadata_document_supported` only for a realm that accepts CIMD.

## MCP clients and consent

A client the realm did not register must name one registered protected resource in `resource`.
That resource becomes the token's only audience, and an unknown one is `invalid_target`.

Such a client gets a code only while the person's consent record for it covers the requested
scopes and names a Grant that still stands. The Grant is the person's own `grant.issue`. The
consent screen shows the client's hostname and redirect hostnames, warns when every redirect is
a loopback one or the client is new, and shows the client's name and logo as the client's own
claim. Every authorization response carries `iss`.

## Token exchange and assertions

An agent trades a token for another with RFC 8693. The subject token can be an Access token of
this realm, an ID token this realm issued to the same client, or a JWT of an issuer the realm's
domain accepts. SAML assertions are not read yet. The subject token is only input: the new token
is the agent's own decision on its own Grant, for the resource it asks for, and never names more
actions or lives longer than an Access subject token. Its `act` lists the agents that delegated
down to the caller, taken from the domain's record and never copied from a presented token, so
two valid tokens cannot be spliced into a chain that was never granted. A resource server never
forwards the token it received; it exchanges it for its own token to the upstream.

`requested_token_type` may also ask for:

- an ID-JAG (`oauth-id-jag+jwt`) for another authorization server: only for a client that
  authenticates with `private_key_jwt`, only after the caller's decision for the `resource`
  allowed it, five minutes at most, and with no authority in it;
- a Transaction Token (`txntoken+jwt`): sixty seconds of audit context naming the Exercise; it is
  never accepted as a subject token.

The JWT bearer grant (RFC 7523) takes an ID-JAG or a cloud workload JWT (AWS, GCP) of an
accepted issuer. The assertion is checked for its signature, `typ`, audience, client and times,
and its `jti` is used once; without the replay store nothing is accepted. The assertion never
grants anything: without the caller's Exercise there is no token, and without a Grant behind it
the answer is `invalid_grant`. An `email` in an assertion is never kept.

## Workload clients (SPIFFE)

A workload authenticates with its SPIFFE credential instead of a secret
(`draft-ietf-oauth-spiffe-client-auth-02`, `spiffe_jwt` and `spiffe_x509`):

- a **JWT-SVID** as `client_assertion` with `client_assertion_type`
  `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`. Its `sub` is the SPIFFE ID, `aud` is
  the realm's issuer and nothing else, `exp` is at most five minutes ahead, and the signature is
  ES256 under a `jwt-svid` key of the trust domain's bundle. Each JWT-SVID is used once;
- an **X.509-SVID** over mutual TLS, with `client_id` the SPIFFE ID in the certificate's URI SAN.
  The chain must verify to the bundle's `x509-svid` roots; the leaf is not a CA and has
  `digitalSignature`. Such a certificate is never a PEP certificate.

The realm registers a workload client with `idp.client.register`: its SPIFFE ID or a
whole-segment prefix written `spiffe://acme.example/agent/finance/*`, the trust domain's Bundle
Endpoint and the agent the workloads act as. A wildcard anywhere else selects nothing. The
trust domain itself must also be accepted: the governing domain's root establishes an
actor-binding Acceptance of the trust domain's issuer id. A trust domain is never an authority
domain.

The Bundle Endpoint is fetched through the same SSRF-guarded outbound client as CIMD documents
(port 443, public addresses, no redirects, 5 s, `Suiss-Access-SPIFFE/1`). The bundle is kept
per trust domain and refreshed after its `spiffe_refresh_hint`, kept within 5 minutes and
24 hours; its sequence never goes back. A bundle older than twice its refresh interval verifies
nothing, so a Bundle Endpoint that stays down eventually stops every SVID of its trust domain.

A verified workload with a DPoP proof is the workload's first presentation: the realm issuer
issues an `identity_binding_workload` Claim about the agent naming the workload URI and the DPoP
key. That key can then open its own Instance of the agent with a self-signed `instance_create`.
Authentication is all this gives: the Instance acts only through a Grant.

## Client interop notes (2026-11-09)

These notes describe what two widely used clients do today. They are not part of the profile;
when a client changes, these notes change, and the rules above stay.

- **Claude** picks CIMD only when the metadata declares `client_id_metadata_document_supported`
  and `none` in `token_endpoint_auth_methods_supported`; otherwise it registers dynamically.
  Claude Code's document lists `http://localhost/callback` and `http://127.0.0.1/callback`
  without a port and binds a random one at run time. Loopback redirect URIs therefore match with
  any port, and only for `localhost`, `127.0.0.1` and `[::1]`. A document without
  `application_type` whose redirects are loopback ones is read as a native client. The token
  endpoint must accept `application/x-www-form-urlencoded`, and a scope challenge needs a `401`.
- **ChatGPT** requires `iss` in every authorization response, compared byte for byte with the
  metadata `issuer`. Its CIMD document uses `private_key_jwt` with `RS256` and a `jwks_uri`.
  RS256 client assertions are accepted only for a client that asks for them, and members the
  server does not know, such as `token_endpoint_auth_methods_supported` in a client document,
  are ignored. It reauthorizes with `id_token_hint`.
