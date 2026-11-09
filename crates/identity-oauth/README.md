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
