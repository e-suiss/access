# access-identity-federation

Social and upstream sign-in for the Access identity plane: Google, Apple, Microsoft, GitHub,
LinkedIn and Facebook out of the box, and any OpenID Connect provider a realm registers.

## Presets are data

Each provider is one TOML file in `presets/`: its endpoints, the scopes it asks for, a logo key,
the claims that identify a user, and what its e-mail address is worth. Adding a provider means
adding a file.

| Provider | Protocol | User key | E-mail trusted when |
|---|---|---|---|
| Google | OIDC | `sub` | `email_verified` and the domain is `gmail.com`, `googlemail.com` or the Workspace `hd` |
| Apple | OIDC | `sub` (team scoped) | `email_verified` |
| Microsoft | OIDC | `tid:oid` | `xms_edov = true` |
| GitHub | OAuth 2.0 | `id` | the primary address of `/user/emails` is verified |
| LinkedIn | OIDC | `sub` | `email_verified` |
| Facebook | OAuth 2.0 | `id` (app scoped) | never |

An address the provider does not vouch for is kept as unconfirmed and proven with our own code
before it is used for recovery or notices.

## Checked in the back end

The browser only carries the redirect. The server exchanges the code with PKCE and checks the ID
token's signature against the provider's keys, under an algorithm the preset names, together with
`iss`, `aud`, `exp` and the flow's `nonce`.

## Keys, not addresses

An external identity is keyed by `(provider, subject)`. A matching e-mail address never links or
combines accounts; linking is an explicit action of a signed-in user who just re-authenticated.

## Development clients

The operator may configure shared development clients. A sandbox realm can use them, so social
sign-in works right away. Any other realm must bring its own client: a shared client is refused
both when the provider is enabled and at every sign-in.

## Apple's client secret

Apple takes no stored client secret. The realm's secret reference names its Sign in with Apple
key: the `.p8` file as Apple issues it, after two lines `team_id=…` and `key_id=…`. Access signs
a fresh five-minute ES256 assertion with it for every code exchange.

## Any other provider

- An OAuth 2.0 provider without ID tokens is one more preset file: the operator puts it in the
  directory `social.presets_dir` names, and realms enable it like a shipped preset. A file whose
  id is already taken stops the server at start-up.

## Enterprise connections

A realm registers an enterprise identity provider (Entra, Okta, Google Workspace, Keycloak, ADFS,
e-Devlet, an operator's mobile signature service) as a connection. Registering it and trusting
it are two separate, reserved decisions; until the governing domain accepts the connection's
issuer, it signs nobody in.

- **Its own profile.** OpenID Connect or SAML 2.0; the subject key (`sub`, or Entra's
  `[tid, oid]`); client authentication, `private_key_jwt` with a key of the realm unless a secret
  method is chosen; an optional preset; the organization it belongs to.
- **Algorithms from discovery.** The discovery document's `issuer` must be the registered one.
  ID token algorithms are the upstream's, cut down to ES256 and RS256: never `none`, never HMAC.
- **RFC 9207.** The authorization response's `iss` must be the issuer, and must be present when
  the upstream says it sends it.
- **`ui_locales`** is passed on only when the upstream lists the language.
- **SAML.** Access signs its `AuthnRequest`; the Response is read in the parser worker and only
  an assertion signed with one of the IdP's pinned certificates counts. An unsolicited Response
  is refused unless the connection opens it. Each assertion is used once.
- **Keys, not addresses.** A person is `(issuer, subject)`. When a known address arrives with a
  new subject from the same connection, nothing is relinked: a conflict is recorded, the account
  holder is told, and only an explicit link after signing in again resolves it.
- **Assurance.** An upstream's `acr`, `amr` or `AuthnContextClassRef` counts only through the
  connection's assurance map; without one the lowest class applies. An upstream never satisfies
  a confirmation tier.
- **Evidence, not content.** The raw ID token or assertion is sealed under the person's own key;
  Claims carry only its digest. A national identity number (TCKN) is sealed with it and appears
  only as a keyed digest.
- **Cut-off.** When the governing domain stops accepting an issuer, its sign-ins stop and the
  sessions it opened end.

Upstream presets (`presets/upstream/*.toml`) are data: e-Devlet and operator mobile signature
need no provider-specific client.
