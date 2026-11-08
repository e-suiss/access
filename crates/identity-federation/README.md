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

- An OpenID provider a realm registers (`idp.upstream.register`) is found through its discovery
  document, whose `issuer` must be the registered one; its ID tokens are checked against the
  registered JWKS. Its addresses carry no assurance.
- An OAuth 2.0 provider without ID tokens is one more preset file: the operator puts it in the
  directory `social.presets_dir` names, and realms enable it like a shipped preset. A file whose
  id is already taken stops the server at start-up.
