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
