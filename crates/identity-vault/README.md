# access-identity-vault

The token vault of the Access identity plane: people connect their accounts at upstream services
(Google, Microsoft 365, GitHub, Slack and 21 more) so that agents acting for them can use those
services, and Access decides every single use.

## Upstreams are data

Each upstream is one TOML file in `catalog/`: authorization and token endpoints, the RFC 7009
revocation endpoint when the service has one, the documented token lifetime, how refreshes behave,
and the scopes it offers. A realm turns one on with `idp.vault.resource_enable`; a service the
catalog does not have is the realm's own upstream, `idp.vault.resource_register`. A catalog entry
grants nothing to anyone.

A realm's Resource names its client at the upstream (the secret is a `secret://` reference, never
stored), the scopes a connection may hold, the `scope_mapping` from the domain's actions to
upstream scopes, and the registered executors a token may go to. The mapping says which scopes an
action needs; it is not authority.

## Connecting an account

The person starts a connection for one agent client. Access redirects to the upstream only when the
person has already approved that client with their Approval Surface signature (a live consent
record). The code is exchanged in the back end with PKCE, and the tokens are sealed under the
person's own key: erasing the account shreds them with every other credential. Tokens are refreshed
five minutes before they expire, under a lease; a refused refresh marks the connection
`needs_reconnect`, shreds its tokens and tells the person through Relay. Nothing falls back.

## Releasing a token

`POST /v1/vault/releases` is the only way a token leaves the vault. It needs all of:

- an Exercise the authority plane allowed, presented with the intent it was allowed for;
- the caller authenticated as that Exercise's PEP, and registered as an executor of the Resource;
- the Exercise's basis still standing (a revoked Grant ends every later release; when the
  Exercise was for the person who owns the connection, the connection then goes to
  `needs_reconnect`, its tokens are shredded and the person is told through Relay);
- the Exercise acting for the person who owns the connection: holding a token is never a reason;
- the Exercise's action mapped by the Resource;
- a single release for each Exercise, and a token used no longer than the decision's horizon.

The token stays with the executor, which makes the call itself (broker as PEP), for every action of
consequence tier CT2 or above and for every action without an accepted schema. Only at CT0–CT1, with
the realm's release mode open (`idp.vault.release_mode_open`), a known expiry within the horizon and
either a lifetime of at most one hour or an upstream revocation endpoint, may the executor hand the
token to the agent's code. Anything less goes to the executor.

Each release is a projection row of its Exercise plus an audit event. The upstream token's content
belongs to the upstream: Access does not guarantee that it stays within the Grant, and the release
says so.

## What the vault is not

Agents have no route to the vault and never see a token in their model's context. Access keeps no
shared passwords or secrets for people and is not a privileged access manager.
