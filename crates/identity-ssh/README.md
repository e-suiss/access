# access-identity-ssh

The realm's SSH user certificate authority. Servers trust the realm's CA key; people and agents
get short-lived OpenSSH certificates instead of keeping long-lived keys on servers. A
certificate is a projection of an `ssh.login` Grant: it never carries more than the Grant names,
and it is never a source of authority itself.

## Certificates

The encoder is our own and writes `ssh-ed25519-cert-v01@openssh.com` user certificates
(OpenSSH `PROTOCOL.certkeys`); its output is checked against `ssh-keygen -L`.

| Field | Source |
|---|---|
| Key | the holder's ephemeral Ed25519 key, bound into the signed projection |
| Serial | 64 bits from the RNG, never 0 |
| Key ID | the projection's `ExerciseID` |
| Principals | the `principal` parameter of the `ssh.login` Grant; a Grant that names none projects nothing |
| `force-command`, `source-address` | the Grant's `force_command` and `source_address` parameters; a Grant's constraint is always carried |
| Extensions | `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`, `permit-X11-forwarding`, `permit-user-rc`, each only when the Grant sets its `permit_*` parameter to `true` |
| Lifetime | person: 8 hours by default, at most 12; agent: 15 minutes by default, at most 1 hour; always within the Grant and the decided horizon, valid from one minute before issuance |

The resource of a certificate is a server group, `ssh/host-group/<name>`. The `ssh` catalog's
one action, `ssh.login` (CT1), is accepted by a realm with the ordinary `schema-definition`
Acceptance.

## Issuance

`POST /realms/{slug}/ssh/certificate` carries the holder's DPoP-bound access token of the realm
(a live sign-in) and its proof.

1. `{"host_group", "public_key", "principals"?, "lifetime_s"?, "agent"?}` answers a draft: the
   `projection.issue` the realm draws from the holder's live `ssh.login` Grant, with the key
   bound in as the `public_key` parameter.
2. `{"exercise"}` carries the draft as a signed token Exercise (`token-exercise.cddl`), its AIS
   by an Instance of the Party the token's account is bound to, or of an agent acting for it.
   The certificate is checked against the Grant before the authority plane decides, and only an
   ALLOW is encoded, signed by the realm's CA key and recorded.

A holder's certificate key and the certificate go to `ssh-agent` with the certificate's lifetime,
or to an OpenSSH private key file (`access-cli ssh login`).

## The CA key

`idp.ssh.ca_enable` makes the realm's Ed25519 CA key in the identity signer (`ssh-ca` purpose).
`ca_rotate` publishes a new key next to the signing one; it signs after 24 hours and the old one
is removed 13 hours later, so `ca.pub` always names every key a valid certificate was signed by.
`ca_emergency` (reserved) replaces every key at once and `ca_disable` removes them all; in both
cases the old keys enter the KRL.

## Revocation

The realm publishes an OpenSSH KRL (`PROTOCOL.krl`, version 1) at `/realms/{slug}/ssh/krl`:
the serials of revoked certificates under each CA key, and every CA key that no longer signs. A
certificate is revoked when its projection's basis ends: its Grant revoked or expired, an Anchor
above it retired, its Party departed. A revocation is never taken back.
`ssh-keygen -Q` reads it. A server picks it up through `RevokedKeys`, pulled on the operator's
schedule.

## Server setup

```
TrustedUserCAKeys /etc/ssh/access-ca.pub     # from /realms/{slug}/ssh/ca.pub
RevokedKeys /etc/ssh/access.krl              # from /realms/{slug}/ssh/krl
```
