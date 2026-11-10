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

## Revocation

The realm publishes an OpenSSH KRL (`PROTOCOL.krl`, version 1) at `/realms/{slug}/ssh/krl`:
the serials of revoked certificates under each CA key, and every CA key that no longer signs.
`ssh-keygen -Q` reads it. A server picks it up through `RevokedKeys`, pulled on the operator's
schedule.

## Server setup

```
TrustedUserCAKeys /etc/ssh/access-ca.pub     # from /realms/{slug}/ssh/ca.pub
RevokedKeys /etc/ssh/access.krl              # from /realms/{slug}/ssh/krl
```
