# access-gw-radius

A RADIUS endpoint for VPN concentrators, Wi-Fi controllers and other network access servers that
can only check a user name and a password. Its one job is an `authentication` Claim for network
access. Every decision is made by `access-server`, which the gateway reaches only over its
mutual-TLS edge channel. The gateway holds no credential, writes nothing and signs nothing.

```
access-gw-radius
```

## What it serves

| Request | Answer |
|---|---|
| Access-Request with `User-Name` and `User-Password` (PAP) | Access-Accept when the password is an app password of the account holding that user name or e-mail address, Access-Reject otherwise |
| Access-Request with MS-CHAP or MS-CHAPv2 | Access-Reject; MS-CHAPv2 derives from NTLM and is never offered |
| Access-Request with CHAP or EAP | Access-Reject |
| Status-Server | Access-Accept |
| Anything else (Accounting-Request included) | No answer |

App passwords are created per application on the account page. The account's primary password
never authenticates over RADIUS. An unknown user name and a wrong password get the same
Access-Reject. Each accepted request becomes an AAL1 `authentication` Claim with method
`password`, signed by the realm's issuer inside `access-server`; the digest of the RadSec
client's certificate is its evidence. There is no eduroam profile.

## Transport

RadSec only (RFC 6614), with RADIUS/1.1 (RFC 9765): TLS 1.3, ALPN `radius/1.1`, and a client
certificate. RADIUS/1.1 removes MD5 from RADIUS: there is no shared secret, no Response
Authenticator, and `User-Password` travels as is inside TLS. A client that does not negotiate
`radius/1.1` is closed. There is no UDP listener, so RADIUS over UDP is never answered.

Each RadSec client is registered with the gateway by its certificate:

```
POST /admin/v1/realms/{slug}/gateways/radius:{gateway}/radius-clients
{ "client": "vpn-1", "certificate": "<base64url DER>" }
```

(`idp.gateway.radius_client_register`). Registering the same client again replaces its
certificate. A client whose certificate is not registered is closed without an answer.

A packet is at most 4096 bytes; its length is checked before it is read.

## Configuration

| Variable | Meaning |
|---|---|
| `ACCESS_GW_RADIUS_LISTEN` | RadSec listener, default `0.0.0.0:2083` |
| `ACCESS_GW_RADIUS_TLS_CERT`, `ACCESS_GW_RADIUS_TLS_KEY` | The gateway's certificate chain and key for RadSec clients, PEM files |
| `ACCESS_GW_RADIUS_SERVER` | `host:port` of `access-server`'s TLS listener |
| `ACCESS_GW_RADIUS_SERVER_NAME` | The name `access-server`'s certificate is checked for |
| `ACCESS_GW_RADIUS_SERVER_ROOTS` | The roots for `access-server`'s certificate, PEM file |
| `ACCESS_GW_RADIUS_CHANNEL_CERT`, `ACCESS_GW_RADIUS_CHANNEL_KEY` | The gateway's edge channel identity: a client certificate whose single SAN URI is `urn:suiss:access:gw:radius:<name>`, and its key |
| `ACCESS_GW_RADIUS_RUN_AS` | `uid:gid` to drop to when started as root |

The gateway reads its files, binds its listener and locks itself down before it serves; it
refuses to start without the lockdown. The realm registers the gateway first with
`idp.gateway.register`.

## License

[Apache License 2.0](../../LICENSE).
