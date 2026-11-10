# access-gw-kerberos

Kerberos single sign-on for browsers on a Windows or MIT Kerberos domain: HTTP Negotiate
(SPNEGO, RFC 4559) with the gateway's own keytab. Access is never a KDC and never replaces a
domain controller; the gateway only accepts tickets. Every decision about who someone is belongs
to `access-server`, which the gateway reaches only over its mutual-TLS edge channel. The gateway
writes nothing and signs nothing.

This crate is its own Cargo workspace, outside the root one, with its own `Cargo.lock`,
`cargo deny` and `cargo vet` runs. It links the system libgssapi (MIT Kerberos), the only C code
in Access, and is built and tested on Linux CI only. It ships as its own image,
`ghcr.io/e-suiss/access-gw-kerberos`; the main image never carries libgssapi.

```
access-gw-kerberos
```

## Flow

| Request | Answer |
|---|---|
| `GET /negotiate` without `Authorization` | 401 with `WWW-Authenticate: Negotiate` and a page that continues to the realm's normal sign-in |
| `GET /negotiate` with an accepted Kerberos ticket of an active account | 303 to the sign-in page, with the `NegTokenResp`; the realm issuer's `authentication` Claim (method `kerberos`, AAL1) is queued |
| `GET /negotiate` with anything else | 303 to the sign-in page, never a second 401 |
| `GET /proxy/...` (with a backend configured) | the same acceptance, then the request is forwarded to the backend with a ticket obtained by S4U2Proxy |

A token is refused, and the browser falls back to normal sign-in, when it is NTLM (raw, or
offered first in SPNEGO), when its ticket is for another service principal than the configured
one (compared exactly), when its enctype is not AES256 (`aes256-cts-hmac-sha1-96` or
`aes256-cts-hmac-sha384-192`; RC4 is never accepted), when its key version is below the realm's
floor, superseded for longer than a ticket lifetime, or overdue for rotation, when libgssapi
cannot decrypt it, or when its principal (`user@REALM` of the SPN's realm) names no active
account by user name. The token is read by the parser worker first; the gateway itself never
parses ASN.1. Tickets larger than 8 KiB (very large PACs) also fall back.

## Browsers

Negotiate needs its own HTTP/1.1 endpoint: the exchange is bound to one connection, so HTTP/2
and pooling proxies break it. Browsers only send Kerberos tickets to hosts on their allowlist:

- Chrome and Edge: the `AuthServerAllowlist` policy (Windows: the Local intranet zone).
- Firefox: `network.negotiate-auth.trusted-uris`.
- Safari: works with the system Kerberos configuration.

A browser whose allowlist does not name the gateway shows the 401 page, which continues to the
normal sign-in page. Signing in never depends on Kerberos.

## Keytab

The keytab holds the service account's keys and is a shared secret. It stays in the operator's
secret store (mounted for the gateway, for example from a Kubernetes secret on a memory file
system), is read once before the lockdown straight into `memfd_secret` memory, and is handed to
libkrb5 as an in-memory keytab. It is never written to disk and never reaches the database or
the authority record. Only AES256 keys of the configured SPN are kept; a keytab without one
stops the gateway.

The realm sets the gateway's keytab policy, the SPN and the rotation period:

```
PUT /admin/v1/realms/{slug}/gateways/kerberos:{gateway}/keytab-policy
{ "spn": "HTTP/access.corp.example@CORP.EXAMPLE", "rotate_days": 30 }
```

(`idp.gateway.keytab_policy`). After a compromise, `POST …/keytab/replace` with the replacement
keytab's key version (`idp.gateway.keytab_emergency`, reserved) refuses every older key version at
once. Rotating the keytab on schedule is operational: export a new keytab with the next key
version and restart the gateway.

## S4U2Proxy

With `ACCESS_GW_KERBEROS_BACKEND_SPN` set, the acceptor credential may also initiate. A request
under `/proxy/` whose ticket is forwardable yields a proxy credential, the gateway obtains a
ticket for the backend SPN for the same user (constrained delegation: the KDC decides what the
gateway's account may delegate to), and forwards one `GET` to the backend over TLS 1.3. The
backend's answer comes back bounded to 1 MiB.

## Configuration

| Variable | Meaning |
|---|---|
| `ACCESS_GW_KERBEROS_LISTEN` | HTTPS listener, default `0.0.0.0:8443` |
| `ACCESS_GW_KERBEROS_TLS_CERT`, `ACCESS_GW_KERBEROS_TLS_KEY` | The gateway's certificate chain and key for browsers, PEM files |
| `ACCESS_GW_KERBEROS_SPN` | The one service principal accepted, `HTTP/host@REALM` |
| `ACCESS_GW_KERBEROS_KEYTAB` | The keytab file in the secret store |
| `ACCESS_GW_KERBEROS_LOGIN` | The realm's normal sign-in page, an `https` URL |
| `ACCESS_GW_KERBEROS_PARSER_SOCKET`, `ACCESS_GW_KERBEROS_PARSER_UID` | The parser worker supervisor's socket and the user it runs as |
| `ACCESS_GW_KERBEROS_KRB5_CONF` | libkrb5's configuration, default `/etc/krb5.conf` |
| `ACCESS_GW_KERBEROS_RCACHE_DIR` | libkrb5's replay cache, on a memory file system |
| `ACCESS_GW_KERBEROS_BACKEND_SPN`, `ACCESS_GW_KERBEROS_BACKEND`, `ACCESS_GW_KERBEROS_BACKEND_NAME`, `ACCESS_GW_KERBEROS_BACKEND_ROOTS`, `ACCESS_GW_KERBEROS_KDC_PORT` | The S4U2Proxy backend: its SPN, `host:port`, certificate name and roots, and the KDC port (default 88) |
| `ACCESS_GW_KERBEROS_SERVER`, `ACCESS_GW_KERBEROS_SERVER_NAME`, `ACCESS_GW_KERBEROS_SERVER_ROOTS` | `access-server`'s TLS listener, its certificate name and roots |
| `ACCESS_GW_KERBEROS_CHANNEL_CERT`, `ACCESS_GW_KERBEROS_CHANNEL_KEY` | The gateway's edge channel identity: a client certificate whose single SAN URI is `urn:suiss:access:gw:kerberos:<name>`, and its key |
| `ACCESS_GW_KERBEROS_RUN_AS` | `uid:gid` to drop to when started as root |

The gateway reads its files, installs its keytab, binds its listener and locks itself down before
it serves; it refuses to start without the lockdown. The realm registers the gateway first with
`idp.gateway.register`.

## License

[Apache License 2.0](../../LICENSE).
