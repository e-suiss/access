# access-gw-ldap

A read-only LDAP endpoint for applications that can only sign people in with an LDAP bind:
mail clients, wikis, NAS boxes, printers. It is a compatibility surface, not a directory: every
decision is made by `access-server`, which the gateway reaches only over its mutual-TLS edge
channel. The gateway holds no credential, writes nothing and signs nothing.

```
access-gw-ldap
```

## What it serves

| Operation | Answer |
|---|---|
| Bind (simple) | An app password, as `dn=token` or under the holder's own DN `uid=<uid>,ou=people,o=<realm>` |
| Bind (SASL `EXTERNAL`) | The client certificate of the TLS session, under the realm's certificate sign-in rules |
| Search | The realm's tree, root DSE and `cn=Subschema`; simple paged results |
| WhoAmI | `dn:<bound DN>`, or empty when anonymous |
| Password modify (RFC 3062) | Replaces the app password that was just presented; the new one is chosen by the directory and shown once |
| StartTLS | Only on the cleartext listener, which is off unless configured |
| Unbind, Abandon | As usual |
| Add, Delete, ModifyDN, Modify, Compare | `unwillingToPerform` (53) |

App passwords are created per application on the account page. The account's primary password
never binds. An empty password with a name (an unauthenticated bind) is refused; an anonymous
client reads the root DSE and nothing else. `DIGEST-MD5`, `SCRAM-*`, `PLAIN` and `GSSAPI` are not
offered. A simple bind without TLS on the cleartext listener answers `confidentialityRequired`
(13).

## Tree

```
o=<realm>
├── ou=people   uid=<username or e-mail>   inetOrgPerson, posixAccount
└── ou=groups   cn=<group>                 groupOfNames, posixGroup
```

`memberOf` is operational (ask for it by name or with `+`), and the in-chain matching rule
`1.2.840.113556.1.4.1941` is understood. `uidNumber` and `gidNumber` are
65 536 + (the first four bytes of SHA-256 of the entry's UUID mod 2³¹ − 65 536).

## Limits

| Input | Limit |
|---|---|
| Message | 256 KiB and 32 levels of nesting, checked before decoding |
| Filter | 16 levels, 255 nodes |
| Search | 5000 entries, 10 s, pages of at most 1000 with an opaque 10-minute cookie |
| TLS | 1.3 only; client chains of at most 8 certificates of 8 KB |

## Configuration

Everything is read from the environment and the files it names before the process locks itself
down (Landlock, seccomp). On a host where the lockdown cannot be applied the gateway refuses to
start.

| Variable | Meaning |
|---|---|
| `ACCESS_GW_LDAP_LISTEN` | LDAPS listener (default `0.0.0.0:636`) |
| `ACCESS_GW_LDAP_STARTTLS_LISTEN` | Cleartext listener that offers StartTLS (off when unset) |
| `ACCESS_GW_LDAP_TLS_CERT`, `ACCESS_GW_LDAP_TLS_KEY` | The certificate chain and key LDAP clients see, PEM |
| `ACCESS_GW_LDAP_SERVER` | `host:port` of `access-server`'s TLS listener |
| `ACCESS_GW_LDAP_SERVER_NAME` | The name its certificate is checked for |
| `ACCESS_GW_LDAP_SERVER_ROOTS` | The roots for that certificate, PEM |
| `ACCESS_GW_LDAP_CHANNEL_CERT`, `ACCESS_GW_LDAP_CHANNEL_KEY` | The gateway's client certificate (one SAN URI `urn:suiss:access:gw:ldap:<name>`) and key, PEM |
| `ACCESS_GW_LDAP_RUN_AS` | `uid:gid` to switch to when started as root |

The gateway must be registered in its realm before it can connect; it serves that realm only.

## License

[Apache License 2.0](../../LICENSE). The LDAP codec, `ldap3_proto`, is MPL-2.0 and linked
unmodified.
