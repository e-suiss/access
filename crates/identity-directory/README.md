# access-identity-directory

Brings people and groups from Active Directory (or any LDAP directory shaped like it) into an
Access realm by pulling, incrementally, over LDAPS.

- **Incremental.** Each run reads only the entries whose `uSNChanged` passed the last watermark,
  in pages, and moves the watermark to the highest value it saw.
- **Stable keys.** Accounts are keyed by `objectGUID`, never by a name that can be reused.
- **No passwords.** The connector binds with a service account and reads a fixed attribute list
  that holds no password material. It never sends a replication request, so it cannot perform
  `DCSync`. People keep signing in with their directory through delegation or SPNEGO.
- **Same rules as SCIM.** A group has exactly one membership issuer. A connector's memberships
  count only for groups the realm accepted it as issuer of; without that acceptance nothing is
  selected. SCIM push stays available as the alternative.
- **Bounded.** TLS 1.3 only, one message at most 256 KiB read before it is allocated, at most
  50 000 entries per run, five minutes per run.

Access works alongside Active Directory; it does not replace it. It runs no KDC and has no write
path into the directory.

## License

[Apache License 2.0](../../LICENSE).
