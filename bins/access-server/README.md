# access-server

The Access server: the authority plane and the identity plane in one process. It reads its
configuration, opens its database pools and its PKCS#11 token, locks itself down (Landlock and
seccomp) and serves three listeners: the public one (ADP, the realms' OAuth and OpenID endpoints,
the hosted login, the Frontend and product APIs, and the protocol gateways' edge channel on
`/edge/v1/*`, open only to a registered gateway's client certificate), the management one (`/admin/v1/*` and the
console) and the internal one (`/livez`, `/readyz`, `/healthz`, `/metrics`).

```
access-server                                   # serve
access-server migrate                           # apply the schema migrations and exit
access-server bootstrap <plan.toml>             # a local deployment's tenants and fixtures
access-server client-update <plan.toml> <product> <display name>
access-server client-retire <plan.toml> <product>
access-server import-accounts <realm> <file.jsonl>   # accounts from another identity provider
```

There is no other mode and no flag that relaxes a check. Two signer processes run beside it and
are reached over Unix sockets only: `access-signer` (authority keys) and `access-identity-signer`
(realm JWKS and the cell's audit checkpoint key).

## Configuration

The file is `access.toml`, or the path in `ACCESS_CONFIG`. A top-level key can also be set from
the environment with the `ACCESS_` prefix (`ACCESS_LOG=debug`,
`ACCESS_DELIVERY_TARGETS='[{url="https://host:8443/path"}]'`). Secrets never come from the
environment: passwords and PINs are always files, and a variable that looks like a secret stops
the start. Unknown keys are refused.

### Top level

| Key | Required | Default | Meaning |
|---|---|---|---|
| `listen` | no | `127.0.0.1:8443` | Public listener. Loopback unless set. |
| `management_listen` | yes | | Management API and console listener; never the public address. |
| `internal_listen` | yes | | Health and metrics listener; never the public or management address. |
| `log` | no | `info` | `tracing` filter directives. |
| `issuer` | yes | | The ADP issuer: an `https` URL without a trailing slash. |
| `signer` | yes | | The authority signer's Unix socket. |
| `security_contacts` | no | the project's advisory URL | `security.txt` `Contact` URIs; must not be empty. |
| `security_policy` | no | the project's policy URL | `security.txt` `Policy` URI. |
| `security_txt_valid_days` | no | `180` | `security.txt` validity, 1 to 364 days. |
| `delivery_targets` | no | `[]` | Push and webhook endpoints that may be on a private address or a port other than 443: `[{ url = "https://host:8443/path", ca_file = "/ca.pem" }]`. |

### `[tls]` (required)

| Key | Required | Meaning |
|---|---|---|
| `cert_file` | yes | PEM certificate chain, leaf first. It must cover the issuer and the management origin. |
| `key_file` | yes | PEM private key, readable by the server's user only. |
| `client_ca_file` | no | PEM CAs that issue PEP client certificates. |

### `[database]` (required)

| Key | Required | Meaning |
|---|---|---|
| `host` | yes | Server host name, checked against its certificate. |
| `port` | yes | Port. |
| `name` | yes | Database name. |
| `root_cert_file` | yes | PEM root the server certificate chains to. |
| `durability` | yes | `replicated` (synchronous standbys) or `single-node`. |
| `sequencer` | yes | Login of `access_sequencer`: authority log commits. |
| `app` | yes | Login of `access_app`: the application. |
| `deriver` | yes | Login of `access_deriver`: the derived index. |
| `router` | yes | Login of `access_router`: `Host` to realm resolution. |
| `archive` | yes | Login of `access_archive`: opens the day and month partitions. |
| `outbox_reader` | yes | Login of `access_outbox_reader`: the couriers' outbox reads. |
| `checkpointer` | yes | Login of `access_checkpointer`: integrates and signs the audit chains. |
| `migrator` | for `migrate` | Login of `access_migrator`; never used while serving. |
| `replica_host` | no | A read replica for admin search and listing, reached with the `app` login. |

Each login is `{ user = "...", password_file = "...", pool = N }` with `pool` at least 1.

### `[hsm]` (required)

| Key | Required | Meaning |
|---|---|---|
| `module` | yes | The PKCS#11 module, loaded before the lockdown. |
| `token` | yes | Token label. |
| `pin_file` | yes | User PIN file. |
| `paths` | no | Directories a file-backed token keeps its objects in. |

### `[identity]` (required)

| Key | Required | Meaning |
|---|---|---|
| `realm_base` | yes | The `https` origin realm issuers are formed under, without a path. |
| `signer` | yes | The identity signer's Unix socket. |
| `outbound_ca_file` | no | PEM trust anchors for clients' own endpoints (`jwks_uri`, back-channel logout); the system bundle otherwise. |

### `[identity.org_domains]`

Organization domain verification (DNS TXT or HTTPS challenge) and its daily MX and registrar watch. Without this section no domain is verified, so autojoin and home realm discovery stay off.

| Key | Required | Meaning |
|---|---|---|
| `doh_url` | yes | A DNS-over-HTTPS resolver (RFC 8484), `https://…/dns-query`. |
| `rdap_url` | yes | An RDAP service the domain is appended to, `https://…/domain/`. |

### `[login]`

| Key | Default | Meaning |
|---|---|---|
| `dist_dir` | none | The built `web/login/dist`. Without it only the login API is served. |
| `redirect_to` | `/` | Where a completed sign-in goes: a path on the realm's origin. |
| `session_idle_s` | `604800` | Session idle lifetime. |
| `session_absolute_s` | `2592000` | Session absolute lifetime. |
| `hash_mean_ms` | `0` | The calibrated password hash time refusals are padded to. |

### `[console]`

| Key | Default | Meaning |
|---|---|---|
| `dist_dir` | none | The built `web/console/dist`. Without it only the console API is served. |

### `[suiss]` (required)

| Key | Required | Meaning |
|---|---|---|
| `region` | yes | The deployment's region, e.g. `eu-central`. |
| `relay` | yes | Relay's base URL. |
| `management_api` | yes | The management API's base URL. |
| `products` | no | Product name to base URL. |
| `platform_realm` | no | The platform tenant's realm slug; without it the platform surface refuses every request. |
| `relay_product` | no | The product name Relay's platform product client is registered under. Only that client may report İYS registration states to `POST /relay/v1/iys-status`; without it every report is refused. |

### `[suiss.relay_platform]` (required)

Every message to a person (codes, links, security notices, CIBA invitations) leaves through
Relay, where Access is a platform tenant. The Relay courier runs in the server: one node at a
time holds its lease, and messages wait in the outbox while Relay is unreachable. At start the
server reads `<relay>/.well-known/relay-configuration` in the background; it sends only once
that document names this Access as `access_issuer`, offers `urn:suiss:relay:events:1` and an
`events_endpoint` on Relay's own origin.

| Key | Required | Meaning |
|---|---|---|
| `tenant` | yes | Access's tenant id in Relay (letters, digits, `_`, `-`). |
| `credential_file` | yes | The credential Relay accepts from Access, owner-readable only; re-read when it changes. |
| `ca_file` | no | PEM trust anchors for Relay's certificate; the system's when not given. |

### `[provider]`

What the operator declares about its key infrastructure, published as is; an undeclared fact is
published as `null`.

| Key | Meaning |
|---|---|
| `kms_quota_per_second` | KMS or HSM operations per second. |
| `kms_shared` | Whether the KMS quota is shared. |
| `hsm_partition_shared` | Whether the HSM partition is shared. |

### `[telemetry]`

| Key | Default | Meaning |
|---|---|---|
| `log_format` | `json` | `json` or `text`. |
| `otlp_endpoint` | none | OTLP/gRPC collector, `http://<host>:<port>`; nothing is exported without it. |
| `environment` | none | `deployment.environment`. |
| `trace_sample_ratio` | `0.1` | Share of traces kept, 0.0 to 1.0. |

### `[risk]`

Each source is optional; a missing one makes its signals `unavailable`, never "fine".

| Key | Meaning |
|---|---|
| `geo_mmdb_path` | A GeoIP/ASN MMDB file, read again when it changes. |
| `breach_range_api` | A k-anonymity range API base (`https://…`). |
| `breach_ranges_dir` | A local mirror of the range files, used when no range API is set. |
| `breach_mirror_source` | A range API base (`https://…`) the mirror is refreshed from every 24 hours; needs `breach_ranges_dir`. A refresh fills a new version directory and switches to it in one rename; the version it replaces is archived, never removed, and a refresh that fails leaves the current one served. |

### `[app_factor]`

| Key | Meaning |
|---|---|
| `apple_app_ids` | App IDs (`TEAMID.bundle.id`) whose App Attest keys may become the app-controlled factor. Android key attestation is checked against the embedded Google roots. |

### `[signup]`

Sign-up never shows a puzzle. A bot signal only decides whether a request is counted as risky;
it never refuses one and never replaces the e-mailed code. A provider that does not answer is a
missing signal. A configured provider whose secret or trust anchors cannot be read stops the
start.

| Key | Default | Meaning |
|---|---|---|
| `bot_provider` | none | `friendly_captcha` or `turnstile`. |
| `bot_site_key` | none | The site key (required for Friendly Captcha). |
| `bot_secret_file` | none | The provider secret, readable by the server's user only. |
| `bot_verify_url` | the provider's | The verify endpoint, `https://host/path`. |
| `bot_timeout_ms` | `2000` | How long the provider may take. |
| `privacy_pass_key_files` | `[]` | DER token keys of the Privacy Pass issuers whose tokens count as a positive signal. |
| `privacy_pass_issuer`, `privacy_pass_origin` | none | The challenge the hosted page presents (required with issuer keys). |
| `mail_domain_check` | `true` | Look up the address's MX record (or A/AAAA without MX) at the host's first nameserver; a domain that takes no mail is refused, an unanswered lookup is not. |
| `dns_timeout_ms` | `1500` | How long one DNS query may take. |

### `[migration]`

| Key | Default | Meaning |
|---|---|---|
| `legacy_idp_verify_url` | none | The previous identity provider's password check (`https://…`) for imported accounts that brought no hash. |

## Moving accounts in

`import-accounts` reads one JSON object per line and prints a summary; a line that cannot be
imported is reported by its number and reason, never echoed:

```json
{"email": "ann@example.com", "password_hash": "$2y$10$…"}
{"email": "bob@example.com", "password_hash": "…", "hash_transform": "prehash=sha256-hex"}
{"username": "cem", "legacy_idp_reference": "auth0|5f1c…"}
```

- **Hashes are not converted on import.** Argon2id strings are kept as they are. Every other
  scheme stays sealed as it came and is checked once, at the account's next sign-in, then
  replaced by Argon2id in the same request. The import list covers bcrypt (`$2a$`, `$2b$`,
  `$2y$`, cut at 72 bytes), Argon2i/d, scrypt, Firebase scrypt, PBKDF2-SHA1/256/512, md5-crypt,
  sha256-crypt, sha512-crypt, LDAP `{SSHA}`-style hashes and the Kratos `$md5$`/`$sha*$`
  pattern forms. A pepper or a pre-hash such as `bcrypt(sha256(password))` is data in
  `hash_transform` (`pepper=prefix|suffix|hmac-sha256:<base64>`,
  `prehash=md5-hex|sha1-hex|sha256-hex|sha256-raw|sha512-hex|sha256-base64`), not code.
- **Without a hash**, the first sign-in asks `legacy_idp_verify_url` with
  `POST {"identifier", "password", "reference"}` and expects `200 {"valid": true|false}`.
  Anything else, or no URL configured, refuses the sign-in.
- The console's sign-in analytics and the `access_legacy_hash_accounts` gauge count the accounts
  still waiting.
- **What does not move:** sessions, refresh tokens, consents and the audit history stay with the
  previous provider. People sign in again; apps ask for consent again, and that consent is
  recorded here as a Grant.
- **Moving identity providers is not a domain handover.** Importing accounts changes where people
  sign in. It does not move a domain's authority to another operator.
- **Passkeys and Parties.** A passkey belongs to its relying party ID, which is your own domain,
  so passkeys keep working when you move to or away from Access as long as the domain stays
  the same. A passkey cannot follow a domain change, and the Credential Exchange Format is not a
  way to move passkeys between relying parties. Party IDs and their key events are portable and
  free to export, so people keep their own keys when the provider changes.

## Background work

While serving, the process also runs, each stopping with the server:

- the day partitions of the protocol tables and this month's and next month's audit partitions,
  opened ahead once a day by one node of the cell;
- the daily tenant analytics, and the release of management API `Idempotency-Key` answers after
  24 hours (cleared in place, never deleted);
- the audit checkpointer: every second the identity audit log and the authority operational
  stream are integrated into their Merkle trees and signed by the identity signer's cell key;
- the domain checkpointer: every 60 seconds the committed head of each domain this process leads
  is signed by the authority signer, a quiet domain's too;
- the Token Status List publisher, which signs a changed list at once and an unchanged one again
  before verifiers would find it stale;
- the back-channel logout courier, the event and webhook fan-outs and couriers, and the SSF
  receiver;
- the export pass: every 10 seconds one node sends each realm's export sinks the audit rows they
  have not accepted yet, as a copy, never the record. Syslog sinks are reached over TLS on port
  6514, or at a declared delivery target's host and port.

`/readyz` answers ready only when every pool answers, both signers accept a connection, every
realm's JWKS loaded at start-up and every courier and consumer is running.

## Tests

```
cargo nextest run -p access-server
```

The tests need PostgreSQL (`DATABASE_URL`) and SoftHSM (`SOFTHSM2_CONF`, set by `just test`).
