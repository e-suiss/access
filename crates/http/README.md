# access-http

The HTTP surfaces of Access: protocol endpoints, the hosted login, the Frontend API and the
management API. This file describes the management API.

## Management API

Served on the management listener only, under two surfaces:

- `/admin/v1/realms/{slug}/…` — realm administration, token audience
  `access-admin:realm:<slug>`, scopes `realm.*`.
- `/admin/v1/platform/…` — platform administration, audience `access-admin:platform`.

The contract is `sdks/openapi/admin-v1.json`, generated from code (`just admin-contract`);
problem codes are listed in `sdks/openapi/problems.json`.

### Reading

A read presents a DPoP-bound access token (`Authorization: DPoP …` with its `DPoP` proof) of the
surface's audience, living at most 60 minutes, with the route's scope. There is no bearer
management token. Lists page with an opaque `cursor` and a `Link` header, take `page[size]`
(1–100, default 50) and a SCIM `filter` over the list's own attributes. A resource another realm
owns is `404`, like a missing one.

### Writing

There is one write path: every write is the caller's AIS, signed with a live Instance key of the
realm's governing domain, and compiles to exactly one `idp.*` Exercise. A write takes two steps:

1. `POST /admin/v1/realms/{slug}/intents` with `{"operation", "key", "body"}` drafts the write.
   It changes nothing and answers with the `body` to send, the `domain`, the `pep` and the
   `intent_digest` the AIS signs (mode `commit`).
2. Send the write with that body and the AIS (`X-Access-AIS` header or `ais` member), and the
   AIS nonce as `Idempotency-Key`. The answer carries `exercise_id`, `position` and the resource.

`PUT` and `PATCH` (JSON Merge Patch) need `If-Match` with the resource's `ETag` (`428` without,
`412` on a mismatch). Nothing is deleted: a client, group or upstream provider is retired with
`POST …/{key}/retire` and its key is never reused. No route sets or reads a credential; a
`client_secret` is shown once in the answer that creates or rotates it.

### Realm resources

| Resource | Paths |
|---|---|
| Clients | `clients`, `clients/{client_id}`, `…/retire`, `…/secret/rotate` |
| Groups | `groups`, `groups/{name}`, `…/retire`, `…/members`, `…/members/remove` |
| Accounts | `accounts`, `accounts/{account_id}`, `…/suspend`, `…/reactivate`, `…/canary` |
| Upstream identity providers | `upstream-idps`, `upstream-idps/{name}`, `…/retire` |
| Settings | `settings`, `settings/signin-policy`, `settings/session-policy`, `settings/branding`, `settings/rp-id`, `settings/jose-alg`, `settings/cimd-policy`, `settings/protection-mode` |
| Mappers | `mappers/{claim}` |
| Bulk jobs | `jobs`, `jobs/{job_id}`, `jobs/{job_id}/items` |
| Reserved | `accounts/{account_id}/delete`, `accounts/{account_id}/reset-intents`, `rehome` |

A group has one membership issuer, `admin` or `upstream:<name>`, fixed at creation; members are
changed here only for `admin` groups. The console session policy lives at most 12 hours,
idles at most 15 minutes and is always bound to the client's network (`asn` or `ip`). Changing
the RP ID makes every registered passkey unusable: the write must carry
`acknowledge_passkey_loss` equal to their count.

A client reads pairwise `sub` values. It reads the realm's public `sub` only with
`subject_type: "public"` and `public_sub_opt_in: true`; discovery then lists `public` among the
realm's subject types. A `sector_identifier_uri` is fetched on every write of the client and must
be a JSON array of `https` URIs listing every redirect URI. A rotated client secret stays valid
for 24 hours next to its successor.

Tightening the protection mode (monitor to enforce, a later SL2 stage, more denied ASNs) is
`idp.realm.protection_mode`; a change that loosens anything is `idp.realm.protection_mode_loosen`,
a higher tier. Brute-force protection is always enforced. Reserved routes check the caller's AIS
and answer `501 reserved-operation`; nothing is applied.

### Platform resources

The platform surface manages tenants and realms as metadata. It has no route into a realm's
resources, settings, accounts, clients or authority state, and its answers carry only the
members listed for each resource: an operator reads no realm content.

| Resource | Paths |
|---|---|
| Tenants | `tenants`, `tenants/{tenant_id}` |
| Realms | `tenants/{tenant_id}/realms` (list, create), `realms/{realm_slug}` (metadata) |
| Sandbox domains | `tenants/{tenant_id}/sandbox-domains` (list, create) |
| Operator health | `operator/health` |

Writes take the same two steps against `POST /admin/v1/platform/intents`; the AIS is signed with
a live Instance key of the platform realm's governing domain (`suiss.platform_realm` in the
configuration) and compiles to one `idp.platform.*` Exercise there.

Creating a realm opens its governing domain with a Genesis whose founding root is the caller's:
`{"joint": {"k": 2, "parties": [...]}}` is recommended; `{"sole": ...}` needs
`"acknowledge_no_recovery": true`. The answer carries `genesis.digest` (the new domain's id),
the root's shape and `genesis.recovery`, which is `not_available` while no recovery entry can
be declared. A realm's `signing_available_at` is when its first key may sign at the latest
(creation plus the 90-minute publish lead); `key_state` says whether its keys are `pending`,
`published` or `signing`.

A sandbox domain is a realm whose governing domain is a separate authority domain; it carries
the sandbox template's fixed daily budget of Exercises and projections. No request brings
authority between a sandbox domain and a production one, in either direction.

### Bulk jobs

`POST /admin/v1/realms/{slug}/jobs` takes
`{"mode": "sequential" | "parallel", "operations": [{"operation", "key", "if_match", "body"}]}`
with 1 to 100 items. Each item is a realm write with its own AIS in its `body`; the envelope's
own AIS signs the job digest, which `POST …/intents` with `"operation": "createJob"` returns. The
answer is `202` with the job; poll `jobs/{job_id}` for its state and counts (committed, failed,
throttled) and read `jobs/{job_id}/items` for each item's Exercise or problem. In a sequential job
a failed item fails the rest with `424 failed-dependency`; parallel items are independent.
Writes that show a secret once are not accepted in a job. Results are shown for 7 days.

List endpoints read from the read replica when `[database] replica_host` is set; a single
resource, which conditional writes compare against, is always read from the primary.
