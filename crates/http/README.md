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
| Accounts | `accounts`, `accounts/{account_id}`, `…/suspend`, `…/reactivate` |
| Upstream identity providers | `upstream-idps`, `upstream-idps/{name}`, `…/retire` |
| Settings | `settings`, `settings/signin-policy`, `settings/session-policy`, `settings/branding`, `settings/rp-id` |
| Mappers | `mappers/{claim}` |

A group has one membership issuer, `admin` or `upstream:<name>`, fixed at creation; members are
changed here only for `admin` groups. The console session policy lives at most 12 hours,
idles at most 15 minutes and is always bound to the client's network (`asn` or `ip`). Changing
the RP ID makes every registered passkey unusable: the write must carry
`acknowledge_passkey_loss` equal to their count.
