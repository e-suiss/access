# access-identity-oidf

OpenID Federation 1.0 for the Access identity plane, written sans I/O: every function takes
the bytes it checks and the current time, and nothing in the crate opens a socket or reads a
clock.

## What it does

- **Entity statements.** Validates entity configurations and subordinate statements: compact
  JWS with `typ` `entity-statement+jwt`, ES256 or RS256 only, a `kid` naming exactly one key,
  `iat`/`exp` with a 60 second skew, no unknown `crit`, and claims only where they belong.
- **Trust chains.** Validates a chain leaf first, up to a trust anchor whose keys the realm
  pinned. A chain holds at most 8 statements, has no entity twice, honours `max_path_length`
  and `allowed_entity_types`, and is valid until its smallest `exp`. Offline
  `trust-chain+json` documents and the `trust_chain` header are accepted.
- **Resolution.** `Resolver` walks `authority_hints` bottom-up and tells the caller which URL
  to fetch next; `app::resolve` drives it over a `Fetch` port.
- **Metadata policy.** The seven standard operators (`value`, `add`, `default`, `one_of`,
  `subset_of`, `superset_of`, `essential`) are merged from the anchor down and applied to the
  leaf's metadata. Any conflict, and any other operator, refuses the chain.
- **Trust marks.** Verifies `trust_mark_type` marks from issuers the anchor lists, parses
  signed status answers, and keeps a status for min(`exp`, 1 hour). A trust mark is extra
  information for policy and display; it never stands in for consent.
- **Registration.** Checks the request object of automatic registration (`jti`, `exp`,
  audience) and the entity configuration an RP posts for explicit registration.
- **Payloads.** Builds the entity configuration, subordinate statements, resolve, list and
  trust mark status answers Access signs with its federation key.

## Example

```rust,ignore
use access_identity_oidf::{TrustAnchor, chain::verify_chain};

let chain = verify_chain(&statements, &[anchor], now_ms)?;
let rp = chain.metadata_of("openid_relying_party");
```
