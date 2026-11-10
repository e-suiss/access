# access-product-twin

A kit for building a domain product against Access the way any third party would: on the published crates only (`esuiss-access-kernel`, `esuiss-access-sdk`, `esuiss-crypto`), over Access's public endpoints only. Tests use it to stand in for Suiss products (Work, Pay, Commerce, Serve, One) and for third-party products, so every seam is exercised through exactly the contract an outside product gets.

It is a library, not a deployed service, and it is not published.

## The Generic Domain Product contract

A domain product:

- **publishes** its action namespace and typed Action Schemas (with each parameter's class), and the Claim classes it issues;
- **owns** its resources and its domain truth: whether an order is refundable, whether a driver is active, whether a shift is open;
- **produces** predicate, lifecycle and effect Claims under its own issuer identity;
- **enforces** its own effects as their PEP, after asking Access for each one;
- **never** writes an Anchor, a Grant or an Acceptance, and never declares authority.

The domain decides what the product's statements mean. Its schema counts only once the domain accepts it (`schema-definition`), its Claims count only once the domain accepts them (`predicate-input`, `subject-selection`), and each acceptance is the domain's own Exercise. A first-party product gets no other path.

## What the kit does

| Call | What happens over the wire |
|---|---|
| `Twin::register` | Pairs with a tenant as a platform client (`private_key_jwt`): one challenge per realm, then the product signs its own `party_register` and `instance_create` with its service key. |
| `Twin::publish_schema` | Publishes a Schema Publication Package with a `check` statement as its own publisher. |
| `Twin::accepted` | Reads whether a domain accepted that package. |
| `Twin::issue_claim` | Signs a Claim with its Instance key and sends it to Claim Ingest. |
| `Twin::sign_claim` | Signs a Claim without sending it, so a request can carry it. |
| `Twin::ask` | Forwards the actor's own statement to the ADP evaluation endpoint as its own PEP and verifies the signed receipt. Anything but a verified ALLOW is a denial. |
| `Twin::enforce` | Runs the product's effect once, only for the intent that was allowed. |
| `Twin::attempt` | Tries a meta-action as the product itself, so a test can show the refusal. |

The transport is a port (`Wire`): a test plugs in Access's public router, a deployment plugs in an HTTPS client with the product's client certificate. Every call names one of `wire::ENDPOINTS`, and `cargo xtask check no-privileged-path` checks that each of them is in a public contract.

## Seam schemas

Product schemas are data under `conformance/seams/schemas/`, one TOML file per product:

```toml
product = "Suiss Ride"
namespace = "ride"
catalog_version = 1

[[actions]]
name = "request"
major = 1
effect_class = "reversible"
consumption_bearing = true
params = { fare = "amount" }
classes = { fare = "amount" }

[[claims]]
class = "ride_driver"
value = "bool"
use = "subject-selection"
```

`Schema::parse` loads a file through the Kernel's own decoders: a schema that needs anything the Kernel does not already have does not load.

## License

Apache-2.0
