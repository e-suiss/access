# esuiss-restriction

The Access Restriction Profile: a forbid-only subset of [Cedar](https://www.cedarpolicy.com) for the rules an organisation writes on top of the authority it delegates. A rule can deny a request or require something before it goes ahead. It can never grant anything. Access, Work and One evaluate these rules with this crate, so a policy means the same thing everywhere, natively and in Wasm.

- **Forbid only.** `permit` and templates do not compile. The engine's only answers are "no objection", "deny" and "require".
- **Errors deny.** An evaluation error is a deny, never "no match".
- **Bounded.** Source size, nesting, tokens, AST depth, weighted cost, policy count and request shape all have limits. They start at fixed defaults and can only be narrowed.
- **Strict schema.** Policies are validated against a Cedar schema in strict mode; a reference to an unknown attribute does not compile.

## Use

```toml
[dependencies]
esuiss-restriction = "=0.2.0"
```

```rust
use suiss_restriction::{Engine, Limits, Outcome, RequestJson};

let engine = Engine::compile(schema, policies, Limits::default())?;
match engine.evaluate(&RequestJson { principal, action, resource, context, entities })? {
    Outcome::NoObjection => { /* the request goes on to the authority decision */ }
    Outcome::Deny(reason) => { /* refuse */ }
    Outcome::Require(refs) => { /* ask for what `refs` names first */ }
}
```

Annotations: `@id` (required, unique), `@require("rs-…")` turns a forbid into a requirement, `@undisclosed` hides the rule's name from the requester, `@doc` is free text. Anything else is rejected.

## Versions

Until 1.0, a breaking change raises the minor version. Pin an exact version. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](../../LICENSE).
