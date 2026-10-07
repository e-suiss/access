# Access

Access is Suiss's identity and authority product: a complete identity provider (OIDC/OAuth 2.1, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, MCP) with an authority plane on top that decides, for every request, whether **this actor, on this authority, may do this exact thing now** — and keeps a verifiable record of the answer.

It is built for a world where AI agents act on behalf of people and organizations: delegation is explicit and only ever narrows, holding an authority is separate from being able to exercise it, revocation takes effect immediately, and decision records can be verified by third parties without asking Access.

- **Overview (English):** [docs/overview.md](docs/overview.md)
- **Specification (Turkish, normative):** [docs/spec/](docs/spec/README.md)
- **Architecture diagrams:** [docs/architecture/](docs/architecture/README.md)

## Status

Specification stage. The canonical specification is frozen; implementation has not started yet. Engineering conventions (repository layout, architecture patterns, code quality, API, data, testing, supply chain, observability, CI/release, developer experience, documentation) are defined in the specification (§14, §16, §17).

## Repository layout

The planned layout is described in the specification (§16.4.3a, OP-62): a single repository containing the Rust workspace (`crates/`, `bins/`), companion services (`services/`), SDKs (`sdks/`), web components and console (`web/`), conformance and test suites, deployment files and documentation (`docs/`).

## License

Access will be fully open source. The license has not been chosen yet; until a `LICENSE` file is added, no license is granted.

## Contributing

Contribution guidelines will be published in `CONTRIBUTING.md`. Code, comments, commit messages and pull requests are written in English.
