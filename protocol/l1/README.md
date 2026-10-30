# L1 Interoperability Profiles

Status: first drafts. Published: [Access Decision Profile](adp.md).

L1 says how Access meets existing standards. Each profile maps one standard onto the L0 model: which of its fields become which L0 values, which of its flows produce which Access artefacts, and what a peer that only speaks that standard can rely on. A profile never changes L0 semantics; where a standard cannot express an L0 limit, the profile narrows what it projects.

Each profile is written together with the feature that implements it and has its own version track.

| Profile | Standards |
|---|---|
| Decisions | OpenID AuthZEN |
| Token projection | OAuth 2.0, Rich Authorization Requests (RFC 9396), DPoP (RFC 9449), Token Exchange (RFC 8693) |
| Identity | OpenID Connect, SAML 2.0, SCIM 2.0 |
| Signals | Shared Signals Framework, CAEP, RISC |
| Credentials | SD-JWT VC, W3C Verifiable Credentials, OpenID4VCI and OpenID4VP |
| Workload identity | SPIFFE |
| Trust bootstrap | OpenID Federation |
| Agents | Model Context Protocol, Agent2Agent |

## License

[Apache License 2.0](../../LICENSE).
