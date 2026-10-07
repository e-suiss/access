# Architecture

C4-style diagrams in Mermaid (OP-70). The container view mirrors the process topology in the specification (§16.4.2, OP-2); on any difference, the specification wins.

## Context

```mermaid
flowchart LR
    users["People<br/>(customers, employees, admins)"]
    agents["AI agents"]
    apps["Customer applications<br/>(OIDC/SAML relying parties, PEPs)"]
    upstream["Upstream IdPs / HR systems<br/>(SAML, OIDC, SCIM)"]
    saas["SaaS service providers<br/>(Salesforce, Slack, AWS, ...)"]
    verifiers["Counterparties and auditors<br/>(offline verification)"]
    suiss["Other Suiss products<br/>(Work, Pay, Relay, One)"]

    access(["Access<br/>identity plane + authority plane"])

    users -->|sign in, consent, approvals| access
    agents -->|identity, authority requests| access
    apps -->|authN, decisions, management API| access
    upstream -->|federated identity, provisioning| access
    access -->|SSO, outbound SCIM| saas
    access -->|signed decision records| verifiers
    suiss <-->|decisions, events, approvals| access
```

## Containers

```mermaid
flowchart TB
    subgraph authority["Authority cell"]
        acore["Authority core<br/>gateway, request verifier, sequencer,<br/>Access Core + Kernel, ingest, checkpointer,<br/>projection issuer, outbox/SSF, export"]
        aquery["Authority derived/query<br/>derived store, query service"]
        asigner["Authority signer<br/>(no network, seccomp/Landlock)"]
        astore[("Authority store<br/>PostgreSQL: domain log, outbox")]
    end

    subgraph identity["Identity cell"]
        icore["Identity core<br/>OIDC OP / OAuth AS, sessions, accounts,<br/>SCIM, admin API, hosted UI, WebAuthn,<br/>federation, audit & signals"]
        isigner["Identity signer<br/>(realm JOSE keys)"]
        istore[("Identity store<br/>PostgreSQL, PII vault")]
    end

    subgraph edge["Edge gateways"]
        gw["SAML · LDAP · Kerberos · RADIUS · WS-Fed<br/>(one process each)"]
        pw["Parser workers<br/>(XML, ASN.1; disposable)"]
    end

    subgraph companions["Companion services"]
        exec["Executor"]
        proxy["Access Proxy<br/>(Envoy or Caddy)"]
        iys["İYS service"]
    end

    nats{{"NATS"}}
    kms[("KMS / HSM")]
    witness(["Witnesses / replica"])

    acore --> astore
    aquery --> astore
    acore --> asigner
    acore --> nats
    acore --> witness
    asigner --> kms

    icore --> istore
    icore --> isigner
    isigner --> kms
    icore -->|internal API: Claims only| acore

    gw -->|internal API| icore
    gw --> pw

    exec -->|public decision API| acore
    proxy -->|forward-auth / ext_authz| acore
    iys -->|webhooks| icore
```

Notes:
- The authority core has no access to the identity store; the identity plane passes identity to the authority plane only as Claims (INV-12, SEC19).
- Signers hold key material outside the HTTP processes and have no network syscalls (OP-2, MD-6).
- Companion services use only public APIs and crates; they have no privileged path (B21–B23, OP-62).
