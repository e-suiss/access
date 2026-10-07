# Access at a glance

English translation of the "Kısaca Access" section of the specification. The specification is written in Turkish; its numbered sections are normative and win on any conflict. Section references (§) and IDs point into [`spec/`](spec/README.md).

## What is Access?

Access is Suiss's **identity and authority product**. It is a single product made of two planes:

- **Identity plane: a complete identity provider (IdP).** It authenticates people (customers, employees, developers, administrators), services, devices and AI agents. It manages accounts, passwords, passkeys and sessions, and speaks the standard protocols: OIDC/OAuth 2.1, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation and MCP. It does the job of Keycloak, Okta, Auth0 or Clerk. (§10–§12)
- **Authority plane.** It records where an authority comes from, how it is delegated from whom to whom, and within which bounds. When an action is requested it decides **ALLOW**, **DENY**, or **REQUIRE_ACTION** (stating what is missing), and produces an immutable, verifiable record of that decision. (§5–§9)

The single question Access answers (§1.6):

> **"May this actor, on this authority, do this exact thing now?"**

## What problem does it solve?

**The core problem: legitimacy of authority exercise** (§1.3). Determining whether an actor — acting for itself or on behalf of someone else — may legitimately use an authority, through an explicit and verifiable chain from the authority's source to this use.

The problem breaks down into five questions:

| # | Question | Access's answer |
|---|---|---|
| 1 | **Who is acting?** | The concrete running instance (Instance) and its authentication assurance. The identity plane answers this as a full IdP |
| 2 | **On whose authority?** | The authority's root, the delegation chain, and the capacity (on one's own behalf / on behalf of someone else) |
| 3 | **Within which bounds?** | Scope, amount, time, purpose, budget. Bounds **only narrow** along the chain, never widen |
| 4 | **Can it be used now, for exactly this?** | A decision made by checking required approvals, proofs, revocation state and restrictions |
| 5 | **What was used?** | An immutable record of which authority was used for which action |

**Why now?** AI agents do almost everything **on behalf of someone else**. Today's IdPs answer "who is this?" well, but not "on whose authority, within which bounds, may this agent do this right now — and how do we prove it afterwards?". If everyone acted only on their own behalf, Access would reduce to an IdP plus an access list. In the agentic world that is not the case; this is why Access exists.

A product using Access reliably gets seven things (§1.4): **actor** (who), **representation and provenance** (on whose behalf, where the authority comes from), **bounds**, **decision**, **continuity** (revocation takes effect from the moment it is committed), **record** (what was used) and **portability** (records are verifiable across organizations without asking Access).

## What it is not

| Access is not ... | Owner of that job | Access's role there |
|---|---|---|
| The system that executes the work (makes the payment, sends the message) | Executor and domain products | Defines the bounds of the work and decides whether it may be done (F7) |
| The owner of business data and business rules ("is this order valid?") | Domain products (Commerce, Serve…) | Uses the domain's claims as input |
| A work coordination or approval-collection system | Work | Decides approval authority |
| A payment or money system | Pay, Money | Decides payment authority and budget |
| A notification or delivery system | Relay | Defines what needs to be notified |
| An agent runtime or orchestrator | One, Executor Runtime | Manages the agent's identity and authority |
| A KYC / remote identity-proofing application | External KYC providers | Accepts the proofing result as a Claim (IDP-34) |
| A Windows domain server replacing Active Directory | AD, Samba AD | Works alongside AD (IDP-38) |
| A PAM vault, fraud engine, SIEM or DLP | Separate product layers | Decides the authority part of their work; emits events and signals (IDP-39) |
| A global trust / reputation scoring system | Nobody (forbidden) | — |

Things Access will never do (§2.8, must-never):

- **Logging in does not grant authority.** No login, token, group membership, session or risk score produces authority on its own (INV-12).
- **No impersonation.** Support staff cannot become the user; they act with the user's permission, under their own identity, and on the record (MD-9).
- **No customer code runs inside Access.** Customization is done through data, templates, and call-outs to the customer's own servers (F23).
- **Fail closed.** If something cannot be verified, the answer is not ALLOW (MD-8).

## Core concepts

**Concepts everyone should know:**

| Concept | Meaning | Example |
|---|---|---|
| **Party** | A person or organization with rights and responsibilities: human, company, agent, service | Ayşe; Acme Inc.; Acme's purchasing agent |
| **Instance** | The concrete acting occurrence of a Party: a session on a given device, a running agent process | Ayşe's session on her work laptop; the agent's run started today |
| **Claim** | Someone's **assertion** about something; not the truth itself, but a record of who said what | HR: "Ayşe is in Finance"; IdP: "Ayşe signed in with a passkey" |
| **Acceptance** | An explicit, revocable decision about whose claims are trusted, and for what purpose. The only meaning of "trust" in Access | "We use the HR system's department data for authority selection" |
| **Grant** | An explicit conferral of authority; the **only** source of authority. Delegation is also a Grant | The finance manager grants the purchasing agent "supplier orders up to EUR 100,000 per month" |
| **Mandate** | The subset of a Party's authority usable by a specific Instance. Holding an authority does not mean being able to use it everywhere | The agent holds the authority, but in this run may use it only up to EUR 10,000 |
| **Authority Exercise** | The use of an authority for a specific action at a specific moment, together with its decision and record. Access's **unit of value** | The agent placing a EUR 50,000 order with Company B at 14:02 |
| **Decision** | Access's verdict: **ALLOW**, **DENY**, or **REQUIRE_ACTION** stating what is missing | REQUIRE_ACTION: "This amount requires the finance manager's approval" |

**Other authority-model concepts:**

| Concept | Meaning |
|---|---|
| **AuthorityDomain** | The scope in which authority records are kept, with a single source of truth; usually an organization |
| **AuthorityAnchor and root** | The point where authority over a resource begins, and that authority's ultimate holder |
| **RestrictionPolicy** | A rule that grants nothing; it only forbids or adds conditions ("no payments on weekends") |
| **Intent / IntentEnvelope** | The exact description of the requested action: what, on which resource, with which parameters, for which purpose |
| **ValidityContract** | How long and under which conditions a decision or artifact remains valid, and how quickly revocation takes effect |
| **Projection** | A short-lived, holder-bound artifact that carries authority outward: a token, an SSH certificate, a signed decision receipt. It is evidence of authority, not authority itself |
| **Consequence Tier (CT0–CT3)** | The risk class of an action, from reads (CT0) to irreversible and critical actions (CT3). Required assurance rises accordingly |

**Identity-plane concepts:** **Tenant** (commercial customer), **Identity Realm** (an isolated identity space where a customer's users live), user record, credential (password, passkey), session, application (client) and connected external IdP. These reach the authority plane only as Claims (§5.16, §5.17).

**Core principles:**

1. **Authority comes only from Grants.** Roles, groups and tokens are not authority; at most they are inputs that select to whom a Grant applies (MD-4).
2. **Authority only narrows along the chain.** No one can delegate more than they hold.
3. **Holding ≠ being able to exercise.** Not every Instance of a Party that holds an authority can use it (Mandate).
4. **Every change goes through one path.** Granting, amending and revoking authority are themselves Authority Exercises, with a decision and a record (INV-2).
5. **Revocation is prospective and definitive.** It applies from the moment it is committed, including to ongoing use.
6. **Records are verifiable outside Access.** A counterparty or auditor can check that a decision is genuine and valid without asking Access (§1.4, promise 7).
