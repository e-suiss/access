# @suiss/access-react

The Access components a product embeds: the **Why?** panel, the **status ladder**, the **step-up** prompt and the **agent** surfaces. Every Suiss product and any third-party app gets the same components under the same contract.

They are renderers. They show the Access data you pass them and hand requests back through callbacks; they keep no copy of authority state, decide nothing and send nothing on their own.

## Components

- **`WhyPanel`** says where an answer comes from ("From the decision record" or "Advisory — not recorded") and whether it is the decision as made then or what would happen if asked now. Each owner's rule is its own line, never merged, and "What could change this" lists only real actions. A deeper level (details, audit) is offered only when you pass its content, so a viewer never sees a depth they may not.
- **`StatusLadder`** shows the six steps — requested, approval recorded, gate satisfied, allowed or not, started, reported — each with its owner and its state in words. No step is inferred from another: allowed is not started, and unknown is neither failed nor done.
- **`StepUp`** asks the person to confirm it's them and starts the ceremony. There is no "remember this".
- **`honesty`** holds the rules for what to show after an authority-changing request: "Submitted" until Access records it, "Not confirmed — checking" when the answer is lost, a retry with the same nonce while the request is still valid, and "Not recorded — try again" only when nothing was ever sent.

- **`agents`** renders agents as agents. `AgentBadge` reads "Agent · Acting for _X_ · operated by _Y_" and an agent never gets a person badge. `OutcomeLabels` shows what a runtime reported about a use, with who reported it and how ("Done as approved, reported by _Y_"), never the agent's own account of it. `StopRows` shows Stop as two rows, the runtime's and Access's, never one "Stopped". `AgentConnections` lists the accounts connected for agents and which agent used each, with one-click Disconnect. `DelegationSuggestion` turns repeated approvals into a suggestion that only opens the exact delegation preview. The `agents` model also reads a runtime's state only from what the runtime confirmed and words the aftermath of a revocation honestly before and after a task's next authority check.

- **`sso.OrganizationSSO`** is the organization SSO setup portal: it renders what a one-use setup link opens (`GET /v1/sso-setup/{link}`) — the identity provider wizard's steps for the chosen protocol, the values to copy into the provider, the fields to paste back, the domains with their TXT records and the SCIM address — and hands each step to your `onSubmit`, which posts it with the SDK's `sso.submitSetup`. What it saves is a draft; the connection test stays off until an owner of the organization turns the connection on. The hosted setup page is the same component.
- **`payment`** holds the payment surfaces. `LimitRows` shows a Grant's authority limit, as Access recorded it, and Pay's financial limit and hold, as Pay stated them, as separate rows under their owners' badges; neither is added to or derived from the other. `OneTimePayment` shows exactly what the decoded intent pays ("Pay 300 TRY to M, once") and refuses a request that would let the merchant charge again. `SaveCard` is the separate "let M charge your card" preview. `Merchants` lists the merchants that can charge the viewer, with "AI agent · acting for M" for a merchant's agent, Stop charges for Access's delegation and Pay's own agreements and consents as separate rows linked to it; what a merchant decides inside its business is not shown.
- **`offline.OfflineStatus`** shows a till's offline window from its declared profile and slice counter ("Offline since 14:02 · can act offline until 18:00 … · 3 voids and 2,000 TRY left"), and once the window ends only that the till must go online.
- **`delegationPage.DelegationPage`** is the delegation page One, Work, Pay and third-party agent apps embed: it renders the experience service's hub with each row's owner, capacity, status, source ("Sync from HR") and both limits, the "Notifications are delayed" and "Authority can't be changed right now" notices, and the coordinator's "N approvals waiting for you →" link. Revoke goes back to your `onRevoke`.
- **`support`** holds support access without impersonation. `SupportRequest` is the person's own "Give _Acme Support_ access" sheet with the exact terms ("view your account settings · case 4411 · for 60 minutes · can't change sign-in methods, payments or email · can't pass on") and "Give access" / "Don't give access"; the operator who asked never opens it. `SupportBanner` is the operator's lasting banner ("Acting for _Ayşe K._ with their support access (case 4411) · read-only · ends 15:30 · every action is recorded under your name"), and `SupportView` renders nothing without it. `SupportActions` offers "Request support access" and "Emergency access (break-glass)" where a support tool would otherwise "log in as" someone.

`@suiss/access-react/elements` registers `<access-status-ladder>`, `<access-why>`, `<access-agent-badge>` and `<access-agent-connections>` custom elements for pages without React; set their `data` property. `<access-agent-connections>` asks the host to disconnect with an `access-disconnect` event.

Texts come from a catalogue you pass as `catalogue`; English is the fallback.

**`Catalogs`** reads Access's Fluent files (`locales/<locale>/*.ftl`) with no dependency, by the same rules as the server: only messages, continuation lines and `{ $name }` placeables (no selectors, terms or attributes), and the fallback chain realm locale → realm language → Access locale → Access language → `en`. A protected key (`conformance/catalog/protected-messages.toml`) is never taken from a realm's overrides. `catalogue(locale)` gives the flat map the components take.

## Develop

```sh
npm ci
npm run lint && npm run typecheck && npm run format:check
npm test
```

## License

Apache-2.0.
