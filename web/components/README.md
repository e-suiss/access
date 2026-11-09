# @suiss/access-react

The Access components a product embeds: the **Why?** panel, the **status ladder**, the **step-up** prompt and the **agent** surfaces. Every Suiss product and any third-party app gets the same components under the same contract.

They are renderers. They show the Access data you pass them and hand requests back through callbacks; they keep no copy of authority state, decide nothing and send nothing on their own.

## Components

- **`WhyPanel`** says where an answer comes from ("From the decision record" or "Advisory — not recorded") and whether it is the decision as made then or what would happen if asked now. Each owner's rule is its own line, never merged, and "What could change this" lists only real actions. A deeper level (details, audit) is offered only when you pass its content, so a viewer never sees a depth they may not.
- **`StatusLadder`** shows the six steps — requested, approval recorded, gate satisfied, allowed or not, started, reported — each with its owner and its state in words. No step is inferred from another: allowed is not started, and unknown is neither failed nor done.
- **`StepUp`** asks the person to confirm it's them and starts the ceremony. There is no "remember this".
- **`honesty`** holds the rules for what to show after an authority-changing request: "Submitted" until Access records it, "Not confirmed — checking" when the answer is lost, a retry with the same nonce while the request is still valid, and "Not recorded — try again" only when nothing was ever sent.

- **`agents`** renders agents as agents. `AgentBadge` reads "Agent · Acting for _X_ · operated by _Y_" and an agent never gets a person badge. `OutcomeLabels` shows what a runtime reported about a use, with who reported it and how ("Done as approved, reported by _Y_"), never the agent's own account of it. `StopRows` shows Stop as two rows, the runtime's and Access's, never one "Stopped". `AgentConnections` lists the accounts connected for agents and which agent used each, with one-click Disconnect. `DelegationSuggestion` turns repeated approvals into a suggestion that only opens the exact delegation preview. The `agents` model also reads a runtime's state only from what the runtime confirmed and words the aftermath of a revocation honestly before and after a task's next authority check.

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
