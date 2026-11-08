# @suiss/access-react

The Access components a product embeds: the **Why?** panel, the **status ladder** and the **step-up** prompt. Every Suiss product and any third-party app gets the same components under the same contract.

They are renderers. They show the Access data you pass them and hand requests back through callbacks; they keep no copy of authority state, decide nothing and send nothing on their own.

## Components

- **`WhyPanel`** says where an answer comes from ("From the decision record" or "Advisory — not recorded") and whether it is the decision as made then or what would happen if asked now. Each owner's rule is its own line, never merged, and "What could change this" lists only real actions. A deeper level (details, audit) is offered only when you pass its content, so a viewer never sees a depth they may not.
- **`StatusLadder`** shows the six steps — requested, approval recorded, gate satisfied, allowed or not, started, reported — each with its owner and its state in words. No step is inferred from another: allowed is not started, and unknown is neither failed nor done.
- **`StepUp`** asks the person to confirm it's them and starts the ceremony. There is no "remember this".
- **`honesty`** holds the rules for what to show after an authority-changing request: "Submitted" until Access records it, "Not confirmed — checking" when the answer is lost, a retry with the same nonce while the request is still valid, and "Not recorded — try again" only when nothing was ever sent.

`@suiss/access-react/elements` registers `<access-status-ladder>` and `<access-why>` custom elements for pages without React; set their `data` property.

Texts come from a catalogue you pass as `catalogue`; English is the fallback.

## Develop

```sh
npm ci
npm run lint && npm run typecheck && npm run format:check
npm test
```

## License

Apache-2.0.
